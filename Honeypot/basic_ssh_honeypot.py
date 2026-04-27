# Honeypot using Docker.py -- logs attacker behavior in structured format and fingerprints SSH clients

import json
import logging
import os
import socket
import threading
import time
import hashlib
from pathlib import Path
from typing import Tuple, TypedDict, Dict, Any

import paramiko
from paramiko.ssh_exception import SSHException
from paramiko.common import (
    AUTH_SUCCESSFUL,
    OPEN_SUCCEEDED,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
)
from threading import Event

# ---- settings ----

class Settings(TypedDict):
    host: str
    port: int
    keyfile: str
    logfile: str
    banner: str
    welcome: str


settings: Settings = {
    "host": "0.0.0.0",
    "port": 2222,
    "keyfile": "server.key",
    "logfile": "honeypot.log",
    "banner": "SSH-2.0-OpenSSH_7.4p1 Honeypot\r\n",
    "welcome": "Welcome to Ubuntu 24.04 LTS\r\n",
}

# ---- helpers ----

def b(s: str | bytes, encoding: str = "utf8") -> bytes:
    return s.encode(encoding) if isinstance(s, str) else s


def u(s: bytes | str, encoding: str = "utf8") -> str:
    return s.decode(encoding) if isinstance(s, (bytes, bytearray)) else str(s)


# ---- logging ----

logging.basicConfig(
    filename=settings["logfile"],
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("honeypot")

json_log = Path("honeypot.json")


def log_json(event: Dict[str, Any]) -> None:
    event["timestamp"] = time.time()
    with json_log.open("a") as f:
        f.write(json.dumps(event) + "\n")


# ---- credential tracking ----

credential_db: Dict[str, int] = {}
connection_counts: Dict[str, int] = {}

# ---- fingerprinting ----

def fingerprint_transport(t: paramiko.Transport) -> Dict[str, Any]:
    return {
        "client_version": getattr(t, "remote_version", None),
        "cipher": getattr(t, "remote_cipher", None),
        "mac": getattr(t, "remote_mac", None),
        "compression": getattr(t, "remote_compression", None),
        "kex": getattr(t, "kex_engine", None).__class__.__name__
        if getattr(t, "kex_engine", None)
        else None,
    }


# ---- fake shell ----

class FakeShell:
    def __init__(self) -> None:
        self.cwd = "/home/admin"

        self.files: Dict[str, str] = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
            "/proc/version": "Linux version 4.4.0-21-generic (gcc version 5.3.1)\n",
            "/etc/hostname": "ubuntu-server\n",
        }

        self.dirs: Dict[str, list[str]] = {
            "/": ["etc", "home", "var", "proc"],
            "/home": ["admin"],
            "/home/admin": ["notes.txt", "secrets.txt"],
            "/etc": ["passwd", "hostname"],
            "/var": ["log"],
            "/var/log": ["auth.log", "syslog"],
            "/proc": ["version"],
        }

    def handle(self, command: str) -> str:
        parts = command.strip().split()
        if not parts:
            return ""

        cmd = parts[0]

        if cmd == "ls":
            return "\n".join(self.dirs.get(self.cwd, [])) + "\r\n"

        if cmd == "pwd":
            return self.cwd + "\r\n"

        if cmd == "whoami":
            return "admin\r\n"

        if cmd == "cd":
            if len(parts) > 1 and parts[1] in self.dirs:
                self.cwd = parts[1]
            return ""

        if cmd == "cat" and len(parts) > 1:
            return self.files.get(parts[1], "No such file\r\n")

        if cmd == "uname":
            return "Linux ubuntu 4.4.0-21-generic x86_64\r\n"

        return f"{cmd}: command not found\r\n"


# ---- key handling ----

def ensure_host_key(path: str) -> paramiko.PKey:
    if not os.path.exists(path):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(path)
        return key
    return paramiko.RSAKey(filename=path)


HOST_KEY = ensure_host_key(settings["keyfile"])


# ---- SSH server interface ----

class SimpleServer(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.event = Event()

    # authentication
    def check_auth_password(self, username: str, password: str) -> int:
        cred_key = f"{username}:{password}"
        credential_db[cred_key] = credential_db.get(cred_key, 0) + 1

        log_json({
            "event": "auth",
            "username": username,
            "password": password,
            "reuse": credential_db[cred_key],
        })

        return AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    # channel handling
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # IMPORTANT FIXES
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self,
        channel,
        term,
        width,
        height,
        pixelwidth,
        pixelheight,
        modes,
    ):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


# ---- client handler ----

def handle_client(client_sock: socket.socket, addr: Tuple[str, int]) -> None:
    ip = addr[0]
    connection_counts[ip] = connection_counts.get(ip, 0) + 1

    session_id = hashlib.md5(f"{addr}{time.time()}".encode()).hexdigest()

    transport = None

    try:
        client_sock.settimeout(10.0)
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)

        server = SimpleServer()
        transport.start_server(server=server)

        chan = transport.accept(10)
        if chan is None:
            return

        # NOW wait for shell request
        if not server.event.wait(10):
            return

        shell = FakeShell()

        chan.send(b(settings["welcome"]))
        chan.send(b("$ "))

        while True:
            data = chan.recv(1024)
            if not data:
                break

            text = u(data).strip()

            log_json({
                "event": "command",
                "input": text,
                "session": session_id,
                "src_ip": ip,
            })

            if text.lower() == "exit":
                chan.send(b("logout\r\n"))
                break

            output = shell.handle(text)
            chan.send(b(output + "$ "))

    except SSHException:
        pass
    except OSError:
        pass
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


# ---- server loop ----

def serve_forever(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)

        print(f"Listening on {host}:{port}")

        while True:
            client, addr = sock.accept()

            thread = threading.Thread(
                target=handle_client,
                args=(client, addr),
                daemon=True,
            )
            thread.start()

    finally:
        sock.close()


if __name__ == "__main__":
    serve_forever(settings["host"], settings["port"])