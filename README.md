# Container-Honeypot
Dockerized SSH Honeypot

A lightweight Python SSH honeypot that logs attacker behavior (auth attempts and commands) in structured JSON and provides a fake shell environment. Designed to run inside Docker for easy deployment and isolation.

**Features**
Listens for SSH connections (default port 2222)
Accepts any username/password and logs credentials with reuse counts
Logs commands, session IDs, and source IPs in JSON lines file
Fingerprints some SSH transport properties
Simple fake shell with basic commands (ls, pwd, whoami, cd, cat, uname)
Generates an RSA host key if none exists
Runs with Paramiko and standard Python libraries
Intended for research and defensive monitoring (do not deploy on production networks without authorization)

**Files**
basic_ssh_honeypot.py — main honeypot implementation (the provided code)
Dockerfile — container image build file (example below)
requirements.txt — Python dependencies (Paramiko)
honeypot.log — text logfile (logging module)
honeypot.json — structured JSONL logfile (one JSON object per line)
Quick start (Docker)

Dockerfile


FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code and set permissions
COPY basic_ssh_honeypot.py

((NOTE - This code worked with Docker 4.48 [most current version when this was published was 4.7]))

EXPOSE 2222

CMD ["python", "honeypot.py"]
requirements.txt


paramiko>=2.11
Build the image:


docker build -t ssh-honeypot:latest .
Run the container (bind port and persist logs/host key):


docker run -d \
  --name ssh-honeypot \
  -p 2222:2222 \
  -v /path/on/host/honeypot.json:/app/honeypot.json \
  -v /path/on/host/server.key:/app/server.key \
  ssh-honeypot:latest
Notes:

Mount a host directory/file for honeypot.json to retain logs outside the container.
Mount a server.key if you want a persistent host key; otherwise the honeypot generates one inside the container.
Configuration
Edit top of honeypot.py to change settings:

python


settings = {
    "host": "0.0.0.0",
    "port": 2222,
    "keyfile": "server.key",
    "logfile": "honeypot.log",
    "banner": "SSH-2.0-OpenSSH_7.4p1 Honeypot\r\n",
    "welcome": "Welcome to Ubuntu 24.04 LTS\r\n",
}
host: bind address (0.0.0.0 for all interfaces)
port: listening TCP port
keyfile: path to RSA private key (generated if missing)
logfile: human-readable log file (via logging)
banner: SSH banner string (currently unused by Paramiko Transport remote_version handling)
welcome: initial text sent to clients after login

**What it logs**
Authentication events:
event: "auth"
username, password, reuse (count for that credential pair)
timestamp (epoch seconds)
Commands:
event: "command"
input (command text), session (md5 session id), src_ip
timestamp
Log lines are appended to honeypot.json as JSON objects (one per line). A separate honeypot.log file receives INFO-level text logs.

**Fake shell**
Implements a minimal simulated filesystem and responses: ls, pwd, whoami, cd, cat, uname
Unknown commands respond with "command: command not found"
This is intentionally simple to encourage attacker interaction while preventing any real filesystem access.

**Security & Legal**
Run only in controlled, authorized environments.
Do not expose this to networks you do not own or control.
This honeypot intentionally accepts and records credentials — treat logs as sensitive.

**Development notes**
Uses Paramiko's ServerInterface to accept password auth and open a session channel.
Always returns AUTH_SUCCESSFUL to capture attacker behavior.
Host key generation uses Paramiko RSAKey.generate(2048) if server.key missing.
Session IDs are MD5 of addr+time (non-cryptographic identifier only).

**License**
GNU GENERAL PUBLIC LICENSE - Version 3, 29 June 2007.
