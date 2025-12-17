# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a simple SSH honeypot that logs connection attempts to a Graylog server via GELF UDP. It captures source IPs of SSH connection attempts but always rejects authentication.

## Dependencies

- Python 3
- paramiko (`apt install python3-paramiko`)
- graypy (`apt install python3-graypy`)

## Running the Honeypot

```bash
# Generate RSA key first (required)
ssh-keygen -t rsa -f server.key

# Run directly (requires root for port 22)
python3 honeypot.py

# With custom options
python3 honeypot.py -k ./server.key -p 2222 --gelf-host 192.168.1.10 --gelf-port 12201
```

## Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-k, --key` | `/opt/honeypot/server.key` | Path to RSA host key |
| `-p, --port` | `22` | SSH port to listen on |
| `--gelf-host` | `localhost` | Graylog GELF UDP host |
| `--gelf-port` | `12201` | Graylog GELF UDP port |

## Systemd Deployment

The `honeypotpy.service` file provides a systemd unit for running as a dedicated non-root user.

```bash
# Create dedicated user
useradd -r -s /usr/sbin/nologin honeypot

# Setup directory
mkdir -p /opt/honeypot
cp honeypot.py /opt/honeypot/
ssh-keygen -t rsa -f /opt/honeypot/server.key -N ''
chown -R honeypot:honeypot /opt/honeypot
chmod 600 /opt/honeypot/server.key

# Install and enable service
cp honeypotpy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now honeypotpy
```

## Architecture

Single-file honeypot using:
- `paramiko.ServerInterface` subclass (`SSHServerHandler`) that always returns `AUTH_FAILED`
- Main socket server accepting connections and spawning `threading.Thread` for each connection
- Graceful shutdown via SIGINT/SIGTERM signal handling

## Logged Data (GELF)

Each SSH login attempt logs to Graylog with:
- `source_ip`: Attacker's IP address
- `source_port`: Attacker's source port
- `username`: Attempted username
- `password`: Attempted password
