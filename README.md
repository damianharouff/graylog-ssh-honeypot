# Python SSH Honeypot

A lightweight SSH honeypot that logs connection attempts and credentials to Graylog via GELF UDP.

## Features

- Captures SSH login attempts (username/password)
- Logs to Graylog via GELF UDP protocol
- Runs as non-root user with minimal privileges
- JSON configuration file
- Graceful shutdown handling

## Requirements

- Python 3
- paramiko
- graypy

```bash
apt install python3-paramiko python3-graypy
```

## Quick Start

```bash
# Generate RSA host key
ssh-keygen -t rsa -f server.key -N ''

# Create config file
cp config.json.example config.json
# Edit config.json with your Graylog server details

# Run (requires root for port 22, or use a high port)
python3 honeypot.py -c config.json
```

## Configuration

Create a `config.json` file:

```json
{
    "key_path": "/opt/honeypot/server.key",
    "ssh_port": 22,
    "gelf_host": "graylog.example.com",
    "gelf_port": 12201
}
```

Command-line options override config file values:

```
-c, --config    Path to config file (default: /opt/honeypot/config.json)
-k, --key       Path to RSA host key
-p, --port      SSH port to listen on
--gelf-host     Graylog GELF UDP host
--gelf-port     Graylog GELF UDP port
```

## Production Deployment

### Setup

```bash
# Create dedicated user
useradd -r -s /usr/sbin/nologin honeypot

# Setup directory
mkdir -p /opt/honeypot
cp honeypot.py /opt/honeypot/
cp config.json.example /opt/honeypot/config.json
ssh-keygen -t rsa -f /opt/honeypot/server.key -N ''
chown -R honeypot:honeypot /opt/honeypot
chmod 600 /opt/honeypot/server.key

# Edit config with your Graylog server
nano /opt/honeypot/config.json

# Install systemd service
cp honeypotpy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now honeypotpy
```

### Security

The systemd unit runs with:
- Dedicated non-root user (`honeypot`)
- Only `CAP_NET_BIND_SERVICE` capability (for port 22)
- Read-only filesystem access
- Private `/tmp`
- Kernel hardening options

## Logged Data

Each authentication attempt sends a GELF message with:

| Field | Description |
|-------|-------------|
| `source_ip` | Attacker's IP address |
| `source_port` | Attacker's source port |
| `username` | Attempted username |
| `password` | Attempted password |

## Graylog Setup

1. Create a GELF UDP input in Graylog (System → Inputs)
2. Set the port to 12201 (or your chosen port)
3. Configure firewall to allow UDP traffic on the GELF port

## License

MIT
