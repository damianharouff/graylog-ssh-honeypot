#!/usr/bin/env python3
import argparse
import logging
import signal
import socket
import sys
import threading

import paramiko  # apt install python3-paramiko
import graypy  # apt install python3-graypy

# Default configuration
DEFAULT_KEY_PATH = '/opt/honeypot/server.key'
DEFAULT_SSH_PORT = 22
DEFAULT_GELF_HOST = 'localhost'
DEFAULT_GELF_PORT = 12201

# Global flag for graceful shutdown
shutdown_event = threading.Event()


def setup_logger(gelf_host, gelf_port):
    """Configure and return the Graylog logger."""
    logger = logging.getLogger('python-ssh-honeypot')
    logger.setLevel(logging.INFO)
    handler = graypy.GELFUDPHandler(gelf_host, gelf_port, debugging_fields=False)
    logger.addHandler(handler)
    return logger


class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self, client_addr, logger):
        self.client_addr = client_addr
        self.logger = logger
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        # Log the credential attempt with source IP
        self.logger.info(
            'SSH login attempt',
            extra={
                'source_ip': self.client_addr[0],
                'source_port': self.client_addr[1],
                'username': username,
                'password': password,
            }
        )
        return paramiko.AUTH_FAILED


def handle_connection(client_socket, client_addr, host_key, logger):
    """Handle a single SSH connection."""
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        server_handler = SSHServerHandler(client_addr, logger)
        transport.start_server(server=server_handler)

        # Wait for a channel request with timeout
        channel = transport.accept(1)
        if channel is not None:
            channel.close()

    except paramiko.SSHException as e:
        logger.warning(
            'SSH exception during connection handling',
            extra={
                'source_ip': client_addr[0],
                'error': str(e),
            }
        )
    except Exception as e:
        logger.error(
            'Unexpected error during connection handling',
            extra={
                'source_ip': client_addr[0],
                'error': str(e),
            }
        )
    finally:
        if transport is not None:
            transport.close()


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    print(f'\nReceived signal {signum}, shutting down...')
    shutdown_event.set()


def main():
    parser = argparse.ArgumentParser(description='SSH Honeypot Server')
    parser.add_argument(
        '-k', '--key',
        default=DEFAULT_KEY_PATH,
        help=f'Path to RSA host key (default: {DEFAULT_KEY_PATH})'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=DEFAULT_SSH_PORT,
        help=f'SSH port to listen on (default: {DEFAULT_SSH_PORT})'
    )
    parser.add_argument(
        '--gelf-host',
        default=DEFAULT_GELF_HOST,
        help=f'Graylog GELF UDP host (default: {DEFAULT_GELF_HOST})'
    )
    parser.add_argument(
        '--gelf-port',
        type=int,
        default=DEFAULT_GELF_PORT,
        help=f'Graylog GELF UDP port (default: {DEFAULT_GELF_PORT})'
    )
    args = parser.parse_args()

    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load host key
    try:
        host_key = paramiko.RSAKey(filename=args.key)
    except FileNotFoundError:
        print(f"ERROR: Host key not found at {args.key}")
        print("Generate one with: ssh-keygen -t rsa -f server.key")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"ERROR: Failed to load host key: {e}")
        sys.exit(1)

    # Setup logger
    logger = setup_logger(args.gelf_host, args.gelf_port)

    # Create server socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(1.0)  # Allow periodic check of shutdown_event
        server_socket.bind(('', args.port))
        server_socket.listen(100)
        print(f'SSH Honeypot Server started on port {args.port}')
    except OSError as e:
        print(f"ERROR: Failed to create socket: {e}")
        sys.exit(1)

    # Main accept loop
    try:
        while not shutdown_event.is_set():
            try:
                client_socket, client_addr = server_socket.accept()
                print(f'Connection received from: {client_addr[0]}:{client_addr[1]}')

                # Start handler thread
                thread = threading.Thread(
                    target=handle_connection,
                    args=(client_socket, client_addr, host_key, logger),
                    daemon=True
                )
                thread.start()

            except socket.timeout:
                # This is expected - allows checking shutdown_event
                continue
            except OSError as e:
                if not shutdown_event.is_set():
                    print(f"ERROR: Client handling failed: {e}")

    finally:
        server_socket.close()
        print('SSH Honeypot Server stopped.')


if __name__ == '__main__':
    main()
