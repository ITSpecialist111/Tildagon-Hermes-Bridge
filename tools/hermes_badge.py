#!/usr/bin/env python3

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import socket
import struct
import sys
import time


TRUSTED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
DEFAULT_PORT = 8266
DEFAULT_DEPLOY_PORT = 8267
REQUEST_FORMAT = "<2sBBQLH64s"
PUT_FILE = 1
GET_FILE = 2
GET_VERSION = 3
TEXT_FRAME = 0x1
BINARY_FRAME = 0x2


class BridgeError(RuntimeError):
    pass


def validate_password(password):
    try:
        encoded = password.encode("ascii")
    except (AttributeError, UnicodeError) as error:
        raise BridgeError("The WebREPL pairing PIN must be ASCII") from error
    if len(encoded) != 9:
        raise BridgeError("The WebREPL pairing PIN must contain exactly 9 characters")
    return password


def validate_target(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise BridgeError("Badge host must be a literal IPv4 address") from error
    network = next((item for item in TRUSTED_NETWORKS if address in item), None)
    if network is None or address in (network.network_address, network.broadcast_address):
        raise BridgeError("Badge host must be an RFC 1918 private IPv4 address")
    return str(address)


def read_password(path):
    password_path = Path(path).expanduser()
    try:
        password = password_path.read_text(encoding="ascii").strip()
    except OSError as error:
        raise BridgeError("Cannot read the WebREPL password file") from error
    except UnicodeError as error:
        raise BridgeError("The WebREPL password must be ASCII") from error

    if os.name != "nt" and password_path.stat().st_mode & 0o077:
        raise BridgeError("The WebREPL password file must have mode 600")
    return validate_password(password)


def save_password(path, password):
    password = validate_password(password)
    password_path = Path(path).expanduser()
    password_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        password_path.parent.chmod(0o700)
    password_path.write_text(password + "\n", encoding="ascii")
    if os.name != "nt":
        password_path.chmod(0o600)
    return password_path


def normalise_app_name(name):
    normalised = name.replace("-", "_")
    if not normalised or any(
        not (character.isalnum() or character == "_") for character in normalised
    ):
        raise BridgeError("App name may contain only letters, digits, '_' or '-'")
    return normalised


def collect_deployment(source, app_name=None):
    source = Path(source).resolve()
    for required in ("app.py", "metadata.json", "tildagon.json"):
        if not (source / required).is_file():
            raise BridgeError("Deployment source is missing " + required)

    remote_root = PurePosixPath("/apps") / normalise_app_name(app_name or source.name)
    files = []
    directories = {PurePosixPath("/apps"), remote_root}
    for local_path in sorted(source.rglob("*")):
        relative = local_path.relative_to(source)
        if any(part.startswith(".") or part == "__pycache__" for part in relative.parts):
            continue
        if local_path.is_symlink():
            raise BridgeError("Symbolic links are not supported: " + str(relative))
        if not local_path.is_file() or local_path.suffix in (".pyc", ".mpy"):
            continue

        remote_path = remote_root.joinpath(*relative.parts)
        if len(str(remote_path).encode("utf-8")) > 64:
            raise BridgeError("Remote path exceeds WebREPL's 64-byte limit: " + str(remote_path))
        files.append((local_path, str(remote_path)))

        parent = remote_path.parent
        while parent != PurePosixPath("/"):
            directories.add(parent)
            parent = parent.parent

    return sorted(str(path) for path in directories), files


class WebSocketTransport:
    def __init__(self, connection):
        self.connection = connection
        self.binary_buffer = bytearray()
        self.text_buffer = bytearray()

    def send(self, payload, opcode):
        payload = bytes(payload)
        mask = secrets.token_bytes(4)
        length = len(payload)
        if length < 126:
            header = struct.pack(">BB", 0x80 | opcode, 0x80 | length)
        elif length <= 0xFFFF:
            header = struct.pack(">BBH", 0x80 | opcode, 0x80 | 126, length)
        else:
            header = struct.pack(">BBQ", 0x80 | opcode, 0x80 | 127, length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.connection.sendall(header + mask + masked)

    def _receive_exact(self, size):
        result = bytearray()
        while len(result) < size:
            data = self.connection.recv(size - len(result))
            if not data:
                raise BridgeError("WebREPL connection closed unexpectedly")
            result.extend(data)
        return bytes(result)

    def receive_frame(self):
        first, second = struct.unpack(">BB", self._receive_exact(2))
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._receive_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._receive_exact(8))[0]

        mask = self._receive_exact(4) if second & 0x80 else None
        payload = self._receive_exact(length)
        if mask:
            payload = bytes(
                value ^ mask[index % 4] for index, value in enumerate(payload)
            )

        if opcode == 0x8:
            raise BridgeError("WebREPL closed the connection")
        if opcode == 0x9:
            self.send(payload, 0xA)
            return self.receive_frame()
        return opcode, payload

    def read_binary(self, size):
        while len(self.binary_buffer) < size:
            opcode, payload = self.receive_frame()
            if opcode == BINARY_FRAME:
                self.binary_buffer.extend(payload)
            elif opcode == TEXT_FRAME:
                self.text_buffer.extend(payload)
        result = bytes(self.binary_buffer[:size])
        del self.binary_buffer[:size]
        return result

    def read_text_until(self, marker, timeout=10):
        deadline = time.monotonic() + timeout
        while marker not in self.text_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeError("Timed out waiting for the WebREPL prompt")
            self.connection.settimeout(remaining)
            try:
                opcode, payload = self.receive_frame()
            except TimeoutError as error:
                raise BridgeError("Timed out waiting for the WebREPL prompt") from error
            if opcode == TEXT_FRAME:
                self.text_buffer.extend(payload)
            elif opcode == BINARY_FRAME:
                self.binary_buffer.extend(payload)

        end = self.text_buffer.index(marker) + len(marker)
        result = bytes(self.text_buffer[:end])
        del self.text_buffer[:end]
        return result


class WebReplClient:
    def __init__(self, host, password, port=DEFAULT_PORT, timeout=10):
        self.host = validate_target(host)
        self.password = password
        self.port = port
        self.timeout = timeout
        self.connection = None
        self.transport = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()

    def connect(self):
        try:
            self.connection = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
            self._handshake()
            self.transport = WebSocketTransport(self.connection)
            self.transport.read_text_until(b"Password: ", self.timeout)
            self.transport.send(self.password.encode("ascii") + b"\r", TEXT_FRAME)
            response = self.transport.read_text_until(b">>> ", self.timeout)
        except (OSError, UnicodeError) as error:
            self.close()
            raise BridgeError("Could not connect to the badge WebREPL") from error
        if b"Access denied" in response:
            self.close()
            raise BridgeError("Badge rejected the WebREPL credential")

    def _handshake(self):
        key = base64.b64encode(secrets.token_bytes(16))
        request = (
            b"GET / HTTP/1.1\r\n"
            + b"Host: "
            + self.host.encode("ascii")
            + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + b"Sec-WebSocket-Key: "
            + key
            + b"\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.connection.sendall(request)

        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.connection.recv(1)
            if not chunk:
                raise BridgeError("Badge closed the WebSocket handshake")
            response.extend(chunk)
            if len(response) > 8192:
                raise BridgeError("Badge returned an invalid WebSocket handshake")

        header = bytes(response).split(b"\r\n\r\n", 1)[0]
        expected = base64.b64encode(
            hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        )
        if not header.startswith(b"HTTP/1.1 101") or expected.lower() not in header.lower():
            raise BridgeError("Badge returned an invalid WebSocket handshake")

    def close(self):
        if self.connection is not None:
            try:
                if self.transport is not None:
                    self.transport.send(b"", 0x8)
            except OSError:
                pass
            self.connection.close()
        self.connection = None
        self.transport = None

    def _request(self, operation, size=0, filename=b""):
        request = struct.pack(
            REQUEST_FORMAT, b"WA", operation, 0, 0, size, len(filename), filename
        )
        self.transport.send(request[:10], BINARY_FRAME)
        self.transport.send(request[10:], BINARY_FRAME)

    def _read_response(self):
        signature, code = struct.unpack("<2sH", self.transport.read_binary(4))
        if signature != b"WB" or code != 0:
            raise BridgeError("Badge rejected a WebREPL file operation")

    def version(self):
        self._request(GET_VERSION)
        return tuple(self.transport.read_binary(3))

    def interrupt(self):
        self.transport.send(b"\r\x03\x03", TEXT_FRAME)
        self.transport.read_text_until(b">>> ", self.timeout)

    def execute(self, command):
        if "\n" in command or "\r" in command:
            raise BridgeError("REPL commands must occupy one line")
        self.transport.send(command.encode("utf-8") + b"\r", TEXT_FRAME)
        response = self.transport.read_text_until(b">>> ", self.timeout)
        if b"Traceback (most recent call last)" in response:
            raise BridgeError("Badge REPL command failed")
        return response

    def create_directories(self, directories):
        script = (
            "import os\nfor path in %r:\n try:\n  os.mkdir(path)\n except OSError:\n  pass"
            % (tuple(directories),)
        )
        self.execute("exec(" + repr(script) + ")")

    def put_file(self, local_path, remote_path):
        remote_name = remote_path.encode("utf-8")
        data = Path(local_path).read_bytes()
        self._request(PUT_FILE, len(data), remote_name)
        self._read_response()
        for offset in range(0, len(data), 1024):
            self.transport.send(data[offset : offset + 1024], BINARY_FRAME)
        self._read_response()

    def get_file(self, remote_path):
        self._request(GET_FILE, filename=remote_path.encode("utf-8"))
        self._read_response()
        result = bytearray()
        while True:
            self.transport.send(b"\0", BINARY_FRAME)
            size = struct.unpack("<H", self.transport.read_binary(2))[0]
            if size == 0:
                break
            result.extend(self.transport.read_binary(size))
        self._read_response()
        return bytes(result)

    def reset(self):
        self.transport.send(b"import machine; machine.reset()\r", TEXT_FRAME)


def build_deployment_package(source, app_name=None):
    source = Path(source).resolve()
    target_name = normalise_app_name(app_name or source.name)
    _directories, files = collect_deployment(source, target_name)
    remote_root = "/apps/" + target_name + "/"
    entries = []
    for local_path, remote_path in files:
        if not remote_path.startswith(remote_root):
            raise BridgeError("Invalid deployment destination")
        data = local_path.read_bytes()
        entries.append(
            {
                "path": remote_path[len(remote_root) :],
                "sha256": hashlib.sha256(data).hexdigest(),
                "content": base64.b64encode(data).decode("ascii"),
            }
        )
    package = json.dumps(
        {"protocol": 1, "app": target_name, "files": entries},
        separators=(",", ":"),
    ).encode("utf-8")
    return target_name, entries, package


def deploy(host, password, source, app_name=None, port=DEFAULT_DEPLOY_PORT, timeout=30):
    host = validate_target(host)
    password = validate_password(password)
    target_name, entries, package = build_deployment_package(source, app_name)
    for entry in entries:
        print("Uploading /apps/%s/%s" % (target_name, entry["path"]))

    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(
            "POST",
            "/deploy",
            body=package,
            headers={
                "Content-Type": "application/json",
                "X-Hermes-Pin": password,
            },
        )
        response = connection.getresponse()
        response_body = response.read()
    except (OSError, http.client.HTTPException) as error:
        raise BridgeError("Could not connect to the badge deployment service") from error
    finally:
        connection.close()

    try:
        result = json.loads(response_body.decode("utf-8"))
    except Exception as error:
        raise BridgeError("Badge returned an invalid deployment response") from error
    if response.status != 200 or not result.get("ok"):
        raise BridgeError(str(result.get("error") or "Badge rejected deployment"))
    if (
        result.get("app") != target_name
        or result.get("files") != len(entries)
        or result.get("verified") is not True
    ):
        raise BridgeError("Badge deployment verification response did not match package")
    print("Upload verified on badge; badge resetting")


def check_deployment_service(host, password, port=DEFAULT_DEPLOY_PORT, timeout=10):
    host = validate_target(host)
    password = validate_password(password)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", "/health", headers={"X-Hermes-Pin": password})
        response = connection.getresponse()
        response_body = response.read()
    except (OSError, http.client.HTTPException) as error:
        raise BridgeError("Could not connect to the badge deployment service") from error
    finally:
        connection.close()

    try:
        result = json.loads(response_body.decode("utf-8"))
    except Exception as error:
        raise BridgeError("Badge returned an invalid health response") from error
    if (
        response.status != 200
        or result.get("ok") is not True
        or result.get("service") != "hermes-bridge"
        or result.get("protocol") != 1
    ):
        raise BridgeError(str(result.get("error") or "Badge health check failed"))
    print("Connected to Hermes Bridge protocol 1 at", host + ":" + str(port))


def build_parser():
    parser = argparse.ArgumentParser(
        description="Deploy Tildagon apps through the guarded Hermes Bridge"
    )
    parser.add_argument("--host", default=os.environ.get("HERMES_BADGE_HOST"))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--deploy-port", type=int, default=DEFAULT_DEPLOY_PORT)
    parser.add_argument(
        "--password-file",
        default=os.environ.get(
            "HERMES_BADGE_PASSWORD_FILE",
            str(Path.home() / ".config" / "hermes-badge" / "password"),
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("pair", help="Securely store the PIN displayed by the badge")
    subparsers.add_parser("check", help="Check authentication and protocol version")
    deploy_parser = subparsers.add_parser("deploy", help="Deploy and verify an app")
    deploy_parser.add_argument("source")
    deploy_parser.add_argument("--name")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "pair":
            import getpass

            password = getpass.getpass("Pairing PIN shown on the badge: ")
            password_path = save_password(args.password_file, password)
            print("Pairing PIN stored in", password_path)
            return 0

        if not args.host:
            parser.error("--host or HERMES_BADGE_HOST is required")

        password = read_password(args.password_file)
        if args.command == "deploy":
            deploy(args.host, password, args.source, args.name, args.deploy_port)
            return 0

        check_deployment_service(args.host, password, args.deploy_port)
    except BridgeError as error:
        print("error:", error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())