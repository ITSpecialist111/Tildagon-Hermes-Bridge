import json
import socket
import time

import app
import machine
import wifi
from events.input import BUTTON_TYPES, Buttons

try:
    from .deployment import (
        MAX_PACKAGE_BYTES,
        PackageError,
        decode_package,
        install_package,
    )
    from .network_policy import is_allowed_address, is_private_address
    from .pairing import load_pairing_pin
except ImportError:
    from deployment import (
        MAX_PACKAGE_BYTES,
        PackageError,
        decode_package,
        install_package,
    )
    from network_policy import is_allowed_address, is_private_address
    from pairing import load_pairing_pin


DEPLOY_PORT = 8267
DEPLOY_TIMEOUT_SECONDS = 15
_active_bridge = None


def deployment_accept_handler(listen_sock):
    if _active_bridge is not None:
        _active_bridge._accept_deployment(listen_sock)


class HermesBridgeApp(app.App):
    def __init__(self):
        super().__init__()
        self.button_states = Buttons(self)
        self.armed = False
        self.badge_ip = wifi.get_ip()
        self.pairing_pin = load_pairing_pin()
        self.status = "Press C to arm"
        self.deploy_listener = None

    @staticmethod
    def _send_http(client, status, payload):
        body = json.dumps(payload).encode("utf-8")
        reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 413: "Payload Too Large"}.get(status, "Error")
        response = (
            "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % (status, reason, len(body))
        ).encode("ascii") + body
        client.sendall(response)

    def _accept_deployment(self, listen_sock):
        client, remote_address = listen_sock.accept()
        remote_ip = remote_address[0]
        should_reset = False
        try:
            if not is_allowed_address(remote_ip, self.badge_ip):
                self._send_http(client, 403, {"ok": False, "error": "source is outside trusted LAN"})
                return

            client.settimeout(DEPLOY_TIMEOUT_SECONDS)
            stream = client.makefile("rwb", 0)
            request_line = stream.readline()
            if len(request_line) > 1024:
                raise PackageError("request line too long")
            parts = request_line.decode("ascii").strip().split()
            if len(parts) != 3 or parts[0] not in ("GET", "POST"):
                raise PackageError("unsupported request")
            method, path = parts[0], parts[1]
            if (method, path) not in (("GET", "/health"), ("POST", "/deploy")):
                raise PackageError("unsupported request")

            headers = {}
            for _ in range(32):
                line = stream.readline()
                if not line or line == b"\r\n":
                    break
                if len(line) > 1024 or b":" not in line:
                    raise PackageError("invalid request header")
                name, value = line.split(b":", 1)
                headers[name.strip().lower()] = value.strip()
            else:
                raise PackageError("too many request headers")

            supplied_pin = headers.get(b"x-hermes-pin", b"").decode("ascii")
            if supplied_pin != self.pairing_pin:
                self._send_http(client, 401, {"ok": False, "error": "invalid pairing PIN"})
                return

            if method == "GET":
                self._send_http(
                    client,
                    200,
                    {"ok": True, "service": "hermes-bridge", "protocol": 1},
                )
                return

            try:
                content_length = int(headers.get(b"content-length", b"0"))
            except ValueError as error:
                raise PackageError("invalid content length") from error
            if content_length <= 0:
                raise PackageError("empty deployment package")
            if content_length > MAX_PACKAGE_BYTES * 2:
                self._send_http(client, 413, {"ok": False, "error": "deployment package too large"})
                return

            body = bytearray()
            while len(body) < content_length:
                chunk = stream.read(min(1024, content_length - len(body)))
                if not chunk:
                    raise PackageError("incomplete deployment package")
                body.extend(chunk)

            app_name, files = decode_package(bytes(body))
            file_count = install_package(app_name, files)
            self.status = "Deployed " + app_name
            self._send_http(
                client,
                200,
                {"ok": True, "verified": True, "app": app_name, "files": file_count},
            )
            should_reset = True
        except PackageError as error:
            print("Hermes deployment rejected from", remote_ip, error)
            self.status = "Deploy rejected"
            self._send_http(client, 400, {"ok": False, "error": str(error)})
        except Exception as error:
            print("Hermes deployment failed from", remote_ip, error)
            self.status = "Deploy failed"
            try:
                self._send_http(client, 500, {"ok": False, "error": "internal deployment error"})
            except Exception:
                pass
        finally:
            client.close()
            if should_reset:
                time.sleep_ms(250)
                machine.reset()

    def _start_deployment_server(self):
        global _active_bridge
        _active_bridge = self
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", DEPLOY_PORT))
        listener.listen(1)
        listener.setsockopt(socket.SOL_SOCKET, 20, deployment_accept_handler)
        self.deploy_listener = listener
        print("Hermes deployment server started on port", DEPLOY_PORT)

    def arm(self):
        self.badge_ip = wifi.get_ip()
        if not wifi.status():
            try:
                wifi.connect()
            except Exception:
                pass
            self.status = "Connecting Wi-Fi"
            return False
        if not is_private_address(self.badge_ip):
            self.status = "Private LAN required"
            return False

        try:
            self._start_deployment_server()
        except Exception as error:
            print("Hermes Bridge failed to start:", error)
            if self.deploy_listener:
                self.deploy_listener.close()
                self.deploy_listener = None
            self.status = "Start failed"
            return False

        self.armed = True
        self.status = "Listening on " + str(DEPLOY_PORT)
        return True

    def disarm(self):
        global _active_bridge
        if self.deploy_listener:
            self.deploy_listener.close()
            self.deploy_listener = None
        if _active_bridge is self:
            _active_bridge = None
        self.armed = False
        self.status = "Disarmed"

    def update(self, _delta):
        if self.button_states.pressed(BUTTON_TYPES["CONFIRM"]):
            if self.armed:
                self.disarm()
            else:
                self.arm()
            self.button_states.clear()

        if self.button_states.pressed(BUTTON_TYPES["CANCEL"]):
            self.disarm()
            self.button_states.clear()
            self.terminate()

    def draw(self, ctx):
        ctx.save()
        ctx.rgb(0.02, 0.03, 0.04).rectangle(-120, -120, 240, 240).fill()
        ctx.text_align = ctx.CENTER
        ctx.text_baseline = ctx.MIDDLE

        if self.armed:
            ctx.rgb(0.25, 0.95, 0.55)
            state = "ARMED"
        else:
            ctx.rgb(0.55, 0.65, 0.72)
            state = "OFF"

        ctx.font_size = 20
        ctx.move_to(0, -66).text("Hermes Bridge")
        ctx.font_size = 16
        ctx.move_to(0, -38).text(state)
        ctx.rgb(0.88, 0.91, 0.93)
        ctx.font_size = 11
        address = str(self.badge_ip or "No Wi-Fi")
        if self.badge_ip:
            address += ":" + str(DEPLOY_PORT)
        ctx.move_to(0, -14).text(address)

        ctx.rgb(0.95, 0.78, 0.24)
        ctx.font_size = 10
        ctx.move_to(0, 13).text("PAIRING PIN")
        ctx.font_size = 20 if self.armed else 12
        ctx.move_to(0, 39).text(self.pairing_pin if self.armed else "Arm to reveal")

        ctx.rgb(0.88, 0.91, 0.93)
        ctx.font_size = 10
        ctx.move_to(0, 68).text(self.status)
        ctx.font_size = 11
        ctx.move_to(0, 92).text("C toggle    F exit")
        ctx.restore()


__app_export__ = HermesBridgeApp