"""A deliberately small Docker GET gateway. The socket remains privileged."""
import contextlib
import http.client
import http.server
import json
import re
import socket
import threading
import time
import urllib.parse

from .common import MIB

CONTAINER = r"[a-f0-9]{12,64}"


def permitted(method, target):
    if method != "GET" or len(target) > 4096 or "%" in target.split("?", 1)[0]:
        return False
    url = urllib.parse.urlsplit(target)
    if url.scheme or url.netloc or url.fragment:
        return False
    path = re.sub(r"^/v1\.[0-9]{2,3}(?=/)", "", url.path)
    try:
        params = urllib.parse.parse_qs(url.query, strict_parsing=True, keep_blank_values=True)
    except ValueError:
        return False
    if any(len(v) != 1 for v in params.values()):
        return False
    params = {k: v[0] for k, v in params.items()}
    if path in ("/_ping", "/version"):
        return not params
    if path == "/containers/json":
        return params == {"all": "1"}
    if re.fullmatch(r"/containers/" + CONTAINER + r"/json", path):
        return not params
    if re.fullmatch(r"/containers/" + CONTAINER + r"/stats", path):
        return params == {"stream": "false", "one-shot": "true"}
    if re.fullmatch(r"/containers/" + CONTAINER + r"/logs", path):
        required = {"stdout": "1", "stderr": "1", "timestamps": "1", "follow": "0"}
        return (params.keys() == required.keys() | {"since", "until", "tail"}
                and all(params.get(k) == v for k, v in required.items())
                and all(params[k].isdigit() for k in ("since", "until", "tail"))
                and 0 < int(params["tail"]) <= 20000
                and 0 <= int(params["until"]) - int(params["since"]) <= 8 * 86400)
    if path == "/events":
        if params.keys() - {"since", "until", "filters"} or not params.get("since", "").isdigit():
            return False
        if "until" in params and not params["until"].isdigit():
            return False
        try:
            return json.loads(params.get("filters", "null")) == {"type": ["container"]}
        except ValueError:
            return False
    return False


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=65):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, socket_path):
        super().__init__(address, Handler)
        self.socket_path = socket_path
        self.slots = threading.BoundedSemaphore(8)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(70)

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.close_connection = True
        if (not permitted("GET", self.path) or self.headers.get("Transfer-Encoding")
                or self.headers.get("Content-Length", "0") != "0"):
            self.send_error(403)
            return
        upstream = UnixConnection(self.server.socket_path)
        sent = False
        try:
            upstream.request("GET", self.path, headers={"Connection": "close"})
            response = upstream.getresponse()
            self.send_response(response.status)
            self.send_header("Content-Type", response.getheader("Content-Type", "application/octet-stream"))
            self.send_header("Connection", "close")
            self.end_headers()
            sent = True
            remaining = 16 * MIB
            deadline = time.monotonic() + 60
            events = urllib.parse.urlsplit(self.path).path.endswith("/events")
            while remaining > 0 and time.monotonic() < deadline:
                chunk = response.readline(min(65536, remaining)) if events else response.read(min(65536, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                remaining -= len(chunk)
        except (OSError, http.client.HTTPException):
            if not sent:
                with contextlib.suppress(OSError):
                    self.send_error(502)
        finally:
            upstream.close()

    def reject(self):
        self.close_connection = True
        self.send_error(403)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_CONNECT = do_OPTIONS = reject
