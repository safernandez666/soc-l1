"""Daemon supervisor: scheduler loop + minimal /healthz HTTP server."""
from __future__ import annotations

import contextlib
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _HealthzHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return  # quiet


class _ServerContext:
    def __init__(self, server: ThreadingHTTPServer, thread: threading.Thread) -> None:
        self._server = server
        self._thread = thread
        self.actual_port = server.server_address[1]

    def shutdown(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)


class HealthDaemon:
    def __init__(self, *, port: int = 8787) -> None:
        self._port = port
        self._stop = threading.Event()

    @contextlib.contextmanager
    def serve_in_thread(self):
        server = ThreadingHTTPServer(("127.0.0.1", self._port), _HealthzHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        ctx = _ServerContext(server, thread)
        try:
            yield ctx
        finally:
            ctx.shutdown()

    def run_forever(self, scheduler, *, tick_interval_s: float = 1.0) -> None:
        signal.signal(signal.SIGTERM, lambda *_: self._stop.set())
        signal.signal(signal.SIGINT, lambda *_: self._stop.set())
        with self.serve_in_thread():
            while not self._stop.is_set():
                scheduler.tick()
                time.sleep(tick_interval_s)
