"""Synthetic summary routes share real origin bounds without production targets."""

from __future__ import annotations

import http.client
import json
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "deploy/nginx/smithguard-domain.conf.example"
API_HOSTS = ("api.smithguard.io", "guard.smithlabs.ai", "guard-staging.smithlabs.ai")


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class SyntheticAPI(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        result = json.dumps(
            {
                "host": self.headers.get("Host"),
                "forwarded_host": self.headers.get("X-Forwarded-Host"),
                "forwarded_for": self.headers.get("X-Forwarded-For"),
                "scheme": self.headers.get("X-Forwarded-Proto"),
                "method": self.command,
                "path": self.path,
                "body": body.decode("ascii"),
            }
        ).encode()
        status = (
            429
            if self.path.endswith("?synthetic=429")
            else 503
            if self.path.endswith("?synthetic=503")
            else 200
        )
        self.send_response(status)
        if status != 200:
            self.send_header("Vary", "Origin")
            if self.headers.get("Origin") == "https://smithguard.io":
                self.send_header("Access-Control-Allow-Origin", "https://smithguard.io")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


class UnixAPI(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class Origin:
    def __init__(self, root, site):
        self.root = root
        self.site = site
        self.counter = 0

    def request(
        self,
        host,
        path="/",
        method="GET",
        body=None,
        client_ip=None,
        headers=None,
        raw_headers=False,
    ):
        self.counter += 1
        with closing(UnixHTTPConnection(self.root / "o.sock")) as conn:
            conn.request(
                method,
                path,
                body=body,
                headers={
                    "Host": host,
                    "CF-Connecting-IP": client_ip or f"192.0.2.{self.counter % 250 + 1}",
                    "X-Forwarded-Host": "untrusted.invalid",
                    "X-Forwarded-For": "untrusted.invalid",
                    **(headers or {}),
                },
            )
            response = conn.getresponse()
            return (
                response.status,
                response.getheaders() if raw_headers else dict(response.getheaders()),
                response.read(),
            )


@contextmanager
def origin(*, legacy=False, missing_site=False, slow_refill=False, unavailable_api=False):
    binary = shutil.which("nginx")
    assert binary, "Install Nginx for the synthetic origin tests; checks cannot be skipped"
    with tempfile.TemporaryDirectory(prefix="sg-origin-") as directory:
        root = Path(directory)
        release = root / "release"
        release.mkdir()
        if not missing_site:
            (release / "site").mkdir()
            (release / "site/index.html").write_text("Synthetic public origin fixture")
        (root / "current").symlink_to(release, target_is_directory=True)
        conf = (ROOT / "deploy/nginx/smithguard.conf" if legacy else CANDIDATE).read_text()
        conf = conf.replace("/run/smithguard-origin/nginx.sock", str(root / "o.sock"))
        conf = conf.replace(
            "/run/smithguard-api/api.sock",
            str(root / ("missing.sock" if unavailable_api else "a.sock")),
        )
        conf = conf.replace("/opt/SmithGuard/current", str(root / "current"))
        if slow_refill:
            # Pin production rates independently; slow only refill in burst/key experiments.
            assert conf.count("rate=100r/s;") == 1 and conf.count("rate=10r/s;") == 2
            conf = conf.replace("rate=100r/s;", "rate=1r/m;").replace("rate=10r/s;", "rate=1r/m;")
        config = root / "nginx.conf"
        config.write_text(
            "daemon off; master_process off;\n"
            f"pid {root}/pid; error_log {root}/error.log;\n"
            "events {}\nhttp {\n"
            f"client_body_temp_path {root}/body; proxy_temp_path {root}/proxy;\n"
            f"fastcgi_temp_path {root}/fastcgi; uwsgi_temp_path {root}/uwsgi;\n"
            f"scgi_temp_path {root}/scgi;\n{conf}\n}}\n"
        )
        api = UnixAPI(str(root / "a.sock"), SyntheticAPI)
        thread = threading.Thread(target=api.serve_forever, daemon=True)
        thread.start()
        process = subprocess.Popen([binary, "-e", "stderr", "-p", str(root), "-c", str(config)])
        try:
            deadline = time.monotonic() + 5
            while not (root / "o.sock").exists():
                log = root / "error.log"
                assert process.poll() is None, log.read_text() if log.exists() else "See stderr"
                assert time.monotonic() < deadline, "Nginx startup deadline"
                time.sleep(0.01)
            yield Origin(root, release / "site")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            api.shutdown()
            api.server_close()
            thread.join(timeout=5)


@pytest.mark.parametrize("path", ["/mcp", "/mcp/summaries", "/v1/artifacts/assessment-summary"])
def test_hosted_mcp_has_exact_post_route_and_trusted_origin_identity(path):
    with origin(legacy=True) as active:
        for host in API_HOSTS:
            status, _, body = active.request(host, path, "POST", b"{}")
            result = json.loads(body)
            assert status == 200 and result["path"] == path and result["method"] == "POST"
            assert result["host"] == "api.smithguard.io"
            assert result["forwarded_for"].startswith("192.0.2.")
            for method in ("GET", "HEAD", "DELETE", "PUT", "OPTIONS"):
                assert active.request(host, path, method)[0] == 405
        assert active.request(API_HOSTS[0], path, "POST", b"x" * 16385)[0] == 413


def test_mcp_and_assessment_share_the_same_global_fuse():
    with origin(slow_refill=True) as limited:
        paths = (
            "/mcp",
            "/v1/artifacts/assess",
            "/mcp/summaries",
            "/v1/artifacts/assessment-summary",
        )
        statuses = [
            limited.request(API_HOSTS[i % 3], paths[i % len(paths)], "POST", b"{}")[0]
            for i in range(250)
        ]
        assert statuses.count(200) == 201 and statuses.count(429) == 49


def test_mcp_and_assessment_share_the_same_per_address_fuse():
    with origin(slow_refill=True) as limited:
        paths = (
            "/mcp",
            "/v1/artifacts/assess",
            "/mcp/summaries",
            "/v1/artifacts/assessment-summary",
        )
        statuses = [
            limited.request(
                API_HOSTS[i % 3], paths[i % len(paths)], "POST", b"{}", client_ip="198.51.100.9"
            )[0]
            for i in range(50)
        ]
        assert statuses.count(200) == 21 and statuses.count(429) == 29
