"""Drop-in shim behavior: namespace passthrough, monkeypatch, wire fidelity."""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import waf_requests
from waf_requests._shim import build_shim, install, uninstall


def test_build_shim_preserves_namespace_and_overrides_api():
    import requests as real

    shim = build_shim()
    assert shim.exceptions.Timeout is real.exceptions.Timeout
    assert shim.auth.HTTPBasicAuth is real.auth.HTTPBasicAuth
    assert shim.packages is real.packages
    from waf_requests.engine import WAFSession

    assert shim.Session is WAFSession
    for name in ("get", "post", "put", "patch", "delete", "head", "options", "request"):
        assert getattr(shim, name).__module__.startswith("waf_requests")


def test_monkeypatch_swaps_and_restores():
    import requests as real_before

    install()
    try:
        import requests as swapped

        assert swapped.get.__module__.startswith("waf_requests")
        assert swapped.Session.__name__ == "WAFSession"
    finally:
        uninstall()
    import requests as restored

    assert restored is real_before


def _capture_server():
    """Threaded HTTP server recording per-request header lists."""
    captured = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            captured.append({
                "path": self.path,
                "ua_all": self.headers.get_all("User-Agent") or [],
            })
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, captured


def test_transformed_request_arrives_on_the_wire():
    """dup_header_firstlast survives to the socket as two header lines."""
    from waf_requests.spec import ReqSpec, to_prepared

    server, captured = _capture_server()
    try:
        spec = ReqSpec(
            "GET", f"http://127.0.0.1:{server.server_address[1]}/search?q=probe",
            {"User-Agent": "'payload-ua'"}, None,
        )
        transformed = waf_requests.TRANSFORMS["dup_header_firstlast"].apply(
            spec, waf_requests.Ctx(profile_limit=8192),
        )
        session = __import__("requests").Session()  # stock transport on purpose
        resp = session.send(to_prepared(transformed), timeout=10)
        assert resp.status_code == 200
        record = captured[-1]
        assert len(record["ua_all"]) == 2              # duplicate UA line preserved
        assert record["ua_all"][1] == "'payload-ua'"   # benign first, payload second
    finally:
        server.shutdown()


FIXTURE = Path(__file__).parent / "fixtures" / "demo_exploit.py"


def test_run_subprocess_maps_import_requests():
    """`python -m waf_requests run` maps `import requests` to the shim."""
    server, captured = _capture_server()
    port = server.server_address[1]
    env = {**os.environ, "TARGET_URL": f"http://127.0.0.1:{port}"}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "waf_requests", "run", str(FIXTURE)],
            capture_output=True, text=True, timeout=60,
            cwd=str(Path(__file__).parents[2]),
            env=env, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "exceptions-ok: True" in proc.stdout
        assert "session-type-ok: True" in proc.stdout
        assert captured, "fixture request never reached the local server"
        # Auto profile cannot fingerprint localhost, so the original goes out.
        assert "alert%281%29" in captured[-1]["path"]
    finally:
        server.shutdown()


def test_public_api_surface_complete():
    for name in ("get", "post", "put", "patch", "delete", "head", "options",
                 "request", "Session", "monkeypatch", "configure", "detect"):
        assert hasattr(waf_requests, name)
