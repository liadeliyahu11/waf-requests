"""vulnapp endpoints: origin-echo win signals and gzip middleware."""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB_DIR))
pytest.importorskip("flask")

from vulnapp.app import app  # noqa: E402


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_search_reflects_and_reports_saw(client):
    resp = client.get("/search?q=' OR '1'='1")
    assert resp.status_code == 200
    assert "sqli" in resp.headers["X-Origin-Saw-Payload"]
    assert json.loads(resp.data)["q"] == "' OR '1'='1"


def test_echo_json_tamper_seen(client):
    resp = client.post("/echo", data=json.dumps({"role": "admin"}),
                       content_type="application/json")
    body = json.loads(resp.data)
    assert body["json"] == {"role": "admin"}
    assert "jsontamper" in resp.headers["X-Origin-Saw-Payload"]


def test_clean_request_has_empty_saw_header(client):
    resp = client.get("/search?q=hello")
    assert resp.headers.get("X-Origin-Saw-Payload", "") == ""


def test_gzip_body_decompressed_when_enabled(client, monkeypatch):
    monkeypatch.setenv("ENABLE_GZIP_IN", "1")
    raw = json.dumps({"q": "{{7*7}}"}).encode()
    resp = client.post("/echo", data=gzip.compress(raw),
                       content_type="application/json",
                       headers={"Content-Encoding": "gzip"})
    body = json.loads(resp.data)
    assert body["json"] == {"q": "{{7*7}}"}
    assert "ssti" in resp.headers["X-Origin-Saw-Payload"]
    monkeypatch.delenv("ENABLE_GZIP_IN")


def test_upload_lists_filenames(client):
    resp = client.post("/upload", data={
        "file": (__import__("io").BytesIO(b"x"), "shell.php.jpg"),
    }, content_type="multipart/form-data")
    files = json.loads(resp.data)["files"]
    assert files and files[0]["filename"] == "shell.php.jpg"
