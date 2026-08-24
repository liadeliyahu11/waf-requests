"""Deliberately observable origin app for WAF-bypass verification.

The win signal is never inferred from a non-block: every endpoint echoes the
attack tokens it actually received through the ``X-Origin-Saw-Payload``
response header and a JSON body. Run behind each protected domain.

Env:
    ENABLE_GZIP_IN=1   decompress gzip/deflate request bodies before routing.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import zlib

from flask import Flask, Response, request

app = Flask(__name__)

#: token name -> needle searched in method+path+query+body (decoded).
MARKERS = {
    "jndi": "${${env",
    "sqli": "' or '1'='1",
    "xss": "<script>alert(1)</script>",
    "ssti": "{{7*7}}",
    "traversal": "../etc/passwd",
    "jsontamper": '"role":"admin"',
}


class DecompressMiddleware:
    """WSGI-level request-body decompression, mirroring real origin stacks."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        if os.environ.get("ENABLE_GZIP_IN"):
            encoding = (environ.get("HTTP_CONTENT_ENCODING") or "").strip().lower()
            length = int(environ.get("CONTENT_LENGTH") or 0)
            raw = environ["wsgi.input"].read(length) if length else b""
            try:
                if encoding == "gzip":
                    plain = gzip.decompress(raw)
                elif encoding == "deflate":
                    plain = zlib.decompress(raw)
                else:
                    plain = None
            except OSError:
                plain = zlib.decompress(raw, -zlib.MAX_WBITS)
            if plain is not None:
                environ["wsgi.input"] = io.BytesIO(plain)
                environ["CONTENT_LENGTH"] = str(len(plain))
                environ.pop("HTTP_CONTENT_ENCODING", None)
        return self.wsgi_app(environ, start_response)


app.wsgi_app = DecompressMiddleware(app.wsgi_app)  # type: ignore[method-assign]


def _decoded_bodies() -> list[str]:
    """Candidate text views of the request: query, path, raw, decoded forms."""
    from urllib.parse import unquote

    raw = request.get_data(cache=True) or b""
    candidates = [
        request.method,
        request.path,
        request.query_string.decode("utf-8", errors="replace"),
        raw.decode("utf-8", errors="replace"),
        unquote(unquote(request.query_string.decode("utf-8", errors="replace"))),
    ]
    try:
        candidates.append(raw.decode("utf-7"))
    except UnicodeDecodeError:
        pass
    if request.form:
        for value in request.form.values():
            candidates.append(value)
    if request.is_json:
        candidates.append(json.dumps(request.get_json(silent=True)))
    return candidates


def saw_tokens() -> str:
    haystack = "".join(_decoded_bodies()).lower()
    compact = "".join(haystack.split())  # whitespace-insensitive matching
    found = []
    for name, needle in MARKERS.items():
        probe = needle.lower()
        if probe in haystack or probe in compact:
            found.append(name)
    return ",".join(found)


@app.after_request
def attach_saw_header(response: Response) -> Response:
    response.headers["X-Origin-Saw-Payload"] = saw_tokens()
    response.headers["X-Origin-App"] = "vulnapp"
    return response


@app.route("/echo", methods=["GET", "POST", "PUT", "PATCH"])
def echo():
    payload = {
        "method": request.method,
        "path": request.path,
        "args": request.args.to_dict(flat=False),
        "form": request.form.to_dict(flat=False),
        "json": request.get_json(silent=True, force=True),
        "content_type": request.content_type,
        "body_preview": (request.get_data() or b"")[:512].decode("utf-8", errors="replace"),
    }
    return Response(json.dumps(payload, indent=2), mimetype="application/json")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return Response(json.dumps({"q": q}), mimetype="application/json")


@app.route("/upload", methods=["POST"])
def upload():
    files = [
        {"field": key, "filename": fs.filename}
        for key, fs in request.files.items()
    ]
    return Response(json.dumps({"files": files}, indent=2), mimetype="application/json")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8090")))
