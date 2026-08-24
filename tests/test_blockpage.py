"""Vendor fingerprint classification for the expanded signature table."""
from __future__ import annotations

import requests

from waf_requests.blockpage import Status, classify


def _resp(status, body: bytes, headers=None):
    r = requests.Response()
    r.status_code = status
    r._content = body
    for k, v in (headers or {}).items():
        r.headers[k] = v
    return r


def test_imperva_incapsula_cookie():
    v = classify(_resp(403, b"blocked", {"Set-Cookie": "visid_incap_1234"}))
    assert v.vendor == "imperva" and v.status is Status.BLOCKED


def test_f5_bigip_reject_page():
    v = classify(_resp(403, b"The requested URL was rejected."))
    assert v.vendor == "f5" and v.status is Status.BLOCKED


def test_fortiweb_cookie():
    v = classify(_resp(403, b"", {"Set-Cookie": "FortiWeb=abc"}))
    assert v.vendor == "fortiweb" and v.status is Status.BLOCKED


def test_barracuda_server_header():
    v = classify(_resp(403, b"", {"Server": "Barracuda"}))
    assert v.vendor == "barracuda" and v.status is Status.BLOCKED


def test_citrix_nsc_cookie():
    v = classify(_resp(403, b"", {"Set-Cookie": "NSC_abc=1"}))
    assert v.vendor == "citrix" and v.status is Status.BLOCKED


def test_radware_header():
    v = classify(_resp(403, b"", {"X-Radware": "1"}))
    assert v.vendor == "radware" and v.status is Status.BLOCKED


def test_wordfence_body():
    v = classify(_resp(403, b"Your access to this site has been limited by the Wordfence firewall"))
    assert v.vendor == "wordfence" and v.status is Status.BLOCKED


def test_sucuri_server_header():
    v = classify(_resp(403, b"", {"Server": "Sucuri/Cloudproxy"}))
    assert v.vendor == "sucuri" and v.status is Status.BLOCKED


def test_modsecurity_heuristic():
    v = classify(_resp(403, b"Forbidden", {"Server": "nginx"}))
    assert v.vendor == "modsecurity" and v.status is Status.BLOCKED


def test_bare_403_without_server_is_unknown():
    v = classify(_resp(403, b"Forbidden"))
    assert v.vendor is None and v.status is Status.UNKNOWN


def test_plain_200_delivered():
    v = classify(_resp(200, b"<html>hello</html>"))
    assert v.status is Status.DELIVERED
