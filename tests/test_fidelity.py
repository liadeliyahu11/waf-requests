"""Origin-equivalence proofs: transforms vs a standards-conforming stack.

Core guarantee under test:
- transparent  -> app_view(transform(spec)) == app_view(spec), always.
- additive     -> original fields byte-intact plus distinct-name decoys.
- differential -> diverges either structurally or by parser policy, which is
  why WAFSession(strict_fidelity=True) excludes them.
"""
from __future__ import annotations

import gzip
import json
from urllib.parse import parse_qsl, quote, urlsplit

import pytest

from waf_requests.fidelity import (
    ADDITIVE,
    DIFFERENTIAL,
    TRANSPARENT,
    app_view,
    tier_of,
)
from waf_requests.spec import ReqSpec, to_prepared
from waf_requests.transforms import Ctx, TRANSFORMS

LIMIT = 8192
CTX = Ctx(profile_limit=LIMIT)

SQLI = "' OR '1'='1"
JSON_BODY = {"q": SQLI, "page": 2}


def json_spec() -> ReqSpec:
    return ReqSpec(
        "POST", "http://t.test/echo?a=1&b=2",
        {"Content-Type": "application/json"},
        json.dumps(JSON_BODY).encode(),
    )


def form_spec() -> ReqSpec:
    return ReqSpec(
        "POST", "http://t.test/echo",
        {"Content-Type": "application/x-www-form-urlencoded"},
        f"q={SQLI}&token=abc".encode(),
    )


def multipart_spec() -> ReqSpec:
    boundary = "XyZ123"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="q"\r\n\r\n'
        f"{SQLI}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="token"\r\n\r\n'
        f"abc\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    return ReqSpec("POST", "http://t.test/upload",
                   {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body)


def get_spec() -> ReqSpec:
    return ReqSpec("GET", "http://t.test/a/b?q=" + quote(SQLI, safe=""), {}, None)


TRANSPARENT_IDS = [
    "pad_json_ws", "json_unicode_escape", "gzip_body", "deflate_body",
    "multipart_boundary_variance", "multipart_payload_last",
    "path_double_slash", "header_pad_early",
]

# Every URL-mutating transform must SURVIVE the client transport: what
# to_prepared puts on the wire keeps the transform's path/query bytes.
# Regression guard: requests' prepare_url silently strips raw dot-segments,
# which turned path_dot_segments into a no-op until it emitted %2e form.
URL_TRANSFORM_IDS = [
    "percent_double_encode", "hpp_duplicate_param", "hpp_semicolon_sep",
    "path_semicolon_params", "path_dot_segments", "path_double_slash",
    "utf8_overlong_path", "path_dotdot_semicolon", "path_collapse_dotdot",
    "null_byte_terminator",
]

REPRESENTATIVE = {
    "pad_json_ws": json_spec,
    "json_unicode_escape": json_spec,
    "gzip_body": json_spec,
    "deflate_body": json_spec,
    "multipart_boundary_variance": multipart_spec,
    "multipart_payload_last": multipart_spec,
    "path_double_slash": get_spec,
    "header_pad_early": get_spec,
}


@pytest.mark.parametrize("tid", URL_TRANSFORM_IDS)
def test_url_transforms_survive_transport(tid):
    """Transformed path/query bytes must reach the wire unchanged."""
    from urllib.parse import urlsplit

    from waf_requests.fidelity import decode_to_fixpoint

    special = {
        "hpp_semicolon_sep": ReqSpec(
            "GET", "http://t.test/s?a=1&q=" + SQLI.replace(" ", "+"), {}, None),
        "path_dotdot_semicolon": ReqSpec(
            "GET", "http://t.test/files/../secret.txt", {}, None),
        "path_collapse_dotdot": ReqSpec(
            "GET", "http://t.test/files/../secret.txt", {}, None),
    }
    spec = special.get(tid, get_spec())
    out = TRANSFORMS[tid].apply(spec, Ctx(profile_limit=None))
    assert out is not None, tid
    wire_path = urlsplit(to_prepared(out).url).path
    want_path = urlsplit(out.url).path
    assert decode_to_fixpoint(wire_path).lower() \
        == decode_to_fixpoint(want_path).lower(), tid
    if tid == "path_dot_segments":
        # explicit anti-strip guard: dot-segments must remain on the wire
        assert "/../" in wire_path and "/./" in wire_path


@pytest.mark.parametrize("tid", sorted(TRANSFORMS))
def test_every_transform_has_a_tier(tid):
    assert tier_of(tid) in (TRANSPARENT, ADDITIVE, DIFFERENTIAL)


@pytest.mark.parametrize("tid", TRANSPARENT_IDS)
def test_transparent_transforms_preserve_origin_view(tid):
    """THE core guarantee: a conforming origin sees the identical request."""
    spec = REPRESENTATIVE[tid]()
    out = TRANSFORMS[tid].apply(spec, CTX)
    assert out is not None, tid
    assert app_view(out) == app_view(spec), tid


def test_gzip_roundtrip_through_transport_layer():
    spec = json_spec()
    out = TRANSFORMS["gzip_body"].apply(spec, CTX)
    assert out.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(out.body) == spec.body


def test_additive_form_param_keeps_original_pairs():
    spec = form_spec()
    out = TRANSFORMS["pad_form_param"].apply(spec, CTX)
    assert out is not None
    original_body = dict(parse_qsl(spec.body.decode(), keep_blank_values=True))
    new_form = dict(parse_qsl(out.body.decode(), keep_blank_values=True))
    for key, value in original_body.items():
        assert new_form.get(key) == value  # originals intact
    assert "waf_filler" in new_form       # decoy is extra


def test_additive_multipart_decoy_keeps_parts_intact():
    spec = multipart_spec()
    out = TRANSFORMS["pad_multipart_decoy"].apply(spec, CTX)
    assert out is not None
    assert spec.body in out.body          # original parts byte-intact


def test_structural_differential_diverges_on_standard_stack(tid="percent_double_encode"):
    spec = get_spec()
    out = TRANSFORMS[tid].apply(spec, Ctx(profile_limit=None))
    assert out is not None
    assert app_view(out) != app_view(spec)


def test_semicolon_separation_diverges_on_standard_stack():
    spec = ReqSpec("GET",
                   "http://t.test/s?a=1&q=" + SQLI.replace(" ", "+"), {}, None)
    out = TRANSFORMS["hpp_semicolon_sep"].apply(spec, Ctx(profile_limit=None))
    assert out is not None
    assert app_view(out) != app_view(spec)


def _first_and_last(pairs):
    first: "dict[str, str]" = {}
    last: "dict[str, str]" = {}
    for key, value in pairs:
        first.setdefault(key, value)
        last[key] = value
    return first, last


def test_hpp_duplicate_flips_with_parser_policy():
    spec = get_spec()
    out = TRANSFORMS["hpp_duplicate_param"].apply(spec, Ctx(profile_limit=None))
    assert out is not None
    pairs = parse_qsl(urlsplit(out.url).query, keep_blank_values=True)
    first, last = _first_and_last(pairs)
    intended = dict(parse_qsl(urlsplit(spec.url).query))["q"]
    assert last["q"] == intended            # payload survives on last-wins
    assert first["q"] != intended           # benign on first-wins


def test_json_dup_key_flips_with_parser_policy():
    spec = json_spec()
    out = TRANSFORMS["json_dup_key_lastwins"].apply(spec, Ctx(profile_limit=None))
    assert out is not None
    pairs = json.loads(out.body.decode(), object_pairs_hook=list)
    first, last = _first_and_last(pairs)
    assert last["q"] == JSON_BODY["q"]      # payload survives on last-wins
    assert first["q"] == "waf_benign"       # benign on first-wins


def test_strict_session_replays_only_safe_transforms():
    """End-to-end: strict session must never send a differential payload."""
    import requests as rq

    sent_bodies = []

    class Adapter(rq.adapters.HTTPAdapter):
        responses = iter([
            (403, b"<html>ERROR: The request could not be satisfied.</body>"
                  b"Generated by cloudfront (CloudFront)", {}),
            (200, b'{"ok": true}', {}),
        ])

        def send(self, request, **kwargs):
            sent_bodies.append(request.body)
            status, body, headers = next(self.responses)
            resp = rq.Response()
            resp.status_code = status
            resp._content = body
            resp.request = request
            return resp

    from waf_requests.engine import WAFSession

    session = WAFSession(profile="aws", ladder=(
        "percent_double_encode", "pad_json_ws"), strict_fidelity=True)
    session.mount("http://", Adapter())
    prepared = rq.PreparedRequest()
    prepared.prepare(method="POST", url="http://x.test/echo",
                     data=json.dumps({"q": SQLI}).encode(),
                     headers={"Content-Type": "application/json"})
    resp = session.send(prepared)
    assert resp.status_code == 200
    # Two sends only: original + pad_json_ws. percent_double_encode filtered.
    assert len(sent_bodies) == 2
    assert sent_bodies[1].startswith(b" ")  # whitespace pad, not re-encoding
    info = resp.payload_fidelity
    assert info["transform"] == "pad_json_ws"
    assert info["tier"] == TRANSPARENT
    assert "identical by construction" in info["note"]
    assert resp.waf_attempts[-1].transform_id == "pad_json_ws"


def test_to_prepared_roundtrip_keeps_semantics():
    spec = json_spec()
    prepared = to_prepared(spec)
    assert prepared.url == spec.url
    assert json.loads(prepared.body) == JSON_BODY
