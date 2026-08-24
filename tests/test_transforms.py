"""Transform correctness: window geometry, origin-parseability, integrity."""
from __future__ import annotations

import gzip
import json
import zlib
from urllib.parse import parse_qsl, unquote, urlsplit

import pytest

from waf_requests.spec import ReqSpec
from waf_requests.transforms import Ctx, TRANSFORMS
from waf_requests.transforms.encoding import _force_utf7
from waf_requests.transforms.multipart import _split_parts

LIMIT = 8192
CTX = Ctx(profile_limit=LIMIT)

SQLI = "' OR '1'='1"


def json_spec(payload: dict) -> ReqSpec:
    return ReqSpec(
        "POST", "http://t.test/echo",
        {"Content-Type": "application/json"},
        json.dumps(payload).encode(),
    )


def form_spec(pairs: str) -> ReqSpec:
    return ReqSpec(
        "POST", "http://t.test/echo",
        {"Content-Type": "application/x-www-form-urlencoded"},
        pairs.encode(),
    )


def multipart_spec() -> ReqSpec:
    boundary = "XyZ123"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="q"\r\n\r\n'
        f"{SQLI}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    ct = f"multipart/form-data; boundary={boundary}"
    return ReqSpec("POST", "http://t.test/upload", {"Content-Type": ct}, body)


# --- pad geometry -----------------------------------------------------------

def test_pad_json_ws_pushes_payload_past_limit():
    spec = json_spec({"q": SQLI})
    out = TRANSFORMS["pad_json_ws"].apply(spec, CTX)
    assert out is not None
    payload_offset = out.body.index(SQLI.encode())
    assert payload_offset >= LIMIT
    assert json.loads(out.body.decode()) == json.loads(spec.body.decode())


def test_pad_form_param_pushes_pairs_past_limit_and_last_wins():
    spec = form_spec(f"benign=x&q={SQLI}")
    out = TRANSFORMS["pad_form_param"].apply(spec, CTX)
    assert out is not None
    assert out.body.index(SQLI.encode()) >= LIMIT
    pairs = parse_qsl(out.body.decode(), keep_blank_values=True)
    assert dict(pairs)["q"] == SQLI  # last value wins
    assert "waf_filler" in dict(pairs)


def test_pad_multipart_decoy_keeps_parts_parseable():
    spec = multipart_spec()
    out = TRANSFORMS["pad_multipart_decoy"].apply(spec, CTX)
    assert out is not None
    boundary = "XyZ123"
    parts = _split_parts(out.body, boundary)
    assert parts is not None and len(parts) == 2
    assert SQLI.encode() in parts[-1]
    assert SQLI.encode() not in parts[0]


def test_pads_return_none_without_body_or_limit():
    assert TRANSFORMS["pad_json_ws"].apply(json_spec({"a": 1}), Ctx(profile_limit=None)) is None
    assert TRANSFORMS["pad_json_ws"].apply(
        ReqSpec("POST", "http://t.test/e", {"Content-Type": "application/json"}, None), CTX,
    ) is None


def test_pad_form_param_rejects_non_urlencoded():
    assert TRANSFORMS["pad_form_param"].apply(json_spec({"q": SQLI}), CTX) is None


def test_pad_multipart_rejects_plain_bodies():
    assert TRANSFORMS["pad_multipart_decoy"].apply(form_spec("q=1"), CTX) is None


# --- encoding integrity ------------------------------------------------------

@pytest.mark.parametrize("tid,decompress", [
    ("gzip_body", gzip.decompress),
    ("deflate_body", zlib.decompress),
])
def test_compression_roundtrip(tid, decompress):
    spec = json_spec({"q": SQLI})
    out = TRANSFORMS[tid].apply(spec, CTX)
    assert out is not None
    assert out.headers["Content-Encoding"] == ("gzip" if tid == "gzip_body" else "deflate")
    assert json.loads(decompress(out.body)) == {"q": SQLI}


def test_charset_utf7_escapes_signature_chars_and_roundtrips():
    spec = ReqSpec(
        "POST", "http://t.test/echo",
        {"Content-Type": "application/json"}, json.dumps({"q": SQLI}).encode(),
    )
    out = TRANSFORMS["charset_utf7"].apply(spec, CTX)
    assert out is not None
    assert out.headers["Content-Type"].endswith("charset=utf-7")
    text = out.body.decode("ascii")
    assert "'" not in text  # every quote hidden behind UTF-7 sequences
    recovered = text.encode("ascii").decode("utf-7")
    assert json.loads(recovered) == {"q": SQLI}


def test_force_utf7_escapes_all_target_chars():
    escaped = _force_utf7("<>\"'()&")
    assert all(ch not in escaped for ch in "<>\"'()&")


# --- unicode / decode-count --------------------------------------------------

def test_percent_double_encode_recovers_after_double_decode():
    spec = ReqSpec("GET", f"http://t.test/search?q={SQLI}", {}, None)
    out = TRANSFORMS["percent_double_encode"].apply(spec, CTX)
    assert out is not None
    query = urlsplit(out.url).query
    once_decoded = unquote(query.split("=", 1)[1])
    assert SQLI not in unquote(query)          # single decode sees noise
    assert unquote(once_decoded) == SQLI       # double decode recovers


def test_json_unicode_escape_values_identical_after_parse():
    spec = json_spec({"q": "<script>alert('x')</script>", "b": 2})
    out = TRANSFORMS["json_unicode_escape"].apply(spec, CTX)
    assert out is not None
    raw = out.body.decode()
    assert "<script>" not in raw
    assert json.loads(raw) == json.loads(spec.body)


def test_utf8_overlong_path_encodes_separators():
    spec = ReqSpec("GET", "http://t.test/a/b.c?q=1", {}, None)
    out = TRANSFORMS["utf8_overlong_path"].apply(spec, CTX)
    assert out is not None
    assert "%c0%af" in out.url and "%c0%ae" in out.url
    assert out.url.endswith("?q=1") or "?q=1" in out.url


# --- JSON differentials -------------------------------------------------------

def test_dup_key_lastwins_keeps_payload_for_last_wins_reader():
    spec = json_spec({"q": SQLI, "b": 2})
    out = TRANSFORMS["json_dup_key_lastwins"].apply(spec, CTX)
    assert out is not None
    parsed = json.loads(out.body)
    assert parsed["q"] == SQLI                      # last wins
    assert out.body.count(b'"q"') == 2              # duplicate present


def test_deep_nest_wrap_parses_with_stdlib():
    spec = json_spec({"q": SQLI})
    out = TRANSFORMS["json_deep_nest_wrap"].apply(spec, CTX)
    assert out is not None
    node = json.loads(out.body)
    depth = 0
    while isinstance(node, list):
        node = node[0]
        depth += 1
    assert depth == 2000
    assert node == {"q": SQLI}


_COMMENT_RE = __import__("re").compile(r"/\*.*?\*/")

def test_comment_inject_stripped_by_lenient_reader():
    spec = json_spec({"q": SQLI})
    out = TRANSFORMS["json_comment_inject"].apply(spec, CTX)
    assert out is not None
    stripped = _COMMENT_RE.sub("", out.body.decode())
    assert json.loads(stripped) == {"q": SQLI}


# --- HPP ---------------------------------------------------------------------

def test_hpp_duplicate_param_first_is_benign_last_is_payload():
    spec = ReqSpec("GET", f"http://t.test/search?q={SQLI}", {}, None)
    out = TRANSFORMS["hpp_duplicate_param"].apply(spec, CTX)
    assert out is not None
    values = [v for k, v in parse_qsl(urlsplit(out.url).query)]
    assert values[0] == "1" and values[-1] == SQLI


def test_hpp_semicolon_sep_splits_on_semicolon():
    spec = ReqSpec("GET", f"http://t.test/search?a=1&q={SQLI}", {}, None)
    out = TRANSFORMS["hpp_semicolon_sep"].apply(spec, CTX)
    assert out is not None
    assert "&" not in urlsplit(out.url).query
    pairs = parse_qsl(urlsplit(out.url).query, separator=";")
    assert dict(pairs)["q"] == SQLI


# --- path --------------------------------------------------------------------

def _normalized(path: str) -> str:
    # RFC 3986 remove_dot_segments (minimal impl sufficient for our shapes).
    segments = []
    for seg in path.split("/"):
        if seg == "." :
            continue
        if seg == "..":
            if segments:
                segments.pop()
            continue
        segments.append(seg)
    return "/".join(segments) or "/"


def test_dot_segments_normalize_to_original():
    from urllib.parse import unquote, urlsplit

    spec = ReqSpec("GET", "http://t.test/a/b?q=1", {}, None)
    out = TRANSFORMS["path_dot_segments"].apply(spec, CTX)
    assert out is not None
    # encoded form: /%2e/waf/%2e%2e decodes to dot segments that normalize
    path = unquote(urlsplit(out.url).path)
    assert _normalized(path) == "/a/b"
    # and must survive requests' URL preparation without stripping
    from waf_requests.spec import to_prepared

    wire = urlsplit(to_prepared(out).url).path
    assert "/../" in wire and "/./" in wire
    assert _normalized(unquote(wire)) == "/a/b"


def test_semicolon_params_keep_route_segment():
    spec = ReqSpec("GET", "http://t.test/a/b?q=1", {}, None)
    out = TRANSFORMS["path_semicolon_params"].apply(spec, CTX)
    assert out is not None
    assert urlsplit(out.url).path.startswith("/a;waf=1/")


def test_double_slash_inserts_empty_segment():
    spec = ReqSpec("GET", "http://t.test/a/b?q=1", {}, None)
    out = TRANSFORMS["path_double_slash"].apply(spec, CTX)
    assert out is not None
    assert "//" in urlsplit(out.url).path


# --- headers ------------------------------------------------------------------

def test_header_pad_early_places_pads_first_under_budget():
    spec = ReqSpec("GET", "http://t.test/a", {"User-Agent": "x"}, None)
    out = TRANSFORMS["header_pad_early"].apply(spec, Ctx(profile_limit=LIMIT))
    assert out is not None
    names = list(out.headers)
    total = sum(len(str(v)) for v in out.headers.values())
    assert all(n.startswith("X-Waf-Pad") for n in names[:10])
    assert total < LIMIT
    assert list(out.headers)[-1] == "User-Agent"


def test_dup_header_firstlast_orders_benign_first():
    spec = ReqSpec("GET", "http://t.test/a", {"User-Agent": "'payload'"}, None)
    out = TRANSFORMS["dup_header_firstlast"].apply(spec, CTX)
    assert out is not None
    ua = out.headers["User-Agent"]
    assert isinstance(ua, list) and ua[1] == "'payload'"


def test_method_override_only_touches_get():
    get_spec = ReqSpec("GET", "http://t.test/a", {}, None)
    out = TRANSFORMS["method_override"].apply(get_spec, CTX)
    assert out.method == "POST"
    assert out.headers["X-HTTP-Method-Override"] == "GET"
    post_spec = ReqSpec("POST", "http://t.test/a", {}, b"x")
    assert TRANSFORMS["method_override"].apply(post_spec, CTX) is None


def test_boundary_variance_quotes_header_only():
    spec = multipart_spec()
    out = TRANSFORMS["multipart_boundary_variance"].apply(spec, CTX)
    assert out is not None
    ct = out.headers["Content-Type"]
    assert 'boundary="XyZ123"' in ct
    assert out.body.count(b"--XyZ123") == 2  # delimiters unchanged


def test_multipart_payload_last_reverses_part_order():
    boundary = "B2"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="first"\r\n\r\n'
        "one\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="second"\r\n\r\n'
        "two\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    spec = ReqSpec("POST", "http://t.test/upload",
                   {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body)
    out = TRANSFORMS["multipart_payload_last"].apply(spec, CTX)
    assert out is not None
    parts = _split_parts(out.body, boundary)
    assert [p[-3:] for p in parts] == [b"two", b"one"]
