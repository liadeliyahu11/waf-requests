"""Payload-fidelity model: does the origin interpret the SAME payload?

Three tiers:

- ``transparent``  - the origin's standard processing (transport decoding,
  RFC parsing, routing normalization) yields the byte-identical logical
  request. Wire bytes change; interpretation cannot change. Safe for any
  conforming target.
- ``additive``     - the original parameters/parts arrive untouched plus
  distinct-name decoys the app ignores. Exploitation fields are intact.
- ``differential`` - correctness depends on the app's parser picking the
  assumed winner (double-decode, last-value-wins, UTF-7 honoring, method
  override). The wire payload DIFFERS from the original; these run only as
  last resort and are excluded by ``strict_fidelity=True``.

``app_view`` simulates a standards-conforming server stack so tests can PROVE
the equivalence claims instead of asserting them.
"""
from __future__ import annotations

import gzip
import json
import re
import zlib

from .spec import ReqSpec

TRANSPARENT = "transparent"
ADDITIVE = "additive"
DIFFERENTIAL = "differential"

#: Transform id -> fidelity tier. Single source of truth, applied to the
#: registry after import. Unmapped ids default to differential (conservative:
 #: treat as manipulating until proven otherwise).
FIDELITY: "dict[str, str]" = {
    # transparent: standard layers erase the difference
    "pad_json_ws": TRANSPARENT,
    "json_unicode_escape": TRANSPARENT,
    "gzip_body": TRANSPARENT,
    "deflate_body": TRANSPARENT,
    "path_double_slash": TRANSPARENT,
    # encoded dot-segments: transparent ONLY for origins that decode then
    # normalize; scanner-dependent -> differential
    "path_dot_segments": DIFFERENTIAL,
    "multipart_payload_last": TRANSPARENT,
    "header_pad_early": TRANSPARENT,
    # additive: decoys with fresh names; original fields byte-intact
    "pad_form_param": ADDITIVE,
    "pad_multipart_decoy": ADDITIVE,
    # differential: app-visible payload differs unless the stack normalizes
    "percent_double_encode": DIFFERENTIAL,
    "hpp_duplicate_param": DIFFERENTIAL,
    "hpp_semicolon_sep": DIFFERENTIAL,
    "json_dup_key_lastwins": DIFFERENTIAL,
    "json_deep_nest_wrap": DIFFERENTIAL,
    "json_comment_inject": DIFFERENTIAL,
    "charset_utf7": DIFFERENTIAL,
    "utf8_overlong_path": DIFFERENTIAL,
    "dup_header_firstlast": DIFFERENTIAL,
    "method_override": DIFFERENTIAL,
    "path_semicolon_params": DIFFERENTIAL,
    # traversal-class (inspired by Ilias1988/waf-bypass LFI layers)
    "path_dotdot_semicolon": DIFFERENTIAL,
    "path_collapse_dotdot": DIFFERENTIAL,
    "null_byte_terminator": DIFFERENTIAL,
    # header-trust misconfiguration (inspired by evilwaf Layer 6)
    "spoof_trusted_ip": DIFFERENTIAL,
}


def apply_fidelity(registry: "dict") -> None:
    """Stamp the tier onto every registered Transform."""
    from dataclasses import replace as _replace

    for tid, tier in FIDELITY.items():
        if tid in registry:
            registry[tid] = _replace(registry[tid], fidelity=tier)


def tier_of(transform_id: str) -> str:
    return FIDELITY.get(transform_id, DIFFERENTIAL)


# ---- standard-origin simulator --------------------------------------------

def _decoded_body(body: "bytes | None", headers: dict) -> "bytes | None":
    """Transport layer: undo Content-Encoding before any app parsing."""
    if body is None:
        return None
    encoding = ""
    for key, value in headers.items():
        if key.lower() == "content-encoding":
            encoding = str(value).strip().lower()
            break
    try:
        if encoding == "gzip":
            return gzip.decompress(body)
        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except OSError:
        return body
    return body


def _normalize_path(path: str) -> str:
    """RFC 3986 remove_dot_segments + empty-segment collapse."""
    segments: "list[str]" = []
    for segment in path.split("/"):
        if segment in (".", ""):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def _parse_multipart(body: bytes, content_type: str) -> "dict[str, str]":
    fields: "dict[str, str]" = {}
    boundary = ""
    for piece in content_type.split(";"):
        piece = piece.strip()
        if piece.startswith("boundary="):
            boundary = piece[len("boundary="):].strip().strip('"')
    if not boundary:
        return fields
    delim = b"--" + boundary.encode("utf-8")
    positions = []
    start = 0
    while True:
        idx = body.find(delim, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + len(delim)
    for i in range(len(positions) - 1):
        seg_start = positions[i] + len(delim) + 2
        seg_end = positions[i + 1] - 2
        segment = body[seg_start:max(seg_start, seg_end)]
        if segment.startswith(b"--"):
            continue  # closer
        head, sep, value = segment.partition(b"\r\n\r\n")
        if not sep:
            continue
        name_match = re.search(rb'name="([^"]*)"', head)
        if name_match:
            fields[name_match.group(1).decode()] = value.decode(
                "utf-8", errors="replace")
    return fields


def app_view(spec: ReqSpec) -> dict:
    """What a standards-conforming application would observe.

    Canonical structure: effective method (after any override header),
    normalized path, last-wins query mapping, and the parsed body per its
    content type (JSON / urlencoded / multipart fields / raw). Transforms
    claiming transparency must reproduce this view exactly.
    """
    parts = urlsplit(spec.url)
    query: "dict[str, str]" = {}
    from urllib.parse import parse_qsl

    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        query[key] = value

    body_kind = "none"
    body_data: object = None
    body = _decoded_body(spec.body, spec.headers)
    content_type = ""
    for key, value in spec.headers.items():
        if key.lower() == "content-type":
            content_type = str(value).lower()
            break
    if body is not None:
        if "multipart/form-data" in content_type:
            body_kind = "multipart"
            body_data = _parse_multipart(body, content_type)
        elif "application/json" in content_type:
            body_kind = "json"
            try:
                body_data = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                body_data = "<unparseable>"
        elif "x-www-form-urlencoded" in content_type:
            body_kind = "form"
            form: "dict[str, str]" = {}
            for key, value in parse_qsl(body.decode("utf-8", errors="replace"),
                                        keep_blank_values=True):
                form[key] = value
            body_data = form
        else:
            body_kind = "raw"
            body_data = body

    method = spec.method
    for key, value in spec.headers.items():
        if key.lower() == "x-http-method-override":
            method = str(value).upper()
            break

    return {
        "method": method,
        "path": _normalize_path(parts.path),
        "query": query,
        "body_kind": body_kind,
        "body": body_data,
    }


def decode_to_fixpoint(text: str, rounds: int = 8) -> str:
    from urllib.parse import unquote as _unquote

    current = text
    for _ in range(rounds):
        step = _unquote(current)
        if step == current:
            break
        current = step
    return current


def reflected_query_value(resp_text: str) -> "str | None":
    """Pull an origin-reflected query string out of common echo shapes.

    Supports waf-debug-raw style JSON ({"request": {"path": ...}}) and falls
    back to scanning for q=<...> patterns; returns the decoded-to-fixpoint
    query string, or None when nothing reflects.
    """
    candidates: "list[str]" = []
    match = re.search(r'"path"\s*:\s*"([^"]+)"', resp_text)
    if match:
        candidates.append(match.group(1))
    match = re.search(r"[?&]q=([^\"&\s<>]+)", resp_text)
    if match:
        candidates.append(match.group(1))
    for candidate in candidates:
        decoded = decode_to_fixpoint(candidate)
        if decoded:
            return decoded
    return None


from urllib.parse import urlsplit  # noqa: E402  (kept late to mirror usage order)
