"""Multipart parser-differential transforms."""
from __future__ import annotations

from dataclasses import replace
from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, content_type, register


def _boundary(content_type_value: str) -> "str | None":
    marker = "boundary="
    idx = content_type_value.find(marker)
    if idx < 0:
        return None
    rest = content_type_value[idx + len(marker):].strip()
    if rest.startswith('"'):
        end = rest.find('"', 1)
        return rest[1:end] if end > 0 else None
    return rest.split(";")[0].strip() or None


def _split_parts(body: bytes, boundary: str) -> "list[bytes] | None":
    """Split a multipart body into its part byte-spans (delimiters excluded)."""
    delim = b"--" + boundary.encode("utf-8")
    positions = []
    start = 0
    while True:
        idx = body.find(delim, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + len(delim)
    if len(positions) < 2:
        return None
    parts = []
    for i in range(len(positions) - 1):
        # Skip the CRLF terminating this delimiter line and the CRLF that
        # precedes the next delimiter.
        seg_start = positions[i] + len(delim) + 2
        seg_end = positions[i + 1] - 2
        parts.append(body[seg_start:max(seg_start, seg_end)])
    return parts


def _ct_key(headers: dict) -> str:
    return next((k for k in headers if k.lower() == "content-type"), "Content-Type")


@register(Transform(
    id="multipart_boundary_variance",
    vendors=VENDORS,
    category="multipart",
    risk="standard",
    docs_path="docs/techniques/multipart_boundary_variance.md",
    explain="re-quote the boundary token in Content-Type only",
))
def multipart_boundary_variance(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Flip boundary quoting between the header and what scanners expect.

    The body keeps its delimiters; the Content-Type header gains quotes around
    an unquoted boundary token. Lenient parsers accept both forms per RFC 7578;
    naive extractors anchored on one spelling capture nothing. Werkzeug
    compatibility is asserted by tests.
    """
    if not spec.body:
        return None
    ctype = content_type(spec)
    boundary = _boundary(ctype)
    if boundary is None or f'boundary="{boundary}"' in ctype:
        return None
    quoted = ctype.replace(f"boundary={boundary}", f'boundary="{boundary}"', 1)
    return replace(spec, headers={**spec.headers, _ct_key(dict(spec.headers)): quoted})


@register(Transform(
    id="multipart_payload_last",
    vendors=VENDORS,
    category="multipart",
    risk="standard",
    docs_path="docs/techniques/multipart_payload_last.md",
    explain="reverse part order so attacker-controlled parts land last",
))
def multipart_payload_last(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Reverse the order of multipart parts.

    Each part stays byte-intact and named-field semantics are unchanged, but
    combined with size-window scanning the final parts sit past the cutoff.
    Pairs with pad_multipart_decoy.
    """
    if not spec.body:
        return None
    ctype = content_type(spec)
    boundary = _boundary(ctype)
    if boundary is None:
        return None
    delim = b"--" + boundary.encode("utf-8")
    body = spec.body
    positions = []
    start = 0
    while True:
        idx = body.find(delim, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + len(delim)
    if len(positions) < 3:  # need at least two parts plus terminator
        return None

    preamble_end = positions[0]
    closer_idx = positions[-1]
    part_spans = []
    for i in range(len(positions) - 1):
        span_start = positions[i] + len(delim) + 2  # skip CRLF after --boundary
        span_end = positions[i + 1] - 2  # strip CRLF before next --boundary
        part_spans.append((span_start, max(span_start, span_end)))
    parts = [body[a:b] for a, b in part_spans]
    rebuilt = (
        body[:preamble_end]
        + b"".join(
            delim + b"\r\n" + part + b"\r\n" for part in reversed(parts)
        )
        + body[closer_idx:]
    )
    return replace(spec, body=rebuilt)

