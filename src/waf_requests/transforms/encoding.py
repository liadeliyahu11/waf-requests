"""Encoding transforms: compressed bodies and charset mismatches."""
from __future__ import annotations

import base64
import gzip
import zlib
from dataclasses import replace

from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, content_type, register

#: Characters force-escaped into UTF-7 sequences even though ASCII permits them
#: literally; escaping these hides classic signature characters from byte scans.
_UTF7_FORCE_CHARS = "<>\"'()&"


def _utf7_escape(ch: str) -> str:
    encoded = base64.b64encode(ch.encode("utf-16-be")).decode("ascii").rstrip("=")
    return f"+{encoded}-"


def _force_utf7(text: str) -> str:
    out = []
    for ch in text:
        out.append(_utf7_escape(ch) if ch in _UTF7_FORCE_CHARS else ch)
    return "".join(out)


def _set_charset(value: str, charset: str) -> str:
    base = value.split(";")[0]
    return f"{base}; charset={charset}"


def _compress_transform(transform_id, codec, encoding_name, explain):
    def apply(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
        if not spec.body or spec.headers.get("Content-Encoding"):
            return None
        compressed = codec(spec.body)
        if compressed == spec.body:
            return None
        updated = replace(
            spec,
            body=compressed,
            headers={**spec.headers, "Content-Encoding": encoding_name},
        )
        return updated
    return register(Transform(
        id=transform_id,
        vendors=VENDORS,
        category="encoding",
        risk="conditional",
        docs_path=f"docs/techniques/{transform_id}.md",
        explain=explain,
    ))(apply)


_compress_transform(
    "gzip_body", gzip.compress, "gzip",
    "gzip the whole request body behind Content-Encoding: gzip",
)
_compress_transform(
    "deflate_body", zlib.compress, "deflate",
    "zlib-compress the whole request body behind Content-Encoding: deflate",
)


@register(Transform(
    id="charset_utf7",
    vendors=VENDORS,
    category="encoding",
    risk="conditional",
    docs_path="docs/techniques/charset_utf7.md",
    explain="re-encode body as UTF-7 with signature characters escaped",
))
def charset_utf7(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Re-encode a textual body as UTF-7 and declare charset=utf-7.

    Signature-bearing ASCII such as ``<`` arrives as ``+ADw-`` so byte-level
    scanners see noise; stacks that honor the declared charset decode back to
    the original string. Requires an origin that decodes UTF-7 - documented,
    historic behavior.
    """
    if not spec.body:
        return None
    ctype = content_type(spec)
    textual = any(t in ctype.lower() for t in ("json", "x-www-form-urlencoded", "text/", "xml"))
    if not textual:
        return None
    try:
        text = spec.body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    escaped = _force_utf7(text).encode("ascii")
    ct_key = next((k for k in spec.headers if k.lower() == "content-type"), "Content-Type")
    headers = dict(spec.headers)
    headers[ct_key] = _set_charset(str(headers[ct_key]), "utf-7")
    return replace(spec, body=escaped, headers=headers)
