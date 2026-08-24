"""Unicode and decode-count differentials."""
from __future__ import annotations

import json
from dataclasses import replace
from urllib.parse import quote, urlsplit, urlunsplit

from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, register

#: Characters escaped as \\uXXXX inside JSON string values. Structural quotes
#: and backslashes use their short escapes; everything else stays literal.
_JSON_FORCE_CHARS = set("\"\\<>()';&|")


@register(Transform(
    id="percent_double_encode",
    vendors=VENDORS,
    category="unicode",
    risk="standard",
    docs_path="docs/techniques/percent_double_encode.md",
    explain="double percent-encode every query value",
))
def percent_double_encode(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Double-encode query values: WAF decodes once and sees encoded noise.

    Origins that decode twice recover the payload. Single-decode frameworks
    see the once-decoded form - the docs page states this prerequisite
    honestly.
    """
    parts = urlsplit(spec.url)
    if not parts.query:
        return None
    pairs = []
    saw_any = False
    for chunk in parts.query.split("&"):
        key, sep, value = chunk.partition("=")
        doubled = quote(quote(value, safe=""), safe="")
        if doubled != value:
            saw_any = True
        pairs.append(f"{quote(key, safe='')}={doubled}" + ("" if not sep else ""))
    if not saw_any:
        return None
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))
    return replace(spec, url=new_url)


def _dump_json(obj) -> str:
    if isinstance(obj, str):
        out = ['"']
        for ch in obj:
            if ch == '"':
                out.append('\\"')
            elif ch == "\\":
                out.append("\\\\")
            elif ch in _JSON_FORCE_CHARS or ord(ch) < 0x20:
                out.append("\\u%04x" % ord(ch))
            else:
                out.append(ch)
        out.append('"')
        return "".join(out)
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, (int, float)):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_dump_json(item) for item in obj) + "]"
    if isinstance(obj, dict):
        return "{" + ",".join(
            f"{_dump_json(str(k))}:{_dump_json(v)}" for k, v in obj.items()
        ) + "}"
    raise TypeError(f"unsupported JSON node: {type(obj)!r}")


@register(Transform(
    id="json_unicode_escape",
    vendors=VENDORS,
    category="unicode",
    risk="standard",
    docs_path="docs/techniques/json_unicode_escape.md",
    explain="escape signature characters in JSON strings as \\uXXXX",
))
def json_unicode_escape(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Rewrite JSON with \\uXXXX escapes for signature-bearing ASCII.

    Any RFC 8259 parser decodes identical values; naive byte scanners lose
    their anchors.
    """
    if not spec.body:
        return None
    try:
        parsed = json.loads(spec.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    dumped = _dump_json(parsed).encode("utf-8")
    if dumped == spec.body:
        return None
    return replace(spec, body=dumped)


@register(Transform(
    id="utf8_overlong_path",
    vendors=VENDORS,
    category="unicode",
    risk="conditional",
    docs_path="docs/techniques/utf8_overlong_path.md",
    explain="encode path separators and dots as overlong UTF-8 sequences",
))
def utf8_overlong_path(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Overlong UTF-8 encodings of ``/`` and ``.`` inside the URL path.

    Mostly historical: helps only where an upstream normalizes overlong forms
    while the signature engine does not; modern routers often reject them.
    Kept as an educational differential with honest expectations.
    """
    parts = urlsplit(spec.url)
    path = parts.path
    if len(path) <= 1 or "%" in path:
        return None
    rebuilt_chars = []
    changed = False
    for i, ch in enumerate(path):
        if ch == "/" and i > 0:
            rebuilt_chars.append("%c0%af")
            changed = True
        elif ch == ".":
            rebuilt_chars.append("%c0%ae")
            changed = True
        else:
            rebuilt_chars.append(ch)
    if not changed:
        return None
    new_url = urlunsplit(
        (parts.scheme, parts.netloc, "".join(rebuilt_chars), parts.query, parts.fragment)
    )
    return replace(spec, url=new_url)
