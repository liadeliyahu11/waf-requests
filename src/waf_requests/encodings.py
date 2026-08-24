"""Pure ``str -> str`` encoders shared by payload mutators and the decode oracle.

Every encoder is deterministic and uses only the standard library. They answer
one question each: if the WAF decodes THIS representation, does it recover the
original payload and block it? The normalization oracle (Phase 2) sends each
representation and reads block-vs-pass.
"""
from __future__ import annotations

import base64
from urllib.parse import quote

#: Characters force-escaped into UTF-7 ``+AXX-`` shift sequences even though
#: ASCII permits them literally; escaping hides classic signature characters.
_UTF7_FORCE_CHARS = "<>\"'()&"


def percent_encode(s: str) -> str:
    """URL-encode every byte (``quote(..., safe='')``)."""
    return quote(s, safe="")


def percent_double_encode(s: str) -> str:
    """URL-encode once, then re-encode the ``%`` signs (``%`` -> ``%25``)."""
    return quote(percent_encode(s), safe="")


def backslash_unicode(s: str) -> str:
    """Escape every character as ``\\u00XX``."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def percent_unicode(s: str) -> str:
    """Escape every character as ``%u00XX`` (IIS-style)."""
    return "".join(f"%u{ord(c):04x}" for c in s)


def html_entity_hex(s: str) -> str:
    """Replace the five HTML-special ASCII characters with hex entities."""
    table = {"'": "&#x27;", "<": "&#x3C;", ">": "&#x3E;",
             "&": "&#x26;", '"': "&#x22;"}
    return "".join(table.get(c, c) for c in s)


def html_entity_named(s: str) -> str:
    """Replace the five HTML-special ASCII characters with named entities."""
    table = {"'": "&apos;", "<": "&lt;", ">": "&gt;",
             "&": "&amp;", '"': "&quot;"}
    return "".join(table.get(c, c) for c in s)


def overlong_utf8(s: str) -> str:
    """Encode every byte as a two-byte overlong UTF-8 sequence (``%c0%XX``)."""
    out = []
    for byte in s.encode("utf-8"):
        out.append(f"%{0xc0 | (byte >> 6):02x}%{0x80 | (byte & 0x3f):02x}")
    return "".join(out)


def base64_encode(s: str) -> str:
    """Base64-encode the UTF-8 bytes of the string."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def utf7_encode(s: str) -> str:
    """Force-escape signature characters as UTF-7 ``+AXX-`` shift sequences.
    Plain ASCII passes through; ``< > " ' ( ) &`` become modified-base64
    sequences (``<`` -> ``+ADw-``). The declared charset is NOT set here - this
    is the byte-level transform only.
    """
    out = []
    for ch in s:
        if ch in _UTF7_FORCE_CHARS:
            encoded = base64.b64encode(ch.encode("utf-16-be")).decode("ascii").rstrip("=")
            out.append(f"+{encoded}-")
        else:
            out.append(ch)
    return "".join(out)


def hex_encode(s: str) -> str:
    """Lowercase hex of the UTF-8 bytes (``a`` -> ``61``)."""
    return s.encode("utf-8").hex()


#: Decode-oracle variants: (name, encoder | None). ``None`` means send the
#: literal payload via ``params=`` so the transport applies its normal
#: single-encoding; the rest are raw query-string values applied manually.
DECODE_VARIANTS: "list[tuple[str, object | None]]" = [
    ("raw", None),
    ("percent", percent_encode),
    ("double", percent_double_encode),
    ("backslash_unicode", backslash_unicode),
    ("percent_unicode", percent_unicode),
    ("html_entity_hex", html_entity_hex),
    ("html_entity_named", html_entity_named),
    ("overlong_utf8", overlong_utf8),
    ("base64", base64_encode),
    ("utf7", utf7_encode),
    ("hex", hex_encode),
]
