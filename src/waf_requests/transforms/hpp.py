"""HTTP parameter pollution differentials."""
from __future__ import annotations

from dataclasses import replace
from urllib.parse import quote, urlsplit, urlunsplit

from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, register


def _split_pairs(query: str) -> "list[tuple[str, bool]]":
    """Split a raw query string into (raw-pair, had-separator) chunks."""
    chunks = []
    for chunk in query.split("&"):
        key, sep, value = chunk.partition("=")
        chunks.append((chunk, bool(sep)))
    return [(c, s) for c, s in chunks]


@register(Transform(
    id="hpp_duplicate_param",
    vendors=VENDORS,
    category="hpp",
    risk="standard",
    docs_path="docs/techniques/hpp_duplicate_param.md",
    explain="prepend a benign duplicate before every query parameter",
))
def hpp_duplicate_param(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Emit ``q=1&q=<original>`` for each query pair.

    First-occurrence readers (common WAF variable extraction) evaluate the
    benign value; last-wins frameworks keep the original.
    """
    parts = urlsplit(spec.url)
    if not parts.query:
        return None
    emitted = []
    for chunk, has_value in _split_pairs(parts.query):
        key = chunk.split("=", 1)[0]
        emitted.append(f"{quote(key, safe='')}=1")
        emitted.append(chunk)
    new_query = "&".join(emitted)
    if new_query == parts.query:
        return None
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    return replace(spec, url=new_url)


@register(Transform(
    id="hpp_semicolon_sep",
    vendors=VENDORS,
    category="hpp",
    risk="standard",
    docs_path="docs/techniques/hpp_semicolon_sep.md",
    explain="replace & separators with ; between query pairs",
))
def hpp_semicolon_sep(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Join query pairs with semicolons instead of ampersands.

    Scanners splitting only on & see one opaque blob parameter; frameworks
    splitting on ; recover the pairs (historic PHP/JSP behavior). Conditional
    on origin separator support - stated on the docs page.
    """
    parts = urlsplit(spec.url)
    query = parts.query
    if "&" not in query:
        return None
    segments = []
    for chunk in query.split("&"):
        key, sep, value = chunk.partition("=")
        # Re-quote so literal ; inside decoded values cannot re-split wrongly.
        segments.append(
            quote(key, safe="")
            + ("=" + quote(value, safe="") if sep else "")
        )
    new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, ";".join(segments), parts.fragment))
    return replace(spec, url=new_url)


