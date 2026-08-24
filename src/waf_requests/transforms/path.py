"""Routing-normalization differentials on the URL path."""
from __future__ import annotations

from dataclasses import replace
from urllib.parse import urlsplit, urlunsplit

from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, register


def _rewrite_path(spec: ReqSpec, new_path: str) -> ReqSpec:
    parts = urlsplit(spec.url)
    new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
    return replace(spec, url=new_url)


@register(Transform(
    id="path_semicolon_params",
    vendors=VENDORS,
    category="path",
    risk="standard",
    docs_path="docs/techniques/path_semicolon_params.md",
    explain="append ;waf=1 matrix parameter to the first path segment",
))
def path_semicolon_params(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Append ``;waf=1`` to the first path segment.

    Tomcat/Jetty-family routers strip matrix parameters before routing while
    signature engines may treat the segment as a different string.
    """
    parts = urlsplit(spec.url)
    path = parts.path or "/"
    head, sep, tail = path.lstrip("/").partition("/")
    if not head:
        return None
    new_path = "/" + head + ";waf=1" + (sep + tail if sep else "")
    return _rewrite_path(spec, new_path)


@register(Transform(
    id="path_dot_segments",
    vendors=VENDORS,
    category="path",
    risk="standard",
    docs_path="docs/techniques/path_dot_segments.md",
    explain="insert percent-encoded /%2e/ and /waf/%2e%2e/ segments normalizing to the same path",
))
def path_dot_segments(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Prefix percent-encoded dot-segments that normalize back identically.

    Raw ``/./`` and ``/../`` are removed by requests' own URL preparation
    (measured no-op), so this emits the encoded form ``/%2e/waf/%2e%2e``:
    it survives the client transport, decodes once at any conformant edge,
    and RFC 3986 remove_dot_segments then yields the original path for the
    origin router. Engines that match before decoding - or normalize in a
    different order - see a different string. Fidelity: differential
    (depends on origin decode-then-normalize behavior).
    """
    parts = urlsplit(spec.url)
    path = parts.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        return None
    new_path = "/%2e/waf/%2e%2e" + path
    return _rewrite_path(spec, new_path)


@register(Transform(
    id="path_double_slash",
    vendors=VENDORS,
    category="path",
    risk="standard",
    docs_path="docs/techniques/path_double_slash.md",
    explain="insert an empty // segment inside the path",
))
def path_double_slash(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Insert an empty segment between the first and second segments.

    Collapsing resolvers route identically; non-collapsing matchers see a
    different string. A leading ``//`` is deliberately avoided because it is
    protocol-relative syntax at scheme-relative URLs.
    """
    parts = urlsplit(spec.url)
    path = parts.path or "/"
    stripped = path.lstrip("/")
    head, sep, tail = stripped.partition("/")
    if not sep or not tail:
        return None
    new_path = "/" + head + "//" + tail
    return _rewrite_path(spec, new_path)
