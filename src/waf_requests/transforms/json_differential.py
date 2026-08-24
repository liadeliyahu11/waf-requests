"""JSON parser-differential transforms."""
from __future__ import annotations

import json
from dataclasses import replace

from ..spec import ReqSpec
from . import Ctx, Transform, VENDORS, register

#: Depth of the nested-array wrap in json_deep_nest_wrap.
NEST_DEPTH = 2000

_BENIGN_DUP_VALUE = "waf_benign"


def _load_pairs(body: bytes):
    """Parse keeping object key order and duplicates as pair lists."""

    def hook(pairs):
        return pairs  # list[(key, value)]

    return json.loads(body.decode("utf-8"), object_pairs_hook=hook)


def _dump(node) -> str:
    """Serialize pair-lists/containers back to compact JSON."""
    if isinstance(node, list) and node and isinstance(node[0], tuple):
        inner = ",".join(f"{json.dumps(str(k))}:{_dump(v)}" for k, v in node)
        return "{" + inner + "}"
    if isinstance(node, list):
        return "[" + ",".join(_dump(item) for item in node) + "]"
    if isinstance(node, dict):
        return "{" + ",".join(
            f"{json.dumps(str(k))}:{_dump(v)}" for k, v in node.items()
        ) + "}"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if node is None:
        return "null"
    if isinstance(node, (int, float)):
        return json.dumps(node)
    if isinstance(node, str):
        return json.dumps(node)
    raise TypeError(f"unsupported node {type(node)!r}")


@register(Transform(
    id="json_dup_key_lastwins",
    vendors=VENDORS,
    category="json",
    risk="standard",
    docs_path="docs/techniques/json_dup_key_lastwins.md",
    explain="emit a benign duplicate of the first key before the payload pair",
))
def json_dup_key_lastwins(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Duplicate the first key with a benign value ahead of the original.

    Last-key-wins parsers (Python json, Jackson default) keep the payload
    value; matchers reading the first or any occurrence see the benign one.
    """
    if not spec.body:
        return None
    try:
        top = _load_pairs(spec.body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not (isinstance(top, list) and top and isinstance(top[0], tuple)):
        return None
    first_key = str(top[0][0])
    first_key_values = [v for k, v in top if str(k) == first_key]
    last_value = first_key_values[-1]

    benign_pair = f"{json.dumps(first_key)}:{json.dumps(_BENIGN_DUP_VALUE)}"
    rest = _dump(top)
    body = ("{" + benign_pair + "," + rest[1:]).encode("utf-8")
    try:
        parsed = json.loads(body.decode("utf-8"))
        if parsed.get(first_key) != last_value:
            return None
    except ValueError:
        return None
    return replace(spec, body=body)


@register(Transform(
    id="json_deep_nest_wrap",
    vendors=VENDORS,
    category="json",
    risk="standard",
    docs_path="docs/techniques/json_deep_nest_wrap.md",
    explain="wrap the value in ~2000 nested arrays to defeat naive scanners",
))
def json_deep_nest_wrap(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Wrap the top-level value in NEST_DEPTH nested arrays.

    stdlib json parses it fine; depth-limited scanners and regex engines give
    up. Changes app-visible shape (value arrives deeply nested) - documented.
    """
    if not spec.body:
        return None
    try:
        parsed = json.loads(spec.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    wrapped = parsed
    for _ in range(NEST_DEPTH):
        wrapped = [wrapped]
    dumped = json.dumps(wrapped, separators=(",", ":")).encode("utf-8")
    return replace(spec, body=dumped)


@register(Transform(
    id="json_comment_inject",
    vendors=VENDORS,
    category="json",
    risk="conditional",
    docs_path="docs/techniques/json_comment_inject.md",
    explain="inject /*waf*/ comments between JSON tokens",
))
def json_comment_inject(spec: ReqSpec, ctx: Ctx) -> "ReqSpec | None":
    """Inject JS-style comments after the first token boundary.

    Strict RFC 8259 parsers reject comments; lenient parsers strip them.
    Marked experimental for exactly that reason. Tests verify integrity with
    comment stripping, mirroring a lenient consumer.
    """
    if not spec.body:
        return None
    try:
        text = spec.body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.lstrip().startswith("{"):
        return None
    commented = text.replace("{", "{/*waf*/", 1).encode("utf-8")
    if commented == spec.body:
        return None
    return replace(spec, body=commented)
