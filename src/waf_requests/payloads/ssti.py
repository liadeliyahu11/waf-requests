"""Server-side template injection payload obfuscation."""
from __future__ import annotations

from ..encodings import backslash_unicode
from . import Payload, register


@register(Payload(
    id="ssti_comment_break", category="ssti",
    explain="insert {##} into the template expression ({{7*7}} -> {{7*{##}7}})",
    fidelity="differential",
))
def ssti_comment_break(payload: str) -> str:
    """Split the inner expression with a Jinja comment so braces tokens differ."""
    if payload.startswith("{{") and payload.endswith("}}") and len(payload) > 4:
        inner = payload[2:-2]
        return "{{" + inner[:-1] + "{##}" + inner[-1] + "}}"
    return payload


@register(Payload(
    id="ssti_unicode_escape", category="ssti",
    explain="backslash-escape every character",
    fidelity="differential",
))
def ssti_unicode_escape(payload: str) -> str:
    """Escape the whole expression so literal ``{{``/``7*7`` bytes vanish."""
    return backslash_unicode(payload)
