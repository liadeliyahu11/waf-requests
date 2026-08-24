"""Command-injection payload obfuscation."""
from __future__ import annotations

from ..encodings import hex_encode
from . import Payload, register


@register(Payload(
    id="cmdi_ifs_space", category="cmdi",
    explain="replace spaces with ${IFS}",
    fidelity="differential",
))
def cmdi_ifs_space(payload: str) -> str:
    """Substitute ``${IFS}`` for spaces; POSIX shells expand it to whitespace."""
    return payload.replace(" ", "${IFS}")


@register(Payload(
    id="cmdi_backtick", category="cmdi",
    explain="wrap in backticks and replace spaces with ${IFS}",
    fidelity="differential",
))
def cmdi_backtick(payload: str) -> str:
    """Backtick-wrap the command and substitute ``${IFS}`` for spaces."""
    return "`" + payload.replace(" ", "${IFS}") + "`"


@register(Payload(
    id="cmdi_hex_echo", category="cmdi",
    explain="echo <hex>|xxd -r -p|sh",
    fidelity="differential",
))
def cmdi_hex_echo(payload: str) -> str:
    """Re-encode the command as hex and pipe it through ``xxd -r -p | sh``."""
    return f"echo {hex_encode(payload)}|xxd -r -p|sh"
