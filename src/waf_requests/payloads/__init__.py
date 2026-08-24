"""Payload mutation registry: pure ``str -> str`` obfuscators per vuln class.

This is the middle layer between the attack string and the request shape.
Request transforms (``transforms/``) reshape the HTTP envelope; payload
mutators rewrite the exploit string itself so signature engines anchored on
literal bytes (``UNION SELECT``, ``<script>``, ``cat /etc``) miss it while the
backend still parses the intended semantics. The fidelity tier means the same
thing here as for transforms: ``transparent`` = byte-different but semantically
identical (delivery = guaranteed win); ``differential`` = depends on backend
interpretation.
"""
from __future__ import annotations

import dataclasses
from typing import Callable

CATEGORIES: frozenset[str] = frozenset({"sqli", "xss", "cmdi", "lfi", "ssrf", "ssti", "xxe"})

@dataclasses.dataclass(frozen=True)
class Payload:
    id: str
    category: str
    explain: str
    #: transparent | differential (same meaning as transform fidelity).
    fidelity: str = "differential"
    apply: "Callable[[str], str] | None" = None


PAYLOADS: "dict[str, Payload]" = {}


def register(payload: Payload) -> Callable:
    """Decorator completing a Payload with the decorated function as apply.

    Mirrors ``transforms.register``: the module-level name stays the plain
    function, the completed entry lives in PAYLOADS.
    """
    def wrap(func: Callable) -> Callable:
        complete = dataclasses.replace(payload, apply=func)
        if complete.id in PAYLOADS:
            raise ValueError(f"duplicate payload id: {complete.id}")
        if complete.category not in CATEGORIES:
            raise ValueError(f"unknown category: {complete.category!r}")
        PAYLOADS[complete.id] = complete
        return func
    return wrap


def by_category(category: str) -> "list[Payload]":
    """Mutators for one vuln class, transparent tier first."""
    members = [p for p in PAYLOADS.values() if p.category == category]
    members.sort(key=lambda p: (p.fidelity != "transparent", p.id))
    return members


# Import submodules so every @register runs at package import time.
from . import cmdi as _cmdi  # noqa: E402,F401
from . import lfi as _lfi  # noqa: E402,F401
from . import sqli as _sqli  # noqa: E402,F401
from . import ssrf as _ssrf  # noqa: E402,F401
from . import ssti as _ssti  # noqa: E402,F401
from . import xss as _xss  # noqa: E402,F401
from . import xxe as _xxe  # noqa: E402,F401
