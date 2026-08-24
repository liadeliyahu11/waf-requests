"""waf_requests: educational drop-in requests shim demonstrating WAF inspection gaps.

Swaps ``import requests`` for a session that replays blocked requests through
bypass transforms sized for AWS WAF, Cloudflare, and Akamai inspection limits.
For education and authorized testing against properties you own only.
"""
from __future__ import annotations

from ._shim import build_shim, install, uninstall
from ._state import configure, get_config
from .api import delete, get, head, options, patch, post, put, request
from .blockpage import Status, Verdict, classify
from .detect import fingerprint
from .engine import AttemptLog, WAFSession
from .profiles import ALL_VENDORS, PROFILES, Profile  # noqa: F401  (PROFILES re-exported)
from .payloads import CATEGORIES, PAYLOADS, Payload, by_category
from .transforms import TRANSFORMS, Ctx, Transform

# Public alias: `waf_requests.Session` behaves like requests.Session but with
# the bypass ladder enabled.
Session = WAFSession

#: Alias matching the plan's public surface: detect(url) -> vendor | None.
detect = fingerprint

__all__ = [
    "AttemptLog",
    "ALL_VENDORS",
    "CATEGORIES",
    "Ctx",
    "PAYLOADS",
    "Payload",
    "Profile",
    "Status",
    "TRANSFORMS",
    "Transform",
    "Verdict",
    "WAFSession",
    "build_shim",
    "by_category",
    "classify",
    "configure",
    "delete",
    "detect",
    "fingerprint",
    "get",
    "get_config",
    "head",
    "install",
    "monkeypatch",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "uninstall",
]


def monkeypatch(undo: bool = False) -> None:
    """Map ``sys.modules['requests']`` to this library's shim, process-local.

    After calling this, unmodified exploit scripts importing requests get the
    bypass ladder. ``monkeypatch(undo=True)`` restores the original module.
    """
    if undo:
        uninstall()
    else:
        install()
