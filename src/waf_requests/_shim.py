"""Build a drop-in replacement of the requests module backed by WAFSession.

The shim copies the real requests namespace (exceptions, auth, codes,
packages, utils all pass through untouched) and overrides only the nine
entry points exploits actually call.
"""
from __future__ import annotations

import sys
import types

import requests as _real_requests

from .api import delete, get, head, options, patch, post, put, request
from .engine import WAFSession


def build_shim() -> "types.ModuleType":
    shim = types.ModuleType("requests")
    shim.__doc__ = "waf_requests drop-in shim over requests"
    shim.__version__ = getattr(_real_requests, "__version__", "0")
    for key, value in vars(_real_requests).items():
        if key.startswith("__") and key != "__version__":
            continue
        setattr(shim, key, value)
    overrides = {
        "get": get,
        "post": post,
        "put": put,
        "patch": patch,
        "delete": delete,
        "head": head,
        "options": options,
        "request": request,
        "Session": WAFSession,
    }
    for key, value in overrides.items():
        setattr(shim, key, value)
    return shim


def install() -> "types.ModuleType":
    """Swap sys.modules['requests'] for the shim (process-local, reversible)."""
    original = sys.modules.get("requests")
    shim = build_shim()
    setattr(shim, "__waf_original_requests__", original)
    sys.modules["requests"] = shim
    return shim


def uninstall() -> None:
    """Restore whatever module install() replaced."""
    current = sys.modules.get("requests")
    original = getattr(current, "__waf_original_requests__", None)
    if isinstance(current, types.ModuleType) and original is not None:
        sys.modules["requests"] = original
