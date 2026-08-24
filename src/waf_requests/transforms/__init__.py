"""Transform registry: pure ReqSpec -> ReqSpec mutations demonstrating WAF gaps."""
from __future__ import annotations

import dataclasses
from typing import Callable

from ..spec import HeaderValue, ReqSpec

VENDORS = frozenset({"aws", "cloudflare", "akamai"})


@dataclasses.dataclass(frozen=True)
class Ctx:
    """What a transform may assume about the target profile."""

    profile_limit: "int | None"
    marker: "str | None" = None


@dataclasses.dataclass(frozen=True)
class Transform:
    id: str
    vendors: frozenset
    category: str
    risk: str  # standard | conditional
    docs_path: str
    explain: str
    #: transparent | additive | differential - stamped by
    #: waf_requests.fidelity.apply_fidelity after registration.
    fidelity: str = "differential"
    apply: "Callable[[ReqSpec, Ctx], ReqSpec | None] | None" = None


TRANSFORMS: "dict[str, Transform]" = {}



def register(transform: Transform) -> Callable:
    """Decorator completing a Transform with the decorated function as apply.

    Usage:
        @register(Transform(id=..., vendors=..., category=..., risk=...,
                            docs_path=..., explain=...))
        def some_transform(spec, ctx): ...

    The module-level name stays the plain function, so callers may invoke it
    directly; the completed entry lives in TRANSFORMS.
    """
    def wrap(func: Callable) -> Callable:
        complete = dataclasses.replace(transform, apply=func)
        if complete.id in TRANSFORMS:
            raise ValueError(f"duplicate transform id: {complete.id}")
        TRANSFORMS[complete.id] = complete
        return func
    return wrap


# ---- shared helpers -------------------------------------------------------

def content_type(spec: ReqSpec) -> str:
    """Content-Type header value with original case preserved.

    Boundary tokens are case-sensitive on the wire; callers doing substring
    checks lower it themselves.
    """
    return spec.headers.get("Content-Type") or ""


def with_headers(spec: ReqSpec, **updates: HeaderValue) -> ReqSpec:
    headers = dict(spec.headers)
    headers.update(updates)
    return dataclasses.replace(spec, headers=headers)


# Import submodules so every @register runs at package import time.
from . import encoding as _encoding  # noqa: E402,F401
from . import headers as _headers  # noqa: E402,F401
from . import hpp as _hpp  # noqa: E402,F401
from . import json_differential as _json_differential  # noqa: E402,F401
from . import multipart as _multipart  # noqa: E402,F401
from . import path as _path  # noqa: E402,F401
from . import size as _size  # noqa: E402,F401
from . import traversal as _traversal  # noqa: E402,F401
from . import unicode as _unicode  # noqa: E402,F401
from ..fidelity import apply_fidelity as _apply_fidelity  # noqa: E402

_apply_fidelity(TRANSFORMS)
