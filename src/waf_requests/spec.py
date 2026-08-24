"""Wire-level request snapshot shared by the engine and every transform."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Union

import requests
from urllib3 import HTTPHeaderDict

HeaderValue = Union[str, "list[str]"]


@dataclass(frozen=True)
class ReqSpec:
    """Immutable byte-level view of one HTTP request.

    Transforms consume and produce ReqSpec instances; nothing mutates the
    caller's objects. A header value may be a list of strings to express a
    genuinely duplicated field (sent as repeated header lines, see
    ``to_prepared``).
    """

    method: str
    url: str
    headers: dict[str, HeaderValue]
    body: "bytes | None" = None


def from_prepared(prepared: "requests.PreparedRequest") -> ReqSpec:
    body = prepared.body
    if isinstance(body, str):
        body = body.encode("utf-8")
    return ReqSpec(
        method=(prepared.method or "GET").upper(),
        url=prepared.url or "",
        headers={str(k): v for k, v in dict(prepared.headers).items()},
        body=body,
    )


def to_prepared(spec: ReqSpec) -> "requests.PreparedRequest":
    """Rebuild a fresh PreparedRequest from a spec.

    List-valued headers are emitted as repeated header lines via
    ``urllib3.HTTPHeaderDict``, which forwards every pair down to the socket.
    """
    prepared = requests.PreparedRequest()
    scalar = {
        k: (v[0] if isinstance(v, list) and len(v) == 1 else v)
        for k, v in spec.headers.items()
        if not isinstance(v, list) or v
    }
    prepared.prepare(
        method=spec.method,
        url=spec.url,
        data=spec.body,
        headers={k: str(v) for k, v in scalar.items()},
    )
    multi = {k: v for k, v in spec.headers.items() if isinstance(v, list) and len(v) > 1}
    if multi:
        merged = HTTPHeaderDict()
        for k, v in prepared.headers.items():
            merged.add(str(k), str(v))
        for name, values in multi.items():
            del merged[name]
            for value in values:
                merged.add(name, str(value))
        prepared.headers = merged
    return prepared
