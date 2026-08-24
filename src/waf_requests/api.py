"""Top-level API mirroring requests.func behavior through WAFSession.

Like ``requests.api``, each call uses its own session (no cookie persistence),
so semantics match stock requests while the bypass ladder still applies.
"""
from __future__ import annotations

from typing import Any

from ._state import default_session


def request(method: str, url: str, **kwargs: Any):
    session = default_session()
    try:
        return session.request(method=method, url=url, **kwargs)
    finally:
        session.close()


def get(url: str, params=None, **kwargs: Any):
    return request("GET", url, params=params, **kwargs)


def options(url: str, **kwargs: Any):
    return request("OPTIONS", url, **kwargs)


def head(url: str, **kwargs: Any):
    return request("HEAD", url, **kwargs)


def post(url: str, data=None, json=None, **kwargs: Any):
    return request("POST", url, data=data, json=json, **kwargs)


def put(url: str, data=None, **kwargs: Any):
    return request("PUT", url, data=data, **kwargs)


def patch(url: str, data=None, **kwargs: Any):
    return request("PATCH", url, data=data, **kwargs)


def delete(url: str, **kwargs: Any):
    return request("DELETE", url, **kwargs)
