"""Active WAF fingerprinting via a benign baseline + canary probe pair."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests

log = logging.getLogger("waf_requests.detect")

#: Throwaway parameter carrying the canary payload.
CANARY_PARAM = "wafprobe"
#: Obvious SQLi token: managed rule sets light up on it, origins echo it.
CANARY_VALUE = "' OR '1'='1"

_HOST_VENDOR: "dict[str, str]" = {}


def host_of(url_or_host: str) -> str:
    """Lowercase host(+port) from a URL or bare host."""
    if "://" in url_or_host:
        return urlparse(url_or_host).netloc.lower()
    return url_or_host.split("/")[0].lower()


def cached_vendor(host: str) -> "str | None":
    return _HOST_VENDOR.get(host)


def fingerprint(url: str, timeout: float = 10.0) -> "str | None":
    """Fingerprint the WAF in front of ``url``; returns vendor name or None.

    Sends a benign baseline and a canary carrying an obvious SQLi token in
    :data:`CANARY_PARAM`. A vendor is claimed only when the canary response
    carries an explicit block/challenge signature (never on UNKNOWN). Results
    are cached per host. Connection failures return None with a logged reason.
    """
    from .blockpage import classify

    host = host_of(url)
    base = url if "://" in url else "http://" + url
    try:
        baseline = requests.get(base, timeout=timeout)
        canary = requests.get(
            base, params={CANARY_PARAM: CANARY_VALUE}, timeout=timeout,
        )
    except requests.RequestException as exc:
        log.warning("probe failed for %s: %s", host, exc)
        return None

    verdict = classify(canary)
    if verdict.vendor and verdict.status.name in ("BLOCKED", "CHALLENGE"):
        _HOST_VENDOR[host] = verdict.vendor
        log.info("fingerprinted %s as %s (%s)", host, verdict.vendor, verdict.evidence)
        return verdict.vendor
    log.info(
        "no explicit signature on canary for %s (baseline=%s canary=%s)",
        host, classify(baseline).status.value, verdict.status.value,
    )
    return None
