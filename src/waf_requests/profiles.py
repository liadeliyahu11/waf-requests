"""Per-vendor inspection assumptions and default transform ladders."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger("waf_requests.profiles")

ALL_VENDORS = frozenset({
    "aws", "cloudflare", "akamai",
    "modsecurity", "imperva", "f5", "fortiweb", "barracuda",
    "citrix", "radware", "wordfence", "sucuri",
})

# Fidelity-safe transforms first: transparent/additive entries never change
# what the origin's parser sees, so exploitation traffic stays intact.
# Differential transforms (double-encode, HPP, dup-keys) run only as last
# resort; WAFSession(strict_fidelity=True) excludes them entirely.
DEFAULT_LADDER: "tuple[str, ...]" = (
    "pad_json_ws",
    "json_unicode_escape",
    "pad_form_param",
    "pad_multipart_decoy",
    "header_pad_early",
    "json_dup_key_lastwins",
    "hpp_duplicate_param",
    "percent_double_encode",
)


@dataclass(frozen=True)
class Profile:
    name: str
    body_limit: "int | None"
    ladder: "tuple[str, ...]"
    notes_path: str


PROFILES: "dict[str, Profile]" = {
    "aws": Profile("aws", 8192, DEFAULT_LADDER, "docs/research/aws.md"),
    "cloudflare": Profile("cloudflare", 131072, DEFAULT_LADDER, "docs/research/cloudflare.md"),
    "akamai": Profile("akamai", 8192, DEFAULT_LADDER, "docs/research/akamai.md"),
    "off": Profile("off", None, (), ""),
    "modsecurity": Profile("modsecurity", 8192, DEFAULT_LADDER, "docs/research/modsecurity.md"),
    "imperva": Profile("imperva", 8192, DEFAULT_LADDER, "docs/research/imperva.md"),
    "f5": Profile("f5", 8192, DEFAULT_LADDER, "docs/research/f5.md"),
    "fortiweb": Profile("fortiweb", 8192, DEFAULT_LADDER, "docs/research/fortiweb.md"),
    "barracuda": Profile("barracuda", 8192, DEFAULT_LADDER, "docs/research/barracuda.md"),
    "citrix": Profile("citrix", 8192, DEFAULT_LADDER, "docs/research/citrix.md"),
    "radware": Profile("radware", 8192, DEFAULT_LADDER, "docs/research/radware.md"),
    "wordfence": Profile("wordfence", 8192, DEFAULT_LADDER, "docs/research/wordfence.md"),
    "sucuri": Profile("sucuri", 8192, DEFAULT_LADDER, "docs/research/sucuri.md"),
}

_warned_hosts: "set[str]" = set()


def effective_limit(profile: Profile) -> "int | None":
    """Profile body limit, overridden by $WAF_REQUESTS_BODY_LIMIT when set."""
    override = os.environ.get("WAF_REQUESTS_BODY_LIMIT")
    if override:
        return int(override)
    return profile.body_limit


def resolve(target: str) -> Profile:
    """Resolve a profile name, hostname, or URL to a Profile.

    Explicit profile names win. Otherwise the host's cached fingerprint decides;
    unknown hosts resolve to ``off`` with a one-time warning. Never raises.
    """
    from . import detect as _detect

    name = target.strip().lower()
    if name in PROFILES:
        return PROFILES[name]

    host = _detect.host_of(target)
    vendor = _detect.cached_vendor(host)
    if vendor and vendor in ALL_VENDORS:
        return PROFILES[vendor]
    if host not in _warned_hosts:
        _warned_hosts.add(host)
        log.warning(
            "no WAF fingerprint for %r; sending unmodified "
            "(run `python -m waf_requests detect <url>`)", host,
        )
    return PROFILES["off"]
