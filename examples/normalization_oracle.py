"""Decode oracle: map which encodings a WAF decodes (and blocks) vs leaves blind.

For each configured host, send a known-blocked payload through every encoding
variant and classify the response. BLOCKED means the WAF decoded that
representation back to the payload; DELIVERED means it did not (a blind spot).
Fills docs/research/normalization.md.

Targets resolve via --targets > $WAF_TARGETS_FILE > examples/waf_targets.local.toml.
"""
from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from waf_requests import encodings  # noqa: E402
from waf_requests.blockpage import classify  # noqa: E402

PAYLOAD = "' OR '1'='1"
PARAM = "q"

#: (variant name, encoder or None) sourced from encodings.DECODE_VARIANTS.
DECODE_VARIANTS = encodings.DECODE_VARIANTS


def resolve_targets_path(explicit: "str | None") -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("WAF_TARGETS_FILE")
    if env:
        return Path(env)
    here = Path(__file__).parent
    local = here / "waf_targets.local.toml"
    return local if local.exists() else here / "waf_targets.example.toml"


def probe(base: str, name: str, encoder, session: requests.Session, timeout: float,
          payload: str) -> str:
    if encoder is None:
        resp = session.get(f"{base}/search", params={PARAM: payload}, timeout=timeout)
    else:
        resp = session.get(f"{base}/search?{PARAM}={encoder(payload)}", timeout=timeout)
    verdict = classify(resp)
    return verdict.status.value


def run_host(vendor: str, entry: dict, session: requests.Session, payload: str) -> "list[tuple]":
    base = (entry.get("base") or "").strip().rstrip("/")
    rows = []
    if not base:
        for name, _ in DECODE_VARIANTS:
            rows.append((vendor, name, "SKIP", "base empty"))
        return rows
    try:
        session.get(f"{base}/search", params={PARAM: "ping"}, timeout=15)
    except requests.RequestException:
        for name, _ in DECODE_VARIANTS:
            rows.append((vendor, name, "SKIP", "unreachable"))
        return rows
    for name, encoder in DECODE_VARIANTS:
        try:
            verdict = probe(base, name, encoder, session, 30.0, payload)
        except requests.RequestException as exc:
            verdict = f"SKIP({exc.__class__.__name__})"
        meaning = "decoded" if verdict == "BLOCKED" else ("blind" if verdict == "DELIVERED" else verdict.lower())
        rows.append((vendor, name, verdict, meaning))
        print(f"   [{name:<16}] {verdict:<10} {meaning}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default=None)
    parser.add_argument("--payload", default=PAYLOAD)
    parser.add_argument("--vendor", default=None, choices=["aws", "cloudflare", "akamai"])
    args = parser.parse_args()

    payload = args.payload
    path = resolve_targets_path(args.targets)
    config = tomllib.loads(path.read_text())
    session = requests.Session()
    all_rows: "list[tuple]" = []
    for vendor, entry in config.items():
        if args.vendor and vendor != args.vendor:
            continue
        base = (entry.get("base") or "").strip().rstrip("/")
        print(f"== {vendor}: {base or '(no base)'} payload={payload!r}")
        all_rows.extend(run_host(vendor, entry or {}, session, payload))

    print()
    print(f"{'vendor':<11} {'variant':<18} {'verdict':<10} meaning")
    for row in all_rows:
        vendor, name, verdict, meaning = row
        print(f"{vendor:<11} {name:<18} {verdict:<10} {meaning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
