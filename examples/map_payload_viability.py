"""Per-payload-mutator viability: raw vs mutated payload against each WAF.

For each configured host and each payload mutator, send the category's
canonical attack raw, then with ONLY that payload mutation applied (no request
transform), through a GET query. A BLOCKED raw that becomes DELIVERED when
mutated is a payload-level bypass. Fills docs/research/payload-viability.md.
"""
from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from waf_requests.blockpage import classify  # noqa: E402
from waf_requests.payloads import CATEGORIES, PAYLOADS  # noqa: E402

CANONICAL = {
    "sqli": "UNION SELECT * FROM users",
    "xss": "<script>alert(1)</script>",
    "cmdi": "cat /etc/passwd",
    "lfi": "../../etc/passwd",
    "ssrf": "http://127.0.0.1/admin",
    "ssti": "{{7*7}}",
    "xxe": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
}


def _reflected(resp_text: str, payload: str) -> bool:
    probe = "".join(payload.lower().split())
    decoded = resp_text.lower()
    for _ in range(8):
        if probe in "".join(decoded.split()):
            return True
        step = unquote(decoded)
        if step == decoded:
            break
        decoded = step
    return False


def resolve_targets_path(explicit: "str | None") -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("WAF_TARGETS_FILE")
    if env:
        return Path(env)
    here = Path(__file__).parent
    local = here / "waf_targets.local.toml"
    return local if local.exists() else here / "waf_targets.example.toml"


def send(session: requests.Session, base: str, payload: str, timeout: float) -> requests.Response:
    return session.get(f"{base}/search?q={requests.utils.quote(payload, safe='')}", timeout=timeout)


def run_host(vendor: str, entry: dict, session: requests.Session) -> "list[tuple]":
    base = (entry.get("base") or "").strip().rstrip("/")
    rows = []
    if not base:
        for pid in PAYLOADS:
            rows.append((vendor, pid, "SKIP", "-", "base empty"))
        return rows
    try:
        session.get(f"{base}/search", params={"q": "ping"}, timeout=15)
    except requests.RequestException:
        for pid in PAYLOADS:
            rows.append((vendor, pid, "SKIP", "-", "unreachable"))
        return rows
    for pid, payload in PAYLOADS.items():
        canonical = CANONICAL[payload.category]
        mutated = payload.apply(canonical)
        try:
            raw_resp = send(session, base, canonical, 30.0)
            raw_v = classify(raw_resp).status.value
            mut_resp = send(session, base, mutated, 30.0)
            mut_v = classify(mut_resp).status.value
        except requests.RequestException as exc:
            rows.append((vendor, pid, "SKIP", "-", exc.__class__.__name__))
            continue
        origin = "reflected" if _reflected(mut_resp.text, mutated) else "not-reflected"
        rows.append((vendor, pid, raw_v, mut_v, origin))
        print(f"   [{pid:<24}] raw={raw_v:<9} mutated={mut_v:<10} origin={origin}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default=None)
    parser.add_argument("--vendor", default=None, choices=sorted(CATEGORIES | {"aws", "cloudflare", "akamai"}))
    args = parser.parse_args()

    path = resolve_targets_path(args.targets)
    config = tomllib.loads(path.read_text())
    session = requests.Session()
    all_rows: "list[tuple]" = []
    for vendor, entry in config.items():
        if args.vendor and vendor != args.vendor:
            continue
        base = (entry.get("base") or "").strip().rstrip("/")
        print(f"== {vendor}: {base or '(no base)'}")
        all_rows.extend(run_host(vendor, entry or {}, session))

    print()
    print(f"{'vendor':<11} {'mutator':<26} {'raw':<10} {'mutated':<11} origin")
    for row in all_rows:
        vendor, pid, raw_v, mut_v, origin = row
        print(f"{vendor:<11} {pid:<26} {raw_v:<10} {mut_v:<11} {origin}")

    bypass = sum(1 for r in all_rows if r[2] == "BLOCKED" and r[3] == "DELIVERED")
    print(f"\npayload-bypass={bypass} total={len(all_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
