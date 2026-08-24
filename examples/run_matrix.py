"""Live raw-vs-shim verification matrix against owned protected domains.

Targets file resolution: --targets arg > $WAF_TARGETS_FILE >
examples/waf_targets.local.toml (gitignored; copy from
waf_targets.example.toml and fill in YOUR protected domains).

    [aws]
    base = "https://your-aws-protected-domain"
    profile = "aws"        # optional override when auto-detect stays silent

Per host and canonical attack: send raw (stock requests) then shimmed
(WAFSession). Wins require a DELIVERED response whose origin echoed the
payload (X-Origin-Saw-Payload header, or reflection decoded to fixpoint).
Block pages can echo URIs and never count.
"""
from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from waf_requests import WAFSession  # noqa: E402
from waf_requests.blockpage import classify  # noqa: E402
from waf_requests.detect import fingerprint  # noqa: E402

ATTACKS = [
    ("jndi", "${${env:MARKER}}"),
    ("sqli", "' OR '1'='1"),
    ("xss", "<script>alert(1)</script>"),
    ("ssti", "{{7*7}}"),
    ("traversal", "../../../../etc/passwd"),
    ("jsontamper", '{"role":"admin"}'),
]


def _reflected(resp_text: str, payload: str) -> bool:
    """True when the response carries the payload after N percent-decodes."""
    from urllib.parse import unquote

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


def _origin_evidence(resp, payload: str) -> str:
    if classify(resp).status.name != "DELIVERED":
        return "-"  # block/challenge pages can echo the URI; never wins
    strong = resp.headers.get("X-Origin-Saw-Payload", "")
    if strong:
        return f"WIN(header:{strong})"
    if _reflected(resp.text, payload):
        return "WIN(reflected)"
    return "-"


def resolve_targets_path(explicit: "str | None") -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("WAF_TARGETS_FILE")
    if env:
        return Path(env)
    here = Path(__file__).parent
    local = here / "waf_targets.local.toml"
    if local.exists():
        return local
    return here / "waf_targets.example.toml"


def run_host(vendor: str, entry: dict) -> "list[tuple]":
    base = (entry.get("base") or "").strip().rstrip("/")
    forced = (entry.get("profile") or "").strip() or None
    rows = []
    print(f"== {vendor}: {base} (profile={forced or 'auto'})")
    if not base:
        for name, _ in ATTACKS:
            rows.append((vendor, name, "SKIP", "-", "base empty"))
        return rows

    detected = fingerprint(base)
    print(f"   detect -> {detected or 'None'}")

    session = requests.Session()
    try:
        session.get(f"{base}/search", params={"q": "ping"}, timeout=15)
    except requests.RequestException:
        print("   SKIP host unreachable")
        for name, _ in ATTACKS:
            rows.append((vendor, name, "SKIP", "-", "unreachable"))
        return rows

    shim = WAFSession(profile=forced or "auto")
    for name, payload in ATTACKS:
        url = f"{base}/search?q={requests.utils.quote(payload, safe='')}"
        try:
            raw_resp = session.get(url, timeout=20)
            raw_verdict = classify(raw_resp).status.value
            shim_resp = shim.get(url, timeout=30)
            evidence = _origin_evidence(shim_resp, payload)
            shim_state = evidence if evidence != "-" else classify(shim_resp).status.value
            rows.append((vendor, name, raw_verdict, shim_state,
                         f"raw={raw_resp.status_code} shim={shim_resp.status_code}"))
            ladder = getattr(shim_resp, "waf_attempts", [])
            applied = "->".join(
                f"{a.transform_id or 'original'}:{a.http_status}" for a in ladder
            )
            if applied:
                print(f"   [{name}] {applied}")
        except requests.RequestException as exc:
            rows.append((vendor, name, "SKIP", "-", exc.__class__.__name__))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default=None)
    args = parser.parse_args()

    targets_path = resolve_targets_path(args.targets)
    print(f"targets: {targets_path}")
    config = tomllib.loads(targets_path.read_text())
    all_rows: "list[tuple]" = []
    for vendor, entry in config.items():
        all_rows.extend(run_host(vendor, entry or {}))

    print()
    width = max(len(r[0]) for r in all_rows) + 2
    print(f"{'vendor':<{width}} {'attack':<12} {'raw':<11} {'shim':<18} note")
    for vendor, name, raw_v, shim_v, note in all_rows:
        print(f"{vendor:<{width}} {name:<12} {raw_v:<11} {shim_v:<18} {note}")

    wins = sum(1 for r in all_rows if str(r[3]).startswith("WIN"))
    skips = sum(1 for r in all_rows if r[2] == "SKIP")
    print(f"\nwins={wins} skips={skips} total={len(all_rows)} "
          "(win = DELIVERED response whose origin echoed the payload)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
