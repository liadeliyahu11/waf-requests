"""Show exactly what each transform does to the WIRE, and what it costs.

For a curated subset spanning all three fidelity tiers: print the original
request line/headers/body, then the transformed one. Transparent transforms
change bytes but not interpretation (proven by tests/test_fidelity.py);
differential ones change what the origin's parser sees unless it normalizes.

Run:  .venv/bin/python examples/wire_demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from waf_requests import TRANSFORMS, Ctx  # noqa: E402
from waf_requests.fidelity import tier_of  # noqa: E402
from waf_requests.spec import ReqSpec, to_prepared  # noqa: E402

SQLI = "' OR '1'='1"
LIMIT = 64  # small limit so pad geometry is visible in printouts


def json_spec() -> ReqSpec:
    return ReqSpec("POST", "http://shop.test/search?q=1",
                   {"Content-Type": "application/json", "User-Agent": "exploit/1.0"},
                   json.dumps({"q": SQLI}).encode())


def url_spec() -> ReqSpec:
    from urllib.parse import quote

    return ReqSpec("GET", "http://shop.test/search?q=" + quote(SQLI, safe=""),
                   {"User-Agent": "exploit/1.0"}, None)


DEMOS = [
    ("pad_json_ws", json_spec, Ctx(profile_limit=LIMIT)),
    ("json_unicode_escape", json_spec, Ctx(profile_limit=None)),
    ("pad_form_param",
     lambda: ReqSpec("POST", "http://shop.test/search",
                     {"Content-Type": "application/x-www-form-urlencoded"},
                     f"q={SQLI}".encode()),
     Ctx(profile_limit=LIMIT)),
    ("percent_double_encode", url_spec, Ctx(profile_limit=None)),
]


def wire(prep) -> str:
    lines = [f"{prep.method} {prep.url} HTTP/1.1"]
    for key, value in prep.headers.items():
        lines.append(f"{key}: {value}")
    body = prep.body or b""
    if isinstance(body, str):
        body = body.encode()
    if body:
        shown = body[:160] + (b" ..." if len(body) > 160 else b"")
        lines.append("")
        lines.append(repr(shown))
    return "\n".join(lines)


for tid, factory, ctx in DEMOS:
    spec = factory()
    out = TRANSFORMS[tid].apply(spec, ctx)
    tier = tier_of(tid)
    print("=" * 72)
    print(f"{tid}   [tier: {tier}]")
    print("-" * 72)
    print("ORIGINAL:")
    print(wire(to_prepared(spec)))
    if out is None:
        print("TRANSFORMED: <inapplicable here>")
        continue
    print(f"TRANSFORMED ({TRANSFORMS[tid].explain}):")
    print(wire(to_prepared(out)))
    same = "= identical interpretation" if tier == "transparent" else (
        "+ decoys only, originals intact" if tier == "additive" else
        "! app parser MUST normalize as documented - verify before trusting")
    print(f"ORIGIN VIEW: {same}")
print("=" * 72)
