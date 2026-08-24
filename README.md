# waf_requests

Educational drop-in replacement for `requests` demonstrating how managed WAFs
(AWS WAF, Cloudflare WAF, Akamai Kona) miss exploits because of how they
inspect requests: body-size windows, unsupported encodings, charset and
unicode mismatches, and framework-vs-WAF parser differentials.

Use only against properties you own or are authorized to test.

## Install

```bash
cd waf_requests
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

## Use

Swap one import in an existing exploit script:

```python
import waf_requests as requests   # everything else unchanged
resp = requests.get("https://your-protected-domain/search",
                    params={"q": "' OR '1'='1"})
print(resp.waf_attempts)          # per-attempt verdict log
```

Or run an unmodified script through the import hook:

```bash
.venv/bin/python -m waf_requests run exploit.py [args...]
```

Behavior: the first send is untouched. When the response classifies as a WAF
block, the engine replays the original request through a ladder of bypass
transforms until one is delivered (max 6 attempts, all methods by default;
`WAFSession(retry_mutating=False)` restricts auto-retry to GET/HEAD/OPTIONS).

## Tools

```bash
python -m waf_requests detect <url>        # fingerprint the edge WAF
python -m waf_requests find-limit <url>    # binary-search inspection cutoff
python -m waf_requests selftest <url>      # canonical attacks raw vs shimmed
python -m waf_requests verify <url>        # prove origin interpreted payload
python -m waf_requests run <script.py>     # shimmed execution
```

## Payload fidelity: does the origin see the SAME exploit?

Every transform carries a fidelity tier (stamped in its docs page):

| Tier | Meaning | Examples |
|---|---|---|
| `transparent` | wire bytes change, the origin's standard layers (transport decode, RFC parsers, routing normalization) restore the identical logical request | `pad_json_ws`, `json_unicode_escape`, `gzip_body`, `header_pad_early` |
| `additive` | originals byte-intact plus distinct-name decoys the app ignores | `pad_form_param`, `pad_multipart_decoy` |
| `differential` | wire payload DIFFERS; correct only if the app's parser picks the documented winner (double-decode, last-wins, UTF-7...) | `percent_double_encode`, `hpp_duplicate_param`, `json_dup_key_lastwins` |

Defaults are fidelity-safe first: the default ladder runs transparent and
additive transforms before any differential one. To forbid manipulation
outright:

```python
WAFSession(strict_fidelity=True)          # differential transforms excluded
waf_requests.configure(strict_fidelity=True)
```

Prove interpretation instead of assuming it - against any origin that
reflects input (vulnapp or an echo endpoint):

```bash
python -m waf_requests verify https://your-domain --profile aws
# PASS  = origin decoded exactly the intended payload
# DIVERGE = origin saw something else (never trust that win)
```

Equivalence itself is enforced offline: tests/test_fidelity.py simulates a
conforming server stack (`fidelity.app_view`) and asserts transparent
transforms reproduce it exactly.

## Which bypasses actually matter: the impact taxonomy

Techniques split by what they guarantee, not by mechanism:

- **Class A - WAF blind-spot (app-guaranteed)**: size-window pads, escapes
  that decode identically anywhere, transport encodings. Delivered == the
  origin executes your ORIGINAL payload. No stack assumptions.
- **Class B - additive**: originals byte-intact plus inert decoys.
- **Class C - parser differential (app-dependent)**: wire payload differs;
  correct only if the app's parser normalizes as documented
  (`percent_double_encode`, HPP, UTF-7, `..;/`, null byte...). Prove each win
  with `verify` before trusting it.

Full mapping with per-technique requirements and win conditions:
[docs/TAXONOMY.md](docs/TAXONOMY.md). Live matrix:

```bash
.venv/bin/python examples/run_matrix.py
```

## Layout

- `src/waf_requests/engine.py` - retry ladder; `transforms/` - 26 documented transforms.
- `docs/research/` - vendor inspection behavior with citations; `docs/techniques/<id>.md` - one page per transform.
- `lab/vulnapp/` - observable origin app; wins are claimed only from its
  `X-Origin-Saw-Payload` echo, never inferred from a non-block page.

## Scope

Single-request parser differentials only. Request-smuggling/desync classes are
excluded by design. Techniques that depend on origin behavior (gzip bodies,
UTF-7 charsets, method override) ship as `risk=conditional`.
