# Viability matrix: technique x WAF

Two evidence streams combine: **measured** (live probe against our owned
protected domains, 2026-08-25) and **documented** (vendor docs read this
session). A measured cell is only claimed when the RAW baseline was BLOCKED on
that property; where the property's ruleset does not fire on the vector, the
cell is NO-RULE - there is nothing to bypass there and the technique is
unmeasurable on that domain, not disproven.

The probe harness is `examples/map_viability.py`; it sends each attack raw,
then with only that one transform applied, and compares verdicts plus what the
echo origin reflected.

## Legend

| Token | Meaning |
|---|---|
| `BYPASS` | measured: raw 403 -> transform 200 (win) |
| `BLOCKED` | measured: raw 403 -> transform 403 (no win) |
| `NO-RULE` | measured: raw delivered; this property has no rule on the vector |
| `UNTESTED` | no domain assigned, or the technique needs a component (path rule, IP-reputation rule) absent on all live properties |
| `(docs: ...)` | documented verdict from the vendor source, quoted |

Measured hosts: the owned AWS domain (CloudFront-scoped WAF) and the owned
Cloudflare domain. Hostnames live in the gitignored
`examples/waf_targets.local.toml` and are never committed. Akamai domain pending.

## Matrix

| Technique | AWS WAF | Cloudflare | Akamai Kona |
|---|---|---|---|
| `pad_json_ws` | **BYPASS** (reflected) | NO-RULE | UNTESTED (docs: 8 KB default window - the canonical Akamai bypass class) |
| `pad_form_param` | **BYPASS** (reflected) | NO-RULE | UNTESTED (docs: 8 KB default window) |
| `pad_multipart_decoy` | **BYPASS** (reflected) | NO-RULE | UNTESTED (docs: 8 KB default window) |
| `multipart_payload_last` | BLOCKED (needs pad to co-win) | NO-RULE | UNTESTED (companion to pad) |
| `header_pad_early` | NO-RULE (no header rule here) | BLOCKED (CF inspects UA regardless of pad) | UNTESTED |
| `gzip_body` | **BYPASS** (WAF-layer; origin not reflected) | NO-RULE | UNTESTED (docs: **Akamai inflates before inspect** - neutralized) |
| `deflate_body` | **BYPASS** (WAF-layer; origin not reflected) | NO-RULE | UNTESTED (docs: inflates before inspect) |
| `charset_utf7` | **BYPASS** (WAF-layer; origin not reflected) | NO-RULE | UNTESTED (docs: policy charset/comment transforms may normalize) |
| `json_unicode_escape` | BLOCKED (AWS JSON parser decodes `\uXXXX`) | NO-RULE | UNTESTED (JSON parser decodes) |
| `json_dup_key_lastwins` | BLOCKED (AWS matches all keys) | NO-RULE | UNTESTED |
| `json_deep_nest_wrap` | BLOCKED (AWS parser descends) | NO-RULE | UNTESTED |
| `json_comment_inject` | BLOCKED (invalid JSON -> AWS string-match fallback still sees SQLi) | NO-RULE | UNTESTED (docs: Kona `removeComments` normalizes this away) |
| `hpp_duplicate_param` | BLOCKED (AWS matches every occurrence) | NO-RULE | UNTESTED |
| `hpp_semicolon_sep` | BLOCKED | NO-RULE | UNTESTED |
| `percent_double_encode` | **BYPASS** (reflected) | NO-RULE | UNTESTED (docs: Kona `decodeURL` count differential) |
| `dup_header_firstlast` | NO-RULE (no header rule here) | **BYPASS** (CF matches FIRST UA) | UNTESTED |
| `method_override` | BLOCKED (rule not method-scoped here) | NO-RULE | UNTESTED |
| `spoof_trusted_ip` | NO-RULE | BLOCKED (no IP-reputation baseline; no interaction with UA rule) | UNTESTED |
| `multipart_boundary_variance` | BLOCKED (AWS parses quoted boundary) | NO-RULE | UNTESTED |
| `path_semicolon_params` | UNTESTED (no path rule on any property) | NO-RULE | UNTESTED |
| `path_dot_segments` | UNTESTED | NO-RULE | UNTESTED |
| `path_double_slash` | UNTESTED | NO-RULE | UNTESTED |
| `path_dotdot_semicolon` | UNTESTED | NO-RULE | UNTESTED |
| `path_collapse_dotdot` | UNTESTED | NO-RULE | UNTESTED |
| `null_byte_terminator` | UNTESTED | NO-RULE | UNTESTED |
| `utf8_overlong_path` | UNTESTED | NO-RULE | UNTESTED |

## What the measured split means

AWS WAF wins and losses track its documented parser capabilities exactly:

- **Window pads win** (`pad_json_ws`, `pad_form_param`, `pad_multipart_decoy`):
  AWS WAF truncates body inspection at the configured window (measured ~16 KB
  on this CloudFront scope). Payload past the cutoff is never seen; the echo
  origin reflected the SQLi intact.
- **Compression wins at the WAF layer only** (`gzip_body`, `deflate_body`,
  `charset_utf7`): AWS WAF has no gzip text transformation and does not decode
  UTF-7 declared charsets, so those bodies flew past inspection. The echo
  origin did NOT reflect them - it does not inflate or honor UTF-7 - so these
  are conditional wins requiring an origin that does.
- **JSON/HPP differentials lose** because AWS WAF uses a real JSON parser and
  inspects every parameter occurrence, not the first. Escapes, duplicate keys,
  nesting, and comments are all normalized or fully walked by the time rules
  run.

Cloudflare's property currently only trips its managed XSS rule against a
malicious User-Agent. The single measurable win there is `dup_header_firstlast`:
Cloudflare's rule matched the FIRST User-Agent occurrence, so a benign-first
duplicate let the payload reach the origin (403 -> 200, reflected). `header_pad_early`
does NOT work on Cloudflare - no aggregate header window exists there - which
docs the AWS-specificity of that technique.

Akamai is documented, not measured (domain pending). The one hard doc contrast:
Akamai inspects the request body AFTER gzip decompression, where AWS WAF does
not - so the same `gzip_body` transform that beats AWS is neutralized on Akamai.
