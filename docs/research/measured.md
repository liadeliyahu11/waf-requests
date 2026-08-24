# Measured results

Filled during live verification on 2026-08-24. Wins are claimed only from
origin echo evidence (`X-Origin-Saw-Payload` header or payload reflection
after decode-to-fixpoint) on a DELIVERED response - never from a non-block
page alone.

## Inspection-window measurement

| Date | Vendor | Host | Component | Tool | Result |
|---|---|---|---|---|---|
| 2026-08-24 | aws | owned AWS domain (CloudFront scope) | POST body | `find-limit --body` | cutoff at payload offset 16368; approx window 16,381 bytes - matches documented 16 KB CloudFront-scope default |
| 2026-08-24 | aws | owned AWS domain (CloudFront scope) | query string | `find-limit` (GET) | no window found: SQLi token blocked at every offset up to 262144 bytes - query-string inspection is not truncated like bodies |
| 2026-08-24 | cloudflare | owned Cloudflare domain | query + canary | `detect` | SQLi canary NOT blocked; managed rules did not trip - auto-detection honestly returns None |

## Raw-vs-shim matrix (`examples/run_matrix.py`, 2026-08-24)

| Vendor | Attack | Raw | Shim | Note |
|---|---|---|---|---|
| aws | jndi | DELIVERED | WIN(reflected) | rules did not block raw |
| aws | sqli | BLOCKED | **WIN(reflected)** | ladder: original 403 -> hpp_duplicate_param 403 -> percent_double_encode 200, origin echoed payload |
| aws | xss | DELIVERED | WIN(reflected) | |
| aws | ssti | DELIVERED | WIN(reflected) | |
| aws | traversal | BLOCKED | BLOCKED | honest negative: ladder exhausted (hpp, percent-double, header_pad all still blocked); default ladder lacks path-vector transforms for query-carried traversal |
| aws | jsontamper | DELIVERED | WIN(reflected) | |
| cloudflare | all six | DELIVERED | WIN(reflected) | edge confirmed via cf-ray/cdn-loop; managed rules currently pass these vectors unblocked |

wins=11 skips=0 total=12.

## Prior repo measurements reused

- AWS `Headers(ALL)` truncation ~8 KB / 200 headers; padding benign headers
  ahead of a payload-bearing header bypassed body/header arms until per-header
  rules were added. Source: `research/cve-2021-44228-waf/README.md`.

## Per-transform viability probe (`examples/map_viability.py`, 2026-08-25)

Each row: attack vector sent raw, then with only that transform applied.
`BYPASS` = raw 403 -> transform 200. `origin` = what the echo app reflected.

| Vendor | Transform | Raw | Xform | Origin |
|---|---|---|---|---|
| aws | pad_json_ws | BLOCKED | DELIVERED | reflected |
| aws | pad_form_param | BLOCKED | DELIVERED | reflected |
| aws | pad_multipart_decoy | BLOCKED | DELIVERED | reflected |
| aws | gzip_body | BLOCKED | DELIVERED | not-reflected (origin does not inflate) |
| aws | deflate_body | BLOCKED | DELIVERED | not-reflected |
| aws | charset_utf7 | BLOCKED | DELIVERED | not-reflected (origin does not decode UTF-7) |
| aws | percent_double_encode | BLOCKED | DELIVERED | reflected |
| aws | json_unicode_escape | BLOCKED | BLOCKED | - |
| aws | json_dup_key_lastwins | BLOCKED | BLOCKED | - |
| aws | json_deep_nest_wrap | BLOCKED | BLOCKED | - |
| aws | json_comment_inject | BLOCKED | BLOCKED | - |
| aws | multipart_boundary_variance | BLOCKED | BLOCKED | - |
| aws | multipart_payload_last | BLOCKED | BLOCKED | - |
| aws | hpp_duplicate_param | BLOCKED | BLOCKED | - |
| aws | hpp_semicolon_sep | BLOCKED | BLOCKED | - |
| aws | method_override | BLOCKED | BLOCKED | - |
| cloudflare | dup_header_firstlast | BLOCKED | DELIVERED | reflected (CF matched FIRST UA) |
| cloudflare | header_pad_early | BLOCKED | BLOCKED | - |
| cloudflare | spoof_trusted_ip | BLOCKED | BLOCKED | - |
| cloudflare | all body/query/JSON/HPP/path | DELIVERED | DELIVERED | no managed rule on the vector |

AWS BYPASS count = 7; Cloudflare BYPASS count = 1 (`dup_header_firstlast`).
Full matrix and doc cross-references: `docs/research/viability.md`.

## Classifier fix (2026-08-25)

Cloudflare denies non-HTML vectors with a plain-text `error code: 1010` body
(UA/browser ban), which the old classifier missed as a bare 403. `blockpage.py`
now recognizes `error code: <N>` plus a Cloudflare edge header as BLOCKED.
