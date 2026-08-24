# Cloudflare WAF - documented inspection behavior

Sources read this session:

- Managed rules: https://developers.cloudflare.com/waf/managed-rules/
- `cf-mitigated` response header: documented Cloudflare signal for challenge
  and block actions (Security > response header semantics).

## Body scan limits (verbatim from the source page, Aug 2026)

Managed rules inspect the request body up to a maximum size that varies by
plan:

| Plan | Body-inspection maximum | Managed rulesets available |
|---|---|---|
| Free | 1 MB | Cloudflare **Free** Managed Ruleset only |
| Pro / Business | lower by default; raise via account team | + full Cloudflare Managed Ruleset, OWASP Core Ruleset |
| Enterprise | 128 KB (configurable ceiling) | + Sensitive Data Detection |

The apparent paradox - Free inspecting more bytes than Enterprise - resolves
once you read the number as a scan-window CEILING, not as protection strength:

- Free zones run only the small "Cloudflare Free Managed Ruleset" (high-impact
  CVEs). The full Cloudflare Managed Ruleset and OWASP Core Ruleset, where deep
  body inspection actually matters, start at Pro.
- Enterprise's lower default is a tunable: account teams can raise it, and
  `http.request.body.truncated` / `http.request.headers.truncated` fields let
  custom rules handle oversize bodies explicitly.
- Content beyond the window is not fully analyzed. The OWASP Core Ruleset
  scores cumulatively, so larger payloads raise false-positive pressure rather
  than create a hard security cutoff.

Practical takeaway for this library: on Free zones the exploitable surface is
the thin ruleset, not a size window; on paid/Enterprise zones size pads sized
to the configured limit apply.

## Signals used by this library

- Response header `cf-mitigated: challenge` -> CHALLENGE verdict.
- `cf-mitigated: block`, body markers (`__cf_chl_opt`, `cf-challenge`,
  `cf-error-details`, "Attention Required") -> BLOCKED/CHALLENGE.
- Plain `server: cloudflare` alone is NOT evidence of blocking.

## Differentials this library exercises

- URL normalization at the edge differs from origin routing
  (`path_*` transforms).
- Query parsing is single-decode; frameworks that decode twice differ
  (`percent_double_encode`, HPP family).
- JSON managed rules match on decoded text, not on parser semantics
  (dup keys, deep nesting, unicode escapes).

## Profile mapping

`profiles.PROFILES["cloudflare"]` assumes 131072 bytes (Enterprise default).
Free-plan targets effectively have no useful size window; size pads still
apply against per-rule content constraints.
