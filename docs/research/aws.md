# AWS WAF - documented inspection behavior

Sources read this session:

- Oversize request components: https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html
- Body component reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_Body.html
- JsonBody fallback: https://docs.aws.amazon.com/waf/latest/APIReference/API_JsonBody.html

## Body inspection limits

| Scope | Limit | Configurable |
|---|---|---|
| ALB, AppSync | 8 KB fixed | no |
| CloudFront, API Gateway, Cognito, App Runner, Verified Access | 16 KB default | up to 64 KB (AssociationConfig, extra cost) |
| Amplify | follows CloudFront | same |

Bodies larger than the limit: only the first N bytes reach AWS WAF. Per-rule
`oversizeHandling` then decides CONTINUE / MATCH / NO_MATCH without seeing the
excess. Consequence: payload placement beyond the cutoff is invisible to body
rules regardless of oversize setting; a truncated JSON slice also flips JsonBody
parsing to its fallback behavior.

## Header inspection

Repo-measured during the log4shell rule work
(`research/cve-2021-44228-waf/README.md`):

- `Headers(ALL)` truncates near 8 KB aggregate / 200 headers.
- Padding benign headers ahead of a payload-bearing header was a measured
  bypass before per-header arms were added. Basis of `header_pad_early`.

## Other components

- URL_DECODE / JS_DECODE are single-pass transformations chosen per rule;
  double-encoded query values decode once at most. Basis of
  `percent_double_encode`.
- JsonBody rules parse strictly; comments or non-object shapes fall back.
  Basis of the json_differential family.

## Profile mapping

`profiles.PROFILES["aws"]` assumes 8192 bytes (ALB-class default, the
conservative floor). Override with `WAF_REQUESTS_BODY_LIMIT` when the ACL runs
on CloudFront scope with a raised limit, or measure with
`python -m waf_requests find-limit`.
