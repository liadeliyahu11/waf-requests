# Citrix NetScaler / AppFirewall - documented inspection behavior

Status: documented, not measured (no owned Citrix property this session).

## Block signature

Cookie `NSC_*`, body containing `Request Prohibited` or `ns_violation`.

## Inspection limits

AppFirewall profiles inspect body content with configurable limits per
signature/safe-object profile; no fixed default is asserted here. Measure live
with `find-limit --body`.

Source: https://docs.netscaler.com/

## Applicable classes

- Size pads target the profile window.
- Parser differentials (HPP, JSON dup-key) depend on the backend language and
  AppFirewall's inspection point.
- Encoding transforms (`gzip_body`) depend on whether the body is decoded
  before AppFirewall signatures run (verify).