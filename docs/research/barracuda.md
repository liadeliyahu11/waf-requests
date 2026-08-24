# Barracuda Web Application Firewall - documented inspection behavior

Status: documented, not measured (no owned Barracuda property this session).

## Block signature

Header `Server: Barracuda` or cookie `barra_counter_session`.

## Inspection limits

Barracuda normalizes traffic (URL decode, HTML entity decode) before string
matching, and body inspection size is configurable; no fixed default is
asserted here. Measure live with `find-limit`.

Source: https://campus.barracuda.com/

## Applicable classes

- Size pads target the configured body window.
- Because Barracuda documents aggressive normalization, HTML-entity and
  percent-encoded payloads are likely normalized away before matching:
  `percent_double_encode` and `xss_html_entity` are the natural candidates to
  test, not assume.
- JSON/HPP differentials are policy-dependent.