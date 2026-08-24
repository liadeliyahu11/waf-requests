# ModSecurity / OWASP Core Rule Set - documented inspection behavior

Status: documented, not measured (no owned ModSecurity property this session).

## Block signature

Heuristic only - ModSecurity has no reliable response signature. Detected as a
403 with a generic `Server: nginx`/`apache`/`Apache/2` header and a `Forbidden`
or `Not Acceptable` body, only when no other vendor matched.

## Inspection limits

Mode-dependent: ModSecurity/CRS runs inside Apache/Nginx and inspects the full
request body buffered by the web server; body inspection size is a web-server
setting (e.g. Apache `SecRequestBodyLimit`, default 12 MB) rather than a fixed
WAF window. Anomaly threshold (default 5) and paranoia level (PL1-4) decide
whether scoring rules block. None of these are independently verified here.

Source: https://owasp.org/www-project-modsecurity-core-rule-set/

## Applicable classes

- CRS is regex/libinjection-driven: payload obfuscation (`sqli_inline_comment`,
  `sqli_version_comment`, `xss_unicode_escape`) targets its signature layer.
- Staying under the anomaly threshold (fewer rule hits) is the win condition.
- Request-size pads are less relevant (no fixed body window by default).