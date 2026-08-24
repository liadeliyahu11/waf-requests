# sqli_whitespace_sub

Category: sqli | Fidelity: transparent

## Mechanism

Replace spaces with /**/.

## Why the WAF misses it

Rules anchored on space-separated keywords miss the `/**/` whitespace.

## Why the origin still accepts it

SQL treats `/**/` as a comment, which is valid whitespace between tokens.

## Prerequisites and limits

DB engine that honors `/**/`.

## References

- https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
UNION SELECT * FROM users
-->
UNION/**/SELECT/**/*/**/FROM/**/users
```

## Measured result

Not yet measured.
