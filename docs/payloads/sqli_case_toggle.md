# sqli_case_toggle

Category: sqli | Fidelity: transparent

## Mechanism

Mixed-case sql keywords (select -> select).

## Why the WAF misses it

Signature rules anchored on lowercase or uppercase keywords miss the mixed-case spelling.

## Why the origin still accepts it

SQL keywords are case-insensitive across every DB engine, so the query means the same thing.

## Prerequisites and limits

DB engine present (any).

## References

- https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
UNION SELECT * FROM users
-->
UnIoN SeLeCt * FrOm users
```

## Measured result

Not yet measured.
