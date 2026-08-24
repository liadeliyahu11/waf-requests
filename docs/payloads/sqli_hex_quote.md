# sqli_hex_quote

Category: sqli | Fidelity: transparent

## Mechanism

Rewrite quoted literals as hex ('' -> 0x... ).

## Why the WAF misses it

Quote-and-string signatures (e.g. `'admin'`) vanish once the literal becomes `0x...`.

## Why the origin still accepts it

The SQL engine resolves hex literals to the same string the quote form denoted.

## Prerequisites and limits

DB engine accepting hex string literals (MySQL, PostgreSQL, MSSQL).

## References

- https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
UNION SELECT * FROM users
-->
UNION SELECT * FROM users
```

## Measured result

Not yet measured.
