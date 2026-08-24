# sqli_inline_comment

Category: sqli | Fidelity: differential

## Mechanism

Split keywords with inline comments (union -> un/**/ion).

## Why the WAF misses it

Regexes matching contiguous `UNION SELECT` fail once letters are split by `/**/`.

## Why the origin still accepts it

The DB parser treats `/**/` as a comment and joins the letters back into the keyword.

## Prerequisites and limits

DB engine that honors `/**/` (MySQL-family and most others).

## References

- https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
UNION SELECT * FROM users
-->
UN/**/ION SE/**/LECT * FR/**/OM users
```

## Measured result

Not yet measured.
