# sqli_comment_extend

Category: sqli | Fidelity: differential

## Mechanism

Append --waf to a trailing comment.

## Why the WAF misses it

A trailing comment token with extra text no longer matches the exact comment signature.

## Why the origin still accepts it

Everything after `--`/`#` is ignored by the DB, so the payload is unchanged in effect.

## Prerequisites and limits

DB engine with line-comment syntax (`--`/`#`).

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
