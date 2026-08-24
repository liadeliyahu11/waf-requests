# sqli_version_comment

Category: sqli | Fidelity: differential

## Mechanism

Wrap keywords in mysql version comments (/*!50000union*/).

## Why the WAF misses it

Rules matching `UNION`/`SELECT` do not match the `/*!50000...*/` spelling.

## Why the origin still accepts it

MySQL executes version-gated comments on any version >= 5.0, recovering the keyword.

## Prerequisites and limits

MySQL (or a compatible parser) on the backend.

## References

- https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
UNION SELECT * FROM users
-->
/*!50000UNION*/ /*!50000SELECT*/ * FROM users
```

## Measured result

Not yet measured.
