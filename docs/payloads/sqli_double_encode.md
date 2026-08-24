# sqli_double_encode

Category: sqli | Fidelity: differential

## Mechanism

Double url-encode the payload (% -> %25).

## Why the WAF misses it

A single-decoding WAF decodes once and still sees percent-encoded noise.

## Why the origin still accepts it

The framework decodes a second time and passes the raw payload to the query.

## Prerequisites and limits

Application layer that decodes the parameter more times than the WAF.

## References

- https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
UNION SELECT * FROM users
-->
UNION%2520SELECT%2520%252A%2520FROM%2520users
```

## Measured result

Not yet measured.
