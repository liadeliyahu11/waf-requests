# ssrf_localhost_alt

Category: ssrf | Fidelity: transparent

## Mechanism

Localhost -> 127.0.0.1, 127.0.0.1 -> [::1].

## Why the WAF misses it

Blocklists keyed on `localhost`/`127.0.0.1` miss the alternate spelling.

## Why the origin still accepts it

The sink resolves `[::1]` to loopback like the literal.

## Prerequisites and limits

Target that resolves IPv6 loopback.

## References

- https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
http://127.0.0.1/admin
-->
http://[::1]/admin
```

## Measured result

Not yet measured.
