# ssrf_dns_rebind

Category: ssrf | Fidelity: differential

## Mechanism

127.0.0.1 -> 7f000001.0a000001.rbndr.us.

## Why the WAF misses it

An allowlist/blocklist sees a public rebinding hostname, not the loopback literal.

## Why the origin still accepts it

The rebind domain resolves to 127.0.0.1 at request time.

## Prerequisites and limits

A rebinding DNS service (out-of-band infrastructure).

## References

- https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
http://127.0.0.1/admin
-->
http://7f000001.0a000001.rbndr.us/admin
```

## Measured result

Not yet measured.
