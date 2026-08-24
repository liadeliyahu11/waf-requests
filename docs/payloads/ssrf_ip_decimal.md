# ssrf_ip_decimal

Category: ssrf | Fidelity: transparent

## Mechanism

127.0.0.1 -> 2130706433.

## Why the WAF misses it

SSRF blocklists keyed on `127.0.0.1` miss the integer form.

## Why the origin still accepts it

Most HTTP clients/servers resolve a dotted-decimal integer to the same address.

## Prerequisites and limits

Target that resolves integer IP forms.

## References

- https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
http://127.0.0.1/admin
-->
http://2130706433/admin
```

## Measured result

Not yet measured.
