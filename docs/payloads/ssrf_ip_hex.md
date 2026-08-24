# ssrf_ip_hex

Category: ssrf | Fidelity: transparent

## Mechanism

127.0.0.1 -> 0x7f000001.

## Why the WAF misses it

Blocklists keyed on the dotted literal miss the hex form.

## Why the origin still accepts it

Many resolvers accept `0x7f000001` as 127.0.0.1.

## Prerequisites and limits

Target that resolves hex IP forms.

## References

- https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
http://127.0.0.1/admin
-->
http://0x7f000001/admin
```

## Measured result

Not yet measured.
