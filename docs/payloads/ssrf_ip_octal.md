# ssrf_ip_octal

Category: ssrf | Fidelity: transparent

## Mechanism

127.0.0.1 -> 0177.0.0.1.

## Why the WAF misses it

Blocklists keyed on decimal octets miss the octal first octet.

## Why the origin still accepts it

C-style octal `0177` resolves to 127.

## Prerequisites and limits

Target that resolves octal IP forms.

## References

- https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
http://127.0.0.1/admin
-->
http://0177.0.0.1/admin
```

## Measured result

Not yet measured.
