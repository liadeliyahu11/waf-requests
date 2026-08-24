# lfi_overlong_utf8

Category: lfi | Fidelity: differential

## Mechanism

Overlong-encode / and . (%c0%af / %c0%ae).

## Why the WAF misses it

Scanners do not normalize overlong UTF-8, so the encoded separators pass.

## Why the origin still accepts it

A permissive decoder normalizes the overlong sequence back to `/`/`.`.

## Prerequisites and limits

Router that normalizes overlong UTF-8 (rare).

## References

- https://owasp.org/www-community/attacks/Path_Traversal
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
../../etc/passwd
-->
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

## Measured result

Not yet measured.
