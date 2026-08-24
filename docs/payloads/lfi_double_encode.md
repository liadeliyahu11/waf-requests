# lfi_double_encode

Category: lfi | Fidelity: differential

## Mechanism

Double-encode ../ and / (%2e%2e%2f).

## Why the WAF misses it

A single-decoding filter sees encoded dot-segments and does not strip them.

## Why the origin still accepts it

The filesystem/router decodes once more and resolves the traversal.

## Prerequisites and limits

Framework/router that decodes twice.

## References

- https://owasp.org/www-community/attacks/Path_Traversal
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
../../etc/passwd
-->
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## Measured result

Not yet measured.
