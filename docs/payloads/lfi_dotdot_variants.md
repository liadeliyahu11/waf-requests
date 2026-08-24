# lfi_dotdot_variants

Category: lfi | Fidelity: differential

## Mechanism

Expand ../ to ....//.

## Why the WAF misses it

A single-pass `../` stripper collapses `....//` to `../` AFTER matching.

## Why the origin still accepts it

The resolved path still contains the traversal the filter meant to remove.

## Prerequisites and limits

A single-pass traversal filter on the origin.

## References

- https://owasp.org/www-community/attacks/Path_Traversal
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
../../etc/passwd
-->
....//....//etc/passwd
```

## Measured result

Not yet measured.
