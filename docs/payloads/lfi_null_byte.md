# lfi_null_byte

Category: lfi | Fidelity: differential

## Mechanism

Append %00 terminator.

## Why the WAF misses it

Suffix/file-type checks match the benign `.png` after the NUL.

## Why the origin still accepts it

Legacy C-string handling truncates at NUL, acting on the prefix.

## Prerequisites and limits

Legacy PHP/C filesystem handling (PHP < 5.3.4 era).

## References

- https://owasp.org/www-community/attacks/Path_Traversal
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
../../etc/passwd
-->
../../etc/passwd%00
```

## Measured result

Not yet measured.
