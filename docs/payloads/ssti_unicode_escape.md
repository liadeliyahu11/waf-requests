# ssti_unicode_escape

Category: ssti | Fidelity: differential

## Mechanism

Backslash-escape every character.

## Why the WAF misses it

Signature bytes for `{{`/`7*7` vanish into `\uXXXX` escapes.

## Why the origin still accepts it

A unicode-decoding layer recovers the expression before templating.

## Prerequisites and limits

Template engine that decodes unicode escapes.

## References

- https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
{{7*7}}
-->
\u007b\u007b\u0037\u002a\u0037\u007d\u007d
```

## Measured result

Not yet measured.
