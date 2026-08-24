# xss_unicode_escape

Category: xss | Fidelity: differential

## Mechanism

Backslash-escape alert/script substrings (alert -> \u0061... ).

## Why the WAF misses it

Byte scanners matching `alert`/`script` do not see the `\uXXXX` spelling.

## Why the origin still accepts it

The JavaScript engine decodes `\uXXXX` escapes in string/identifier context.

## Prerequisites and limits

Browser/JS engine that decodes unicode escapes in the sink context.

## References

- https://github.com/larbi67/WAF-XSS-Bypass
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<script>alert(1)</script>
-->
<\u0073\u0063\u0072\u0069\u0070\u0074>\u0061\u006c\u0065\u0072\u0074(1)</\u0073\u0063\u0072\u0069\u0070\u0074>
```

## Measured result

Not yet measured.
