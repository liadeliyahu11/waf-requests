# xss_js_concat

Category: xss | Fidelity: differential

## Mechanism

Break alert( and script with unicode + /**/.

## Why the WAF misses it

Contiguous `alert(`/`script` anchors fail once split by `\u0065`/`/**/`.

## Why the origin still accepts it

The JS engine folds the unicode escape and comment back into the call.

## Prerequisites and limits

Reflection into a JS-parsed context.

## References

- https://github.com/larbi67/WAF-XSS-Bypass
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<script>alert(1)</script>
-->
<scr/**/ipt>al\u0065rt(1)</scr/**/ipt>
```

## Measured result

Not yet measured.
