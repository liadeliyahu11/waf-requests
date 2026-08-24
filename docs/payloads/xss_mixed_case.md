# xss_mixed_case

Category: xss | Fidelity: transparent

## Mechanism

Mixed-case tag/function names (<script>, alert).

## Why the WAF misses it

Case-sensitive signatures for `<script>`/`alert` miss the mixed-case form.

## Why the origin still accepts it

HTML tag names and JS function names are case-insensitive where reflected.

## Prerequisites and limits

Case-insensitive HTML/JS parser context.

## References

- https://github.com/larbi67/WAF-XSS-Bypass
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<script>alert(1)</script>
-->
<sCrIpT>aLerT(1)</script>
```

## Measured result

Not yet measured.
