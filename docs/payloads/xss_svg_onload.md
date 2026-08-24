# xss_svg_onload

Category: xss | Fidelity: differential

## Mechanism

Rewrite <script>alert(1)</script> to <svg onload=alert(1)>.

## Why the WAF misses it

Rules keyed on `<script>` do not fire on an `<svg onload>` handler.

## Why the origin still accepts it

The browser executes `onload` on the injected svg element.

## Prerequisites and limits

Reflection into an HTML body where svg is rendered.

## References

- https://github.com/larbi67/WAF-XSS-Bypass
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<script>alert(1)</script>
-->
<svg onload=alert(1)>
```

## Measured result

Not yet measured.
