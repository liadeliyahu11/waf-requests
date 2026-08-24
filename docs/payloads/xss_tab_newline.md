# xss_tab_newline

Category: xss | Fidelity: differential

## Mechanism

Insert tab/newline inside tag brackets.

## Why the WAF misses it

Regexes expecting a clean `<tag>` miss the inserted whitespace.

## Why the origin still accepts it

HTML tolerates tabs/newlines inside tag brackets.

## Prerequisites and limits

Reflection into an HTML-parsed context.

## References

- https://github.com/larbi67/WAF-XSS-Bypass
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<script>alert(1)</script>
-->
<	script>
alert(1)<	/script>

```

## Measured result

Not yet measured.
