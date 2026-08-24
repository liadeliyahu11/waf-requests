# ssti_comment_break

Category: ssti | Fidelity: differential

## Mechanism

Insert {##} into the template expression ({{7*7}} -> {{7*{##}7}}).

## Why the WAF misses it

Rules anchored on `{{7*7}}` miss the comment-split expression.

## Why the origin still accepts it

Jinja strips `{##}` comments and evaluates the surrounding expression.

## Prerequisites and limits

Jinja2 (or a compatible `{# #}` comment syntax).

## References

- https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
{{7*7}}
-->
{{7*{##}7}}
```

## Measured result

Not yet measured.
