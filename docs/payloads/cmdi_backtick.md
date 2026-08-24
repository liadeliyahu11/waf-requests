# cmdi_backtick

Category: cmdi | Fidelity: differential

## Mechanism

Wrap in backticks and replace spaces with ${ifs}.

## Why the WAF misses it

Rules anchored on the bare command miss the backtick-wrapped form.

## Why the origin still accepts it

Backticks are command substitution; the inner command still runs.

## Prerequisites and limits

POSIX shell (sh/bash) sink.

## References

- https://hacktricks.wiki/en/pentesting-web/command-injection
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
cat /etc/passwd
-->
`cat${IFS}/etc/passwd`
```

## Measured result

Not yet measured.
