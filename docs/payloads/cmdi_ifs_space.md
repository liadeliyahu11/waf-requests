# cmdi_ifs_space

Category: cmdi | Fidelity: differential

## Mechanism

Replace spaces with ${ifs}.

## Why the WAF misses it

Space-separated command signatures miss the `${IFS}` spelling.

## Why the origin still accepts it

POSIX shells expand `${IFS}` to whitespace before executing.

## Prerequisites and limits

POSIX shell (sh/bash) sink.

## References

- https://hacktricks.wiki/en/pentesting-web/command-injection
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
cat /etc/passwd
-->
cat${IFS}/etc/passwd
```

## Measured result

Not yet measured.
