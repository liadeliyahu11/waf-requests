# xxe_utf16_bom

Category: xxe | Fidelity: differential

## Mechanism

Prefix a utf-16 bom so the parser decodes utf-16.

## Why the WAF misses it

ASCII scanners see NUL-interleaved bytes and miss the entity declarations.

## Why the origin still accepts it

An XML parser that sees the BOM decodes the whole document as UTF-16.

## Prerequisites and limits

XML parser that honors a UTF-16 BOM.

## References

- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
-->
﻿<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

## Measured result

Not yet measured.
