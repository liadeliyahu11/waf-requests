# xxe_parameter_entity

Category: xxe | Fidelity: differential

## Mechanism

Wrap in a parameter-entity declaration.

## Why the WAF misses it

Rules matching the inline entity miss the parameter-entity indirection.

## Why the origin still accepts it

The XML parser resolves parameter entities before the main entity is used.

## Prerequisites and limits

XML parser with parameter-entity support.

## References

- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- https://github.com/Ilias1988/waf-bypass

## Before / After

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
-->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

## Measured result

Not yet measured.
