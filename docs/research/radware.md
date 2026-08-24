# Radware AppWall - documented inspection behavior

Status: documented, not measured (no owned Radware property this session).

## Block signature

Header `X-Radware` or `X-SL-CompState`.

## Inspection limits

AppWall body inspection is policy/config-driven; no fixed default is asserted
here. Measure live with `find-limit --body`.

Source: https://www.radware.com/security/application-and-network-protection/

## Applicable classes

- Size pads target the configured body window.
- Parser differentials and encoding transforms are policy-dependent; verify
  decompression/normalization behavior before relying on them.