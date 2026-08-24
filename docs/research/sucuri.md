# Sucuri WebSite Firewall - documented inspection behavior

Status: documented, not measured (no owned Sucuri property this session).

## Block signature

Header `Server: Sucuri/Cloudproxy` or body containing `Sucuri WebSite
Firewall`.

## Inspection limits

Sucuri is a reverse-proxy WAF; its request body inspection size is not public
and is not asserted here. Measure live with `find-limit --body`.

Source: https://docs.sucuri.net/

## Applicable classes

- Size pads and encoding transforms target the proxy inspection window; verify
  decompression/normalization first.
- Parser differentials (HPP, JSON) depend on the origin stack behind Sucuri.