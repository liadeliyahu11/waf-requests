# Lab: protected-domain wiring

Targets are owned properties with the vendor's managed rulesets enforced.
The origin behind each domain must expose vulnapp endpoints so wins are
observable (`X-Origin-Saw-Payload`). No vendor API automation here.

## Run vulnapp locally

```bash
cd lab
docker build -t waf-vulnapp .
docker run -d --name waf-vulnapp -p 8090:8090 -e ENABLE_GZIP_IN=1 waf-vulnapp
curl -s http://127.0.0.1:8090/search?q=test
```

`ENABLE_GZIP_IN=1` turns on request-body decompression, required to
demonstrate `gzip_body`/`deflate_body`.

## AWS WAF

- Domain: your AWS protected domain (managed rules enforced).
- Point the origin (or one path behavior) at the vulnapp container host:port.
- Prior art and live-check discipline:
  `research/cve-2021-44228-waf/harness/run_live_check.py`. Reap leftover
  probe rules before trusting ALLOW verdicts.

## Cloudflare

- Domain: your Cloudflare protected domain.
  Console checklist: Security > WAF > Managed rules ON (OWASP + Cloudflare
  managed set, default sensitivity). Origin = vulnapp. DNS proxied (orange
  cloud) so traffic traverses the edge.
- Observed 2026-08-24 on our instance: edge confirmed Cloudflare
  (cf-ray/cdn-loop headers) but the SQLi canary was NOT blocked - rules likely
  run in log mode or lack that signature. `detect` honestly returns None;
  force the profile via `profile = "cloudflare"` in your local targets file.

## Akamai

- Domain pending assignment. When live: property with Kona Rule Set +
  Adaptive Risk Engine on default settings, request-body inspection limit at
  its default 8 KB, origin = vulnapp. Fill `[akamai]` in
  `examples/waf_targets.toml`; the matrix skips empty entries.

## Verify wiring

```bash
python -m waf_requests detect <domain>          # expect vendor name
curl -s "<domain>/search?q=%27+OR+%271%27%3D%271" -i | grep X-Origin-Saw
```

If the edge blocks the canary, `X-Origin-Saw` is absent and the response is a
block page: correct lab state. If you get 404 from an app that is not
vulnapp, the origin is not wired yet.
