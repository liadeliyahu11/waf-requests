# Akamai (Kona) - documented inspection behavior

Sources read this session:

- Request-body inspection settings:
  https://techdocs.akamai.com/application-security/reference/put-advanced-settings-request-body

## Body inspection limits

- Default request-body inspection limit: 8 KB.
- Configurable to 16 or 32 KB only (no 128 KB tier - corrected from an
  earlier draft). Source:
  https://techdocs.akamai.com/application-security/reference/put-advanced-settings-request-body
- Changes require the account team; per policy or per configuration via the
  Application Security API.

Junk-prepending past this window is a publicly demonstrated bypass class
against Akamai's 8 KB default (decoy part / filler parameter ahead of the
payload). Basis of `pad_multipart_decoy` and `pad_form_param`.

## Compressed request bodies

Akamai evaluates the request body AFTER decompression: the inspection limit
applies to the uncompressed content (documented in Akamai's Terraform/docs and
restated by the Securify bypass write-up). Consequence: `gzip_body` and
`deflate_body` do NOT hide a payload from Akamai the way they do from AWS WAF -
Akamai inflates first, then inspects. Viability differs from AWS for the same
technique (see docs/research/viability.md).

- Securify: https://securifyai.co/blog/bypass-waf-due-to-misconfigured-request-inspection-limit-size/
- Akamai request-body settings: https://techdocs.akamai.com/terraform/docs/request-body-settings

## Policy transformations

Kona rules evaluate variables after policy-configured normalizations
(decodeURL, decodeBase64, removeComments, compressWhitespace, normalizePath).
The transform set mirrors the gaps these create:

- decode-count differences -> `percent_double_encode`.
- comment stripping vs strict parsers -> `json_comment_inject`.
- path normalization scope -> `path_*`.

## Edge signals

- Block pages carry `Reference #<hex>.<hex>.<hex>` bodies; matched by
  `blockpage.classify`.
- `server: AkamaiGHost` with 403/503 supports the vendor guess.

## Profile mapping

`profiles.PROFILES["akamai"]` assumes 8192 bytes. Live domain pending
assignment; matrix rows SKIP until `[akamai].base` lands in
`examples/waf_targets.toml`.
