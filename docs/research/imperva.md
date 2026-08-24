# Imperva (Incapsula) - documented inspection behavior

Status: documented, not measured (no owned Imperva property this session).

## Block signature

Cookie `visid_incap_*` or `incap_ses_*`, header `X-Iinfo`, header
`X-CDN: Incapsula`, or body containing `Incapsula`.

## Inspection limits

Imperva inspects request bodies up to a configured size with decompression
before inspection; exact defaults are account/policy-dependent and not
independently verified here. Measure live with `find-limit --body`.

Source: https://docs.imperva.com/

## Applicable classes

- Size pads (`pad_json_ws`, `pad_form_param`, `pad_multipart_decoy`) target the
  body window once measured.
- `gzip_body`/`deflate_body` neutralized if Imperva inflates before inspection
  (verify).
- HPP and JSON differentials are policy-normalization-dependent.