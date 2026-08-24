# Fortinet FortiWeb - documented inspection behavior

Status: documented, not measured (no owned FortiWeb property this session).

## Block signature

Cookie `FortiWeb=` or body containing `FortiWeb`.

## Inspection limits

FortiWeb body inspection size is configurable per protection profile; no fixed
default is asserted here. Measure live with `find-limit --body`.

Source: https://docs.fortinet.com/product/fortiweb

## Applicable classes

- Size pads target the profile body window.
- Parser differentials (JSON/HPP/dup-header) depend on FortiWeb's decoding
  policy.
- `gzip_body`/`charset_utf7` depend on whether FortiWeb restores the content
  encoding before matching (verify).