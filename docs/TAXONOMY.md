# Impact taxonomy: what does a bypass actually buy you?

One question decides whether a bypass is worth anything:

> Did the origin interpret the request as the ORIGINAL exploit intended?

Slipping a blocked request past a WAF proves nothing by itself. If the
application parses it differently than the original payload would have been,
the exploitation goal is lost. Every transform in this library is classified
by which side of that line it sits on.

## Class A - WAF blind-spot, application-guaranteed

Fidelity tier: `transparent` (+ `additive`).

The WAF cannot SEE the payload (inspection window ends before it, body is
compressed, charset opaque) or cannot MATCH it (signature characters are
escaped in forms every RFC parser decodes identically). The application's
parser - any conforming parser - reconstructs the original bytes on its own.
No assumption about the stack beyond conformance.

**Win condition: DELIVERED == EXPLOITED.** Nothing to verify beyond delivery.

| Transform | WAF failure exploited |
|---|---|
| `pad_json_ws` | body inspection window ends before the payload |
| `pad_form_param`, `pad_multipart_decoy` | same window, form/multipart shapes |
| `header_pad_early` | header-inspection budget exhausted early (measured ~8 KB / 200 headers) |
| `json_unicode_escape` | signature anchoring vs `\uXXXX` escapes |
| `gzip_body`, `deflate_body` | no transport decompression of request bodies |
| `multipart_boundary_variance` | boundary extraction spelling |
| `multipart_payload_last` | parts after the scan cutoff |
| `path_dot_segments`* | path matching pre-normalization |
| `path_double_slash`* | empty-segment collapsing mismatch |

\* conditional on the router normalizing; see Class C nuance below.

## Class B - additive noise

Fidelity tier: `additive`. Original parameters/parts arrive byte-intact plus
distinct-name decoys nothing reads (`waf_filler=AAAA...`, `waf_decoy` part).
Same guarantee as Class A for the fields the exploit cares about.

## Class C - parser differential, application-dependent

Fidelity tier: `differential`. The wire payload DIFFERS from the original.
Delivery means the origin received something else; it becomes the original
exploit only if the stack's parser picks the documented winner. These are
opportunities, not wins - each names its exact prerequisite:

| Transform | Origin requirement | Verify |
|---|---|---|
| `percent_double_encode` | framework decodes twice | PASS(reflected-equal) measured on AWS lab |
| `hpp_duplicate_param` | last-wins parameter handling (most frameworks) | reflected equality |
| `hpp_semicolon_sep` | splits pairs on `;` (historic PHP/JSP) | echo parse |
| `json_dup_key_lastwins` | last-key-wins deserializer (Python json, Jackson default) | parsed-value check |
| `json_deep_nest_wrap` | accepts deeply nested arrays unchanged in meaning | shape check |
| `json_comment_inject` | lenient JSON parser (comments stripped) | strip+parse |
| `charset_utf7` | honors declared UTF-7 charset (legacy ASP-era) | decode check |
| `utf8_overlong_path` | normalizes overlong UTF-8 in routing (rare today) | route probe |
| `dup_header_firstlast` | reads LAST duplicate (stack-defined order) | header echo |
| `method_override` | honors X-HTTP-Method-Override | method echo |
| `path_semicolon_params` | strips matrix params (Tomcat/Jetty family) | route probe |
| `path_dot_segments` | decodes `%2e` then removes dot segments AFTER matching | route probe |
| `path_dotdot_semicolon` | strips path params before resolving dots (Tomcat/WebLogic) | route probe |
| `path_collapse_dotdot` | single-pass `../` sanitizer re-created by `....//` | file reached |
| `null_byte_terminator` | NUL-truncating string handling (PHP < 5.3.4 era) | suffix check |
| `spoof_trusted_ip` | edge trusts inbound XFF/CF-Connecting-IP/True-Client-IP | IP-dependent rule bypass |

## Reading a result

```
DELIVERED  + transparent/additive tier -> guaranteed win
DELIVERED  + differential tier         -> candidate win; run verify until PASS
BLOCKED    regardless of tier          -> no delivery, ladder continues/exhausts
```

`python -m waf_requests verify <url>` automates exactly this judgment against
origins that reflect input. `strict_fidelity=True` restricts the ladder to
Classes A+B so manipulation can never happen.

## The three layers (and where inspiration fits)

| Layer | Mutates | Library coverage |
|---|---|---|
| Payload content | the attack string itself: case toggling, `UNION/**/SELECT`, `${IFS}`, hex encoding, PHP wrappers | out of scope - compose with tools like Ilias1988/waf-bypass |
| Request shape & parsing | windows, encodings, charsets, parameter/path/header semantics | this library |
| Transport identity | TLS/JA3 fingerprints, H2 frames, source ports, origin-IP discovery | out of scope - see matrixleons/evilwaf |

A real engagement usually needs all three: transport identity to avoid
behavioral blocking, a request-layer blind-spot to deliver untouched, and
payload mutation only when the engine still inspects your content.
