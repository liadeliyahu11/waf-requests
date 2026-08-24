"""Emit one docs/payloads/<id>.md per registered payload mutator.

Authored content (mechanism, why-WAF-misses, why-origin-accepts, prereq, ref)
lives in DOCS below; the Before/After section is computed by calling the real
mutator on a per-category canonical payload, so it can never drift from code.
Run: `.venv/bin/python scripts/gen_payload_docs.py`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from waf_requests.payloads import PAYLOADS  # noqa: E402

DOCS_DIR = Path(__file__).resolve().parents[1] / "docs" / "payloads"

#: Canonical exploit per category used for the Before/After example.
CANONICAL = {
    "sqli": "UNION SELECT * FROM users",
    "xss": "<script>alert(1)</script>",
    "cmdi": "cat /etc/passwd",
    "lfi": "../../etc/passwd",
    "ssrf": "http://127.0.0.1/admin",
    "ssti": "{{7*7}}",
    "xxe": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
}

REF = {
    "sqli": "https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF",
    "xss": "https://github.com/larbi67/WAF-XSS-Bypass",
    "cmdi": "https://hacktricks.wiki/en/pentesting-web/command-injection",
    "lfi": "https://owasp.org/www-community/attacks/Path_Traversal",
    "ssrf": "https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery",
    "ssti": "https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html",
    "xxe": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
}

#: id -> (why_waf_misses, why_origin_accepts, prereq). Mechanism is the mutator's
#: explain string; the Before/After is computed.
DOCS = {
    "sqli_case_toggle": (
        "Signature rules anchored on lowercase or uppercase keywords miss the mixed-case spelling.",
        "SQL keywords are case-insensitive across every DB engine, so the query means the same thing.",
        "DB engine present (any)."),
    "sqli_inline_comment": (
        "Regexes matching contiguous `UNION SELECT` fail once letters are split by `/**/`.",
        "The DB parser treats `/**/` as a comment and joins the letters back into the keyword.",
        "DB engine that honors `/**/` (MySQL-family and most others)."),
    "sqli_version_comment": (
        "Rules matching `UNION`/`SELECT` do not match the `/*!50000...*/` spelling.",
        "MySQL executes version-gated comments on any version >= 5.0, recovering the keyword.",
        "MySQL (or a compatible parser) on the backend."),
    "sqli_hex_quote": (
        "Quote-and-string signatures (e.g. `'admin'`) vanish once the literal becomes `0x...`.",
        "The SQL engine resolves hex literals to the same string the quote form denoted.",
        "DB engine accepting hex string literals (MySQL, PostgreSQL, MSSQL)."),
    "sqli_double_encode": (
        "A single-decoding WAF decodes once and still sees percent-encoded noise.",
        "The framework decodes a second time and passes the raw payload to the query.",
        "Application layer that decodes the parameter more times than the WAF."),
    "sqli_whitespace_sub": (
        "Rules anchored on space-separated keywords miss the `/**/` whitespace.",
        "SQL treats `/**/` as a comment, which is valid whitespace between tokens.",
        "DB engine that honors `/**/`."),
    "sqli_comment_extend": (
        "A trailing comment token with extra text no longer matches the exact comment signature.",
        "Everything after `--`/`#` is ignored by the DB, so the payload is unchanged in effect.",
        "DB engine with line-comment syntax (`--`/`#`)."),
    "xss_unicode_escape": (
        "Byte scanners matching `alert`/`script` do not see the `\\uXXXX` spelling.",
        "The JavaScript engine decodes `\\uXXXX` escapes in string/identifier context.",
        "Browser/JS engine that decodes unicode escapes in the sink context."),
    "xss_html_entity": (
        "Tag-pattern rules matching `<...>` miss the `&#x3C;...&#x3E;` spelling.",
        "The HTML parser decodes entities into angle brackets before scripting runs.",
        "Reflection into an HTML-parsed context."),
    "xss_js_concat": (
        "Contiguous `alert(`/`script` anchors fail once split by `\\u0065`/`/**/`.",
        "The JS engine folds the unicode escape and comment back into the call.",
        "Reflection into a JS-parsed context."),
    "xss_mixed_case": (
        "Case-sensitive signatures for `<script>`/`alert` miss the mixed-case form.",
        "HTML tag names and JS function names are case-insensitive where reflected.",
        "Case-insensitive HTML/JS parser context."),
    "xss_tab_newline": (
        "Regexes expecting a clean `<tag>` miss the inserted whitespace.",
        "HTML tolerates tabs/newlines inside tag brackets.",
        "Reflection into an HTML-parsed context."),
    "xss_svg_onload": (
        "Rules keyed on `<script>` do not fire on an `<svg onload>` handler.",
        "The browser executes `onload` on the injected svg element.",
        "Reflection into an HTML body where svg is rendered."),
    "cmdi_ifs_space": (
        "Space-separated command signatures miss the `${IFS}` spelling.",
        "POSIX shells expand `${IFS}` to whitespace before executing.",
        "POSIX shell (sh/bash) sink."),
    "cmdi_backtick": (
        "Rules anchored on the bare command miss the backtick-wrapped form.",
        "Backticks are command substitution; the inner command still runs.",
        "POSIX shell (sh/bash) sink."),
    "cmdi_hex_echo": (
        "The command's literal bytes vanish into a hex blob plus a decode pipe.",
        "`xxd -r -p | sh` reconstructs the original command and executes it.",
        "`xxd` + `sh` available on the target."),
    "lfi_double_encode": (
        "A single-decoding filter sees encoded dot-segments and does not strip them.",
        "The filesystem/router decodes once more and resolves the traversal.",
        "Framework/router that decodes twice."),
    "lfi_overlong_utf8": (
        "Scanners do not normalize overlong UTF-8, so the encoded separators pass.",
        "A permissive decoder normalizes the overlong sequence back to `/`/`.`.",
        "Router that normalizes overlong UTF-8 (rare)."),
    "lfi_null_byte": (
        "Suffix/file-type checks match the benign `.png` after the NUL.",
        "Legacy C-string handling truncates at NUL, acting on the prefix.",
        "Legacy PHP/C filesystem handling (PHP < 5.3.4 era)."),
    "lfi_dotdot_variants": (
        "A single-pass `../` stripper collapses `....//` to `../` AFTER matching.",
        "The resolved path still contains the traversal the filter meant to remove.",
        "A single-pass traversal filter on the origin."),
    "ssrf_ip_decimal": (
        "SSRF blocklists keyed on `127.0.0.1` miss the integer form.",
        "Most HTTP clients/servers resolve a dotted-decimal integer to the same address.",
        "Target that resolves integer IP forms."),
    "ssrf_ip_hex": (
        "Blocklists keyed on the dotted literal miss the hex form.",
        "Many resolvers accept `0x7f000001` as 127.0.0.1.",
        "Target that resolves hex IP forms."),
    "ssrf_ip_octal": (
        "Blocklists keyed on decimal octets miss the octal first octet.",
        "C-style octal `0177` resolves to 127.",
        "Target that resolves octal IP forms."),
    "ssrf_localhost_alt": (
        "Blocklists keyed on `localhost`/`127.0.0.1` miss the alternate spelling.",
        "The sink resolves `[::1]` to loopback like the literal.",
        "Target that resolves IPv6 loopback."),
    "ssrf_dns_rebind": (
        "An allowlist/blocklist sees a public rebinding hostname, not the loopback literal.",
        "The rebind domain resolves to 127.0.0.1 at request time.",
        "A rebinding DNS service (out-of-band infrastructure)."),
    "ssti_comment_break": (
        "Rules anchored on `{{7*7}}` miss the comment-split expression.",
        "Jinja strips `{##}` comments and evaluates the surrounding expression.",
        "Jinja2 (or a compatible `{# #}` comment syntax)."),
    "ssti_unicode_escape": (
        "Signature bytes for `{{`/`7*7` vanish into `\\uXXXX` escapes.",
        "A unicode-decoding layer recovers the expression before templating.",
        "Template engine that decodes unicode escapes."),
    "xxe_utf16_bom": (
        "ASCII scanners see NUL-interleaved bytes and miss the entity declarations.",
        "An XML parser that sees the BOM decodes the whole document as UTF-16.",
        "XML parser that honors a UTF-16 BOM."),
    "xxe_parameter_entity": (
        "Rules matching the inline entity miss the parameter-entity indirection.",
        "The XML parser resolves parameter entities before the main entity is used.",
        "XML parser with parameter-entity support."),
}


def render(p: object) -> str:
    canonical = CANONICAL[p.category]
    before = canonical
    after = p.apply(canonical)  # type: ignore[attr-defined]
    why_waf, why_origin, prereq = DOCS[p.id]
    return (
        f"# {p.id}\n\n"
        f"Category: {p.category} | Fidelity: {p.fidelity}\n\n"
        f"## Mechanism\n\n{p.explain.capitalize()}.\n\n"
        f"## Why the WAF misses it\n\n{why_waf}\n\n"
        f"## Why the origin still accepts it\n\n{why_origin}\n\n"
        f"## Prerequisites and limits\n\n{prereq}\n\n"
        f"## References\n\n- {REF[p.category]}\n"
        f"- https://github.com/Ilias1988/waf-bypass\n\n"
        f"## Before / After\n\n```\n{before}\n-->\n{after}\n```\n\n"
        f"## Measured result\n\nNot yet measured.\n"
    )


def main() -> int:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    missing = [pid for pid in PAYLOADS if pid not in DOCS]
    if missing:
        print(f"DOCS map missing entries: {missing}", file=sys.stderr)
        return 1
    for pid, payload in PAYLOADS.items():
        (DOCS_DIR / f"{pid}.md").write_text(render(payload))
    print(f"wrote {len(PAYLOADS)} payload docs to {DOCS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
