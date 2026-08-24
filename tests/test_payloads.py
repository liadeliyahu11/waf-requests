"""Payload mutator invariants and transparent-tier semantic round-trips."""
from __future__ import annotations

from waf_requests.payloads import CATEGORIES, PAYLOADS

#: A payload exercising every category's canonical shape.
SAMPLE = {
    "sqli": "UNION SELECT * FROM users WHERE '1'='1'",
    "xss": "<script>alert(1)</script>",
    "cmdi": "cat /etc/passwd",
    "lfi": "../../etc/passwd",
    "ssrf": "http://127.0.0.1/admin",
    "ssti": "{{7*7}}",
    "xxe": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
}


def test_every_payload_returns_deterministic_str():
    for pid, payload in PAYLOADS.items():
        assert payload.category in CATEGORIES, pid
        out = payload.apply(SAMPLE[payload.category])
        assert isinstance(out, str), pid
        assert out == payload.apply(SAMPLE[payload.category]), pid


def test_payload_ids_unique():
    ids = [p.id for p in PAYLOADS.values()]
    assert len(ids) == len(set(ids))


def test_transparent_sqli_case_toggle_round_trips():
    src = "UNION SELECT * FROM users"
    assert PAYLOADS["sqli_case_toggle"].apply(src).lower() == src.lower()


def test_sqli_hex_quote_decodes_back_to_word():
    assert PAYLOADS["sqli_hex_quote"].apply("'admin'") == "0x" + "admin".encode().hex()


def test_sqli_whitespace_sub_replaces_spaces():
    assert PAYLOADS["sqli_whitespace_sub"].apply("a b") == "a/**/b"


def test_transparent_xss_mixed_case_round_trips():
    src = "<script>alert(1)</script>"
    assert PAYLOADS["xss_mixed_case"].apply(src).lower() == src.lower()


def test_ssrf_ip_decimal():
    assert PAYLOADS["ssrf_ip_decimal"].apply("127.0.0.1") == "2130706433"


def test_ssrf_ip_hex():
    assert PAYLOADS["ssrf_ip_hex"].apply("127.0.0.1") == "0x7f000001"


def test_ssrf_ip_octal():
    assert PAYLOADS["ssrf_ip_octal"].apply("127.0.0.1") == "0177.0.0.1"


def test_ssti_comment_break_canonical():
    assert PAYLOADS["ssti_comment_break"].apply("{{7*7}}") == "{{7*{##}7}}"
