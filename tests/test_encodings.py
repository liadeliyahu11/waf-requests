"""Encoding helpers: determinism and exact byte spellings."""
from __future__ import annotations

from waf_requests import encodings


ENCODERS = [
    encodings.percent_encode,
    encodings.percent_double_encode,
    encodings.backslash_unicode,
    encodings.percent_unicode,
    encodings.html_entity_hex,
    encodings.html_entity_named,
    encodings.overlong_utf8,
    encodings.base64_encode,
    encodings.utf7_encode,
    encodings.hex_encode,
]


def test_every_encoder_is_deterministic():
    for fn in ENCODERS:
        assert fn("a'b") == fn("a'b"), fn.__name__


def test_percent_encode():
    assert encodings.percent_encode("'") == "%27"


def test_percent_double_encode():
    assert encodings.percent_double_encode("'") == "%2527"


def test_backslash_unicode():
    assert encodings.backslash_unicode("A") == "\\u0041"


def test_percent_unicode():
    assert encodings.percent_unicode("A") == "%u0041"


def test_utf7_encode():
    assert encodings.utf7_encode("<") == "+ADw-"


def test_overlong_utf8():
    assert encodings.overlong_utf8("/") == "%c0%af"
    assert encodings.overlong_utf8(".") == "%c0%ae"


def test_hex_encode():
    assert encodings.hex_encode("a") == "61"


def test_base64_encode():
    assert encodings.base64_encode("a") == "YQ=="
