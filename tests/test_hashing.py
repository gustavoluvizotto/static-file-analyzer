import hashlib
import os

import pytest

from triage.hashing import hash_bytes, shannon_entropy


def test_hashes_match_hashlib():
    data = b"hello triage"
    result = hash_bytes(data)
    assert result["md5"] == hashlib.md5(data).hexdigest()
    assert result["sha256"] == hashlib.sha256(data).hexdigest()


def test_known_md5_of_empty_input():
    assert hash_bytes(b"")["md5"] == "d41d8cd98f00b204e9800998ecf8427e"


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"", 0.0),
        (b"AAAAAAAA", 0.0),
        (b"ABABABAB", 1.0),
        (b"ABCD" * 10, 2.0),
        (bytes(range(256)), 8.0),
    ],
)
def test_entropy_known_values(data, expected):
    assert shannon_entropy(data) == pytest.approx(expected)


def test_random_data_is_near_maximum():
    assert shannon_entropy(os.urandom(1 << 16)) > 7.9


def test_english_text_is_mid_range():
    text = b"The quick brown fox jumps over the lazy dog. " * 20
    assert 3.5 < shannon_entropy(text) < 5.0


def test_entropy_is_rounded_in_result():
    result = hash_bytes(b"ABC")
    assert result["entropy"] == round(result["entropy"], 4)
