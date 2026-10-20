import pytest

from triage.iocs import VERSION_REASON, extract_iocs, extract_strings


def ip_values(result):
    return [entry["value"] for entry in result["ips"]]


# --- strings ---------------------------------------------------------------

def test_ascii_strings_respect_min_length():
    assert extract_strings(b"\x00abc\x00abcd\x01longer string\xff") == ["abcd", "longer string"]


def test_utf16le_strings():
    data = b"\x00\x00" + "kernel32.dll".encode("utf-16-le") + b"\x00\x00"
    assert "kernel32.dll" in extract_strings(data)


def test_short_utf16le_ignored():
    assert extract_strings("abc".encode("utf-16-le")) == []


# --- URLs ------------------------------------------------------------------

def test_urls_found_and_trailing_punctuation_stripped():
    data = b"go to http://bad-example.com/payload.bin. or (https://example.org/a?b=1)"
    assert extract_iocs(data)["urls"] == [
        "http://bad-example.com/payload.bin",
        "https://example.org/a?b=1",
    ]


def test_url_inside_binary_noise():
    data = b"\x00\x13\x88MZ\x90" + b"http://example.net/x" + b"\x00\xff"
    assert extract_iocs(data)["urls"] == ["http://example.net/x"]


def test_url_in_utf16le():
    data = "see https://example.com/u16".encode("utf-16-le")
    assert extract_iocs(data)["urls"] == ["https://example.com/u16"]


def test_url_host_goes_to_domains_and_path_file_to_filenames():
    result = extract_iocs(b"http://Bad-Example.com:8080/payload.bin")
    assert "bad-example.com" in result["domains"]
    assert "payload.bin" in result["filenames"]


def test_url_with_ip_host_goes_to_ips_without_reason():
    result = extract_iocs(b"http://192.0.2.10/x")
    assert result["ips"] == [{"value": "192.0.2.10"}]


def test_url_host_without_public_suffix_is_not_a_domain():
    assert extract_iocs(b"http://localhost:8000/admin")["domains"] == []


def test_malformed_url_does_not_crash():
    result = extract_iocs(b"http://[::1/broken")
    assert result["urls"] == ["http://[::1/broken"]


# --- IPv4 ------------------------------------------------------------------

def test_plain_ipv4():
    result = extract_iocs(b"connect 198.51.100.7 now")
    assert result["ips"] == [{"value": "198.51.100.7"}]


@pytest.mark.parametrize(
    "text",
    [b"999.1.1.1", b"1.2.3", b"1.2.3.4.5", b"256.256.256.256", b"01.2.3.4"],
)
def test_not_ipv4(text):
    assert extract_iocs(text)["ips"] == []


@pytest.mark.parametrize(
    "text",
    [
        b"version 1.2.3.4",
        b"Version: 1.2.3.4",
        b"v1.2.3.4",
        b"build 4.2.0.17",
        b"openssl-1.1.1.4",
        b"libfoo_2.0.0.1",
    ],
)
def test_version_like_ipv4_is_flagged(text):
    result = extract_iocs(text)
    assert len(result["ips"]) == 1
    assert result["ips"][0]["reason"] == VERSION_REASON


def test_ip_seen_in_ip_context_at_least_once_is_not_flagged():
    result = extract_iocs(b"version 1.2.3.4\nping 1.2.3.4\n")
    assert result["ips"] == [{"value": "1.2.3.4"}]


def test_ips_sorted_numerically_and_deduplicated():
    result = extract_iocs(b"10.0.0.2 9.9.9.9 10.0.0.2 192.0.2.1")
    assert ip_values(result) == ["9.9.9.9", "10.0.0.2", "192.0.2.1"]


# --- domains and file names -----------------------------------------------

def test_bare_domain():
    assert extract_iocs(b"beacon to c2.bad-example.com daily")["domains"] == ["c2.bad-example.com"]


def test_multi_label_suffix():
    assert extract_iocs(b"mail.example.co.uk")["domains"] == ["mail.example.co.uk"]


@pytest.mark.parametrize("token", ["kernel32.dll", "config.json", "payload.bin", "os.path"])
def test_no_public_suffix_means_filename(token):
    result = extract_iocs(token.encode())
    assert result["domains"] == []
    assert result["filenames"] == [token]


@pytest.mark.parametrize("token", ["setup.py", "invoice.zip", "install.sh", "notes.md"])
def test_file_lookalike_tld_is_both(token):
    result = extract_iocs(token.encode())
    assert result["domains"] == [token]
    assert result["filenames"] == [token]


def test_com_domain_is_not_also_a_filename():
    result = extract_iocs(b"example.com")
    assert result["domains"] == ["example.com"]
    assert result["filenames"] == []


@pytest.mark.parametrize("text", [b"e.g. this", b"pi is 3.14159", b"U.S and i.e"])
def test_noise_is_neither_domain_nor_filename(text):
    result = extract_iocs(text)
    assert result["domains"] == []
    assert result["filenames"] == []


def test_domains_lowercased_filenames_keep_case():
    result = extract_iocs(b"EXAMPLE.ORG and Report.PDF")
    assert result["domains"] == ["example.org"]
    assert result["filenames"] == ["Report.PDF"]


def test_empty_input():
    assert extract_iocs(b"") == {"urls": [], "ips": [], "domains": [], "filenames": []}


def test_dotted_number_with_octet_over_255_is_ignored_entirely():
    assert extract_iocs(b"build 10.0.19041.1")["ips"] == []
