"""Extract printable strings and IOCs (URLs, IPv4 addresses, domains, file names)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

MIN_STRING_LEN = 4
VERSION_REASON = "possible software version instead of real IPv4 address."

_ASCII_RE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING_LEN)
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_STRING_LEN)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`{}|\\^]+", re.IGNORECASE)
_URL_TRAILING_PUNCT = ".,;:!?)]}"
# A dotted run of digits; only runs of exactly four parts are IPv4 candidates.
_DOTTED_NUM_RE = re.compile(r"(?<![\d.])\d+(?:\.\d+)+(?!\d)")
_VERSION_PREFIX_RE = re.compile(
    r"(?:\bv|\bver|\bversion|\brelease|\brel|\bbuild|\brev|\brevision)[\s:=#_-]*$",
    re.IGNORECASE,
)
# "name.ext" or "a.b.example.com": labels of letters, digits, '-' and '_'.
_DOTTED_NAME_RE = re.compile(r"(?<![\w.-])[\w-]+(?:\.[\w-]+)+(?![\w-])", re.ASCII)
_EXTENSION_RE = re.compile(r"[A-Za-z0-9]{2,8}")

# Common file extensions. A token whose public suffix is one of these (e.g. setup.py,
# invoice.zip, run.sh) is reported both as a domain and as a file name. "com" is
# deliberately absent: otherwise every .com domain would also be listed as a file.
FILE_EXTENSIONS = frozenset(
    """
    7z ai apk app bat bin cab cc cfg cmd cpl crt dat deb dll dmg doc docm docx elf eml
    exe gif gz hta htm html img in ini iso jar jpg js jse json key lnk log md mo mov
    mp3 mp4 msg msi ml one pdf pem php pkg pl pm png po ps ps1 py rar rb rpm rs rtf
    run scr sh so sys tar tmp ts txt vbe vbs wsf ws xls xlsm xlsx xml xz zip
    """.split()
)

# Offline: use tldextract's bundled Public Suffix List snapshot, never the network.
_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def extract_strings(data: bytes) -> list[str]:
    """Printable ASCII and UTF-16LE runs of at least MIN_STRING_LEN characters."""
    found = [m.group().decode("ascii") for m in _ASCII_RE.finditer(data)]
    found += [m.group().decode("utf-16-le") for m in _UTF16LE_RE.finditer(data)]
    return found


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def _looks_like_version(string: str, start: int) -> bool:
    if start and (string[start - 1].isalpha() or string[start - 1] in "-_"):
        return True
    return bool(_VERSION_PREFIX_RE.search(string[max(0, start - 16):start]))


def _classify_name(token: str) -> tuple[str | None, str | None]:
    """Return (domain, filename) for a dotted token; either may be None."""
    labels = token.split(".")
    if all(label.isdigit() for label in labels):
        return None, None
    ext = _tld(token)
    last = labels[-1].lower()
    if ext.suffix and ext.domain:
        filename = token if last in FILE_EXTENSIONS else None
        return token.lower(), filename
    if _EXTENSION_RE.fullmatch(labels[-1]) and not labels[-1].isdigit():
        return None, token
    return None, None


def _url_host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def extract_iocs(data: bytes) -> dict[str, list]:
    """Return {"urls", "ips", "domains", "filenames"}, each sorted and de-duplicated.

    "ips" holds {"value": ip} objects, plus a "reason" when the match looks like a
    software version. An address seen at least once in a non-version context is
    reported without a reason.
    """
    urls: set[str] = set()
    ips: dict[str, bool] = {}  # ip -> looks like a version in every occurrence
    domains: set[str] = set()
    filenames: set[str] = set()

    def add_ip(ip: str, version_like: bool) -> None:
        ips[ip] = ips.get(ip, True) and version_like

    for string in extract_strings(data):
        for match in _URL_RE.finditer(string):
            url = match.group().rstrip(_URL_TRAILING_PUNCT)
            urls.add(url)
            host = _url_host(url)
            if not host:
                continue
            if _is_ipv4(host):
                add_ip(host, False)
            elif _tld(host).suffix and _tld(host).domain:
                domains.add(host.lower())

        for match in _DOTTED_NUM_RE.finditer(string):
            if match.group().count(".") == 3 and _is_ipv4(match.group()):
                add_ip(match.group(), _looks_like_version(string, match.start()))

        for match in _DOTTED_NAME_RE.finditer(string):
            domain, filename = _classify_name(match.group())
            if domain:
                domains.add(domain)
            if filename:
                filenames.add(filename)

    return {
        "urls": sorted(urls),
        "ips": [
            {"value": ip, "reason": VERSION_REASON} if version_like else {"value": ip}
            for ip, version_like in sorted(ips.items(), key=lambda kv: ipaddress.IPv4Address(kv[0]))
        ],
        "domains": sorted(domains),
        "filenames": sorted(filenames),
    }
