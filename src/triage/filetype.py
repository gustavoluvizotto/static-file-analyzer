"""Identify a file's type from its leading bytes (no external `file` command)."""

from __future__ import annotations

import struct

PE, ELF, ZIP, PDF, TEXT, SCRIPT, UNKNOWN = (
    "pe", "elf", "zip", "pdf", "text", "script", "unknown",
)

TEXT_SAMPLE_SIZE = 8192
PRINTABLE_RATIO = 0.95
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
# Lower-cased markers that make a text file a script even without a shebang.
SCRIPT_MARKERS = (
    "<?php",
    "@echo off",
    "powershell",
    "invoke-expression",
    "<script",
    "wscript.",
    "createobject(",
)


def _is_pe(data: bytes) -> bool:
    # DOS header "MZ"; e_lfanew at 0x3C points to the "PE\0\0" signature.
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    return data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


def _decode_text(sample: bytes) -> str | None:
    """Return the sample as text if it looks like text, else None."""
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return sample.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in sample:
        return None
    # The sample may cut a multi-byte UTF-8 character in half; ignore that tail.
    text = sample.decode("utf-8", errors="replace")
    if text.endswith("�"):
        text = text.rstrip("�")
    if not text:
        return None
    printable = sum(ch.isprintable() or ch in "\t\r\n\f" for ch in text)
    return text if printable / len(text) >= PRINTABLE_RATIO else None


def _is_script(text: str) -> bool:
    text = text.lstrip("﻿")
    if text.startswith("#!"):
        return True
    head = text[:4096].lower()
    return any(marker in head for marker in SCRIPT_MARKERS)


def detect(data: bytes) -> str:
    """Return one of: pe, elf, zip, pdf, text, script, unknown."""
    if _is_pe(data):
        return PE
    if data.startswith(b"\x7fELF"):
        return ELF
    if data.startswith(ZIP_MAGICS):
        return ZIP
    # The PDF spec tolerates junk before the header, within the first 1 KB.
    if b"%PDF-" in data[:1024]:
        return PDF
    text = _decode_text(data[:TEXT_SAMPLE_SIZE])
    if text is None:
        return UNKNOWN
    return SCRIPT if _is_script(text) else TEXT
