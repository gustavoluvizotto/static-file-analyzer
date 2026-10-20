import io
import os
import struct
import zipfile

import pytest

from triage.filetype import detect


def make_pe(e_lfanew: int = 0x80) -> bytes:
    header = bytearray(e_lfanew + 24)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, e_lfanew)
    header[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    return bytes(header)


def test_pe():
    assert detect(make_pe()) == "pe"


def test_mz_without_pe_signature_is_unknown():
    data = bytearray(make_pe())
    data[0x80:0x84] = b"XXXX"
    assert detect(bytes(data)) == "unknown"


def test_mz_with_out_of_range_e_lfanew_does_not_crash():
    data = bytearray(0x40)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0xFFFFFFF0)
    assert detect(bytes(data)) == "unknown"


def test_truncated_mz_header():
    assert detect(b"MZ") == "text"  # two printable bytes, no PE header


def test_elf():
    assert detect(b"\x7fELF\x02\x01\x01" + b"\x00" * 57) == "elf"


def test_zip_built_with_zipfile():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hi")
    assert detect(buf.getvalue()) == "zip"


def test_empty_zip():
    assert detect(b"PK\x05\x06" + b"\x00" * 18) == "zip"


def test_pdf_at_start_and_with_leading_junk():
    assert detect(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n") == "pdf"
    assert detect(b"junk junk\n%PDF-1.4\n") == "pdf"


@pytest.mark.parametrize(
    "data",
    [
        b"Just some notes.\nNothing else here.\n",
        "Café crème, naïve résumé\n".encode("utf-8"),
        "plain utf-16 text\n".encode("utf-16"),
    ],
)
def test_text(data):
    assert detect(data) == "text"


@pytest.mark.parametrize(
    "data",
    [
        b"#!/bin/sh\necho hi\n",
        b"#!/usr/bin/env python3\nprint('x')\n",
        b"@echo off\r\nrem batch\r\n",
        b"<?php echo 'x'; ?>",
        b"$x = 1\nInvoke-Expression $x\n",
        "#!/bin/bash\necho utf16\n".encode("utf-16"),
    ],
)
def test_script(data):
    assert detect(data) == "script"


def test_utf8_cut_in_the_middle_of_sample_is_still_text():
    data = ("a" * 8191 + "é" * 10).encode("utf-8")  # sample boundary splits 'é'
    assert detect(data) == "text"


def test_random_bytes_are_unknown():
    assert detect(os.urandom(4096)) == "unknown"


def test_binary_with_nul_is_unknown():
    assert detect(b"hello\x00world") == "unknown"


def test_empty_is_unknown():
    assert detect(b"") == "unknown"
