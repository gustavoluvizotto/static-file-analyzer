"""Walk a directory, decide what to skip, and build one result record per file.

The walk is file-descriptor based: every directory is opened relative to its
already-open parent with O_NOFOLLOW, and every file relative to its directory.
Swapping any path component for a symlink mid-scan therefore cannot redirect a
read outside the tree being scanned.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from dataclasses import dataclass
from typing import Iterator

from triage import filetype, hashing, iocs, yara_scan

MB = 1024 * 1024
MAX_FILE_SIZE = 50 * MB
MAX_DEPTH = 64
READ_CHUNK = 1 * MB
ROOT_PROTECTED = "file is root protected"

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC


@dataclass
class Skip:
    """Why a path was not analysed: a stable code plus a human-readable reason."""
    code: str
    reason: str
    size: int | None = None


@dataclass(frozen=True)
class Entry:
    """A walked path. `name` is relative to `dir_fd`, which stays open only until
    the walk advances; `path` is the display path, as walked from the root."""
    path: str
    name: str
    dir_fd: int | None = None


def _size_text(limit: int) -> str:
    return f"{limit // MB} MB" if limit % MB == 0 else f"{limit} bytes"


def _kind(mode: int) -> str:
    if stat.S_ISFIFO(mode):
        return "named pipe (FIFO)"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    return "special file"


def _dir_skip(exc: OSError) -> Skip:
    if isinstance(exc, PermissionError):
        return Skip("permission_denied", "directory is root protected; its contents were not scanned")
    if isinstance(exc, FileNotFoundError):
        return Skip("vanished", "directory disappeared before it could be read")
    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
        return Skip("changed_during_scan", "directory was replaced while being scanned (not followed)")
    return Skip("read_error", f"could not list directory: {exc.strerror or exc}")


def walk(root: str) -> Iterator[tuple[Entry, Skip | None]]:
    """Yield (entry, skip) for every entry below `root`, sorted, without following
    symlinks. Unreadable or too-deep directories are yielded as skips."""
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC)
    except OSError as exc:
        yield Entry(root, root), _dir_skip(exc)
        return
    yield from _walk_dir(root_fd, root, 0)


def _walk_dir(fd: int, path: str, depth: int) -> Iterator[tuple[Entry, Skip | None]]:
    """Walk the open directory `fd` (closed when done), whose display path is `path`."""
    try:
        try:
            # scandir(fd) works on a duplicate of fd, so fd stays usable below.
            entries = sorted(os.scandir(fd), key=lambda e: e.name)
        except OSError as exc:
            yield Entry(path, path), _dir_skip(exc)
            return
        for entry in entries:
            child = os.path.join(path, entry.name)
            if not entry.is_dir(follow_symlinks=False):
                yield Entry(child, entry.name, fd), None
                continue
            if depth >= MAX_DEPTH:
                yield Entry(child, entry.name), Skip(
                    "too_deep", f"directory nested deeper than {MAX_DEPTH} levels; contents not scanned"
                )
                continue
            try:
                child_fd = os.open(entry.name, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                yield Entry(child, entry.name), _dir_skip(exc)
                continue
            yield from _walk_dir(child_fd, child, depth + 1)
    finally:
        os.close(fd)


def _read_bounded(fd: int, max_size: int) -> bytes:
    """Read at most max_size + 1 bytes in chunks, so small files stay cheap."""
    chunks: list[bytes] = []
    remaining = max_size + 1
    while remaining > 0:
        chunk = os.read(fd, min(READ_CHUNK, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_sample(
    path: str, max_size: int = MAX_FILE_SIZE, dir_fd: int | None = None
) -> tuple[bytes | None, Skip | None]:
    """Read a regular file of 1..max_size bytes, or explain why it was skipped.
    With `dir_fd`, `path` is resolved relative to that open directory."""
    try:
        st = os.lstat(path, dir_fd=dir_fd)
    except FileNotFoundError:
        return None, Skip("vanished", "file disappeared before it could be read")
    except OSError as exc:
        return None, Skip("read_error", f"could not stat file: {exc.strerror or exc}")

    if stat.S_ISLNK(st.st_mode):
        return None, Skip("symlink", "symbolic link (not followed)")
    if not stat.S_ISREG(st.st_mode):
        return None, Skip("not_regular_file", f"not a regular file: {_kind(st.st_mode)}")
    if st.st_size == 0:
        return None, Skip("empty", "file is empty", 0)
    if st.st_size > max_size:
        return None, Skip("too_large", f"file is larger than the {_size_text(max_size)} limit", st.st_size)

    # O_NOFOLLOW/O_NONBLOCK + fstat: if the path was swapped for a symlink or FIFO
    # after lstat, we neither follow it nor block on it.
    try:
        fd = os.open(path, _FILE_FLAGS, dir_fd=dir_fd)
    except PermissionError:
        return None, Skip("permission_denied", ROOT_PROTECTED, st.st_size)
    except FileNotFoundError:
        return None, Skip("vanished", "file disappeared before it could be read")
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, Skip("changed_during_scan", "file was replaced by a symbolic link (not followed)")
        return None, Skip("read_error", f"could not open file: {exc.strerror or exc}", st.st_size)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, Skip("changed_during_scan", "file changed type while being scanned")
        data = _read_bounded(fd, max_size)
    except OSError as exc:
        return None, Skip("read_error", f"could not read file: {exc.strerror or exc}", st.st_size)
    finally:
        os.close(fd)

    if len(data) > max_size:  # grew after lstat
        return None, Skip("too_large", f"file is larger than the {_size_text(max_size)} limit", len(data))
    if not data:
        return None, Skip("empty", "file is empty", 0)
    return data, None


def analyse(data: bytes, ruleset: yara_scan.RuleSet | None) -> dict:
    """All per-file fields except path/status/scan_ms."""
    record: dict = {"size": len(data)}
    record.update(hashing.hash_bytes(data))
    record["file_type"] = filetype.detect(data)
    # Keep the field order readable: entropy after file_type.
    record["entropy"] = record.pop("entropy")
    record["iocs"] = iocs.extract_iocs(data)
    if ruleset is not None:
        names, error = yara_scan.match(ruleset.combined, data)
        record["yara_matches"] = names
        if error:
            record["yara_error"] = error
    return record


def scan_file(
    path: str,
    ruleset: yara_scan.RuleSet | None,
    max_size: int = MAX_FILE_SIZE,
    *,
    dir_fd: int | None = None,
    name: str | None = None,
) -> dict:
    """Scan one file. `path` is what the record reports; with `dir_fd`, the file is
    opened as `name` relative to that directory."""
    start = time.perf_counter()
    data, skip = read_sample(name if dir_fd is not None else path, max_size, dir_fd)
    if skip is not None:
        record = _skip_record(path, skip)
    else:
        try:
            record = {"path": path, "status": "ok", **analyse(data, ruleset)}
        except Exception as exc:  # one bad file must never stop the scan
            record = {"path": path, "status": "error", "reason": f"{type(exc).__name__}: {exc}"}
    record["scan_ms"] = round((time.perf_counter() - start) * 1000, 3)
    return record


def _skip_record(path: str, skip: Skip) -> dict:
    record = {"path": path, "status": "skipped", "skip_reason": skip.code, "reason": skip.reason}
    if skip.size is not None:
        record["size"] = skip.size
    return record


def scan_tree(root: str, ruleset: yara_scan.RuleSet | None, max_size: int = MAX_FILE_SIZE) -> Iterator[dict]:
    """Yield one record per entry under `root`; paths are as walked from `root`."""
    for entry, skip in walk(root):
        if skip is not None:
            yield {**_skip_record(entry.path, skip), "scan_ms": 0.0}
        else:
            yield scan_file(entry.path, ruleset, max_size, dir_fd=entry.dir_fd, name=entry.name)


def iter_samples(root: str, max_size: int = MAX_FILE_SIZE) -> Iterator[tuple[str, bytes | None, dict | None]]:
    """Yield (path, data, None) for each scannable file under `root`, or
    (path, None, skip_record). Only one file's bytes are held at a time."""
    for entry, skip in walk(root):
        data = None
        if skip is None:
            data, skip = read_sample(entry.name, max_size, entry.dir_fd)
        if skip is not None:
            yield entry.path, None, _skip_record(entry.path, skip)
        else:
            yield entry.path, data, None
