import os

import pytest

from triage import scanner
from triage.scanner import ROOT_PROTECTED, iter_samples, read_sample, scan_file, scan_tree, walk
from triage.yara_scan import load_rules

from conftest import is_root


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "t"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"visit http://example.com today\n")
    (root / "sub" / "b.bin").write_bytes(b"\x00\x01\x02\x03")
    return root


@pytest.fixture
def ruleset(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "url.yar").write_text('rule AnyUrl { strings: $u = "http://" condition: $u }')
    return load_rules(d)


def test_walk_is_sorted_recursive_and_keeps_given_prefix(tree):
    root = str(tree)
    assert [e.path for e, _ in walk(root)] == [os.path.join(root, "a.txt"), os.path.join(root, "sub", "b.bin")]


def test_walk_relative_root_keeps_paths_relative(tree, monkeypatch):
    monkeypatch.chdir(tree.parent)
    assert [e.path for e, _ in walk("t")] == ["t/a.txt", "t/sub/b.bin"]


def test_ok_record_has_all_fields(tree, ruleset):
    record = scan_file(str(tree / "a.txt"), ruleset)
    assert list(record) == [
        "path", "status", "size", "md5", "sha256", "file_type", "entropy", "iocs", "yara_matches", "scan_ms",
    ]
    assert record["status"] == "ok"
    assert record["file_type"] == "text"
    assert record["iocs"]["urls"] == ["http://example.com"]
    assert record["yara_matches"] == ["AnyUrl"]
    assert record["scan_ms"] >= 0


def test_without_rules_there_is_no_yara_field(tree):
    assert "yara_matches" not in scan_file(str(tree / "a.txt"), None)


def test_empty_file(tmp_path):
    (tmp_path / "e").write_bytes(b"")
    data, skip = read_sample(str(tmp_path / "e"))
    assert data is None and skip.code == "empty" and skip.reason == "file is empty"


def test_too_large_uses_lstat_size_before_reading(tmp_path, monkeypatch):
    path = tmp_path / "big"
    path.write_bytes(b"x" * 101)
    monkeypatch.setattr(os, "open", lambda *a, **k: pytest.fail("should not open"))
    data, skip = read_sample(str(path), max_size=100)
    assert skip.code == "too_large" and skip.size == 101
    assert skip.reason == "file is larger than the 100 bytes limit"


def test_too_large_reason_in_mb():
    assert scanner._size_text(50 * scanner.MB) == "50 MB"


def test_exactly_at_limit_is_scanned(tmp_path):
    (tmp_path / "f").write_bytes(b"x" * 100)
    data, skip = read_sample(str(tmp_path / "f"), max_size=100)
    assert skip is None and len(data) == 100


@pytest.mark.skipif(is_root, reason="root can read chmod 000 files")
def test_chmod_000_is_root_protected(tmp_path):
    path = tmp_path / "locked"
    path.write_bytes(b"secret")
    path.chmod(0o000)
    try:
        record = scan_file(str(path), None)
    finally:
        path.chmod(0o644)
    assert record["status"] == "skipped"
    assert record["skip_reason"] == "permission_denied"
    assert record["reason"] == ROOT_PROTECTED == "file is root protected"


@pytest.mark.skipif(is_root, reason="root can list chmod 000 directories")
def test_unreadable_directory_is_reported_not_fatal(tree):
    locked = tree / "sub"
    locked.chmod(0o000)
    try:
        records = list(scan_tree(str(tree), None))
    finally:
        locked.chmod(0o755)
    by_path = {r["path"]: r for r in records}
    assert by_path[str(tree / "a.txt")]["status"] == "ok"
    assert by_path[str(locked)]["skip_reason"] == "permission_denied"


def test_symlinks_are_not_followed(tree, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside the scanned tree")
    (tree / "link_file").symlink_to(outside)
    (tree / "link_dir").symlink_to(tree)  # would loop forever if followed
    records = {os.path.basename(r["path"]): r for r in scan_tree(str(tree), None)}
    assert records["link_file"]["skip_reason"] == "symlink"
    assert records["link_dir"]["skip_reason"] == "symlink"
    assert len(records) == 4


def test_fifo_is_skipped_without_blocking(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    data, skip = read_sample(str(fifo))
    assert skip.code == "not_regular_file"
    assert "FIFO" in skip.reason


def test_vanished_file(tmp_path):
    data, skip = read_sample(str(tmp_path / "gone"))
    assert skip.code == "vanished"


def test_analysis_crash_becomes_error_record(tree, monkeypatch):
    def boom(_data):
        raise RuntimeError("bug")
    monkeypatch.setattr(scanner.filetype, "detect", boom)
    record = scan_file(str(tree / "a.txt"), None)
    assert record["status"] == "error"
    assert record["reason"] == "RuntimeError: bug"


def test_scan_tree_on_corpus(corpus):
    records = {os.path.basename(r["path"]): r for r in scan_tree(str(corpus / "good"), None)}
    assert records["empty.txt"]["skip_reason"] == "empty"
    assert records["random.bin"]["entropy"] > 7.9
    assert records["calc_like.exe"]["file_type"] == "pe"
    if not is_root:
        assert records["unreadable.txt"]["reason"] == "file is root protected"


def test_iter_samples_splits_readable_and_skipped(corpus):
    items = list(iter_samples(str(corpus / "good")))
    readable = {path for path, data, skip in items if skip is None}
    skipped = {os.path.basename(path) for path, data, skip in items if skip is not None}
    assert str(corpus / "good" / "notes.txt") in readable
    assert skipped >= {"empty.txt"}
