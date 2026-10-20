"""Hostile-input tests: races, resource exhaustion, and untrusted file names."""

import io
import json
import os
import tracemalloc
import zipfile

import pytest

from triage import scanner
from triage.cli import format_report, main, safe_text
from triage.scanner import MAX_DEPTH, read_sample, scan_tree, walk
from triage.yara_scan import RuleStats, evaluate, load_rules

URL_RULE = 'rule AnyUrl { strings: $u = "http://" condition: $u }'


@pytest.fixture
def url_rules(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "url.yar").write_text(URL_RULE)
    return d


def open_fds():
    return len(os.listdir("/dev/fd"))


# --- H1: symlink swap of a parent directory (TOCTOU) ----------------------

@pytest.fixture
def race_tree(tmp_path):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "a.txt").write_bytes(b"first")
    (tree / "sub" / "f.txt").write_bytes(b"inside file")
    outside = tmp_path / "secret"
    outside.mkdir()
    (outside / "f.txt").write_bytes(b"SECRET http://leaked.example.com")
    return tree, outside


def swap_for_symlink(directory, target):
    directory.rename(directory.with_name(directory.name + "_moved"))
    directory.symlink_to(target)


def test_parent_swapped_after_listing_does_not_redirect_read(race_tree):
    tree, outside = race_tree
    walker = walk(str(tree))
    for entry, skip in walker:
        if entry.name == "f.txt":
            swap_for_symlink(tree / "sub", outside)
            data, skip = read_sample(entry.name, dir_fd=entry.dir_fd)
            break
    walker.close()
    assert data == b"inside file"  # the directory we listed, not the symlink target


def test_directory_swapped_before_descent_is_skipped_not_followed(race_tree):
    tree, outside = race_tree
    walker = walk(str(tree))
    first, _ = next(walker)
    assert first.name == "a.txt"
    swap_for_symlink(tree / "sub", outside)  # after the root listing, before descending
    rest = list(walker)
    assert [(e.path, s.code) for e, s in rest] == [(str(tree / "sub"), "changed_during_scan")]


def test_file_swapped_for_symlink_before_open_is_not_followed(tmp_path, monkeypatch):
    target = tmp_path / "secret"
    target.write_bytes(b"SECRET")
    victim = tmp_path / "victim"
    victim.write_bytes(b"ok")
    real_open = os.open

    def swap_then_open(path, flags, *args, **kwargs):
        if str(path).endswith("victim"):
            victim.unlink()
            victim.symlink_to(target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_then_open)
    data, skip = read_sample(str(victim))
    assert data is None and skip.code == "changed_during_scan"


def test_walk_closes_every_directory_fd(race_tree):
    tree, _ = race_tree
    before = open_fds()
    list(walk(str(tree)))
    assert open_fds() == before
    walker = walk(str(tree))
    next(walker)
    walker.close()  # consumer stops early
    assert open_fds() == before


def test_deep_nesting_is_capped_without_recursion_error(tmp_path):
    level = tmp_path / "deep"
    level.mkdir()
    root = level
    for _ in range(MAX_DEPTH + 5):
        level = level / "d"
        level.mkdir()
        (level / "f.txt").write_bytes(b"x")
    records = list(scan_tree(str(root), None))
    too_deep = [r for r in records if r.get("skip_reason") == "too_deep"]
    assert len(too_deep) == 1
    assert sum(r["status"] == "ok" for r in records) == MAX_DEPTH


# --- M3: read buffer proportional to file size ---------------------------

def test_small_file_does_not_allocate_max_size_buffer(tmp_path):
    path = tmp_path / "tiny"
    path.write_bytes(b"hello")
    tracemalloc.start()
    read_sample(str(path))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 2 * scanner.MB


# --- H2: test-rules memory independent of corpus size --------------------

def test_test_rules_streams_samples(tmp_path, url_rules, capsys):
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.mkdir()
    bad.mkdir()
    for i in range(30):
        (good / f"g{i:02}.bin").write_bytes(os.urandom(scanner.MB))
    (bad / "b.txt").write_bytes(b"http://example.com")
    tracemalloc.start()
    assert main(["test-rules", "--rules", str(url_rules), "--good", str(good), "--bad", str(bad)]) == 0
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 10 * scanner.MB  # holding all samples would be > 30 MB
    assert "AnyUrl" in capsys.readouterr().out


def test_evaluate_consumes_samples_lazily(url_rules):
    consumed = []

    def samples():
        for i in range(3):
            consumed.append(i)
            yield "bad", f"s{i}", b"http://x"

    result = evaluate(load_rules(url_rules), samples)
    assert consumed == [0, 1, 2]
    assert result.stats[0].detections == ["s0", "s1", "s2"]


def test_test_rules_memory_with_full_rules_dir(corpus):
    """Regression: test-rules held ~480 per-file compiled rule sets (~1.25 GB peak)."""
    import subprocess
    import sys

    from conftest import RULES_DIR

    code = (
        "import resource, subprocess, sys; "
        "subprocess.run([sys.executable, '-m', 'triage', 'test-rules', '--rules', sys.argv[1], "
        "'--good', sys.argv[2], '--bad', sys.argv[3]], check=True, capture_output=True); "
        "rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss; "
        "print(rss if sys.platform == 'darwin' else rss * 1024)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(RULES_DIR), str(corpus / "good"), str(corpus / "bad")],
        capture_output=True, text=True, check=True,
    )
    assert int(result.stdout) < 500 * scanner.MB


# --- M1: untrusted file names in human-readable output -------------------

EVIL_NAME = "x\nAnyUrl  forged  0-1  0-1\x1b[2J\u202etxt.exe"


def test_report_escapes_hostile_file_names(tmp_path, url_rules, capsys):
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.mkdir()
    bad.mkdir()
    (good / EVIL_NAME).write_bytes(b"http://example.com")
    (good / "empty\nline").write_bytes(b"")
    (bad / "b.txt").write_bytes(b"http://example.com")
    main(["test-rules", "--rules", str(url_rules), "--good", str(good), "--bad", str(bad)])
    captured = capsys.readouterr()
    for stream in (captured.out, captured.err):
        assert "\x1b" not in stream and "\u202e" not in stream
    assert not any(line.startswith("AnyUrl  forged") for line in captured.out.splitlines())
    assert "x\\x0aAnyUrl  forged  0-1  0-1\\x1b[2J\\u202etxt.exe" in captured.out
    assert "skipped sample " + str(good) + "/empty\\x0aline: file is empty" in captured.err


def test_hostile_rule_file_name_in_warning(tmp_path, capsys):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "ok.yar").write_text(URL_RULE)
    (rules / "evil\nwarning: all good.yar").write_text("rule X { condition: nope }")
    main(["scan", str(tmp_path / "rules"), "--rules", str(rules), "--out", os.devnull])
    err = capsys.readouterr().err
    assert not any(line.startswith("warning: all good") for line in err.splitlines())


def test_non_utf8_file_name_does_not_crash_report():
    # On Linux, os.scandir returns undecodable bytes as lone surrogates.
    stats = [RuleStats("AnyUrl", "url.yar", [], ["bad\udcff.bin"], 1.0)]
    report = format_report(stats, 1, 0, show_all=False)
    report.encode("utf-8")  # strict, as on a UTF-8 terminal; must not raise
    assert "bad\\udcff.bin" in report


def test_safe_text_keeps_normal_unicode():
    assert safe_text("café 日本 report.pdf") == "café 日本 report.pdf"


# --- already safe: regression tests --------------------------------------

def test_zip_bomb_is_not_expanded(tmp_path):
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        with zf.open("zeros.bin", "w") as f:
            for _ in range(64):
                f.write(bytes(scanner.MB))
    record = scanner.scan_file(str(bomb), None)
    assert record["file_type"] == "zip"
    assert record["size"] == bomb.stat().st_size < scanner.MB


def test_newline_file_name_is_one_jsonl_line(tmp_path, url_rules):
    d = tmp_path / "d"
    d.mkdir()
    (d / "two\nlines.txt").write_bytes(b"http://example.com")
    out = tmp_path / "r.jsonl"
    main(["scan", str(d), "--rules", str(url_rules), "--out", str(out)])
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["path"] == str(d / "two\nlines.txt")
