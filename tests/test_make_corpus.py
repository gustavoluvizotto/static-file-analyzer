import os

import pytest

from make_corpus import LARGE_SIZE, MARKER, SENTINEL, build_corpus
from triage.filetype import detect
from triage.hashing import shannon_entropy

from conftest import is_root


def read(path):
    return path.read_bytes()


def test_expected_types(corpus):
    good, bad = corpus / "good", corpus / "bad"
    assert detect(read(good / "calc_like.exe")) == "pe"
    assert detect(read(good / "tool.elf")) == "elf"
    assert detect(read(good / "photos.zip")) == "zip"
    assert detect(read(good / "manual.pdf")) == "pdf"
    assert detect(read(good / "random.bin")) == "unknown"
    assert detect(read(good / "notes.txt")) == "text"
    assert detect(read(good / "install.sh")) == "script"
    assert detect(read(bad / "dropper.exe")) == "pe"
    assert detect(read(bad / "implant.elf")) == "elf"
    assert detect(read(bad / "loader.ps1")) == "script"
    assert detect(read(bad / "invoice.zip")) == "zip"


def test_random_blob_is_high_entropy(corpus):
    assert shannon_entropy(read(corpus / "good" / "random.bin")) > 7.9


def test_marker_only_in_bad_set(corpus):
    for path in (corpus / "bad").iterdir():
        assert MARKER in read(path), path.name
    for path in (corpus / "good").iterdir():
        if os.access(path, os.R_OK):
            assert MARKER not in read(path), path.name


def test_empty_and_unreadable_files(corpus):
    assert (corpus / "good" / "empty.txt").stat().st_size == 0
    unreadable = corpus / "good" / "unreadable.txt"
    assert unreadable.stat().st_mode & 0o777 == 0
    if not is_root:
        assert not os.access(unreadable, os.R_OK)


def test_deterministic(tmp_path):
    a = build_corpus(tmp_path / "a")
    b = build_corpus(tmp_path / "b")
    for pa, pb in zip(a["bad"], b["bad"]):
        assert read(pa) == read(pb)
    for path in (a["good"][-1], b["good"][-1]):
        path.chmod(0o644)


def test_rebuild_over_previous_corpus(corpus):
    build_corpus(corpus)
    assert (corpus / SENTINEL).exists()


def test_refuses_to_wipe_foreign_directory(tmp_path):
    foreign = tmp_path / "mine"
    foreign.mkdir()
    (foreign / "important.txt").write_text("keep me")
    with pytest.raises(SystemExit):
        build_corpus(foreign)
    assert (foreign / "important.txt").read_text() == "keep me"


def test_with_large_is_sparse_and_over_limit(tmp_path):
    build_corpus(tmp_path / "c", with_large=True)
    large = tmp_path / "c" / "good" / "large.bin"
    assert large.stat().st_size == LARGE_SIZE
    (tmp_path / "c" / "good" / "unreadable.txt").chmod(0o644)
