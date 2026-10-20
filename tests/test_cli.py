import json
import subprocess
import sys

import pytest

from triage.cli import format_report, main
from triage.yara_scan import RuleStats

from conftest import REPO, RULES_DIR, is_root


@pytest.fixture
def own_rules_dir(tmp_path):
    d = tmp_path / "own_rules"
    d.mkdir()
    for path in RULES_DIR.glob("*.yar"):
        (d / path.name).write_bytes(path.read_bytes())
    return d


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_scan_writes_one_line_per_path(corpus, own_rules_dir, tmp_path, capsys):
    out = tmp_path / "results.jsonl"
    assert main(["scan", str(corpus / "bad"), "--rules", str(own_rules_dir), "--out", str(out)]) == 0
    records = {r["path"].rsplit("/", 1)[-1]: r for r in read_jsonl(out)}
    assert len(records) == 6
    assert all(r["status"] == "ok" for r in records.values())
    dropper = records["dropper.exe"]
    assert dropper["file_type"] == "pe"
    assert dropper["yara_matches"] == [
        "Triage_Noisy_Any_URL", "Triage_PE_Remote_Injection_APIs", "Triage_Synthetic_Marker",
    ]
    assert "http://bad-example.com/stage2.bin" in dropper["iocs"]["urls"]
    assert "update.bad-example.net" in dropper["iocs"]["domains"]  # from a UTF-16LE string
    assert "6 ok, 0 skipped" in capsys.readouterr().err


def test_scan_paths_are_as_walked(corpus, own_rules_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(corpus)
    out = tmp_path / "r.jsonl"
    main(["scan", "good", "--rules", str(own_rules_dir), "--out", str(out)])
    assert all(r["path"].startswith("good/") for r in read_jsonl(out))


def test_scan_records_skips_and_version_ip(corpus, own_rules_dir, tmp_path):
    out = tmp_path / "r.jsonl"
    main(["scan", str(corpus / "good"), "--rules", str(own_rules_dir), "--out", str(out)])
    records = {r["path"].rsplit("/", 1)[-1]: r for r in read_jsonl(out)}
    assert records["empty.txt"]["skip_reason"] == "empty"
    if not is_root:
        assert records["unreadable.txt"]["reason"] == "file is root protected"
    notes_ips = records["notes.txt"]["iocs"]["ips"]
    assert {"value": "1.2.3.4", "reason": "possible software version instead of real IPv4 address."} in notes_ips
    assert {"value": "192.0.2.10"} in notes_ips
    assert "setup.py" in records["notes.txt"]["iocs"]["domains"]
    assert "setup.py" in records["notes.txt"]["iocs"]["filenames"]


def test_scan_max_size(corpus, own_rules_dir, tmp_path):
    out = tmp_path / "r.jsonl"
    main(["scan", str(corpus / "good"), "--rules", str(own_rules_dir), "--out", str(out), "--max-size-mb", "0.01"])
    records = {r["path"].rsplit("/", 1)[-1]: r for r in read_jsonl(out)}
    assert records["random.bin"]["skip_reason"] == "too_large"
    assert records["notes.txt"]["status"] == "ok"


def test_scan_to_stdout(corpus, own_rules_dir, capsys):
    main(["scan", str(corpus / "bad"), "--rules", str(own_rules_dir)])
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 6 and all(json.loads(line)["status"] == "ok" for line in lines)


def test_scan_missing_dir_and_bad_rules(tmp_path, own_rules_dir, capsys):
    assert main(["scan", str(tmp_path / "nope"), "--rules", str(own_rules_dir)]) == 2
    (own_rules_dir / "broken.yar").write_text("rule X { condition: nope }")
    assert main(["scan", str(tmp_path), "--rules", str(own_rules_dir), "--strict"]) == 2
    assert main(["scan", str(tmp_path), "--rules", str(own_rules_dir)]) == 0
    assert "warning: skipped rule file broken.yar" in capsys.readouterr().err


def test_test_rules_report(corpus, own_rules_dir, capsys):
    code = main([
        "test-rules", "--rules", str(own_rules_dir), "--good", str(corpus / "good"), "--bad", str(corpus / "bad"),
    ])
    assert code == 0
    out = capsys.readouterr().out
    lines = {line.split()[0]: line.split() for line in out.splitlines() if line.startswith("Triage_")}
    assert lines["Triage_Synthetic_Marker"][2:4] == ["6/6", "0/7"]
    assert lines["Triage_PE_Remote_Injection_APIs"][2:4] == ["1/6", "0/7"]
    assert lines["Triage_Noisy_Any_URL"][2:4] == ["2/6", "2/7"]
    assert "Triage_Noisy_Any_URL: install.sh, notes.txt" in out


def test_report_hides_silent_rules_unless_all():
    stats = [RuleStats("Hit", "a.yar", ["b1"], [], 1.0), RuleStats("Quiet", "b.yar", [], [], 2.0)]
    assert "Quiet" not in format_report(stats, 1, 1, show_all=False)
    assert "1 more rules matched nothing" in format_report(stats, 1, 1, show_all=False)
    assert "Quiet" in format_report(stats, 1, 1, show_all=True)


def test_python_dash_m_entry_point(corpus, own_rules_dir):
    result = subprocess.run(
        [sys.executable, "-m", "triage", "scan", str(corpus / "bad"), "--rules", str(own_rules_dir)],
        capture_output=True, text=True, cwd=REPO, timeout=60,
    )
    assert result.returncode == 0
    assert len(result.stdout.splitlines()) == 6


def test_test_rules_multiple_passes_report_once(corpus, own_rules_dir, capsys):
    code = main([
        "test-rules", "--rules", str(own_rules_dir), "--good", str(corpus / "good"), "--bad", str(corpus / "bad"),
        "--batch-size", "1",
    ])
    assert code == 0
    captured = capsys.readouterr()
    assert captured.err.count("skipped sample") == 2  # empty.txt + unreadable.txt (or 1 as root)
    assert "samples: 7 good, 6 bad (3 passes)" in captured.err
    lines = {line.split()[0]: line.split() for line in captured.out.splitlines() if line.startswith("Triage_")}
    assert lines["Triage_Synthetic_Marker"][2:4] == ["6/6", "0/7"]
    assert lines["Triage_Noisy_Any_URL"][2:4] == ["2/6", "2/7"]


def test_test_rules_rejects_zero_batch_size(corpus, own_rules_dir):
    with pytest.raises(SystemExit) as exc:
        main(["test-rules", "--rules", str(own_rules_dir), "--good", str(corpus / "good"),
              "--bad", str(corpus / "bad"), "--batch-size", "0"])
    assert exc.value.code == 2


def test_test_rules_corpus_changing_between_passes_fails(corpus, own_rules_dir, monkeypatch, capsys):
    from triage import scanner

    real_iter = scanner.iter_samples
    calls = []

    def flaky_iter(root, max_size):
        calls.append(root)
        for path, data, skip in real_iter(root, max_size):
            if data is not None and len(calls) > 2 and path.endswith("notes.txt"):
                data = data + b"tampered"
            yield path, data, skip

    monkeypatch.setattr(scanner, "iter_samples", flaky_iter)
    code = main([
        "test-rules", "--rules", str(own_rules_dir), "--good", str(corpus / "good"), "--bad", str(corpus / "bad"),
        "--batch-size", "1",
    ])
    err = capsys.readouterr().err
    assert code == 1
    assert "good sample 'notes.txt' changed during evaluation" in err
