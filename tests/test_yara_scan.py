from pathlib import Path

import pytest

from triage import yara_scan
from triage.yara_scan import (
    RuleLoadError, SampleSetChanged, evaluate, find_rule_files, load_rules, match,
)

from conftest import RULES_DIR

MARKER_RULE = 'rule Marker { strings: $m = "MARK" condition: $m }'
URL_RULE = 'rule AnyUrl { strings: $u = "http://" condition: $u }'


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "rules"
    (d / "sub").mkdir(parents=True)
    (d / "marker.yar").write_text(MARKER_RULE)
    (d / "sub" / "url.yara").write_text(URL_RULE)
    (d / "notes.txt").write_text("not a rule")
    return d


def test_find_rule_files_recurses_and_skips_index_and_non_rules(rules_dir):
    (rules_dir / "malware_index.yar").write_text('include "./marker.yar"')
    names = [p.name for p in find_rule_files(rules_dir)]
    assert names == ["marker.yar", "url.yara"]


def test_find_rule_files_skips_deprecated_dirs(rules_dir):
    for sub in ("deprecated", "sub/Deprecated", "deprecated/nested"):
        (rules_dir / sub).mkdir(parents=True, exist_ok=True)
        (rules_dir / sub / "old.yar").write_text(MARKER_RULE)
    (rules_dir / "deprecated_notes.yar").write_text(MARKER_RULE)  # a file, not a directory
    names = [p.relative_to(rules_dir).as_posix() for p in find_rule_files(rules_dir)]
    assert names == ["deprecated_notes.yar", "marker.yar", "sub/url.yara"]


def test_rules_root_inside_a_deprecated_dir_still_loads(tmp_path, rules_dir):
    root = tmp_path / "deprecated" / "rules"
    root.mkdir(parents=True)
    (root / "marker.yar").write_text(MARKER_RULE)
    assert [p.name for p in find_rule_files(root)] == ["marker.yar"]


def test_load_and_match(rules_dir):
    ruleset = load_rules(rules_dir)
    assert ruleset.rule_count == 2
    assert set(ruleset.sources) == {"marker.yar", "sub/url.yara"}
    assert match(ruleset.combined, b"MARK http://x") == (["AnyUrl", "Marker"], None)
    assert match(ruleset.combined, b"nothing") == ([], None)


def test_same_rule_name_in_two_files_is_allowed(rules_dir):
    (rules_dir / "dup.yar").write_text(MARKER_RULE)
    assert load_rules(rules_dir).rule_count == 3


def test_broken_file_is_skipped_by_default(rules_dir):
    (rules_dir / "broken.yar").write_text("rule Broken { condition: nonsense_identifier }")
    ruleset = load_rules(rules_dir)
    assert [ns for ns, _ in ruleset.broken] == ["broken.yar"]
    assert "nonsense_identifier" in ruleset.broken[0][1]
    assert ruleset.rule_count == 2


def test_broken_file_fails_in_strict_mode(rules_dir):
    (rules_dir / "broken.yar").write_text("rule Broken { condition: nonsense_identifier }")
    with pytest.raises(RuleLoadError, match="broken.yar"):
        load_rules(rules_dir, strict=True)


def test_missing_or_empty_rules_dir(tmp_path):
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path / "nope")
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path)


def as_samples(good, bad):
    return [("good", n, d) for n, d in good.items()] + [("bad", n, d) for n, d in bad.items()]


def test_evaluate_counts_detections_false_positives_and_time(rules_dir):
    ruleset = load_rules(rules_dir)
    good = {"g1": b"see http://example.com", "g2": b"plain"}
    bad = {"b1": b"MARK", "b2": b"MARK http://example.com"}
    stats = {s.rule: s for s in evaluate(ruleset, lambda: as_samples(good, bad)).stats}
    assert stats["Marker"].detections == ["b1", "b2"]
    assert stats["Marker"].false_positives == []
    assert stats["AnyUrl"].detections == ["b2"]
    assert stats["AnyUrl"].false_positives == ["g1"]
    assert stats["AnyUrl"].rule_file == "sub/url.yara"
    assert all(s.avg_match_us > 0 for s in stats.values())


@pytest.fixture
def own_rules(tmp_path):
    """Only the three project rules (rules/*.yar), without the community set."""
    d = tmp_path / "own_rules"
    d.mkdir()
    for path in RULES_DIR.glob("*.yar"):
        (d / path.name).write_bytes(path.read_bytes())
    return load_rules(d, strict=True)


def test_project_rules_against_corpus(corpus, own_rules):
    good = {p.name: p.read_bytes() for p in (corpus / "good").iterdir() if p.name != "unreadable.txt"}
    bad = {p.name: p.read_bytes() for p in (corpus / "bad").iterdir()}
    stats = {s.rule: s for s in evaluate(own_rules, lambda: as_samples(good, bad)).stats}
    assert sorted(stats["Triage_Synthetic_Marker"].detections) == sorted(bad)
    assert stats["Triage_Synthetic_Marker"].false_positives == []
    assert stats["Triage_PE_Remote_Injection_APIs"].detections == ["dropper.exe"]
    assert stats["Triage_PE_Remote_Injection_APIs"].false_positives == []
    assert sorted(stats["Triage_Noisy_Any_URL"].false_positives) == ["install.sh", "notes.txt"]


def test_full_rules_dir_loads_with_community_rules():
    ruleset = load_rules(RULES_DIR)
    assert ruleset.rule_count > 1000
    assert "marker.yar" in ruleset.sources
    # Community files using YARA module fields that no longer exist are skipped, not fatal.
    assert all(ns.startswith("yara-rules/") for ns, _ in ruleset.broken)


def test_evaluate_with_no_samples(rules_dir):
    result = evaluate(load_rules(rules_dir), lambda: [])
    assert all(s.avg_match_us == 0.0 and not s.detections for s in result.stats)
    assert sum(result.counts.values()) == 0


def test_load_rules_memory_with_full_rules_dir():
    """Regression: keeping ~480 per-file compiled sets used ~1.5 GB and got the
    container scan OOM-killed under a 1 GB limit."""
    import subprocess
    import sys

    code = (
        "import resource, sys; from triage.yara_scan import load_rules; "
        f"load_rules({str(RULES_DIR)!r}); "
        "rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss; "
        "print(rss if sys.platform == 'darwin' else rss * 1024)"
    )
    peak = int(subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout)
    assert peak < 400 * 1024 * 1024


# --- batched evaluation ----------------------------------------------------

@pytest.fixture
def three_rule_files(tmp_path):
    d = tmp_path / "three"
    d.mkdir()
    (d / "a.yar").write_text('rule A { strings: $s = "alpha" condition: $s }')
    (d / "b.yar").write_text('rule B { strings: $s = "beta" condition: $s }')
    (d / "c.yar").write_text('rule C { strings: $s = "gamma" condition: $s }')
    return load_rules(d)


SAMPLES = [("good", "g1", b"alpha"), ("bad", "b1", b"alpha beta"), ("bad", "b2", b"gamma")]


def summary(result):
    return sorted((s.rule, s.rule_file, s.detections, s.false_positives) for s in result.stats)


@pytest.mark.parametrize("batch_size", [1, 2, 3, 64])
def test_batch_size_does_not_change_results(three_rule_files, batch_size):
    reference = evaluate(three_rule_files, lambda: SAMPLES, batch_size=64)
    result = evaluate(three_rule_files, lambda: SAMPLES, batch_size=batch_size)
    assert summary(result) == summary(reference) == [
        ("A", "a.yar", ["b1"], ["g1"]),
        ("B", "b.yar", ["b1"], []),
        ("C", "c.yar", ["b2"], []),
    ]
    assert result.counts == {"good": 1, "bad": 2}  # counted once, not once per pass


@pytest.mark.parametrize("batch_size, passes", [(1, 3), (2, 2), (3, 1), (64, 1)])
def test_samples_streamed_once_per_batch(three_rule_files, batch_size, passes):
    calls = []

    def samples():
        calls.append(1)
        yield from SAMPLES

    evaluate(three_rule_files, samples, batch_size=batch_size)
    assert len(calls) == passes


def test_project_rules_batched_match_unbatched(corpus, own_rules):
    good = {p.name: p.read_bytes() for p in (corpus / "good").iterdir() if p.name != "unreadable.txt"}
    bad = {p.name: p.read_bytes() for p in (corpus / "bad").iterdir()}
    one = evaluate(own_rules, lambda: as_samples(good, bad), batch_size=64)
    many = evaluate(own_rules, lambda: as_samples(good, bad), batch_size=1)
    assert summary(one) == summary(many)


def changing_samples(second_pass):
    passes = []

    def samples():
        passes.append(1)
        return SAMPLES if len(passes) == 1 else second_pass

    return samples


@pytest.mark.parametrize(
    "second_pass, message",
    [
        ([("good", "g1", b"alpha!"), *SAMPLES[1:]], "good sample 'g1' changed"),
        ([*SAMPLES, ("bad", "b3", b"new")], "bad sample 'b3' appeared"),
        (SAMPLES[:2], "1 sample(s) disappeared"),
    ],
)
def test_samples_differing_between_passes_raise(three_rule_files, second_pass, message):
    with pytest.raises(SampleSetChanged, match=message.replace("(", r"\(").replace(")", r"\)")):
        evaluate(three_rule_files, changing_samples(second_pass), batch_size=1)


def test_single_batch_takes_no_fingerprints(three_rule_files, monkeypatch):
    monkeypatch.setattr(yara_scan, "_check_fingerprint", lambda *a: pytest.fail("fingerprinted"))
    evaluate(three_rule_files, lambda: SAMPLES, batch_size=64)


def test_batch_size_must_be_positive(three_rule_files):
    with pytest.raises(ValueError):
        evaluate(three_rule_files, lambda: SAMPLES, batch_size=0)


def test_rule_file_broken_after_loading(three_rule_files):
    Path(three_rule_files.sources["b.yar"]).write_text("rule B { condition: nope }")
    with pytest.raises(RuleLoadError, match="b.yar"):
        evaluate(three_rule_files, lambda: SAMPLES, batch_size=1)
