"""Load YARA rules from a directory, match bytes, and measure per-rule results."""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import yara

RULE_SUFFIXES = (".yar", ".yara")
# Directories whose rules are never loaded. Yara-Rules keeps retired rules in
# deprecated/; most of them no longer compile with current YARA.
EXCLUDED_DIRS = frozenset({"deprecated"})
MATCH_TIMEOUT_S = 10
# Rule files compiled at once by evaluate(). Compiling one file on its own costs
# 4-19 MB (median ~9 MB, mostly fixed overhead, so a count is a fair proxy). Peak
# test-rules memory with the full rules/ dir: 111 MB at 1, 294 MB at 16, 861 MB at
# 64, versus 1.25 GB when all ~480 files were held at once. Each extra batch is one
# more pass over the samples.
DEFAULT_BATCH_SIZE = 16


class RuleLoadError(Exception):
    """No usable rules, or a broken rule file while loading in strict mode."""


class SampleSetChanged(Exception):
    """The samples differed between evaluate() passes, so results would mix contents."""


@dataclass
class RuleSet:
    root: Path
    combined: yara.Rules
    # namespace (rule file path relative to root) -> path, for every usable rule file
    sources: dict[str, str]
    # (namespace, compiler error) for each rule file that did not compile
    broken: list[tuple[str, str]] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return sum(1 for _ in self.combined)


def find_rule_files(rules_dir: Path) -> list[Path]:
    """All .yar/.yara files under `rules_dir`, sorted. Skipped: index files that
    only `include` other files (their rules would load twice), and anything below a
    directory named in EXCLUDED_DIRS (matched below `rules_dir` only)."""
    root = Path(rules_dir)
    return sorted(
        p for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in RULE_SUFFIXES
        and "index" not in p.stem.lower()
        and not EXCLUDED_DIRS.intersection(part.lower() for part in p.relative_to(root).parts[:-1])
    )


def load_rules(rules_dir: Path, strict: bool = False) -> RuleSet:
    """Compile every rule file under `rules_dir` into one set, each file in its own
    namespace.

    Each file is first compiled on its own (and discarded) to find broken ones.
    Files that fail are collected in `RuleSet.broken` and skipped, or raise
    RuleLoadError when `strict` is set.
    """
    root = Path(rules_dir)
    if not root.is_dir():
        raise RuleLoadError(f"rules directory not found: {root}")
    sources: dict[str, str] = {}
    broken: list[tuple[str, str]] = []
    for path in find_rule_files(root):
        namespace = path.relative_to(root).as_posix()
        try:
            yara.compile(filepath=str(path))
        except yara.Error as exc:
            if strict:
                raise RuleLoadError(f"{namespace}: {exc}") from exc
            broken.append((namespace, str(exc)))
            continue
        sources[namespace] = str(path)
    if not sources:
        raise RuleLoadError(f"no usable YARA rules in {root}")
    combined = yara.compile(filepaths=sources)
    return RuleSet(root=root, combined=combined, sources=sources, broken=broken)


def match(rules: yara.Rules, data: bytes, timeout: int = MATCH_TIMEOUT_S) -> tuple[list[str], str | None]:
    """Return (sorted unique matching rule names, error or None)."""
    try:
        matches = rules.match(data=data, timeout=timeout)
    except yara.TimeoutError:
        return [], f"yara timeout after {timeout}s"
    except yara.Error as exc:
        return [], f"yara error: {exc}"
    return sorted({m.rule for m in matches}), None


@dataclass
class RuleStats:
    rule: str
    rule_file: str
    detections: list[str] = field(default_factory=list)       # bad files hit
    false_positives: list[str] = field(default_factory=list)  # good files hit
    avg_match_us: float = 0.0  # mean time to match this rule's file against one sample


@dataclass
class Evaluation:
    stats: list[RuleStats]
    counts: Counter  # number of samples per group ("good", "bad")


Sample = tuple[str, str, bytes]  # (group "good"/"bad", name, data)


def evaluate(
    ruleset: RuleSet,
    samples: Callable[[], Iterable[Sample]],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> Evaluation:
    """Match every rule file separately against every sample.

    Rule files are compiled `batch_size` at a time; `samples()` is called once per
    batch and must stream the same samples each time. Memory is one batch of
    compiled rule files plus one sample, whatever the number of samples or rule
    files. With more than one batch, a SHA-256 of each sample is recorded on the
    first pass and checked on later ones; any difference raises SampleSetChanged.

    YARA cannot time a single rule inside a compiled set, so timing is measured
    per rule file and reported for each rule it contains.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    namespaces = list(ruleset.sources)
    batches = [namespaces[i:i + batch_size] for i in range(0, len(namespaces), batch_size)]
    fingerprints: dict[tuple[str, str], bytes] | None = {} if len(batches) > 1 else None
    counts: Counter = Counter()
    stats: list[RuleStats] = []
    for pass_no, batch in enumerate(batches):
        stats += _evaluate_batch(ruleset, batch, samples(), pass_no, fingerprints, counts)
    return Evaluation(stats, counts)


def _evaluate_batch(
    ruleset: RuleSet,
    batch: list[str],
    samples: Iterable[Sample],
    pass_no: int,
    fingerprints: dict[tuple[str, str], bytes] | None,
    counts: Counter,
) -> list[RuleStats]:
    """One pass over the samples with one batch of rule files. The compiled rules
    are local, so they are freed when this returns."""
    compiled: dict[str, yara.Rules] = {}
    for namespace in batch:
        try:
            compiled[namespace] = yara.compile(filepath=ruleset.sources[namespace])
        except yara.Error as exc:  # rule file changed since load_rules()
            raise RuleLoadError(f"{namespace}: {exc}") from exc
    by_file = {
        namespace: {r.identifier: RuleStats(r.identifier, namespace) for r in rules}
        for namespace, rules in compiled.items()
    }
    elapsed_ns = dict.fromkeys(compiled, 0)
    n_samples = 0
    for group, name, data in samples:
        n_samples += 1
        if pass_no == 0:
            counts[group] += 1
        if fingerprints is not None:
            _check_fingerprint(fingerprints, (group, name), data, pass_no)
        for namespace, rules in compiled.items():
            start = time.perf_counter_ns()
            names, _error = match(rules, data)
            elapsed_ns[namespace] += time.perf_counter_ns() - start
            for rule_name in names:
                target = by_file[namespace][rule_name]
                (target.detections if group == "bad" else target.false_positives).append(name)
    if pass_no > 0 and n_samples != sum(counts.values()):
        raise SampleSetChanged(
            f"{sum(counts.values()) - n_samples} sample(s) disappeared or became unreadable during evaluation"
        )

    stats: list[RuleStats] = []
    for namespace, by_rule in by_file.items():
        avg_us = elapsed_ns[namespace] / n_samples / 1000 if n_samples else 0.0
        for rule_stats in by_rule.values():
            rule_stats.avg_match_us = avg_us
            stats.append(rule_stats)
    return stats


def _check_fingerprint(
    fingerprints: dict[tuple[str, str], bytes], key: tuple[str, str], data: bytes, pass_no: int
) -> None:
    digest = hashlib.sha256(data).digest()
    if pass_no == 0:
        fingerprints[key] = digest
        return
    expected = fingerprints.get(key)
    if expected is None:
        raise SampleSetChanged(f"{key[0]} sample {key[1]!r} appeared during evaluation")
    if expected != digest:
        raise SampleSetChanged(f"{key[0]} sample {key[1]!r} changed during evaluation")
