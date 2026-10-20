"""Command line: `triage scan` and `triage test-rules`."""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import unicodedata
from collections import Counter
from typing import Iterable, Iterator, TextIO

from triage import scanner, yara_scan

EXIT_OK, EXIT_FAILURE, EXIT_USAGE = 0, 1, 2


# Control (Cc), format (Cf, e.g. bidi overrides), surrogate (Cs) and line/paragraph
# separator (Zl, Zp) characters must never reach the terminal raw.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def safe_text(text: str) -> str:
    """Escape characters in untrusted text (file names, rule paths) so it cannot
    break lines, drive the terminal, or fail to encode as UTF-8."""
    out = []
    for ch in text:
        if unicodedata.category(ch) not in _UNSAFE_CATEGORIES:
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _load_rules(args) -> yara_scan.RuleSet | None:
    try:
        ruleset = yara_scan.load_rules(args.rules, strict=args.strict)
    except yara_scan.RuleLoadError as exc:
        _err(f"error: {safe_text(str(exc))}")
        return None
    for namespace, error in ruleset.broken:
        _err(f"warning: skipped rule file {safe_text(namespace)}: {safe_text(error)}")
    _err(
        f"rules: {ruleset.rule_count} rules from {len(ruleset.sources)} files"
        + (f" ({len(ruleset.broken)} files skipped, see warnings)" if ruleset.broken else "")
    )
    return ruleset


def _check_dir(path: str, label: str) -> bool:
    if not os.path.isdir(path):
        _err(f"error: {label} is not a directory: {safe_text(path)}")
        return False
    return True


def cmd_scan(args) -> int:
    if not _check_dir(args.dir, "scan target"):
        return EXIT_USAGE
    ruleset = _load_rules(args)
    if ruleset is None:
        return EXIT_USAGE
    max_size = int(args.max_size_mb * scanner.MB)
    status = Counter()
    matched = 0
    out: TextIO = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    try:
        for record in scanner.scan_tree(args.dir, ruleset, max_size):
            out.write(json.dumps(record) + "\n")
            status[record["status"]] += 1
            matched += bool(record.get("yara_matches"))
    finally:
        if out is not sys.stdout:
            out.close()
    _err(
        f"scanned {sum(status.values())} paths: {status['ok']} ok, {status['skipped']} skipped, "
        f"{status['error']} errors; {matched} with YARA matches"
        + ("" if args.out == "-" else f" -> {args.out}")
    )
    return EXIT_OK


def format_report(stats: list[yara_scan.RuleStats], n_good: int, n_bad: int, show_all: bool) -> str:
    def hits(s: yara_scan.RuleStats) -> int:
        return len(s.detections) + len(s.false_positives)

    rows = sorted(stats, key=lambda s: (-len(s.false_positives), -len(s.detections), s.rule.lower()))
    shown = rows if show_all else [s for s in rows if hits(s)]
    headers = ("RULE", "RULE FILE", "DETECTIONS", "FALSE POS", "AVG MATCH")
    table = [
        (
            safe_text(s.rule),
            safe_text(s.rule_file),
            f"{len(s.detections)}/{n_bad}",
            f"{len(s.false_positives)}/{n_good}",
            f"{s.avg_match_us:.1f} µs",
        )
        for s in shown
    ]
    widths = [max(len(h), *(len(row[i]) for row in table)) if table else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in table:
        lines.append("  ".join(
            cell.rjust(w) if i >= 2 else cell.ljust(w) for i, (cell, w) in enumerate(zip(row, widths))
        ).rstrip())
    silent = len(rows) - len(shown)
    if silent:
        lines.append(f"... {silent} more rules matched nothing (use --all to list them)")

    noisy = [s for s in shown if s.false_positives]
    if noisy:
        lines += ["", "False positives:"]
        lines += [
            f"  {safe_text(s.rule)}: {', '.join(safe_text(n) for n in sorted(s.false_positives))}"
            for s in noisy
        ]
    lines += ["", "AVG MATCH is per sample, measured per rule file (shared by all rules in that file)."]
    return "\n".join(lines)


def _samples(root: str, group: str, max_size: int, report_skips: bool) -> Iterator[yara_scan.Sample]:
    """Stream (group, name relative to root, data), optionally reporting skipped files."""
    for path, data, skip in scanner.iter_samples(root, max_size):
        if skip is not None:
            if report_skips:
                _err(f"skipped sample {safe_text(path)}: {safe_text(skip['reason'])}")
            continue
        yield group, os.path.relpath(path, root), data


def cmd_test_rules(args) -> int:
    if not (_check_dir(args.good, "--good") and _check_dir(args.bad, "--bad")):
        return EXIT_USAGE
    ruleset = _load_rules(args)
    if ruleset is None:
        return EXIT_USAGE
    max_size = int(args.max_size_mb * scanner.MB)
    passes = 0

    def samples() -> Iterable[yara_scan.Sample]:
        # Called once per batch of rule files; report skipped files only once.
        nonlocal passes
        passes += 1
        return itertools.chain(
            _samples(args.good, "good", max_size, report_skips=passes == 1),
            _samples(args.bad, "bad", max_size, report_skips=passes == 1),
        )

    try:
        result = yara_scan.evaluate(ruleset, samples, batch_size=args.batch_size)
    except yara_scan.SampleSetChanged as exc:
        _err(f"error: {safe_text(str(exc))}; results would be inconsistent, rerun on a stable corpus")
        return EXIT_FAILURE
    except yara_scan.RuleLoadError as exc:
        _err(f"error: rule file changed during evaluation: {safe_text(str(exc))}")
        return EXIT_FAILURE
    counts = result.counts
    _err(f"samples: {counts['good']} good, {counts['bad']} bad ({passes} pass{'es' if passes != 1 else ''})")
    print(format_report(result.stats, counts["good"], counts["bad"], args.all))
    return EXIT_OK


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage", description="Toy malware-triage file scanner.")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--rules", required=True, help="directory of .yar/.yara files (searched recursively)")
        p.add_argument("--strict", action="store_true", help="fail if any rule file does not compile")
        p.add_argument(
            "--max-size-mb", type=float, default=scanner.MAX_FILE_SIZE / scanner.MB,
            help="skip files larger than this (default: 50)",
        )

    scan = sub.add_parser("scan", help="scan a directory and write one JSON line per file")
    scan.add_argument("dir", help="directory to scan")
    scan.add_argument("--out", default="-", help="output .jsonl file (default: stdout)")
    common(scan)
    scan.set_defaults(func=cmd_scan)

    test = sub.add_parser("test-rules", help="measure detections and false positives per rule")
    test.add_argument("--good", required=True, help="directory of known-good samples")
    test.add_argument("--bad", required=True, help="directory of known-bad samples")
    test.add_argument("--all", action="store_true", help="also list rules that matched nothing")
    test.add_argument(
        "--batch-size", type=_positive_int, default=yara_scan.DEFAULT_BATCH_SIZE,
        help=f"rule files compiled at once (default: {yara_scan.DEFAULT_BATCH_SIZE}; ~5-20 MB each); "
             "lower uses less memory but reads the samples once more per batch",
    )
    common(test)
    test.set_defaults(func=cmd_test_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
