#!/usr/bin/env bash
# Run `triage scan` on a sample directory inside the Podman sandbox defined in
# docker-compose.yml.
#
#   ./run_isolated.sh [options] <sample_dir> <output.jsonl> [-- extra `triage scan` args]
#
# Options:
#   -r, --rules DIR        scan with this rules directory (mounted read-only by
#                          docker-compose.rules.yml) instead of the image's rules
#       --no-build         do not rebuild the image first
#       --selinux-relabel  relabel the mounts on SELinux hosts (TRIAGE_SELINUX=,Z)
#   -h, --help             show this help
#
# Runs `podman compose`, with docker-compose or podman-compose as its provider.
# Sandbox settings, limits and build arguments live in docker-compose.yml; override
# them with TRIAGE_* environment variables or a .env file (see .env.example).
#
# Before scanning, `python -m triage.sandbox_check` runs in the same service, and the
# scan is refused unless every sandbox setting is in effect. Results go to the
# container's stdout and are written to <output.jsonl> only if the scan succeeds.
# Paths in the output start with /samples/.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

die() { echo "run_isolated.sh: $*" >&2; exit 2; }
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"; }

# Absolute, symlink-free path of an existing directory. ':' and ',' are refused
# because they would change the meaning of a short-syntax volume spec.
host_dir() {
  [[ -d "$1" ]] || die "not a directory: $1"
  local abs
  abs="$(cd "$1" && pwd -P)"
  [[ "$abs" != *[:,]* ]] || die "path may not contain ':' or ',': $abs"
  printf '%s\n' "$abs"
}

rules=""
build=1
positional=()
while (($#)); do
  case "$1" in
    -r|--rules) [[ $# -ge 2 ]] || die "$1 needs a value"; rules="$2"; shift 2 ;;
    --no-build) build=0; shift ;;
    --selinux-relabel) export TRIAGE_SELINUX=",Z"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown option: $1 (try --help)" ;;
    *) positional+=("$1"); shift ;;
  esac
done
[[ ${#positional[@]} -eq 2 ]] || { usage >&2; exit 2; }

export TRIAGE_SAMPLES PODMAN_COMPOSE_WARNING_LOGS=false
TRIAGE_SAMPLES="$(host_dir "${positional[0]}")"
output="${positional[1]}"
[[ -d "$(dirname "$output")" ]] || die "output directory does not exist: $(dirname "$output")"

compose=(podman compose -f "$HERE/docker-compose.yml")
rules_in_container=/opt/triage/rules
if [[ -n "$rules" ]]; then
  export TRIAGE_RULES
  TRIAGE_RULES="$(host_dir "$rules")"
  compose+=(-f "$HERE/docker-compose.rules.yml")
  rules_in_container=/rules
fi

# podman-compose (1.5.0) silently ignores `ipc` and `memswap_limit`. When it is the
# provider, pass both as podman run arguments, reading the swap limit from the
# resolved config so that it is defined only in docker-compose.yml.
if podman compose version 2>/dev/null | grep -q podman-compose; then
  swap="$("${compose[@]}" config 2>/dev/null | awk '/^ *memswap_limit:/ {v = $2} END {print v}')" || true
  [[ -n "$swap" ]] || die "could not read memswap_limit from the compose config"
  compose+=(--podman-run-args="--ipc=none --memory-swap=$swap")
fi

if ((build)); then
  echo "building image ..." >&2
  "${compose[@]}" build >&2
fi

echo "verifying sandbox ..." >&2
"${compose[@]}" run --rm -T --entrypoint python triage -m triage.sandbox_check >&2 \
  || { echo "run_isolated.sh: sandbox check failed; refusing to scan" >&2; exit 1; }

# Write to a temporary file next to the output and move it into place only on
# success, so a failed scan never leaves a truncated results file behind.
tmp="$(mktemp "$output.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
"${compose[@]}" run --rm -T triage scan /samples --rules "$rules_in_container" --out - ${@+"$@"} >"$tmp" \
  || { status=$?; echo "run_isolated.sh: scan failed with exit code $status; $output not written" >&2; exit "$status"; }
mv "$tmp" "$output"
trap - EXIT
echo "results written to $output" >&2
