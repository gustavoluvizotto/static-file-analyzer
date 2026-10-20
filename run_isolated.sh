#!/usr/bin/env bash
# Run `triage scan` on a sample directory inside the sandbox defined in
# docker-compose.yml.
#
#   ./run_isolated.sh [options] <sample_dir> <output.jsonl> [-- extra `triage scan` args]
#
# Requires a compose tool: `docker compose` for docker, `podman compose` for podman
# (backed by docker-compose or podman-compose).
#
# Options:
#   -e, --engine docker|podman  container engine (default: $CONTAINER_ENGINE, else docker)
#   -r, --rules DIR             scan with this rules directory, mounted read-only by
#                               docker-compose.rules.yml, instead of the image's rules
#       --no-build              do not (re)build the image first
#       --selinux-relabel       relabel mounts for SELinux hosts (TRIAGE_SELINUX=,Z)
#       --dry-run               print the compose commands instead of running them
#   -h, --help                  show this help
#
# Sandbox settings, resource limits and build arguments live in docker-compose.yml.
# Override them with TRIAGE_* environment variables or a .env file next to it (see
# .env.example). TRIAGE_COMPOSE overrides the compose command, e.g. "docker-compose"
# or "podman-compose".
#
# Before scanning, `python -m triage.sandbox_check` runs in the same service and the
# scan is refused unless every sandbox setting is in effect. The scan's JSONL goes to
# the container's stdout and is written to <output.jsonl> by this script, so the
# container needs no writable mount. Paths in the output start with /samples/.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SERVICE=triage

die() { echo "run_isolated.sh: $*" >&2; exit 2; }
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"; }

engine="${CONTAINER_ENGINE:-docker}"
rules=""
build=1
dry_run=0
positional=()
while (($#)); do
  case "$1" in
    -e|--engine) [[ $# -ge 2 ]] || die "$1 needs a value"; engine="$2"; shift 2 ;;
    -r|--rules) [[ $# -ge 2 ]] || die "$1 needs a value"; rules="$2"; shift 2 ;;
    --no-build) build=0; shift ;;
    --selinux-relabel) export TRIAGE_SELINUX=",Z"; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown option: $1 (try --help)" ;;
    *) positional+=("$1"); shift ;;
  esac
done
extra_args=("$@")
[[ ${#positional[@]} -eq 2 ]] || { usage >&2; exit 2; }

case "$engine" in docker|podman) ;; *) die "engine must be docker or podman, got: $engine" ;; esac

export PODMAN_COMPOSE_WARNING_LOGS=false
if [[ -n "${TRIAGE_COMPOSE:-}" ]]; then
  read -r -a compose <<<"$TRIAGE_COMPOSE"
else
  compose=("$engine" compose)
fi

# podman-compose (1.5.0) silently ignores `ipc` and `memswap_limit`. Detect it,
# whether called directly or as the provider behind `podman compose`, so the two
# settings can be passed as podman run arguments below.
uses_podman_compose=0
if [[ "$(basename "${compose[0]}")" == podman-compose ]]; then
  uses_podman_compose=1
elif [[ "${compose[*]}" == "podman compose" ]] && podman compose version 2>/dev/null | grep -q podman-compose; then
  uses_podman_compose=1
fi

# Absolute, symlink-free host path, refusing characters that would change the
# meaning of a short-syntax volume (':' separates fields, ',' separates options).
# Checking existence here also stops Docker from creating a missing source dir.
host_dir() {
  [[ -d "$1" ]] || die "not a directory: $1"
  local abs
  abs="$(cd "$1" && pwd -P)"
  [[ "$abs" != *[:,]* ]] || die "path may not contain ':' or ',': $abs"
  printf '%s\n' "$abs"
}

export TRIAGE_SAMPLES
TRIAGE_SAMPLES="$(host_dir "${positional[0]}")"
output="${positional[1]}"
[[ -d "$(dirname "$output")" ]] || die "output directory does not exist: $(dirname "$output")"

files=(-f "$HERE/docker-compose.yml")
rules_in_container=/opt/triage/rules
if [[ -n "$rules" ]]; then
  export TRIAGE_RULES
  TRIAGE_RULES="$(host_dir "$rules")"
  files+=(-f "$HERE/docker-compose.rules.yml")
  rules_in_container=/rules
fi

# For podman-compose, take the swap limit from the resolved compose config so the
# value is defined only in docker-compose.yml.
global_args=()
if ((uses_podman_compose)); then
  swap="$("${compose[@]}" "${files[@]}" config 2>/dev/null | sed -n 's/^ *memswap_limit: *//p' | head -1)" || true
  [[ -n "$swap" ]] || die "could not read memswap_limit from the compose config"
  global_args=(--podman-run-args="--ipc=none --memory-swap=$swap")
fi

base=("${compose[@]}" ${global_args[@]+"${global_args[@]}"} "${files[@]}")
build_cmd=("${base[@]}" build)
check_cmd=("${base[@]}" run --rm -T --entrypoint python "$SERVICE" -m triage.sandbox_check)
scan_cmd=("${base[@]}" run --rm -T "$SERVICE" scan /samples --rules "$rules_in_container" --out -
          ${extra_args[@]+"${extra_args[@]}"})

if ((dry_run)); then
  for var in TRIAGE_SAMPLES TRIAGE_RULES TRIAGE_SELINUX; do
    if [[ -n "${!var:-}" ]]; then printf 'export %s=%q\n' "$var" "${!var}"; fi
  done
  if ((build)); then printf '%q ' "${build_cmd[@]}"; echo; fi
  printf '%q ' "${check_cmd[@]}"; echo
  printf '%q ' "${scan_cmd[@]}"; printf '> %q\n' "$output"
  exit 0
fi

if ((build)); then
  echo "building image with ${compose[*]} ..." >&2
  "${build_cmd[@]}" >&2
fi

echo "verifying sandbox ..." >&2
if ! "${check_cmd[@]}" >&2; then
  echo "run_isolated.sh: sandbox check failed; refusing to scan" >&2
  exit 1
fi

# Write to a temporary file next to the output and move it into place only on
# success, so a failed scan never leaves a truncated results file behind.
tmp="$(mktemp "$output.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
status=0
"${scan_cmd[@]}" >"$tmp" || status=$?
if ((status != 0)); then
  echo "run_isolated.sh: scan failed with exit code $status; $output not written" >&2
  exit "$status"
fi
mv "$tmp" "$output"
trap - EXIT
echo "results written to $output" >&2
