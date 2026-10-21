# triage

A small Python tool that mimics the file-scanning stage of a malware analysis
pipeline: hashes, magic-byte file type, entropy, IOCs from strings, and YARA matches.
It ships with a generator for a **synthetic, harmless** corpus. No real malware is used.

## Setup

Requires Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

Dependencies: `yara-python`, `tldextract` (used offline with its bundled Public
Suffix List; it never downloads), and `pytest` for tests. Exact runtime versions
are pinned in `requirements.lock`, which the container build uses.

## Usage

```bash
.venv/bin/python make_corpus.py --with-large       # writes corpus/good and corpus/bad
.venv/bin/triage scan corpus --rules rules --out results.jsonl
.venv/bin/triage test-rules --rules rules --good corpus/good --bad corpus/bad
```

`python -m triage ...` works too.

### `triage scan <dir> --rules <rules_dir> [--out results.jsonl]`

Walks `<dir>` recursively (sorted, without following symlinks) and writes one JSON
line per path (stdout if `--out` is omitted). A summary goes to stderr.

```json
{"path": "corpus/good/notes.txt", "status": "ok", "size": 246,
 "md5": "...", "sha256": "...", "file_type": "text", "entropy": 4.8525,
 "iocs": {"urls": ["http://example.com/docs"],
          "ips": [{"value": "1.2.3.4", "reason": "possible software version instead of real IPv4 address."},
                  {"value": "192.0.2.10"}],
          "domains": ["example.com", "setup.py"],
          "filenames": ["setup.py"]},
 "yara_matches": ["Triage_Noisy_Any_URL"], "scan_ms": 1.1}
```

- **file_type**: `pe`, `elf`, `zip`, `pdf`, `text`, `script` (shebang or script
  markers such as `<?php`, `@echo off`, `powershell`), or `unknown`. Detected from
  magic bytes only; the `file` command is not used.
- **entropy**: Shannon entropy in bits per byte (0 = one repeated byte, 8 = random).
- **iocs**: taken from printable ASCII and UTF-16LE strings (4+ chars).
  - `ips`: valid IPv4 only. A `reason` is added when the match looks like a version
    number (after `v`/`version`/`build`/…, or glued to a name like `openssl-1.1.1.4`).
  - `domains` / `filenames`: a `name.ext` token is a domain if `tldextract` finds a
    public suffix, otherwise a file name. When the suffix is also a common file
    extension (`setup.py`, `invoice.zip`, `run.sh`), it is listed in **both**. URL
    hosts always count as domains.
- **Skipped paths** still get a line, with `status: "skipped"`, a `skip_reason` code,
  and a human `reason`:

  | skip_reason | reason |
  |---|---|
  | `empty` | file is empty |
  | `too_large` | file is larger than the 50 MB limit (`--max-size-mb`) |
  | `permission_denied` | file is root protected |
  | `symlink` | symbolic link (not followed) |
  | `not_regular_file` | FIFO, socket or device; never opened, so the scan cannot hang |
  | `changed_during_scan` | file or directory was swapped (e.g. for a symlink) mid-scan; not followed |
  | `too_deep` | directory nested deeper than 64 levels; contents not scanned |
  | `vanished` / `read_error` | file disappeared or the OS refused the read |

  An unexpected exception while analysing one file produces `status: "error"` rather
  than stopping the scan.

### `triage test-rules --rules <rules_dir> --good <dir> --bad <dir> [--all] [--batch-size N]`

For each rule: hits on the bad set (detections), hits on the good set (false
positives), and average match time per sample. Rules that matched nothing are
summarised in one line unless `--all` is given.

Timing is measured **per rule file**, because YARA cannot time a single rule inside a
compiled set. Every rule in a file shows that file's time. For the single-rule
project files the time is exact.

Timing per file means each rule file is compiled on its own, at 4–19 MB each. To
bound memory, rule files are compiled `--batch-size` at a time (default 16), and the
samples are streamed through each batch. That is one pass over the samples per
batch.

| `--batch-size` | Peak memory (full `rules/`) | Passes over samples |
|---|---|---|
| 1 | 111 MB | 482 |
| 16 (default) | 281 MB | 31 |
| 64 | 861 MB | 8 |

Before batching, all ~480 files were held at once (1.19 GB peak). Use a lower value
on small machines, or a higher one for large sample sets to read them fewer times.

With more than one pass, the first pass records a SHA-256 of every sample, about
100 bytes per sample. If a later pass sees a sample that changed, appeared or
disappeared, `test-rules` stops with exit code 1 instead of reporting results that
mix two versions of the corpus.

## Running isolated (Podman)

The sandbox is defined in [docker-compose.yml](docker-compose.yml): no network,
read-only filesystem, samples mounted read-only, non-root user, capped resources.
`run_isolated.sh` runs it with `podman compose`, which delegates to docker-compose
or podman-compose (whichever podman is configured to use). The script:

1. Checks the paths.
2. Builds the image (cached builds take seconds, so the image always matches the
   source).
3. Runs `python -m triage.sandbox_check` in the same service, and refuses to scan
   unless every sandbox setting is in effect.
4. Runs the scan and writes the results file.

```bash
./run_isolated.sh corpus results.jsonl                 # scan with the rules in the image
./run_isolated.sh -r my_rules corpus results.jsonl     # your own rules, mounted read-only
./run_isolated.sh corpus results.jsonl -- --max-size-mb 10 --strict   # extra scan args
./run_isolated.sh --no-build corpus results.jsonl      # skip the build step
./run_isolated.sh --selinux-relabel corpus results.jsonl   # SELinux hosts (Fedora, RHEL)
```

The scan writes JSONL to the container's stdout, and the script saves it to the
output file on the host. The container therefore has no writable mount at all. If
the sandbox check or the scan fails, the output file is not created or overwritten.
Paths in the results start with `/samples/`, the mount point of the sample directory.

### Configuration

Every parameter is a `${VAR:-default}` placeholder in `docker-compose.yml`. Set it in
the environment or in a `.env` file next to the compose file (copy
[.env.example](.env.example)). The environment takes precedence.

| Variable | Default | Used for |
|---|---|---|
| `TRIAGE_IMAGE` | `triage:0.1.0` | image name and tag |
| `TRIAGE_PYTHON_IMAGE` | `docker.io/library/python:3.12-slim` | base image (build arg `PYTHON_IMAGE`); pin by digest for reproducible builds |
| `TRIAGE_UID` / `TRIAGE_GID` | `10001` | user the image is built for and the container runs as; 0 is rejected at build time |
| `TRIAGE_MEMORY` | `1g` | memory limit; swap limit is the same value, i.e. no swap |
| `TRIAGE_CPUS` | `2` | CPU limit |
| `TRIAGE_PIDS` | `64` | process limit |
| `TRIAGE_SAMPLES` | required | sample directory (absolute path); set by the script |
| `TRIAGE_RULES` | required by the overlay | rules directory for `docker-compose.rules.yml`; set by `-r` |
| `TRIAGE_SELINUX` | empty | `,Z` to relabel mounts on SELinux hosts; set by `--selinux-relabel` |

The compose provider is podman's own setting: `PODMAN_COMPOSE_PROVIDER`, or
`compose_providers` in `containers.conf`.

Files:
- `docker-compose.yml`: build arguments and every runtime setting.
- `docker-compose.rules.yml`: overlay that mounts `TRIAGE_RULES` read-only at `/rules`.
- `Dockerfile`: takes `PYTHON_IMAGE`, `TRIAGE_UID` and `TRIAGE_GID` as build arguments.

### Using compose directly

```bash
export TRIAGE_SAMPLES="$PWD/corpus"          # absolute path to an existing directory
podman compose build
podman compose run --rm -T --entrypoint python triage -m triage.sandbox_check
podman compose run --rm -T triage scan /samples --rules /opt/triage/rules --out - > results.jsonl

# with your own rules
TRIAGE_RULES="$PWD/my_rules" podman compose -f docker-compose.yml -f docker-compose.rules.yml \
  run --rm -T triage scan /samples --rules /rules --out - > results.jsonl
```

`-T` disables the pseudo-terminal so stdout carries only JSONL. Two cautions apply
when you skip the script:
- **Missing paths:** if `TRIAGE_SAMPLES` doesn't exist, both providers **create it on
  the host**, because compose's short volume syntax implies `create_host_path`. The
  script checks the paths first. The short syntax is kept because it is the only form
  that supports optional SELinux relabeling the same way in docker-compose and
  podman-compose.
- **Silently dropped settings:** with the podman-compose provider, `ipc` and
  `memswap_limit` are ignored (see below). Run `sandbox_check` before scanning.

### Compose providers

| Provider behind `podman compose` | What the script does | Result |
|---|---|---|
| docker-compose (v2.29.1 tested) | nothing extra | all settings honored |
| podman-compose (1.5.0 tested) | detects it and adds `--podman-run-args="--ipc=none --memory-swap=<memswap_limit>"` | 1.5.0 drops `ipc` and `memswap_limit` without warning; with the added args all checks pass |

Without the added arguments, podman-compose leaves `/dev/shm` writable and allows
1 GB of swap. `sandbox_check` catches both, and the script refuses to scan.

### The image

The image ([Dockerfile](Dockerfile)) is a two-stage build:
- The build stage installs only prebuilt wheels at the versions in
  `requirements.lock` (`--only-binary=:all:`), so no dependency's build script runs.
  It then removes `pip` and precompiles bytecode, so nothing needs writing at runtime.
- The runtime stage contains the Python base image, the virtualenv and the rules
  (owned by root), and runs as the numeric non-root user `TRIAGE_UID:TRIAGE_GID`. All
  setuid and setgid bits are removed (`su`, `passwd`, `mount`, …), so nothing in the
  image can raise privileges, even if `no-new-privileges` were missing at runtime.

### What each setting does

All settings below are in `docker-compose.yml`. `sandbox_check` verifies them from
inside the container before every scan: Podman 6.1.4 (rootless, cgroups v2, SELinux)
passes all 11 checks with both providers.

| Compose setting | Protects against |
|---|---|
| `network_mode: none` | The container has only a loopback interface. Content in a sample, or a compromised scanner, cannot download anything, reach a C2 server, or send sample data or results out. |
| `read_only: true` | The container's root filesystem is read-only. A compromised process cannot plant files, change the scanner or rules, or leave anything behind for a later run. Python bytecode is precompiled in the image, so nothing needs writing. |
| `tmpfs: /tmp, /var/tmp, /run` mounted `ro` | Podman mounts writable tmpfs on these paths for read-only containers, and compose has no setting to turn that off. Mounting empty, read-only tmpfs there first leaves nothing writable. |
| `ipc: none` | Gives the container its own IPC namespace with no `/dev/shm`, which Podman otherwise mounts writable. Removes the last scratch space and any shared-memory channel. |
| `volumes: …:/samples:ro` | The samples are visible but cannot be changed, deleted or encrypted. The original evidence stays intact. |
| `user: 10001:10001` (and `USER` in the image) | The scanner never runs as root, even if the image's `USER` is overridden. Root in a container is much closer to root on the host: it is the same UID unless user namespaces are used. |
| `cap_drop: [ALL]` | Removes every Linux capability (e.g. `CAP_CHOWN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`, `CAP_SYS_CHROOT`) from the default set. A compromised process cannot use them, which shrinks the kernel attack surface for escapes. |
| `security_opt: no-new-privileges:true` | Sets the kernel's `no_new_privs` flag. A setuid or setcap binary cannot raise privileges, so dropping root and capabilities cannot be undone. |
| `pids_limit: 64` | A fork bomb stops at 64 processes instead of exhausting the host's process table. |
| `mem_limit` + `memswap_limit` (equal) | Hard memory cap with no extra swap. A file crafted to blow up memory gets the container OOM-killed instead of starving the host. |
| `cpus: 2` | CPU cap. A regex or rule that runs away cannot monopolize the host. |
| `ulimits: core: 0` | No core dumps. A crash cannot write process memory, which holds sample bytes, through the host's `core_pattern` handler (e.g. systemd-coredump) to host storage. |
| `ulimits: nofile: 1024` | Bounds open file descriptors. The scanner needs about 70 at most (64 nested directories plus a few files). |
| `pull_policy: never` | Runs only the image you built locally. A typo or a registry entry named `triage` can never be pulled and run in its place. |
| `run --rm` | Removes the container after the run, so no stopped container with sample-derived state lingers. |
| `x-podman: in_pod: false` | podman-compose would otherwise put the container in a shared pod. docker-compose ignores `x-` keys. |

Podman also applies its default seccomp profile (restricts system calls) and
AppArmor/SELinux confinement where the host has it. Nothing here disables them.

### Podman notes

- **Rootless Podman** (the default) runs everything in a user namespace, so
  container UID 10001 maps to an unprivileged subordinate UID on the host. With
  rootful Podman, UID 10001 is UID 10001 on the host, which is still non-root.
- **macOS and Windows:** Podman runs containers inside a Linux VM (`podman machine`).
  The sample directory must be shared with that VM; on macOS `/Users` is shared by
  default.
- **File permissions:** the scanner runs as UID 10001, so it can read only files
  readable by "others" (e.g. mode 644). Other files are reported as skipped with
  `file is root protected`. To scan such files, make a world-readable copy.
- **macOS file-sharing quirk:** inside `podman machine`, an
  unreadable (e.g. mode 000) file may be reported as `vanished` or `read_error`
  instead of `permission_denied`. The VM's file-sharing layer (virtiofs) gives
  inconsistent errors for such files. The file is still skipped safely. Native
  Linux hosts report it correctly.
- **SELinux hosts** (Fedora, RHEL): the mount is denied unless relabeled. Pass
  `--selinux-relabel` (or set `TRIAGE_SELINUX=,Z`), which adds `:Z`. This **changes
  the SELinux label of the host files**, the only host-side change the script can
  make. Use it only where needed.
- **`docker-credential-desktop` not found** when building with the docker-compose
  provider: it reads `~/.docker/config.json`, which names a credential helper that is
  not installed (often left behind by an uninstalled Docker Desktop). Remove its
  `"credsStore"` line, or build with `DOCKER_CONFIG` pointing at a directory without it.
- **`Cannot connect to the Docker daemon`** with the docker-compose provider: a
  `DOCKER_HOST` set in your shell takes precedence over the socket `podman compose`
  would choose. Unset it, or point it at the machine's API socket:
  `export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"`.

### What the container does not protect against

- **Kernel exploits.** Containers share the host kernel. For real, untrusted malware,
  use a VM or a sandboxed runtime such as gVisor (`podman --runtime=runsc`).
- **Forged results.** The JSONL comes out of the sandbox. A compromised scanner
  could write misleading results, so treat the output as untrusted data.
- **Long runs.** There is no wall-clock timeout. YARA has a per-file timeout of 10
  seconds, but a huge sample directory can still take a long time.

## Security notes

The scanner assumes the files it scans are hostile:

- **No path tricks.** Directories are opened relative to their already-open parent
  with `O_NOFOLLOW`, and files relative to their directory (`openat`-style). Swapping
  a directory for a symlink mid-scan cannot make the scanner read outside the tree.
  Symlinks are never followed, so symlink loops are harmless.
- **Bounded resources.** Each file is read in 1 MB chunks up to the size limit.
  Archives are never extracted, so a zip bomb is scanned as its compressed bytes.
  `test-rules` streams samples and compiles rule files in batches, so memory does
  not grow with the corpus or the rule set.
- **Safe output.** JSONL output is escaped by `json.dumps`. Human-readable output
  escapes control, bidi and surrogate characters in file and rule names, so names
  cannot forge report lines, send terminal escape codes, or crash on non-UTF-8 names.

Known limitations (not fixed yet):

- No cap on IOCs per file. A 50 MB file of `name.ext` tokens yields a very large
  JSON line and takes tens of seconds.
- A file edited while it is being read is hashed as a mix of old and new bytes,
  and nothing flags it.
- Rule files may `include` other paths. Treat the rules directory as trusted.
- `--out` follows symlinks, and if it points inside the scanned directory it is
  scanned too.

## Rules

- `rules/marker.yar`: matches the harmless marker planted in every bad file. All
  detections, no false positives.
- `rules/fake_pe_injector.yar`: a PE naming `VirtualAlloc`, `WriteProcessMemory` and
  `CreateRemoteThread`. Hits `bad/dropper.exe` only.
- `rules/noisy_http.yar`: **deliberately noisy**, matches any `http(s)://`, so it
  produces false positives on `good/notes.txt` and `good/install.sh`.
- `rules/yara-rules/`: the community set from
  [Yara-Rules/rules](https://github.com/Yara-Rules/rules) (GPL-2.0, see its LICENSE),
  as a git submodule pinned to commit `0f93570194a80d2f2032869055808b0ddcdfb360`.

Rule files are found recursively under `--rules`. Two kinds are skipped:
- `*_index.yar` / `*index*.yar` files, which only `include` other files, so their
  rules would load twice.
- Anything inside a `deprecated/` directory: rules their authors retired, most of
  which no longer compile.

Clone with the submodule, and initialize only the top level. Yara-Rules has its own
submodule, `utils/yara-forensics`, whose rules would otherwise be loaded too:

```bash
git clone <this repo> && cd <repo>
git submodule update --init rules/yara-rules
```

Without the submodule, `rules/yara-rules/` is empty and the tool, and the container
image, run with only the three project rules. `tests/test_yara_scan.py` fails in
that case (it expects more than 1,000 rules), which flags the missing checkout.

Every rule file is compiled separately. A file that does not compile is skipped with
a warning (8 community files use YARA module fields removed in recent YARA releases).
Pass `--strict` to fail instead (exit code 2).

## Corpus

`make_corpus.py` writes, from a fixed seed:

- `corpus/good`: fake PE, fake ELF, a zip, a minimal PDF, a 64 KB random blob, a text
  file with planted URLs/IPs/version string, a shell script, an empty file, a
  `chmod 000` file, and (with `--with-large`) a 51 MB sparse file.
- `corpus/bad`: fake PE/ELF, a PowerShell-style script, a stored zip, a high-entropy
  blob, and a text file, each containing the marker `TRIAGE-SYNTHETIC-MARKER-7f3a`.

All network indicators use documentation-reserved names and ranges (`example.com`,
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). The script only overwrites an
output directory it created itself (marked by `.triage-corpus`).

## Tests

```bash
.venv/bin/python -m pytest
```

Each module has its own test file under `tests/`, and `test_cli.py` runs both
commands end to end on a generated corpus.

## Layout

```
make_corpus.py            synthetic corpus generator
run_isolated.sh           sandboxed scan with podman compose: build, verify, scan
docker-compose.yml        sandbox settings, limits and build arguments
docker-compose.rules.yml  overlay: mount your own rules read-only
.env.example              template for overriding compose parameters
Dockerfile                container image (non-root, pinned deps)
requirements.lock         exact runtime dependency versions
rules/                    YARA rules (3 project rules + yara-rules/ community set)
src/triage/hashing.py     md5, sha256, Shannon entropy
src/triage/filetype.py    magic-byte file type
src/triage/iocs.py        strings, URLs, IPv4, domains, file names
src/triage/yara_scan.py   rule loading, matching, per-rule evaluation
src/triage/scanner.py     directory walk, skip rules, per-file record
src/triage/cli.py         `scan` and `test-rules`
src/triage/sandbox_check.py  in-container check that the sandbox settings applied
tests/                    pytest suite
```
