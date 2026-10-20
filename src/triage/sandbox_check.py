"""Verify, from inside the container, that the sandbox settings actually applied.

Compose implementations differ in which settings they honour: podman-compose 1.5.0,
for example, silently drops `ipc` and `memswap_limit`. run_isolated.sh therefore
runs `python -m triage.sandbox_check` in the same service before every scan and
refuses to scan unless every check passes.

Exit code 0 when all checks pass, 1 otherwise. One line per check on stdout.
"""

from __future__ import annotations

import os
import resource
import sys
from dataclasses import dataclass
from pathlib import Path

# Kernel interfaces, not storage; their writability is governed by other controls.
_PSEUDO_FS_PREFIXES = ("/proc", "/sys")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def parse_status(text: str) -> dict[str, str]:
    """Parse /proc/self/status into {field: value}."""
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def parse_mount_points(text: str) -> list[str]:
    """Mount points from /proc/self/mounts (octal escapes such as \\040 decoded)."""
    points = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            points.append(parts[1].encode().decode("unicode_escape"))
    return points


def is_writable(path: str) -> bool:
    """True if this process could create files in `path`: neither a read-only
    mount nor denied by permissions. Nothing is written."""
    try:
        if os.statvfs(path).f_flag & os.ST_RDONLY:
            return False
    except OSError:
        return False
    return os.path.isdir(path) and os.access(path, os.W_OK)


def check_identity(uid: int, gid: int) -> Check:
    return Check("non-root user", uid != 0 and gid != 0, f"uid={uid} gid={gid}")


def check_capabilities(status: dict[str, str]) -> Check:
    sets = {k: status.get(k, "?") for k in ("CapEff", "CapPrm", "CapBnd")}
    ok = all(v.strip("0") == "" and v != "?" for v in sets.values())
    return Check("no capabilities", ok, " ".join(f"{k}={v}" for k, v in sets.items()))


def check_no_new_privs(status: dict[str, str]) -> Check:
    value = status.get("NoNewPrivs", "?")
    return Check("no-new-privileges", value == "1", f"NoNewPrivs={value}")


def check_seccomp(status: dict[str, str]) -> Check:
    value = status.get("Seccomp", "?")
    return Check("seccomp filter", value == "2", f"Seccomp={value} (2 = filter)")


def check_network(interfaces: list[str]) -> Check:
    return Check("no network", sorted(interfaces) == ["lo"], f"interfaces={sorted(interfaces)}")


def check_no_writable_mounts(mount_points: list[str], writable=is_writable) -> Check:
    candidates = sorted({m for m in mount_points if not m.startswith(_PSEUDO_FS_PREFIXES)})
    found = [m for m in candidates if writable(m)]
    return Check(
        "no writable mounts", not found,
        f"writable: {found}" if found else f"{len(candidates)} mount points, none writable",
    )


def check_no_shm(shm_exists: bool, shm_writable: bool) -> Check:
    ok = not shm_exists or not shm_writable
    return Check("no /dev/shm", ok, "absent" if not shm_exists else ("read-only" if ok else "writable"))


def check_cgroup_limits(cgroup: dict[str, str | None]) -> list[Check]:
    """cgroup v2 files; None means the file is missing (e.g. cgroup v1 host)."""
    def limited(name: str) -> Check:
        value = cgroup.get(name)
        return Check(f"{name} set", value not in (None, "max"), f"{name}={value}")

    swap = cgroup.get("memory.swap.max")
    return [
        limited("memory.max"),
        limited("pids.max"),
        Check("no swap", swap == "0", f"memory.swap.max={swap}"),
    ]


def check_core_dumps(core_limit: tuple[int, int]) -> Check:
    return Check("no core dumps", core_limit == (0, 0), f"RLIMIT_CORE={core_limit}")


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def run_checks() -> list[Check]:
    status = parse_status(_read("/proc/self/status") or "")
    mounts = parse_mount_points(_read("/proc/self/mounts") or "")
    try:
        interfaces = os.listdir("/sys/class/net")
    except OSError:
        interfaces = []
    cgroup = {name: _read(f"/sys/fs/cgroup/{name}") for name in ("memory.max", "memory.swap.max", "pids.max")}
    return [
        check_identity(os.getuid(), os.getgid()),
        check_capabilities(status),
        check_no_new_privs(status),
        check_seccomp(status),
        check_network(interfaces),
        check_no_writable_mounts(mounts),
        check_no_shm(os.path.exists("/dev/shm"), is_writable("/dev/shm")),
        *check_cgroup_limits(cgroup),
        check_core_dumps(resource.getrlimit(resource.RLIMIT_CORE)),
    ]


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("sandbox_check: not running on Linux; nothing to verify", file=sys.stderr)
        return 1
    checks = run_checks()
    for c in checks:
        print(f"{'ok  ' if c.ok else 'FAIL'}  {c.name}: {c.detail}")
    return 0 if all(c.ok for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
