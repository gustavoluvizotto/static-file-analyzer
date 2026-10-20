import sys

import pytest

from triage import sandbox_check as sc

STATUS = """Name:\tpython
Uid:\t10001\t10001\t10001\t10001
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
NoNewPrivs:\t1
Seccomp:\t2
"""

MOUNTS = """overlay / overlay ro,relatime 0 0
proc /proc proc rw,nosuid 0 0
tmpfs /dev tmpfs ro,nosuid 0 0
virtiofs /samples virtiofs ro 0 0
tmpfs /with\\040space tmpfs ro 0 0
"""


def test_parse_status():
    status = sc.parse_status(STATUS)
    assert status["CapEff"] == "0000000000000000"
    assert status["NoNewPrivs"] == "1"


def test_parse_mount_points_decodes_octal_escapes():
    assert sc.parse_mount_points(MOUNTS) == ["/", "/proc", "/dev", "/samples", "/with space"]


def test_all_status_checks_pass_on_locked_down_status():
    status = sc.parse_status(STATUS)
    for check in (sc.check_capabilities(status), sc.check_no_new_privs(status), sc.check_seccomp(status)):
        assert check.ok, check


@pytest.mark.parametrize(
    "field, value, check",
    [
        ("CapEff", "00000000a80425fb", sc.check_capabilities),
        ("CapBnd", "00000000a80425fb", sc.check_capabilities),
        ("NoNewPrivs", "0", sc.check_no_new_privs),
        ("Seccomp", "0", sc.check_seccomp),
    ],
)
def test_status_checks_fail_when_setting_missing(field, value, check):
    status = sc.parse_status(STATUS)
    status[field] = value
    assert not check(status).ok


def test_missing_status_fields_fail_closed():
    assert not sc.check_capabilities({}).ok
    assert not sc.check_no_new_privs({}).ok
    assert not sc.check_seccomp({}).ok


@pytest.mark.parametrize("uid, gid, ok", [(10001, 10001, True), (0, 10001, False), (10001, 0, False)])
def test_identity(uid, gid, ok):
    assert sc.check_identity(uid, gid).ok is ok


@pytest.mark.parametrize("interfaces, ok", [(["lo"], True), (["lo", "eth0"], False), ([], False)])
def test_network(interfaces, ok):
    assert sc.check_network(interfaces).ok is ok


def test_writable_mount_detected_and_pseudo_fs_ignored():
    points = sc.parse_mount_points(MOUNTS) + ["/tmp"]
    check = sc.check_no_writable_mounts(points, writable=lambda m: m in ("/tmp", "/proc"))
    assert not check.ok and "/tmp" in check.detail and "/proc" not in check.detail
    assert sc.check_no_writable_mounts(points, writable=lambda m: False).ok


@pytest.mark.parametrize("exists, writable, ok", [(False, False, True), (True, False, True), (True, True, False)])
def test_shm(exists, writable, ok):
    assert sc.check_no_shm(exists, writable).ok is ok


def test_cgroup_limits():
    good = {"memory.max": "1073741824", "memory.swap.max": "0", "pids.max": "64"}
    assert all(c.ok for c in sc.check_cgroup_limits(good))
    for key, bad in [("memory.max", "max"), ("pids.max", "max"), ("memory.swap.max", "1073741824"),
                     ("memory.max", None), ("memory.swap.max", None)]:
        checks = sc.check_cgroup_limits({**good, key: bad})
        assert not all(c.ok for c in checks), (key, bad)


def test_core_dumps():
    assert sc.check_core_dumps((0, 0)).ok
    assert not sc.check_core_dumps((0, -1)).ok


def test_is_writable_on_real_paths(tmp_path):
    assert sc.is_writable(str(tmp_path))
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    try:
        assert not sc.is_writable(str(locked)) or sc.os.geteuid() == 0
    finally:
        locked.chmod(0o700)
    assert not sc.is_writable(str(tmp_path / "missing"))


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="only meaningful outside Linux")
def test_main_refuses_to_pass_outside_linux(capsys):
    assert sc.main() == 1
