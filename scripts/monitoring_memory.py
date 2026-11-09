"""Read-only, identity-checked resident memory for the manager's owned tree."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import subprocess
from typing import Callable, Mapping

MAX_PROCESS_ROWS = 1024
MAX_CENSUS_BYTES = 48 * 1024
MAX_TREE_PROCESSES = 128
MAX_RSS_BYTES = 2**63 - 1


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    ppid: int
    uid: int
    seconds: int
    microseconds: int
    path: str


class _RusageInfoV0(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64)
        for name in (
            "user_time", "system_time", "pkg_idle_wakeups", "interrupt_wakeups",
            "pageins", "wired_size", "resident_size", "physical_footprint",
            "start_abstime", "exit_abstime",
        )
    ]


def _reader() -> Callable[[int], int]:
    if os.uname().sysname != "Darwin":
        raise OSError("unsupported")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_pid_rusage
    function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    function.restype = ctypes.c_int

    def resident_bytes(pid: int) -> int:
        value = _RusageInfoV0()
        pointer = ctypes.cast(ctypes.byref(value), ctypes.POINTER(ctypes.c_void_p))
        if function(pid, 0, pointer) != 0 or value.exit_abstime != 0 or value.start_abstime == 0:
            raise OSError("unavailable")
        if value.resident_size > MAX_RSS_BYTES:
            raise OSError("overflow")
        return int(value.resident_size)

    return resident_bytes


def _process_output() -> str:
    process = subprocess.Popen(["/bin/ps", "-axo", "pid=,ppid="],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        raw = process.stdout.read(MAX_CENSUS_BYTES + 1)
        if len(raw) > MAX_CENSUS_BYTES:
            process.kill()
            process.wait(timeout=2)
            raise OSError("census")
        if process.wait(timeout=5) != 0:
            raise OSError("census")
        return raw.decode("ascii", errors="strict")
    except Exception:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        raise
def process_census() -> dict[int, int]:
    output = _process_output()
    rows: dict[int, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2:
            raise OSError("census")
        pid, ppid = map(int, parts)
        if pid < 1 or ppid < 0 or pid in rows:
            raise OSError("census")
        rows[pid] = ppid
        if len(rows) > MAX_PROCESS_ROWS:
            raise OSError("census")
    return rows


def descendant_pids(process_rows: Mapping[int, int], root_pid: int) -> tuple[int, ...]:
    if root_pid not in process_rows:
        raise OSError("root")
    children: dict[int, list[int]] = {}
    for pid, ppid in process_rows.items():
        children.setdefault(ppid, []).append(pid)
    result: list[int] = []
    pending = list(children.get(root_pid, ()))
    visited = {root_pid}
    while pending:
        pid = pending.pop()
        if pid in visited:
            raise OSError("cycle")
        visited.add(pid)
        result.append(pid)
        if len(result) > MAX_TREE_PROCESSES:
            raise OSError("tree")
        pending.extend(children.get(pid, ()))
    return tuple(sorted(result))


def _unavailable() -> dict[str, object]:
    return {
        "status": "UNAVAILABLE",
        "managerRssBytes": None,
        "ownedDescendantTreeRssBytes": None,
        "summedOwnedRssBytes": None,
        "ownedDescendantProcessCount": None,
        "measurement": "summed-resident-bytes-not-unique-physical-ram",
    }


def sample_owned_tree(
    manager: ProcessIdentity,
    *,
    launcher_identity: ProcessIdentity,
    identity,
    process_rows: Mapping[int, int],
    process_rows_after: Mapping[int, int] | None = None,
    census_reader: Callable[[], Mapping[int, int]] | None = None,
    usage_reader: Callable[[int], int],
    uid: int,
) -> dict[str, object]:
    """Sample a manager and all census-proven descendants, or discard all values."""
    try:
        if (manager.uid != uid or launcher_identity.uid != uid or manager.ppid != launcher_identity.pid
                or process_rows.get(manager.pid) != launcher_identity.pid
                or process_rows.get(launcher_identity.pid) is None):
            return _unavailable()
        descendants = descendant_pids(process_rows, manager.pid)
        roots = (launcher_identity, manager)
        before_roots = tuple(identity.process(value.pid) for value in roots)
        if before_roots != roots:
            return _unavailable()

        descendants_before = []
        for pid in descendants:
            value = identity.process(pid)
            if value.pid != pid or value.uid != uid or process_rows.get(pid) != value.ppid:
                return _unavailable()
            descendants_before.append(value)

        manager_rss = usage_reader(manager.pid)
        tree_rss_values = [usage_reader(value.pid) for value in descendants_before]
        if any(type(value) is not int or value < 0 or value > MAX_RSS_BYTES
               for value in [manager_rss, *tree_rss_values]):
            return _unavailable()

        if census_reader is not None:
            process_rows_after = census_reader()
        descendants_after = tuple(identity.process(value.pid) for value in descendants_before)
        roots_after = tuple(identity.process(value.pid) for value in roots)
        if descendants_after != tuple(descendants_before) or roots_after != roots:
            return _unavailable()
        if process_rows_after is not None and (
                process_rows_after.get(manager.pid) != launcher_identity.pid
                or descendant_pids(process_rows_after, manager.pid) != descendants):
            return _unavailable()
        tree_rss = sum(tree_rss_values)
        total = manager_rss + tree_rss
        if max(tree_rss, total) > MAX_RSS_BYTES:
            return _unavailable()
        return {
            "status": "AVAILABLE",
            "managerRssBytes": manager_rss,
            "ownedDescendantTreeRssBytes": tree_rss,
            "summedOwnedRssBytes": total,
            "ownedDescendantProcessCount": len(descendants),
            "measurement": "summed-resident-bytes-not-unique-physical-ram",
        }
    except Exception:
        return _unavailable()


def sample_owned_memory(context, service_identity) -> dict[str, object]:
    """Use the native process identity and a bounded ps census around RSS reads."""
    try:
        from owner_watch import NativeIdentity

        native = NativeIdentity()
        manager = service_identity.manager
        launcher = service_identity.launcher
        rows = process_census()
        return sample_owned_tree(
            manager,
            launcher_identity=launcher,
            identity=native,
            process_rows=rows,
            usage_reader=_reader(),
            uid=os.getuid(),
            census_reader=process_census,
        )
    except Exception:
        return _unavailable()
