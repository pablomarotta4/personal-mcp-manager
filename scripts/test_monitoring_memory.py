"""Identity-race and tree-bound checks for owned RSS sampling."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


def identity(pid, ppid, path, *, uid=501, seconds=10):
    return SimpleNamespace(pid=pid, ppid=ppid, uid=uid, seconds=seconds,
                           microseconds=pid, path=path, status=0)


class MonitoringMemoryTests(unittest.TestCase):
    def test_samples_manager_and_verified_descendant_tree_separately(self):
        import monitoring_memory

        manager = identity(100, 50, "/synthetic/node")
        launcher = identity(50, 1, "/synthetic/python")
        children = {
            101: identity(101, 100, "/synthetic/backend-one"),
            102: identity(102, 101, "/synthetic/backend-two"),
        }
        identities = {100: manager, 50: launcher, **children}
        probe = SimpleNamespace(process=Mock(side_effect=lambda pid: identities[pid]))
        result = monitoring_memory.sample_owned_tree(
            manager,
            launcher_identity=launcher,
            identity=probe,
            process_rows={1: 0, 50: 1, 100: 50, 101: 100, 102: 101},
            usage_reader=lambda pid: {100: 1000, 101: 1500, 102: 2000}[pid],
            uid=501,
        )

        self.assertEqual(result["status"], "AVAILABLE")
        self.assertEqual(result["managerRssBytes"], 1000)
        self.assertEqual(result["ownedDescendantTreeRssBytes"], 3500)
        self.assertEqual(result["summedOwnedRssBytes"], 4500)
        self.assertEqual(result["measurement"], "summed-resident-bytes-not-unique-physical-ram")

    def test_identity_change_or_unproven_parent_discards_the_whole_sample(self):
        import monitoring_memory

        manager = identity(100, 50, "/synthetic/node")
        changed = identity(100, 50, "/synthetic/other-node", seconds=11)
        launcher = identity(50, 1, "/synthetic/python")
        def changing_process(pid):
            if pid == 100:
                changing_process.manager_reads += 1
                return manager if changing_process.manager_reads == 1 else changed
            return launcher
        changing_process.manager_reads = 0
        probe = SimpleNamespace(process=Mock(side_effect=changing_process))
        unavailable = monitoring_memory.sample_owned_tree(
            manager, launcher_identity=launcher, identity=probe,
            process_rows={1: 0, 50: 1, 100: 50}, usage_reader=lambda _pid: 1000, uid=501,
        )
        self.assertEqual(unavailable["status"], "UNAVAILABLE")
        self.assertIsNone(unavailable["managerRssBytes"])
        self.assertIsNone(unavailable["ownedDescendantTreeRssBytes"])

        foreign_child = identity(101, 999, "/synthetic/foreign")
        probe = SimpleNamespace(process=Mock(side_effect=lambda pid: {
            100: manager, 50: launcher, 101: foreign_child,
        }[pid]))
        broken = monitoring_memory.sample_owned_tree(
            manager, launcher_identity=launcher, identity=probe,
            process_rows={1: 0, 50: 1, 100: 50, 101: 100},
            usage_reader=lambda _pid: 1000, uid=501,
        )
        self.assertEqual(broken["status"], "UNAVAILABLE")
        self.assertIsNone(broken["ownedDescendantTreeRssBytes"])

    def test_process_tree_overflow_and_partial_usage_failure_are_unavailable(self):
        import monitoring_memory

        manager = identity(100, 50, "/synthetic/node")
        launcher = identity(50, 1, "/synthetic/python")
        overflow = {1: 0, 50: 1, 100: 50}
        overflow.update({pid: 100 for pid in range(101, 230)})
        probe = SimpleNamespace(process=Mock(side_effect=lambda pid: {
            100: manager, 50: launcher,
        }.get(pid, identity(pid, 100, f"/synthetic/backend-{pid}"))))
        usage = Mock(return_value=1000)
        result = monitoring_memory.sample_owned_tree(
            manager, launcher_identity=launcher, identity=probe,
            process_rows=overflow, usage_reader=usage, uid=501,
        )
        self.assertEqual(result["status"], "UNAVAILABLE")
        usage.assert_not_called()

        probe = SimpleNamespace(process=Mock(side_effect=lambda pid: {
            100: manager, 50: launcher,
        }[pid]))
        partial = monitoring_memory.sample_owned_tree(
            manager, launcher_identity=launcher, identity=probe,
            process_rows={1: 0, 50: 1, 100: 50},
            usage_reader=lambda _pid: (_ for _ in ()).throw(OSError()), uid=501,
        )
        self.assertEqual(partial["status"], "UNAVAILABLE")
        self.assertIsNone(partial["managerRssBytes"])
        self.assertIsNone(partial["ownedDescendantTreeRssBytes"])

    def test_process_census_accepts_system_pid_one(self):
        import monitoring_memory

        with patch.object(monitoring_memory, "_process_output", return_value="1 0\n42 1\n"):
            self.assertEqual(monitoring_memory.process_census(), {1: 0, 42: 1})


if __name__ == "__main__":
    unittest.main()
