import os
from pathlib import Path
import tempfile
import threading
import unittest

from install_transaction import INSTALL_ORDER


class FakeOperations:
    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at
        for name in INSTALL_ORDER:
            setattr(self, name, self._operation(name))

    def _operation(self, name):
        def call():
            self.calls.append(name)
            if self.fail_at == name:
                raise RuntimeError("synthetic failure")
            return {"status": "PASS", "stage": name}
        return call


class InstallTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        from install_transaction import INSTALL_ORDER
        self.order = INSTALL_ORDER

    def tearDown(self):
        self.temporary.cleanup()

    def journal(self):
        from install_transaction import AuthenticatedJournal
        return AuthenticatedJournal(self.root / "transactions/install.jsonl", b"synthetic-install-key" * 2)

    def test_runs_exact_reviewed_order_and_records_only_authenticated_phase_digests(self):
        from install_transaction import INSTALL_ORDER, read_journal, run_transaction

        operations = FakeOperations()
        result = run_transaction(operations, self.journal())
        self.assertEqual(tuple(operations.calls), INSTALL_ORDER)
        self.assertEqual(tuple(result), INSTALL_ORDER)
        records = read_journal(self.root / "transactions/install.jsonl", b"synthetic-install-key" * 2)
        self.assertGreaterEqual(len(records), 2 * (len(INSTALL_ORDER) - 3))
        self.assertTrue(all("recordHmac" in record for record in records))
        self.assertNotIn("synthetic-install-key", (self.root / "transactions/install.jsonl").read_text())

    def test_failure_stops_before_later_stages_and_journal_rejects_tampering(self):
        from install_transaction import InstallTransactionError, read_journal, run_transaction

        for failing in self.order:
            with self.subTest(failing=failing):
                path = self.root / f"{failing}.jsonl"
                operations = FakeOperations(fail_at=failing)
                with self.assertRaises(RuntimeError):
                    run_transaction(operations, self.journal_at(path))
                self.assertEqual(operations.calls, list(self.order[: self.order.index(failing) + 1]))
                if self.order.index(failing) < 3:
                    self.assertFalse(path.exists())
                    continue
                content = path.read_text()
                self.assertNotIn("synthetic failure", content)
                records = read_journal(path, b"synthetic-install-key" * 2)
                self.assertTrue(records)
                path.write_text(content.replace('"event":"started"', '"event":"tampered"', 1))
                with self.assertRaises(InstallTransactionError):
                    read_journal(path, b"synthetic-install-key" * 2)

    def journal_at(self, path):
        from install_transaction import AuthenticatedJournal
        return AuthenticatedJournal(path, b"synthetic-install-key" * 2)

    def test_no_client_projection_runs_until_service_verification_passes(self):
        from install_transaction import INSTALL_ORDER, run_transaction

        for failing in ("register_service", "verify_service"):
            operations = FakeOperations(fail_at=failing)
            journal = self.journal_at(self.root / f"{failing}.jsonl")
            with self.assertRaises(RuntimeError):
                run_transaction(operations, journal)
            self.assertNotIn("project_clients", operations.calls)
            self.assertEqual(operations.calls[-1], failing)
            self.assertLess(INSTALL_ORDER.index(failing), INSTALL_ORDER.index("project_clients"))

    def test_concurrent_installer_lock_refuses_second_owner(self):
        from install_transaction import InstallationLock, InstallTransactionError

        lock_path = self.root / "install.lock"
        entered = threading.Event()
        release = threading.Event()
        errors = []

        def owner():
            with InstallationLock(lock_path):
                entered.set()
                release.wait(2)

        thread = threading.Thread(target=owner)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            with self.assertRaises(InstallTransactionError):
                with InstallationLock(lock_path, blocking=False):
                    pass
        except Exception as exc:
            errors.append(exc)
        finally:
            release.set()
            thread.join(timeout=2)
        self.assertEqual(errors, [])

    def test_transaction_journal_never_persists_operation_secrets(self):
        from install_transaction import run_transaction

        operations = FakeOperations()
        operations.stage_release = lambda: {"status": "PASS", "token": "synthetic-secret"}
        run_transaction(operations, self.journal())
        journal = (self.root / "transactions/install.jsonl").read_text()
        self.assertNotIn("synthetic-secret", journal)

    def test_transaction_journal_authenticates_selection_release_and_projection_binding(self):
        from install_transaction import AuthenticatedJournal, read_journal

        binding = {
            "planHash": "1" * 64,
            "releaseDigest": "2" * 64,
            "selectionDigest": "3" * 64,
            "projectionDigest": "4" * 64,
        }
        path = self.root / "bound.jsonl"
        journal = AuthenticatedJournal(path, b"synthetic-install-key" * 2, binding=binding)
        journal.append("started", "stage_release")
        records = read_journal(path, b"synthetic-install-key" * 2)
        self.assertEqual(records[0]["binding"], binding)
        altered = path.read_text().replace('"selectionDigest":"' + "3" * 64, '"selectionDigest":"' + "5" * 64)
        path.write_text(altered)
        with self.assertRaises(Exception):
            read_journal(path, b"synthetic-install-key" * 2)


if __name__ == "__main__":
    unittest.main()
