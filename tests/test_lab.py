"""Exercise real isolated workloads and suspension of a verified lab child."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import psutil

from ciphersentry.containment import ContainmentError, ManagedContainment
from ciphersentry.process_identity import OwnedProcessLaunch


def worker_command(root, scenario="suspicious", files=8, delay=0.01):
    return [sys.executable, "-m", "ciphersentry.lab_worker", "--workspace", str(root), "--scenario", scenario, "--files", str(files), "--delay", str(delay)]


class LabWorkerTests(unittest.TestCase):
    def test_legitimate_compression_creates_real_archives_and_preserves_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(worker_command(Path(directory).resolve(), scenario="compression"), capture_output=True, text=True, check=True, timeout=15)
            records = [json.loads(line) for line in result.stdout.splitlines()]
            events = [record["event"] for record in records if record["type"] == "event"]
            self.assertEqual(len(events), 8)
            for event in events:
                self.assertEqual(event["operation"], "created")
                self.assertIsNone(event["entropy_before"])
                path = Path(event["path"])
                original = path.with_suffix(".txt")
                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(archive.read(original.name), original.read_bytes())

    def test_suspicious_workload_only_changes_its_new_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            existing = root / "existing-user-document.txt"
            existing.write_text("Keep this user document", encoding="utf-8")
            result = subprocess.run(worker_command(root), capture_output=True, text=True, check=True, timeout=15)
            records = [json.loads(line) for line in result.stdout.splitlines()]
            events = [record["event"] for record in records if record["type"] == "event"]
            self.assertEqual(len(events), 8)
            self.assertEqual(records[-1]["completed"], 8)
            self.assertEqual(existing.read_text(encoding="utf-8"), "Keep this user document")
            run_root = Path(records[0]["root"])
            self.assertEqual(run_root.parent, root)
            self.assertTrue((run_root / ".ciphersentry-lab-owned").is_file())
            for event in events:
                self.assertEqual(event["source"], "lab")
                self.assertEqual(event["operation"], "moved")
                self.assertGreater(event["entropy_after"] - event["entropy_before"], 2.0)
                self.assertTrue(Path(event["path"]).is_relative_to(run_root))

    def test_benign_workload_has_no_entropy_surge_or_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(worker_command(Path(directory).resolve(), scenario="benign"), capture_output=True, text=True, check=True, timeout=15)
            records = [json.loads(line) for line in result.stdout.splitlines()]
            events = [record["event"] for record in records if record["type"] == "event"]
            self.assertEqual(len(events), 8)
            for event in events:
                self.assertEqual(event["operation"], "modified")
                self.assertLess(abs(event["entropy_after"] - event["entropy_before"]), 0.5)

    def test_rejects_unregistered_and_unrelated_process(self):
        manager = ManagedContainment()
        with self.assertRaises(ContainmentError):
            manager.suspend(os.getpid())
        with self.assertRaises(ContainmentError):
            manager.register(os.getpid())
        process = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.readline()"], stdin=subprocess.PIPE)
        try:
            with self.assertRaises(ContainmentError):
                manager.register(process.pid)
            self.assertIsNone(process.poll())
        finally:
            process.stdin.close()
            process.wait(timeout=5)

    def test_packaged_worker_requires_exact_same_executable_and_worker_flag(self):
        with patch.object(sys, "frozen", True, create=True):
            self.assertTrue(ManagedContainment._is_lab_command([sys.executable, "--lab-worker", "--scenario", "benign"], sys.executable))
            self.assertFalse(ManagedContainment._is_lab_command([sys.executable, "--scenario", "benign"], sys.executable))
            self.assertFalse(ManagedContainment._is_lab_command([sys.executable, "--lab-worker"], str(Path(sys.executable).parent / "unrelated-executable")))

    def test_suspend_resume_and_stop_verified_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            command = [*worker_command(Path(directory).resolve(), files=60, delay=0.1), "--managed"]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            manager = ManagedContainment()
            pid = None
            try:
                launch = OwnedProcessLaunch.capture(process.pid, command[1:])
                ready = json.loads(process.stdout.readline())
                self.assertEqual(ready["type"], "ready")
                pid = ready["pid"]
                self.assertTrue(manager.register(pid, launch=launch, expected_create_time=ready["create_time"]))
                context = manager.validate(pid)
                self.assertEqual(context["launch_pid"], process.pid)
                self.assertEqual(context["create_time"], ready["create_time"])
                if os.name == "nt" and Path(sys.executable).resolve() != Path(sys._base_executable).resolve():
                    self.assertNotEqual(pid, process.pid)
                    self.assertEqual(context["parent_pid"], process.pid)
                self.assertTrue(manager.suspend(pid))
                self.assertTrue(manager.is_suspended(pid))
                process.stdin.write("start\n")
                process.stdin.flush()
                snapshot = {str(path): path.stat().st_mtime_ns for path in Path(ready["root"]).rglob("sample-*")}
                time.sleep(0.2)
                frozen = {str(path): path.stat().st_mtime_ns for path in Path(ready["root"]).rglob("sample-*")}
                self.assertEqual(snapshot, frozen, "Worker modified fixtures while suspended")
                self.assertTrue(manager.resume(pid))
                self.assertFalse(manager.is_suspended(pid))
                event = json.loads(process.stdout.readline())
                self.assertEqual(event["type"], "event")
                manager.suspend(pid)
                self.assertTrue(manager.terminate(pid))
                process.wait(timeout=5)
                self.assertIsNotNone(process.returncode)
                self.assertFalse(psutil.pid_exists(pid))
            finally:
                if process.poll() is None:
                    try:
                        manager.terminate(pid)
                    except ContainmentError:
                        pass
                    process.stdin.close()
                    process.kill()
                    process.wait(timeout=5)
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()

    def test_managed_worker_does_not_modify_without_parent_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([*worker_command(Path(directory).resolve()), "--managed"],
                                    input="", capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            ready = json.loads(result.stdout.splitlines()[0])
            self.assertEqual(ready["type"], "ready")
            root = Path(ready["root"])
            self.assertEqual(len(list(root.rglob("sample-*.txt"))), 8)
            self.assertEqual(list(root.rglob("*.locked-demo")), [])


if __name__ == "__main__":
    unittest.main()
