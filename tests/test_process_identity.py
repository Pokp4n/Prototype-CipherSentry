"""OS identity checks for direct launches and Windows virtualenv redirectors."""

from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import sys

import psutil
import pytest

from ciphersentry.containment import ContainmentError, ManagedContainment
from ciphersentry import process_identity as identity


@pytest.fixture
def process_tree(monkeypatch, tmp_path):
    owner = os.getpid()
    launcher_pid, worker_pid = 1000001, 1000002
    launcher_exe = str(tmp_path / "venv" / "python.exe")
    base_exe = str(tmp_path / "base" / "python.exe")
    arguments = ["-m", "ciphersentry.lab_worker", "--workspace", str(tmp_path / "fixtures")]
    records = {
        owner: dict(created=100.0, parent=50, executable=base_exe, command=[base_exe], alive=True),
        launcher_pid: dict(created=101.0, parent=owner, executable=launcher_exe,
                           command=[launcher_exe, *arguments], alive=True),
        worker_pid: dict(created=102.0, parent=launcher_pid, executable=base_exe,
                         command=[base_exe, *arguments], alive=True),
    }
    controls = []

    class Process:
        def __init__(self, pid):
            self.pid = pid
            if pid not in records:
                raise psutil.NoSuchProcess(pid)

        def field(self, name):
            if self.pid not in records:
                raise psutil.NoSuchProcess(self.pid)
            if records[self.pid].get("denied"):
                raise psutil.AccessDenied(self.pid)
            return records[self.pid][name]

        def create_time(self):
            return self.field("created")

        def ppid(self):
            return self.field("parent")

        def exe(self):
            return self.field("executable")

        def cmdline(self):
            return list(self.field("command"))

        def is_running(self):
            return self.field("alive")

        def status(self):
            return psutil.STATUS_RUNNING if self.field("alive") else psutil.STATUS_DEAD

        def suspend(self):
            controls.append(("suspend", self.pid))

        def resume(self):
            controls.append(("resume", self.pid))

        def terminate(self):
            controls.append(("terminate", self.pid))
            records[self.pid]["alive"] = False

        def kill(self):
            controls.append(("kill", self.pid))
            records[self.pid]["alive"] = False

    monkeypatch.setattr(identity, "WINDOWS", True)
    monkeypatch.setattr(sys, "executable", launcher_exe)
    monkeypatch.setattr(sys, "_base_executable", base_exe, raising=False)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(psutil, "Process", Process)
    return dict(owner=owner, launcher=launcher_pid, worker=worker_pid, arguments=arguments,
                records=records, controls=controls, base=base_exe, executable=launcher_exe)


def capture(tree):
    return identity.OwnedProcessLaunch.capture(tree["launcher"], tree["arguments"])


def test_windows_redirect_binds_os_verified_child_and_controls_only_it(process_tree):
    tree = process_tree
    launch = capture(tree)
    worker = launch.verify_worker(tree["worker"], 102.0)
    assert worker.pid == tree["worker"]
    assert worker.launch_pid == tree["launcher"]
    assert worker.parent_pid == tree["launcher"]
    assert worker.executable == tree["base"]
    with pytest.raises(FrozenInstanceError):
        worker._worker = None
    manager = ManagedContainment()
    assert manager.register(worker.pid, launch=launch, expected_create_time=102.0)
    assert manager.validate(worker.pid) == dict(pid=worker.pid, create_time=102.0,
                                               parent_pid=tree["launcher"], executable=tree["base"],
                                               launch_pid=tree["launcher"])
    manager.suspend(worker.pid)
    manager.resume(worker.pid)
    manager.terminate(worker.pid)
    assert tree["controls"] == [("suspend", worker.pid), ("resume", worker.pid), ("terminate", worker.pid)]


def test_direct_interpreter_is_supported_without_redirect(process_tree, monkeypatch):
    tree = process_tree
    monkeypatch.setattr(identity, "WINDOWS", False)
    launch = capture(tree)
    worker = launch.verify_worker(tree["launcher"], 101.0)
    assert worker.pid == worker.launch_pid
    manager = ManagedContainment()
    manager.register(worker.pid)
    manager.suspend(worker.pid)
    assert tree["controls"] == [("suspend", worker.pid)]
    with pytest.raises(identity.ProcessIdentityError):
        launch.verify_worker(tree["worker"], 102.0)


@pytest.mark.parametrize("claim,created", [(1000001, 101.0), (1000002, 999.0), (1000003, 102.0),
                                         (True, 102.0), (1000002, True), (1000002, float("nan"))])
def test_forged_worker_claims_are_rejected(process_tree, claim, created):
    with pytest.raises(identity.ProcessIdentityError):
        capture(process_tree).verify_worker(claim, created)
    assert process_tree["controls"] == []


@pytest.mark.parametrize("target,field,value", [
    ("worker", "parent", 2000000),
    ("worker", "created", 99.0),
    ("worker", "executable", ""),
    ("worker", "command", ["unrelated.exe", "-m", "ciphersentry.lab_worker"]),
    ("worker", "denied", True),
    ("worker", "alive", False),
    ("launcher", "created", 105.0),
    ("launcher", "parent", 2000000),
    ("launcher", "denied", True),
    ("launcher", "alive", False),
    ("owner", "created", 99.0),
])
def test_changed_metadata_prevents_registration(process_tree, target, field, value):
    tree = process_tree
    launch = capture(tree)
    tree["records"][tree[target]][field] = value
    with pytest.raises(identity.ProcessIdentityError):
        launch.verify_worker(tree["worker"], 102.0)
    assert tree["controls"] == []


@pytest.mark.parametrize("target,field,value", [
    ("worker", "created", 103.0),
    ("worker", "parent", 2000000),
    ("worker", "command", [str(Path(sys.executable).resolve()), "-c", "pass"]),
    ("worker", "executable", ""),
    ("worker", "denied", True),
    ("worker", "alive", False),
    ("launcher", "created", 103.0),
    ("launcher", "parent", 2000000),
    ("launcher", "denied", True),
    ("launcher", "alive", False),
])
@pytest.mark.parametrize("action", ["suspend", "resume", "terminate"])
def test_every_control_revalidates_worker_and_launch(process_tree, target, field, value, action):
    tree = process_tree
    manager = ManagedContainment()
    manager.register(tree["worker"], launch=capture(tree), expected_create_time=102.0)
    if action == "resume":
        manager.suspend(tree["worker"])
        tree["controls"].clear()
    tree["records"][tree[target]][field] = value
    with pytest.raises(ContainmentError):
        getattr(manager, action)(tree["worker"])
    assert tree["controls"] == []


@pytest.mark.parametrize("target", ["worker", "launcher"])
def test_exited_process_is_not_replaced_by_another_pid(process_tree, target):
    tree = process_tree
    worker = capture(tree).verify_worker(tree["worker"], 102.0)
    del tree["records"][tree[target]]
    with pytest.raises(identity.ProcessIdentityError):
        worker.validate()


def test_windows_wrapper_cannot_be_controlled_as_the_execution_worker(process_tree):
    tree = process_tree
    manager = ManagedContainment()
    with pytest.raises(ContainmentError, match="interpreter child"):
        manager.register(tree["launcher"])
    with pytest.raises(ContainmentError):
        manager.suspend(tree["launcher"])
    assert tree["controls"] == []


def test_capture_rejects_wrong_invocation_and_nonchild(process_tree):
    tree = process_tree
    with pytest.raises(identity.ProcessIdentityError):
        identity.OwnedProcessLaunch.capture(tree["launcher"], ["-c", "pass"])
    with pytest.raises(identity.ProcessIdentityError):
        identity.OwnedProcessLaunch.capture(tree["worker"], tree["arguments"])


def test_base_interpreter_must_match_the_current_os_executable(process_tree):
    tree = process_tree
    tree["records"][tree["owner"]]["executable"] = tree["executable"]
    with pytest.raises(identity.ProcessIdentityError, match="base interpreter"):
        capture(tree)


def test_unrelated_module_argument_cannot_authorize_containment(process_tree):
    tree = process_tree
    arguments = ["-c", "pass", "-m", "ciphersentry.lab_worker"]
    tree["records"][tree["launcher"]]["command"] = [tree["executable"], *arguments]
    tree["records"][tree["worker"]]["command"] = [tree["base"], *arguments]
    launch = identity.OwnedProcessLaunch.capture(tree["launcher"], arguments)
    with pytest.raises(ContainmentError, match="not a CipherSentry lab worker"):
        ManagedContainment().register(tree["worker"], launch=launch, expected_create_time=102.0)
    assert not ManagedContainment._is_lab_command([tree["executable"], *arguments], tree["executable"])


def test_frozen_worker_is_direct_and_does_not_admit_a_redirect_child(process_tree, monkeypatch):
    tree = process_tree
    monkeypatch.setattr(sys, "frozen", True)
    arguments = ["--lab-worker", "--scenario", "benign"]
    tree["records"][tree["launcher"]]["command"] = [tree["executable"], *arguments]
    launch = identity.OwnedProcessLaunch.capture(tree["launcher"], arguments)
    manager = ManagedContainment()
    manager.register(tree["launcher"], launch=launch, expected_create_time=101.0)
    with pytest.raises(identity.ProcessIdentityError):
        launch.verify_worker(tree["worker"], 102.0)


def test_unavailable_ancestry_does_not_forget_live_suspended_worker(process_tree):
    tree = process_tree
    manager = ManagedContainment()
    manager.register(tree["worker"], launch=capture(tree), expected_create_time=102.0)
    manager.suspend(tree["worker"])
    tree["records"][tree["launcher"]]["denied"] = True
    with pytest.raises(ContainmentError):
        manager.unregister(tree["worker"])
    tree["records"][tree["launcher"]]["denied"] = False
    manager.resume(tree["worker"])
    assert tree["controls"] == [("suspend", tree["worker"]), ("resume", tree["worker"])]
