import os
from pathlib import Path

import psutil
import pytest

from ciphersentry.attribution import collect_process_context
from ciphersentry.monitor import FolderMonitor
from ciphersentry.telemetry import MonitorProtocol, WATCHDOG_CAPABILITIES
from scripts.attribution_probe import run_attribution_probe, summarize_observations


def test_process_metadata_is_stable_and_does_not_claim_file_attribution():
    process = psutil.Process()
    result = collect_process_context(process.pid, process.create_time())
    assert result["identity_verified"]
    assert result["create_time"] == process.create_time()
    assert result["parent_pid"] == os.getppid()
    assert result["signature_status"] == "not_checked"
    assert "command_line" not in result
    assert "does not attribute" in result["attribution_note"]


def test_wrong_process_creation_time_is_not_reused():
    result = collect_process_context(os.getpid(), psutil.Process().create_time() - 100)
    assert result["status"] == "identity_changed"
    assert not result["identity_verified"]
    assert result["name"] is None


@pytest.mark.parametrize("pid", [0, -1, True, "12"])
def test_invalid_pid_is_reported_without_process_lookup(pid):
    result = collect_process_context(pid)
    assert not result["identity_verified"]
    assert result["errors"]


def test_collector_contract_exposes_absent_attribution(tmp_path):
    monitor = FolderMonitor(tmp_path, lambda event: None)
    assert isinstance(monitor, MonitorProtocol)
    assert not monitor.capabilities.process_attribution
    assert "read" not in WATCHDOG_CAPABILITIES.operations
    assert not WATCHDOG_CAPABILITIES.write_payload


def test_independent_writer_probe_reports_missing_attribution(tmp_path):
    existing = tmp_path / "personal.txt"
    existing.write_text("Do not touch", encoding="utf-8")
    report = run_attribution_probe(tmp_path / "report.json", files=4, workspace=tmp_path)
    metrics = report["metrics"]
    assert metrics["expected_unique_file_modifications"] == 4
    assert metrics["observed_unique_file_modifications"] == 4
    assert metrics["missing_file_modifications"] == 0
    assert metrics["correctly_attributed_notifications"] == 0
    assert metrics["unattributed_notifications"] >= 4
    assert metrics["attribution_coverage"] == 0
    assert report["writer_identity_consistent"]
    assert report["ground_truth_identity"]["pid"] != os.getpid()
    assert all(item["pid"] is None for item in report["observations"])
    assert all(item["attribution"] == "unavailable" for item in report["observations"])
    assert report["collector_errors"] == []
    assert existing.read_text(encoding="utf-8") == "Do not touch"


def test_summary_counts_missing_duplicate_and_wrong_identity():
    truth = [dict(path="/dummy/a", pid=20, create_time=1.0, started_monotonic=10, started_wall=100),
             dict(path="/dummy/b", pid=20, create_time=1.0, started_monotonic=10, started_wall=100)]
    event = dict(path="/dummy/a", operation="modified", pid=None, observed_at=100.01, received_monotonic=10.1)
    wrong = dict(event, pid=20, process_context={"create_time": 2.0})
    summary = summarize_observations(truth, [event, wrong])
    assert summary["missing_file_modifications"] == 1
    assert summary["duplicate_modified_notifications"] == 1
    assert summary["incorrect_or_unstable_attribution_notifications"] == 1
    assert summary["unattributed_notifications"] == 1
    assert summary["correctly_attributed_notifications"] == 0
