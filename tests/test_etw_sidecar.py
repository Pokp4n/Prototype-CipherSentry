"""Tests for read-only packaged ETW collector discovery."""

import sys

import pytest

from ciphersentry.etw_sidecar import find_packaged_collector


def make_package(tmp_path):
    application = tmp_path / "CipherSentry.exe"
    application.write_bytes(b"test-gui")

    collector_dir = tmp_path / "etw"
    collector_dir.mkdir()

    collector = collector_dir / "LiveEtwStreamer.exe"
    collector.write_bytes(b"test-collector")

    return application, collector


def test_finds_collector_beside_packaged_gui(tmp_path):
    application, collector = make_package(tmp_path)

    assert find_packaged_collector(application) == collector


def test_missing_collector_returns_none(tmp_path):
    application, collector = make_package(tmp_path)
    collector.unlink()

    assert find_packaged_collector(application) is None


def test_wrong_application_name_returns_none(tmp_path):
    application, _ = make_package(tmp_path)
    wrong_application = application.with_name("OtherApp.exe")

    assert find_packaged_collector(wrong_application) is None


def test_relative_application_path_is_rejected():
    with pytest.raises(ValueError, match="absolute"):
        find_packaged_collector("CipherSentry.exe")


def test_source_mode_does_not_autodiscover(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)

    assert find_packaged_collector() is None


def test_packaged_mode_uses_executable_location(tmp_path, monkeypatch):
    application, collector = make_package(tmp_path)

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(application))

    assert find_packaged_collector() == collector
