"""Tests for the autonomous VT hunter."""

import json
import os
import tempfile

import pytest
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import patch, MagicMock

from driveratlas.hunter import DriverHunter, HuntResult
from driveratlas.scoring import AttackSurfaceScore, ScoreContribution


# ── Helpers ───────────────────────────────────────────────────────────


@dataclass
class FakeProfile:
    name: str = "test.sys"
    sha256: str = "a" * 64
    size: int = 50000
    signer: Optional[str] = None
    framework: str = "wdm_raw"
    import_count: int = 25
    imports: dict = field(default_factory=dict)
    device_names: list = field(default_factory=list)
    symbolic_links: list = field(default_factory=list)
    notable_strings: list = field(default_factory=list)


def _make_hunt_result(name: str, score_total: float, sha256: str = None) -> HuntResult:
    """Create a HuntResult with a given score for testing."""
    sha = sha256 or ("a" * 64)
    return HuntResult(
        sha256=sha,
        name=name,
        score=AttackSurfaceScore(
            total=score_total,
            risk_level="critical" if score_total >= 10 else "high" if score_total >= 8 else "medium",
            contributions=[],
            flags=[f"flag for {name}"],
        ),
        path=f"/tmp/{name}",
        source="test",
    )


# ── Dedup Persistence Tests ──────────────────────────────────────────


class TestDedupPersistence:
    """Test that seen SHA256 hashes persist across hunter instances."""

    def test_save_and_load_seen(self, tmp_path):
        seen_path = str(tmp_path / "seen.json")
        hunter = DriverHunter(seen_path=seen_path)
        hunter._mark_seen("abc123")
        hunter._mark_seen("def456")

        # New instance should load the same seen set
        hunter2 = DriverHunter(seen_path=seen_path)
        assert "abc123" in hunter2._seen
        assert "def456" in hunter2._seen

    def test_empty_seen_file(self, tmp_path):
        seen_path = str(tmp_path / "seen.json")
        hunter = DriverHunter(seen_path=seen_path)
        assert len(hunter._seen) == 0

    def test_corrupted_seen_file(self, tmp_path):
        seen_path = str(tmp_path / "seen.json")
        with open(seen_path, "w") as f:
            f.write("not valid json{{{")
        hunter = DriverHunter(seen_path=seen_path)
        assert len(hunter._seen) == 0

    def test_seen_file_created_in_subdirectory(self, tmp_path):
        seen_path = str(tmp_path / "subdir" / "deep" / "seen.json")
        hunter = DriverHunter(seen_path=seen_path)
        hunter._mark_seen("test123")
        assert os.path.exists(seen_path)


# ── Directory Hunting Tests ──────────────────────────────────────────


class TestDirectoryHunting:
    """Test local directory scanning and scoring."""

    @patch("driveratlas.hunter.scan_driver")
    def test_hunt_directory_sorts_by_score(self, mock_scan, tmp_path):
        """Results should be sorted by score descending."""
        for name in ["low.sys", "high.sys", "mid.sys"]:
            (tmp_path / name).write_bytes(b"MZ" + b"\x00" * 100)

        def fake_scan(path, classifier=None, categories_path=None):
            name = os.path.basename(path)
            if name == "high.sys":
                # BYOVD-like: device name, IOCTL, MmMapIoSpace, no security
                return FakeProfile(
                    name=name, size=40000, framework="wdm_raw", import_count=25,
                    signer="Acme Corp",
                    imports={"ntoskrnl.exe": ["MmMapIoSpace", "IoCreateDevice", "ExAllocatePool"]},
                    device_names=["\\Device\\Test"],
                    symbolic_links=["\\DosDevices\\Test"],
                    notable_strings=["IOCTL_TEST"],
                )
            elif name == "mid.sys":
                # Some exposure but with basic security
                return FakeProfile(
                    name=name, size=200000, framework="wdm_raw", import_count=80,
                    imports={"ntoskrnl.exe": ["IoCreateDevice", "ProbeForRead"]},
                    device_names=["\\Device\\Mid"],
                )
            else:
                # Safe minifilter, Microsoft signed
                return FakeProfile(
                    name=name, size=500000, framework="minifilter", import_count=300,
                    signer="Microsoft Windows",
                    imports={"ntoskrnl.exe": ["ProbeForRead", "ProbeForWrite", "SeAccessCheck", "IoCreateDeviceSecure"]},
                )

        mock_scan.side_effect = fake_scan

        hunter = DriverHunter(seen_path=str(tmp_path / "seen.json"))
        results = hunter.hunt_directory(str(tmp_path), recursive=False, min_score=0.0)

        assert len(results) == 3
        assert results[0].name == "high.sys"
        assert results[0].score.total > results[1].score.total
        assert results[1].score.total > results[2].score.total

    @patch("driveratlas.hunter.scan_driver")
    def test_hunt_directory_min_score_filter(self, mock_scan, tmp_path):
        """Only results above min_score should be returned."""
        for name in ["low.sys", "high.sys"]:
            (tmp_path / name).write_bytes(b"MZ" + b"\x00" * 100)

        def fake_scan(path, classifier=None, categories_path=None):
            name = os.path.basename(path)
            if name == "high.sys":
                return FakeProfile(
                    name=name, imports={"ntoskrnl.exe": ["MmMapIoSpace", "IoCreateDevice"]},
                    device_names=["\\Device\\Test"], notable_strings=["IOCTL_TEST"],
                    framework="wdm_raw", import_count=25, size=40000,
                )
            return FakeProfile(
                name=name, imports={"ntoskrnl.exe": ["IoCreateDevice"]},
                device_names=[], framework="minifilter", import_count=200, size=500000,
                signer="Microsoft Windows",
            )

        mock_scan.side_effect = fake_scan

        hunter = DriverHunter(seen_path=str(tmp_path / "seen.json"))
        results = hunter.hunt_directory(str(tmp_path), recursive=False, min_score=5.0)

        assert all(r.score.total >= 5.0 for r in results)

    @patch("driveratlas.hunter.scan_driver")
    def test_hunt_empty_directory(self, mock_scan, tmp_path):
        """Empty directory returns empty results."""
        hunter = DriverHunter(seen_path=str(tmp_path / "seen.json"))
        results = hunter.hunt_directory(str(tmp_path), min_score=0.0)
        assert results == []
        mock_scan.assert_not_called()


# ── Telegram Alert Tests ─────────────────────────────────────────────


class TestTelegramAlert:
    """Test Telegram alert formatting and sending (mocked)."""

    @patch("requests.post")
    def test_alert_sends_for_high_scores(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)

        findings = [
            _make_hunt_result("vuln.sys", 12.0),
            _make_hunt_result("safe.sys", 3.0),
        ]

        hunter = DriverHunter(seen_path="/tmp/test_seen.json")
        result = hunter.alert_telegram(
            findings, token="test_token", chat_id="test_chat", min_score=8.0
        )

        assert result is True
        mock_post.assert_called_once()
        body = mock_post.call_args[1]["json"]
        assert "vuln.sys" in body["text"]
        assert "safe.sys" not in body["text"]

    def test_alert_no_findings_above_threshold(self):
        findings = [
            _make_hunt_result("low1.sys", 3.0),
            _make_hunt_result("low2.sys", 5.0),
        ]

        hunter = DriverHunter(seen_path="/tmp/test_seen.json")
        result = hunter.alert_telegram(
            findings, token="test_token", chat_id="test_chat", min_score=8.0
        )

        # Returns False immediately, no HTTP call made
        assert result is False

    @patch("requests.post")
    def test_alert_formats_multiple_findings(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)

        findings = [
            _make_hunt_result("vuln1.sys", 12.0, sha256="a" * 64),
            _make_hunt_result("vuln2.sys", 10.0, sha256="b" * 64),
            _make_hunt_result("vuln3.sys", 9.0, sha256="c" * 64),
        ]

        hunter = DriverHunter(seen_path="/tmp/test_seen.json")
        hunter.alert_telegram(
            findings, token="tok", chat_id="chat", min_score=8.0
        )

        body = mock_post.call_args[1]["json"]
        text = body["text"]
        assert "vuln1.sys" in text
        assert "vuln2.sys" in text
        assert "vuln3.sys" in text
        assert "3 high-risk drivers" in text


# ── HuntResult Tests ─────────────────────────────────────────────────


class TestHuntResult:
    """Test HuntResult serialization."""

    def test_to_dict(self):
        result = _make_hunt_result("test.sys", 8.5)
        d = result.to_dict()
        assert d["name"] == "test.sys"
        assert d["score"]["total"] == 8.5
        assert "sha256" in d
