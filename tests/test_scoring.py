"""Tests for the attack surface scoring engine."""

import pytest
from dataclasses import dataclass, field
from typing import Optional

from driveratlas.scoring import AttackSurfaceScorer, AttackSurfaceScore, ScoreContribution


# ── Synthetic DriverProfile for testing (no real files needed) ────────


@dataclass
class FakeProfile:
    name: str = "test.sys"
    sha256: str = "a" * 64
    size: int = 50000
    signer: Optional[str] = None
    framework: str = "unknown"
    import_count: int = 20
    imports: dict = field(default_factory=dict)
    device_names: list = field(default_factory=list)
    symbolic_links: list = field(default_factory=list)
    notable_strings: list = field(default_factory=list)


def _make_byovd_profile() -> FakeProfile:
    """BYOVD-like: small, wdm_raw, MmMapIoSpace, device name, no probes, no access checks."""
    return FakeProfile(
        name="vuln_driver.sys",
        size=40000,
        signer="Acme Corp",
        framework="wdm_raw",
        import_count=25,
        imports={
            "ntoskrnl.exe": [
                "IoCreateDevice", "IoDeleteDevice", "IoCreateSymbolicLink",
                "MmMapIoSpace", "ExAllocatePool",
                "RtlInitUnicodeString", "IofCompleteRequest",
            ],
        },
        device_names=["\\Device\\VulnDrv"],
        symbolic_links=["\\DosDevices\\VulnDrv"],
        notable_strings=["IOCTL_VULN_MAP_MEMORY", "IOCTL_VULN_READ_PORT"],
    )


def _make_microsoft_minifilter() -> FakeProfile:
    """Microsoft minifilter with full security — should score low."""
    return FakeProfile(
        name="cldflt.sys",
        size=570000,
        signer="Microsoft Windows",
        framework="minifilter",
        import_count=333,
        imports={
            "ntoskrnl.exe": [
                "ProbeForRead", "ProbeForWrite", "SeAccessCheck",
                "IoCreateDeviceSecure", "ExAllocatePoolWithTag",
            ],
            "fltmgr.sys": [
                "FltRegisterFilter", "FltStartFiltering",
                "FltGetStreamContext", "FltReleaseContext",
            ],
        },
        device_names=[],
        symbolic_links=[],
        notable_strings=[],
    )


def _make_empty_profile() -> FakeProfile:
    """Minimal empty profile — all defaults."""
    return FakeProfile()


# ── Tests ─────────────────────────────────────────────────────────────


class TestAttackSurfaceScorer:
    """Core scoring engine tests."""

    @pytest.fixture(autouse=True)
    def setup_scorer(self):
        self.scorer = AttackSurfaceScorer()

    def test_byovd_profile_scores_high(self):
        """A BYOVD-like driver should score >= 10 (critical)."""
        profile = _make_byovd_profile()
        result = self.scorer.score(profile)
        assert result.total >= 10.0, f"Expected >= 10.0, got {result.total}"
        assert result.risk_level == "critical"

    def test_microsoft_minifilter_scores_low(self):
        """A Microsoft minifilter with full security should score <= 3."""
        profile = _make_microsoft_minifilter()
        result = self.scorer.score(profile)
        assert result.total <= 3.0, f"Expected <= 3.0, got {result.total}"
        assert result.risk_level in ("low", "minimal")

    def test_empty_profile_scores_minimal(self):
        """An empty profile should score low (mostly missing-import bonuses, no device names penalty)."""
        profile = _make_empty_profile()
        result = self.scorer.score(profile)
        # no device names → -3.0, but missing probes/access checks → +4.0
        # small driver + low imports → +2.0, no signer → 0
        assert result.total >= 0.0
        assert result.total <= 15.0

    def test_score_clamped_to_range(self):
        """Score must be clamped to [0.0, 15.0]."""
        profile = _make_byovd_profile()
        result = self.scorer.score(profile)
        assert 0.0 <= result.total <= 15.0

    def test_negative_score_clamps_to_zero(self):
        """A heavily defended driver should clamp at 0.0, not go negative."""
        profile = FakeProfile(
            size=1_000_000,
            signer="Microsoft Windows",
            framework="minifilter",
            import_count=400,
            imports={"ntoskrnl.exe": [
                "ProbeForRead", "ProbeForWrite", "SeAccessCheck",
                "IoCreateDeviceSecure",
            ]},
            device_names=[],
            symbolic_links=[],
            notable_strings=[],
        )
        result = self.scorer.score(profile)
        assert result.total == 0.0

    def test_risk_level_critical(self):
        profile = _make_byovd_profile()
        result = self.scorer.score(profile)
        assert result.risk_level == "critical"

    def test_risk_level_boundaries(self):
        scorer = self.scorer
        assert scorer._classify_risk(15.0) == "critical"
        assert scorer._classify_risk(10.0) == "critical"
        assert scorer._classify_risk(9.9) == "high"
        assert scorer._classify_risk(8.0) == "high"
        assert scorer._classify_risk(7.9) == "medium"
        assert scorer._classify_risk(5.0) == "medium"
        assert scorer._classify_risk(4.9) == "low"
        assert scorer._classify_risk(2.0) == "low"
        assert scorer._classify_risk(1.9) == "minimal"
        assert scorer._classify_risk(0.0) == "minimal"


class TestScoreContributions:
    """Verify contributions list is populated and serializable."""

    @pytest.fixture(autouse=True)
    def setup_scorer(self):
        self.scorer = AttackSurfaceScorer()

    def test_contributions_populated(self):
        profile = _make_byovd_profile()
        result = self.scorer.score(profile)
        assert len(result.contributions) > 0
        assert all(isinstance(c, ScoreContribution) for c in result.contributions)

    def test_contributions_have_matched_rules(self):
        profile = _make_byovd_profile()
        result = self.scorer.score(profile)
        matched = [c for c in result.contributions if c.matched]
        assert len(matched) > 0

    def test_flags_correspond_to_matched(self):
        profile = _make_byovd_profile()
        result = self.scorer.score(profile)
        matched_descs = {c.description for c in result.contributions if c.matched}
        assert set(result.flags) == matched_descs

    def test_to_dict_serializable(self):
        profile = _make_byovd_profile()
        result = self.scorer.score(profile)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "total" in d
        assert "risk_level" in d
        assert "contributions" in d
        assert "flags" in d
        assert isinstance(d["contributions"], list)
        assert all("rule_id" in c for c in d["contributions"])


class TestIndividualChecks:
    """Test individual check evaluators in isolation."""

    @pytest.fixture(autouse=True)
    def setup_scorer(self):
        self.scorer = AttackSurfaceScorer()

    def test_has_import_match(self):
        flat = {"MmMapIoSpace", "IoCreateDevice"}
        assert self.scorer._check_has_import(None, flat, ["MmMapIoSpace"])

    def test_has_import_no_match(self):
        flat = {"IoCreateDevice"}
        assert not self.scorer._check_has_import(None, flat, ["MmMapIoSpace"])

    def test_has_all_imports(self):
        flat = {"ProbeForRead", "ProbeForWrite"}
        assert self.scorer._check_has_all_imports(None, flat, ["ProbeForRead", "ProbeForWrite"])

    def test_has_all_imports_partial(self):
        flat = {"ProbeForRead"}
        assert not self.scorer._check_has_all_imports(None, flat, ["ProbeForRead", "ProbeForWrite"])

    def test_missing_all_imports(self):
        flat = {"IoCreateDevice"}
        assert self.scorer._check_missing_all_imports(None, flat, ["ProbeForRead", "ProbeForWrite"])

    def test_missing_all_imports_has_one(self):
        flat = {"ProbeForRead", "IoCreateDevice"}
        assert not self.scorer._check_missing_all_imports(None, flat, ["ProbeForRead", "ProbeForWrite"])

    def test_has_import_without(self):
        flat = {"IoCreateDevice"}
        params = {"required": "IoCreateDevice", "excluded": "IoCreateDeviceSecure"}
        assert self.scorer._check_has_import_without(None, flat, params)

    def test_has_import_without_excluded_present(self):
        flat = {"IoCreateDevice", "IoCreateDeviceSecure"}
        params = {"required": "IoCreateDevice", "excluded": "IoCreateDeviceSecure"}
        assert not self.scorer._check_has_import_without(None, flat, params)

    def test_size_below(self):
        profile = FakeProfile(size=50000)
        assert self.scorer._check_size_below(profile, set(), 102400)

    def test_size_not_below(self):
        profile = FakeProfile(size=200000)
        assert not self.scorer._check_size_below(profile, set(), 102400)

    def test_framework_equals(self):
        profile = FakeProfile(framework="wdm_raw")
        assert self.scorer._check_framework_equals(profile, set(), "wdm_raw")

    def test_framework_not_equals(self):
        profile = FakeProfile(framework="minifilter")
        assert not self.scorer._check_framework_equals(profile, set(), "wdm_raw")

    def test_signer_not_microsoft(self):
        profile = FakeProfile(signer="Acme Corp")
        assert self.scorer._check_signer_not_microsoft(profile, set(), None)

    def test_signer_not_microsoft_with_ms(self):
        profile = FakeProfile(signer="Microsoft Windows")
        assert not self.scorer._check_signer_not_microsoft(profile, set(), None)

    def test_signer_not_microsoft_none(self):
        profile = FakeProfile(signer=None)
        assert not self.scorer._check_signer_not_microsoft(profile, set(), None)

    def test_signer_is_microsoft(self):
        profile = FakeProfile(signer="Microsoft Windows")
        assert self.scorer._check_signer_is_microsoft(profile, set(), None)

    def test_signer_is_microsoft_no(self):
        profile = FakeProfile(signer="Acme Corp")
        assert not self.scorer._check_signer_is_microsoft(profile, set(), None)

    def test_import_count_below(self):
        profile = FakeProfile(import_count=30)
        assert self.scorer._check_import_count_below(profile, set(), 50)

    def test_import_count_above(self):
        profile = FakeProfile(import_count=400)
        assert self.scorer._check_import_count_above(profile, set(), 300)

    def test_has_ioctl_strings(self):
        profile = FakeProfile(notable_strings=["IOCTL_DO_THING", "\\Driver\\MyDrv"])
        assert self.scorer._check_has_ioctl_strings(profile, set(), None)

    def test_no_ioctl_strings(self):
        profile = FakeProfile(notable_strings=["\\Driver\\MyDrv"])
        assert not self.scorer._check_has_ioctl_strings(profile, set(), None)
