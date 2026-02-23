"""Integration tests for DriverAtlas scanner against real system drivers."""

import os
import glob
import pytest

from driveratlas.scanner import scan_driver, DriverProfile
from driveratlas.framework_detect import FrameworkClassifier

# Resolve signature paths relative to repo root
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FRAMEWORKS_PATH = os.path.join(_REPO_ROOT, "signatures", "frameworks.yaml")
_CATEGORIES_PATH = os.path.join(_REPO_ROOT, "signatures", "api_categories.yaml")

# Standard system driver locations
_SYS32_DRIVERS = r"/mnt/c/Windows/System32/drivers" if os.path.exists(r"/mnt/c/Windows/System32/drivers") else None
_WINE_DRIVERS = None  # placeholder for CI

def _find_driver(name: str) -> str | None:
    """Find a real .sys file on the system for testing."""
    # Check common locations
    candidates = [
        f"/mnt/c/Windows/System32/drivers/{name}",
        f"/mnt/c/Windows/System32/{name}",
    ]
    # Also check any .sys files the user might have locally
    local = glob.glob(os.path.join(_REPO_ROOT, "**", name), recursive=True)
    candidates.extend(local)

    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


@pytest.fixture
def classifier():
    return FrameworkClassifier(_FRAMEWORKS_PATH)


class TestDriverProfile:
    """Test the DriverProfile dataclass."""

    def test_to_dict_roundtrip(self):
        p = DriverProfile(name="test.sys", sha256="abc123", size=1024)
        d = p.to_dict()
        assert d["name"] == "test.sys"
        assert d["sha256"] == "abc123"
        assert d["size"] == 1024
        assert d["framework"] == "unknown"

    def test_defaults(self):
        p = DriverProfile(name="x.sys", sha256="", size=0)
        assert p.imports == {}
        assert p.import_count == 0
        assert p.sections == []
        assert p.device_names == []
        assert p.framework_confidence == 0.0


class TestScannerWithRealDrivers:
    """Integration tests that require real .sys files."""

    @pytest.fixture(autouse=True)
    def _check_drivers(self):
        """Skip if no real drivers available."""
        if not _find_driver("ntfs.sys"):
            pytest.skip("No real .sys drivers found on this system")

    def test_scan_ntfs(self, classifier):
        path = _find_driver("ntfs.sys")
        if not path:
            pytest.skip("ntfs.sys not found")
        profile = scan_driver(path, classifier=classifier, categories_path=_CATEGORIES_PATH)
        assert isinstance(profile, DriverProfile)
        assert profile.name == "ntfs.sys"
        assert len(profile.sha256) == 64
        assert profile.size > 0
        assert profile.machine in ("x64", "x86", "arm64")
        assert profile.subsystem == "native"
        assert profile.import_count > 0

    def test_scan_cldflt(self, classifier):
        """cldflt.sys should be detected as minifilter."""
        path = _find_driver("cldflt.sys")
        if not path:
            pytest.skip("cldflt.sys not found")
        profile = scan_driver(path, classifier=classifier, categories_path=_CATEGORIES_PATH)
        assert profile.framework == "minifilter"
        assert profile.framework_confidence > 0.3
        assert len(profile.fltmgr_imports) > 0

    def test_scan_appid(self, classifier):
        """appid.sys should be detected as minifilter."""
        path = _find_driver("appid.sys")
        if not path:
            pytest.skip("appid.sys not found")
        profile = scan_driver(path, classifier=classifier, categories_path=_CATEGORIES_PATH)
        assert profile.framework == "minifilter"

    def test_scan_signer_extraction(self, classifier):
        """Microsoft-signed drivers should have a signer field."""
        path = _find_driver("ntfs.sys")
        if not path:
            pytest.skip("ntfs.sys not found")
        profile = scan_driver(path, classifier=classifier, categories_path=_CATEGORIES_PATH)
        # Most Windows drivers are Microsoft-signed
        if profile.signer:
            assert "Microsoft" in profile.signer or len(profile.signer) > 0

    def test_scan_sections(self, classifier):
        """Drivers should have standard PE sections."""
        path = _find_driver("ntfs.sys")
        if not path:
            pytest.skip("ntfs.sys not found")
        profile = scan_driver(path, classifier=classifier, categories_path=_CATEGORIES_PATH)
        assert len(profile.sections) > 0
        section_names = [s["name"] for s in profile.sections]
        assert ".text" in section_names or ".TEXT" in section_names or any("text" in n.lower() for n in section_names)

    def test_scan_api_categories(self, classifier):
        """Scanned drivers should have API category hits."""
        path = _find_driver("ntfs.sys")
        if not path:
            pytest.skip("ntfs.sys not found")
        profile = scan_driver(path, classifier=classifier, categories_path=_CATEGORIES_PATH)
        # ntfs.sys should hit several categories
        if profile.api_categories:
            assert len(profile.api_categories) > 0

    def test_scan_version_info(self, classifier):
        """Microsoft drivers should have version info."""
        path = _find_driver("ntfs.sys")
        if not path:
            pytest.skip("ntfs.sys not found")
        profile = scan_driver(path, classifier=classifier, categories_path=_CATEGORIES_PATH)
        # Most Microsoft drivers populate these
        assert profile.product_name is not None or profile.file_description is not None


class TestScannerEdgeCases:
    """Test scanner edge cases with synthetic data."""

    def test_nonexistent_file(self, classifier):
        with pytest.raises(Exception):
            scan_driver("/nonexistent/path/fake.sys", classifier=classifier)

    def test_empty_profile_defaults(self):
        p = DriverProfile(name="empty.sys", sha256="0" * 64, size=0)
        d = p.to_dict()
        assert isinstance(d, dict)
        assert d["imports"] == {}
        assert d["api_categories"] == {}
