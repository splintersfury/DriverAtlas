"""Tests for driveratlas.blocklist — LOLDrivers + WDAC lookup."""

import json
import os
import tempfile
import time

import pytest

from driveratlas.blocklist import (
    BlocklistChecker,
    BlocklistEntry,
    BlocklistMatch,
    hash_file_sha256,
)

# ---------------------------------------------------------------------------
# Inline fixtures
# ---------------------------------------------------------------------------

LOLDRIVERS_CSV = """\
Id,Tags,Category,KnownVulnerableSamples_SHA256,Commands_Mitre_id,Verified,Commands_Command_Description
abc123,RTCore64,vulnerable driver,aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222,T1068,TRUE,MSI Afterburner
def456,DbUtil,malicious,1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff,T1014,FALSE,Dell BIOS util
multi01,MultiHash,vulnerable driver,"aaaa000000000000000000000000000000000000000000000000000000000001,aabb000000000000000000000000000000000000000000000000000000000002",,TRUE,Multi-hash entry
"""

WDAC_XML_SNIPPET = """\
<SiPolicy>
  <FileRules>
    <Deny ID="ID_DENY_1" FriendlyName="baddriver.sys" Hash="dddd0000111122223333444455556666777788889999aaaabbbbccccddddeee1" />
    <Deny ID="ID_DENY_2" FriendlyName="path\\evildrv.sys" Hash="dddd0000111122223333444455556666777788889999aaaabbbbccccddddeee2" />
    <Deny ID="ID_DENY_SHORT" FriendlyName="shortsha1.sys" Hash="aabbccdd" />
  </FileRules>
</SiPolicy>
"""


# ---------------------------------------------------------------------------
# TestBlocklistEntry
# ---------------------------------------------------------------------------

class TestBlocklistEntry:
    def test_to_dict(self):
        e = BlocklistEntry(
            sha256="abcd" * 16,
            source="loldrivers",
            category="vulnerable driver",
            driver_name="RTCore64",
            mitre_id="T1068",
            verified=True,
        )
        d = e.to_dict()
        assert d["sha256"] == "abcd" * 16
        assert d["source"] == "loldrivers"
        assert d["category"] == "vulnerable driver"
        assert d["verified"] is True

    def test_defaults(self):
        e = BlocklistEntry(sha256="a" * 64, source="wdac", category="blocked")
        assert e.driver_name == ""
        assert e.mitre_id == ""
        assert e.loads_despite_hvci is False


# ---------------------------------------------------------------------------
# TestBlocklistMatch
# ---------------------------------------------------------------------------

class TestBlocklistMatch:
    def test_clean_match(self):
        m = BlocklistMatch(sha256="a" * 64, matched=False)
        assert m.badge() == "-"
        assert m.sources == []
        assert not m.is_malicious
        assert not m.is_vulnerable

    def test_single_hit(self):
        entry = BlocklistEntry(
            sha256="a" * 64, source="loldrivers", category="vulnerable driver",
        )
        m = BlocklistMatch(sha256="a" * 64, matched=True, entries=[entry])
        assert "VULNERABLE" in m.badge()
        assert "loldrivers" in m.badge()
        assert m.is_vulnerable
        assert not m.is_malicious
        assert m.sources == ["loldrivers"]

    def test_malicious_hit(self):
        entry = BlocklistEntry(
            sha256="a" * 64, source="loldrivers", category="malicious",
        )
        m = BlocklistMatch(sha256="a" * 64, matched=True, entries=[entry])
        assert m.is_malicious

    def test_multi_source(self):
        e1 = BlocklistEntry(sha256="a" * 64, source="loldrivers", category="vulnerable driver")
        e2 = BlocklistEntry(sha256="a" * 64, source="wdac", category="blocked")
        m = BlocklistMatch(sha256="a" * 64, matched=True, entries=[e1, e2])
        assert m.sources == ["loldrivers", "wdac"]
        assert "VULNERABLE" in m.badge()
        assert "BLOCKED" in m.badge()

    def test_to_dict(self):
        entry = BlocklistEntry(sha256="a" * 64, source="wdac", category="blocked")
        m = BlocklistMatch(sha256="a" * 64, matched=True, entries=[entry])
        d = m.to_dict()
        assert d["matched"] is True
        assert len(d["entries"]) == 1
        assert d["entries"][0]["source"] == "wdac"


# ---------------------------------------------------------------------------
# TestBlocklistChecker
# ---------------------------------------------------------------------------

class TestBlocklistChecker:
    def test_parse_loldrivers_csv(self):
        index = BlocklistChecker.parse_loldrivers_csv_data(LOLDRIVERS_CSV)
        # Row 1: single hash
        sha1 = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        assert sha1 in index
        assert index[sha1].source == "loldrivers"
        assert index[sha1].category == "vulnerable driver"
        assert index[sha1].verified is True

    def test_parse_loldrivers_malicious(self):
        index = BlocklistChecker.parse_loldrivers_csv_data(LOLDRIVERS_CSV)
        sha2 = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
        assert sha2 in index
        assert index[sha2].category == "malicious"
        assert index[sha2].verified is False

    def test_parse_loldrivers_multi_hash(self):
        """Comma-separated SHA256 values in one row should produce multiple entries."""
        index = BlocklistChecker.parse_loldrivers_csv_data(LOLDRIVERS_CSV)
        sha_a = "aaaa000000000000000000000000000000000000000000000000000000000001"
        sha_b = "aabb000000000000000000000000000000000000000000000000000000000002"
        assert sha_a in index
        assert sha_b in index
        assert index[sha_a].driver_name == "MultiHash"
        assert index[sha_b].driver_name == "MultiHash"

    def test_parse_wdac_xml(self):
        checker = BlocklistChecker()
        index = checker._parse_wdac_xml(WDAC_XML_SNIPPET)
        sha1 = "dddd0000111122223333444455556666777788889999aaaabbbbccccddddeee1"
        sha2 = "dddd0000111122223333444455556666777788889999aaaabbbbccccddddeee2"
        assert sha1 in index
        assert index[sha1].source == "wdac"
        assert index[sha1].category == "blocked"
        assert index[sha1].driver_name == "baddriver.sys"
        # Backslash path should extract filename
        assert sha2 in index
        assert index[sha2].driver_name == "evildrv.sys"
        # Short hash should be skipped
        assert len(index) == 2

    def test_cache_ttl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_path = os.path.join(tmpdir, "test.meta.json")
            checker = BlocklistChecker(cache_dir=tmpdir, ttl=10)

            # No meta file -> not fresh
            assert not checker._cache_fresh(meta_path)

            # Fresh meta -> fresh
            checker._write_meta(meta_path)
            assert checker._cache_fresh(meta_path)

            # Expired meta -> not fresh
            with open(meta_path, "w") as f:
                json.dump({"timestamp": time.time() - 20}, f)
            assert not checker._cache_fresh(meta_path)

    def test_lookup_hit_and_miss(self):
        checker = BlocklistChecker()
        checker._loaded = True
        sha_hit = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        checker._loldrivers = BlocklistChecker.parse_loldrivers_csv_data(LOLDRIVERS_CSV)
        checker._wdac = {}

        hit = checker.lookup(sha_hit)
        assert hit.matched
        assert len(hit.entries) == 1
        assert hit.entries[0].source == "loldrivers"

        miss = checker.lookup("0000" * 16)
        assert not miss.matched
        assert miss.entries == []

    def test_lookup_many(self):
        checker = BlocklistChecker()
        checker._loaded = True
        checker._loldrivers = BlocklistChecker.parse_loldrivers_csv_data(LOLDRIVERS_CSV)
        checker._wdac = {}

        sha_hit = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        sha_miss = "0000" * 16
        results = checker.lookup_many([sha_hit, sha_miss])
        assert results[sha_hit].matched
        assert not results[sha_miss].matched

    def test_stats(self):
        checker = BlocklistChecker()
        checker._loaded = True
        checker._loldrivers = BlocklistChecker.parse_loldrivers_csv_data(LOLDRIVERS_CSV)
        checker._wdac = checker._parse_wdac_xml(WDAC_XML_SNIPPET)

        s = checker.stats
        assert s["loldrivers"] == 4  # 1 + 1 + 2 from multi-hash row
        assert s["wdac"] == 2

    def test_offline_fallback_empty(self):
        """With no cache and no network, checker returns empty dicts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            checker = BlocklistChecker(cache_dir=tmpdir, ttl=0)
            # Monkeypatch _fetch_url to always return None (simulate offline)
            checker._fetch_url = lambda url: None
            checker.load()
            assert checker.stats == {"loldrivers": 0, "wdac": 0}

    def test_offline_fallback_stale_cache(self):
        """With stale cache and no network, checker uses stale data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            checker = BlocklistChecker(cache_dir=tmpdir, ttl=0)

            # Write a stale loldrivers cache
            csv_path = os.path.join(tmpdir, "loldrivers.csv")
            with open(csv_path, "w") as f:
                f.write(LOLDRIVERS_CSV)

            # Write a stale wdac cache
            wdac_entries = checker._parse_wdac_xml(WDAC_XML_SNIPPET)
            wdac_path = os.path.join(tmpdir, "wdac_hashes.json")
            with open(wdac_path, "w") as f:
                json.dump({sha: e.to_dict() for sha, e in wdac_entries.items()}, f)

            # No meta files -> ttl=0 means not fresh -> tries network -> fails -> falls back
            checker._fetch_url = lambda url: None
            checker.load()
            assert checker.stats["loldrivers"] == 4
            assert checker.stats["wdac"] == 2


# ---------------------------------------------------------------------------
# TestHashFile
# ---------------------------------------------------------------------------

class TestHashFile:
    def test_hash_file_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sys") as f:
            f.write(b"hello driver world")
            path = f.name
        try:
            h = hash_file_sha256(path)
            assert len(h) == 64
            assert h == hash_file_sha256(path)  # deterministic
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# TestCheckCLI
# ---------------------------------------------------------------------------

class TestCheckCLI:
    def test_check_sha256_clean(self):
        from click.testing import CliRunner
        from driveratlas.cli import main

        runner = CliRunner()
        # Use a SHA256 that won't be in any blocklist
        result = runner.invoke(main, ["check", "0" * 64, "--no-network"])
        assert result.exit_code == 0
        assert "CLEAN" in result.output

    def test_check_json_output(self):
        from click.testing import CliRunner
        from driveratlas.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["check", "0" * 64, "--no-network", "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["matched"] is False

    def test_check_invalid_sha(self):
        from click.testing import CliRunner
        from driveratlas.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["check", "not_a_sha"])
        assert result.exit_code != 0 or "invalid" in result.output.lower() or "not a valid" in result.output.lower()
