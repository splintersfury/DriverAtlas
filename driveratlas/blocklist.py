"""LOLDrivers and WDAC blocklist lookup for known-vulnerable driver triage."""

import csv
import hashlib
import io
import json
import logging
import os
import time
from dataclasses import dataclass, field

logger = logging.getLogger("driveratlas.blocklist")

LOLDRIVERS_CSV_URL = "https://www.loldrivers.io/api/drivers.csv"
WDAC_BLOCKLIST_URL = (
    "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/"
    "public/windows/security/application-security/application-control/"
    "app-control-for-business/design/"
    "applications-that-can-bypass-appcontrol.md"
)

DEFAULT_CACHE_DIR = os.path.expanduser("~/.driveratlas/cache")
DEFAULT_TTL = 86400  # 24 hours


@dataclass
class BlocklistEntry:
    """One record from a blocklist source."""

    sha256: str
    source: str  # "loldrivers" | "wdac"
    category: str  # "vulnerable driver" | "malicious" | "blocked"
    driver_name: str = ""
    mitre_id: str = ""
    verified: bool = False
    loads_despite_hvci: bool = False
    company: str = ""

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "source": self.source,
            "category": self.category,
            "driver_name": self.driver_name,
            "mitre_id": self.mitre_id,
            "verified": self.verified,
            "loads_despite_hvci": self.loads_despite_hvci,
            "company": self.company,
        }


@dataclass
class BlocklistMatch:
    """Result of checking one SHA256 against all blocklists."""

    sha256: str
    matched: bool
    entries: list[BlocklistEntry] = field(default_factory=list)

    @property
    def sources(self) -> list[str]:
        return sorted({e.source for e in self.entries})

    @property
    def is_malicious(self) -> bool:
        return any(e.category == "malicious" for e in self.entries)

    @property
    def is_vulnerable(self) -> bool:
        return any(e.category == "vulnerable driver" for e in self.entries)

    def badge(self) -> str:
        """Short display string for table columns."""
        if not self.matched:
            return "-"
        parts = []
        for entry in self.entries:
            label = entry.category.upper().replace("VULNERABLE DRIVER", "VULNERABLE")
            parts.append(f"{label} {entry.source}")
        return "; ".join(parts)

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "matched": self.matched,
            "entries": [e.to_dict() for e in self.entries],
        }


class BlocklistChecker:
    """Fetch, cache, and look up SHA256 hashes against LOLDrivers and WDAC."""

    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR, ttl: int = DEFAULT_TTL):
        self.cache_dir = os.path.expanduser(cache_dir)
        self.ttl = ttl
        self._loldrivers: dict[str, BlocklistEntry] = {}
        self._wdac: dict[str, BlocklistEntry] = {}
        self._loaded = False

    def load(self):
        """Load both sources from cache or network."""
        os.makedirs(self.cache_dir, exist_ok=True)
        self._loldrivers = self._load_loldrivers()
        self._wdac = self._load_wdac()
        self._loaded = True

    def lookup(self, sha256: str) -> BlocklistMatch:
        """Check a single SHA256 against all loaded blocklists."""
        if not self._loaded:
            self.load()
        sha = sha256.lower().strip()
        entries = []
        if sha in self._loldrivers:
            entries.append(self._loldrivers[sha])
        if sha in self._wdac:
            entries.append(self._wdac[sha])
        return BlocklistMatch(sha256=sha, matched=bool(entries), entries=entries)

    def lookup_many(self, sha256_list: list[str]) -> dict[str, BlocklistMatch]:
        """Batch check multiple SHA256 values."""
        if not self._loaded:
            self.load()
        return {sha: self.lookup(sha) for sha in sha256_list}

    @property
    def stats(self) -> dict[str, int]:
        if not self._loaded:
            self.load()
        return {"loldrivers": len(self._loldrivers), "wdac": len(self._wdac)}

    # -- LOLDrivers -----------------------------------------------------------

    def _load_loldrivers(self) -> dict[str, BlocklistEntry]:
        csv_path = os.path.join(self.cache_dir, "loldrivers.csv")
        meta_path = csv_path + ".meta.json"

        if self._cache_fresh(meta_path):
            try:
                return self._parse_loldrivers_csv(csv_path)
            except Exception as e:
                logger.warning("Cached LOLDrivers CSV corrupted, re-fetching: %s", e)

        # Try network fetch
        raw = self._fetch_url(LOLDRIVERS_CSV_URL)
        if raw is not None:
            try:
                with open(csv_path, "wb") as f:
                    f.write(raw)
                self._write_meta(meta_path)
                return self._parse_loldrivers_csv(csv_path)
            except Exception as e:
                logger.warning("Failed to parse LOLDrivers CSV: %s", e)

        # Fall back to stale cache
        if os.path.exists(csv_path):
            logger.info("Using stale LOLDrivers cache")
            try:
                return self._parse_loldrivers_csv(csv_path)
            except Exception:
                pass

        logger.warning("LOLDrivers blocklist unavailable")
        return {}

    def _parse_loldrivers_csv(self, path: str) -> dict[str, BlocklistEntry]:
        """Parse LOLDrivers CSV into sha256 -> BlocklistEntry index."""
        index: dict[str, BlocklistEntry] = {}
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # SHA256 field may contain comma-separated hashes
                sha_field = row.get("KnownVulnerableSamples_SHA256", "")
                if not sha_field:
                    continue
                hashes = [h.strip().lower() for h in sha_field.split(",") if h.strip()]

                driver_name = row.get("Tags", "") or row.get("Id", "")
                category_raw = row.get("Category", "vulnerable driver").strip().lower()
                if category_raw not in ("vulnerable driver", "malicious"):
                    category_raw = "vulnerable driver"
                mitre_id = row.get("Commands_Mitre_id", "") or ""
                verified = row.get("Verified", "").strip().upper() == "TRUE"
                company = row.get("Commands_Command_Description", "") or ""

                for sha in hashes:
                    if len(sha) == 64:  # valid SHA256 length
                        index[sha] = BlocklistEntry(
                            sha256=sha,
                            source="loldrivers",
                            category=category_raw,
                            driver_name=driver_name,
                            mitre_id=mitre_id,
                            verified=verified,
                            company=company,
                        )
        logger.info("Loaded %d LOLDrivers hashes", len(index))
        return index

    @classmethod
    def parse_loldrivers_csv_data(cls, csv_text: str) -> dict[str, BlocklistEntry]:
        """Parse LOLDrivers CSV from a string (for testing)."""
        index: dict[str, BlocklistEntry] = {}
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            sha_field = row.get("KnownVulnerableSamples_SHA256", "")
            if not sha_field:
                continue
            hashes = [h.strip().lower() for h in sha_field.split(",") if h.strip()]

            driver_name = row.get("Tags", "") or row.get("Id", "")
            category_raw = row.get("Category", "vulnerable driver").strip().lower()
            if category_raw not in ("vulnerable driver", "malicious"):
                category_raw = "vulnerable driver"
            mitre_id = row.get("Commands_Mitre_id", "") or ""
            verified = row.get("Verified", "").strip().upper() == "TRUE"
            company = row.get("Commands_Command_Description", "") or ""

            for sha in hashes:
                if len(sha) == 64:
                    index[sha] = BlocklistEntry(
                        sha256=sha,
                        source="loldrivers",
                        category=category_raw,
                        driver_name=driver_name,
                        mitre_id=mitre_id,
                        verified=verified,
                        company=company,
                    )
        return index

    # -- WDAC -----------------------------------------------------------------

    def _load_wdac(self) -> dict[str, BlocklistEntry]:
        cache_path = os.path.join(self.cache_dir, "wdac_hashes.json")
        meta_path = cache_path + ".meta.json"

        if self._cache_fresh(meta_path):
            try:
                return self._load_wdac_cache(cache_path)
            except Exception as e:
                logger.warning("Cached WDAC data corrupted, re-fetching: %s", e)

        raw = self._fetch_url(WDAC_BLOCKLIST_URL)
        if raw is not None:
            try:
                entries = self._parse_wdac_xml(raw.decode("utf-8", errors="replace"))
                self._save_wdac_cache(cache_path, entries)
                self._write_meta(meta_path)
                return entries
            except Exception as e:
                logger.warning("Failed to parse WDAC blocklist: %s", e)

        # Fall back to stale cache
        if os.path.exists(cache_path):
            logger.info("Using stale WDAC cache")
            try:
                return self._load_wdac_cache(cache_path)
            except Exception:
                pass

        logger.warning("WDAC blocklist unavailable")
        return {}

    def _parse_wdac_xml(self, text: str) -> dict[str, BlocklistEntry]:
        """Extract Deny rules from WDAC policy XML embedded in markdown."""
        import re

        index: dict[str, BlocklistEntry] = {}

        # Extract SHA256 hashes from Deny rules
        # Pattern: <Deny ID="..." FriendlyName="..." Hash="..." />
        # The Hash field can be SHA1, SHA256, or SHA256 Page hashes
        deny_pattern = re.compile(
            r'<Deny\s+[^>]*?'
            r'FriendlyName="([^"]*)"[^>]*?'
            r'Hash="([^"]*)"',
            re.IGNORECASE,
        )
        for match in deny_pattern.finditer(text):
            friendly_name = match.group(1)
            hash_val = match.group(2)

            # WDAC uses raw hex bytes for hashes; SHA256 = 32 bytes = 64 hex chars
            hex_hash = hash_val.strip().lower()
            if len(hex_hash) != 64:
                continue

            # Extract driver name from FriendlyName (format varies)
            driver_name = friendly_name.split("\\")[-1] if "\\" in friendly_name else friendly_name

            index[hex_hash] = BlocklistEntry(
                sha256=hex_hash,
                source="wdac",
                category="blocked",
                driver_name=driver_name,
            )

        # Also try alternate XML format with Hash attribute order variations
        deny_alt = re.compile(
            r'<Deny\s+[^>]*?'
            r'Hash="([^"]*)"[^>]*?'
            r'FriendlyName="([^"]*)"',
            re.IGNORECASE,
        )
        for match in deny_alt.finditer(text):
            hash_val = match.group(1)
            friendly_name = match.group(2)

            hex_hash = hash_val.strip().lower()
            if len(hex_hash) != 64:
                continue
            if hex_hash in index:
                continue

            driver_name = friendly_name.split("\\")[-1] if "\\" in friendly_name else friendly_name
            index[hex_hash] = BlocklistEntry(
                sha256=hex_hash,
                source="wdac",
                category="blocked",
                driver_name=driver_name,
            )

        logger.info("Loaded %d WDAC hashes", len(index))
        return index

    def _save_wdac_cache(self, path: str, entries: dict[str, BlocklistEntry]):
        data = {sha: e.to_dict() for sha, e in entries.items()}
        with open(path, "w") as f:
            json.dump(data, f)

    def _load_wdac_cache(self, path: str) -> dict[str, BlocklistEntry]:
        with open(path) as f:
            data = json.load(f)
        return {
            sha: BlocklistEntry(**vals)
            for sha, vals in data.items()
        }

    # -- Shared helpers -------------------------------------------------------

    def _cache_fresh(self, meta_path: str) -> bool:
        if not os.path.exists(meta_path):
            return False
        try:
            with open(meta_path) as f:
                meta = json.load(f)
            return (time.time() - meta.get("timestamp", 0)) < self.ttl
        except (json.JSONDecodeError, OSError):
            return False

    def _write_meta(self, meta_path: str):
        with open(meta_path, "w") as f:
            json.dump({"timestamp": time.time()}, f)

    def _fetch_url(self, url: str) -> bytes | None:
        try:
            import requests
        except ImportError:
            logger.warning(
                "requests not installed — install with: pip install 'driveratlas[blocklist]'"
            )
            return None
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            logger.warning("Failed to fetch %s: %s", url, e)
            return None


def hash_file_sha256(path: str) -> str:
    """Compute SHA256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().lower()
