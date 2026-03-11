"""LOLDrivers batch analysis pipeline.

Downloads every driver from LOLDrivers.io via VirusTotal, runs DriverAtlas
Tier 1 (PE scan) and Tier 2 (Ghidra deep analysis) on each, and exports
a comprehensive dataset for KernelSight publication.
"""

import csv
import hashlib
import io
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("driveratlas.loldrivers_pipeline")

# ── Configuration ──────────────────────────────────────────────────────

LOLDRIVERS_CSV_URL = "https://www.loldrivers.io/api/drivers.csv"
DEFAULT_WORK_DIR = os.path.expanduser("~/.driveratlas/loldrivers")
VT_DOWNLOAD_URL = "https://www.virustotal.com/api/v3/files/{sha256}/download"
VT_RATE_LIMIT_DELAY = 15.5  # VT standard API: 4 requests/min


@dataclass
class LOLDriverEntry:
    """A single LOLDrivers catalog entry."""
    sha256: str
    driver_name: str = ""
    category: str = ""        # "vulnerable driver" | "malicious"
    mitre_id: str = ""
    verified: bool = False
    company: str = ""


@dataclass
class AnalysisResult:
    """Combined Tier 1 + Tier 2 result for a single driver."""
    sha256: str
    driver_name: str = ""
    lol_category: str = ""
    lol_mitre_id: str = ""
    lol_verified: bool = False
    lol_company: str = ""

    # Tier 1: PE scan
    machine: str = ""
    subsystem: str = ""
    size: int = 0
    signer: str = ""
    framework: str = ""
    import_count: int = 0
    imphash: str = ""
    mitigations_on: list = field(default_factory=list)
    mitigations_off: list = field(default_factory=list)
    device_names: list = field(default_factory=list)
    symbolic_links: list = field(default_factory=list)
    dangerous_imports: list = field(default_factory=list)
    api_categories: dict = field(default_factory=dict)
    sections: list = field(default_factory=list)

    # Attack surface score
    score: float = 0.0
    risk_level: str = ""
    score_flags: list = field(default_factory=list)

    # Tier 2: Ghidra deep analysis
    ioctl_count: int = 0
    ioctls: list = field(default_factory=list)      # Summarized IOCTL info
    deep_dives: list = field(default_factory=list)   # Per-IOCTL deep dive
    neither_io_count: int = 0
    taint_path_count: int = 0
    taint_paths: list = field(default_factory=list)
    missing_checks_count: int = 0
    gadget_total: int = 0
    gadget_categories: dict = field(default_factory=dict)
    high_value_gadgets: list = field(default_factory=list)
    yara_rule: str = ""

    # Status
    tier1_ok: bool = False
    tier2_ok: bool = False
    error: str = ""
    analysis_date: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Phase 0: Fetch LOLDrivers catalog ──────────────────────────────────

def fetch_loldrivers_catalog(cache_dir: str = DEFAULT_WORK_DIR) -> list:
    """Fetch LOLDrivers CSV and parse into LOLDriverEntry objects.

    Returns:
        List of LOLDriverEntry with unique SHA256 hashes
    """
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, "drivers.csv")

    # Use cache if < 24h old
    if os.path.exists(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        if age < 86400:
            logger.info(f"Using cached LOLDrivers CSV ({age/3600:.1f}h old)")
            with open(cache_path, "r") as f:
                return _parse_csv(f.read())

    logger.info(f"Fetching LOLDrivers catalog from {LOLDRIVERS_CSV_URL}")
    resp = requests.get(LOLDRIVERS_CSV_URL, timeout=30)
    resp.raise_for_status()

    with open(cache_path, "w") as f:
        f.write(resp.text)

    return _parse_csv(resp.text)


def _parse_csv(text: str) -> list:
    """Parse LOLDrivers CSV into LOLDriverEntry objects."""
    entries = {}  # sha256 -> LOLDriverEntry (deduplicate)
    reader = csv.DictReader(io.StringIO(text))

    for row in reader:
        sha256_field = row.get("KnownVulnerableSamples_SHA256", "")
        hashes = [h.strip().lower() for h in sha256_field.split(",") if len(h.strip()) == 64]

        for sha in hashes:
            if sha in entries:
                continue
            entries[sha] = LOLDriverEntry(
                sha256=sha,
                driver_name=row.get("Tags", row.get("Id", "")),
                category=row.get("Category", "").lower().strip(),
                mitre_id=row.get("Commands_Mitre_id", ""),
                verified=row.get("Verified", "").upper() == "TRUE",
                company=row.get("Commands_Command_Description", ""),
            )

    logger.info(f"Parsed {len(entries)} unique driver hashes from LOLDrivers")
    return list(entries.values())


# ── Phase 1: Download binaries from VirusTotal ─────────────────────────

def download_from_vt(
    sha256: str,
    vt_api_key: str,
    download_dir: str,
) -> Optional[str]:
    """Download a driver binary from VirusTotal.

    Returns:
        Path to downloaded file, or None on failure
    """
    out_path = os.path.join(download_dir, f"{sha256}.sys")
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        return out_path

    url = VT_DOWNLOAD_URL.format(sha256=sha256)
    headers = {"x-apikey": vt_api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=60)
        if resp.status_code == 200:
            with open(out_path, "wb") as f:
                f.write(resp.content)
            # Verify hash
            actual_hash = hashlib.sha256(resp.content).hexdigest()
            if actual_hash != sha256:
                logger.warning(f"Hash mismatch for {sha256}: got {actual_hash}")
                os.unlink(out_path)
                return None
            return out_path
        elif resp.status_code == 404:
            logger.debug(f"Not found on VT: {sha256}")
            return None
        elif resp.status_code == 429:
            logger.warning("VT rate limit hit, waiting 60s...")
            time.sleep(60)
            return download_from_vt(sha256, vt_api_key, download_dir)
        else:
            logger.warning(f"VT download failed ({resp.status_code}): {sha256}")
            return None
    except Exception as e:
        logger.warning(f"VT download error for {sha256}: {e}")
        return None


def batch_download(
    entries: list,
    vt_api_key: str,
    download_dir: str,
    delay: float = VT_RATE_LIMIT_DELAY,
    max_drivers: int = 0,
) -> dict:
    """Download all LOLDriver binaries from VT.

    Args:
        entries: LOLDriverEntry list
        vt_api_key: VirusTotal API key
        download_dir: Directory to save binaries
        delay: Seconds between requests (rate limiting)
        max_drivers: Limit downloads (0 = all)

    Returns:
        Dict of sha256 -> local path (only successful downloads)
    """
    os.makedirs(download_dir, exist_ok=True)
    downloaded = {}
    to_process = entries[:max_drivers] if max_drivers > 0 else entries
    total = len(to_process)

    for i, entry in enumerate(to_process):
        # Check if already downloaded
        cached_path = os.path.join(download_dir, f"{entry.sha256}.sys")
        if os.path.exists(cached_path) and os.path.getsize(cached_path) > 0:
            downloaded[entry.sha256] = cached_path
            continue

        logger.info(f"[{i+1}/{total}] Downloading {entry.driver_name or entry.sha256[:16]}...")
        path = download_from_vt(entry.sha256, vt_api_key, download_dir)
        if path:
            downloaded[entry.sha256] = path

        # Rate limit (skip delay for cached files)
        if i < total - 1:
            time.sleep(delay)

    logger.info(f"Downloaded {len(downloaded)}/{total} drivers")
    return downloaded


# ── Phase 2: Tier 1 PE scan ────────────────────────────────────────────

def run_tier1(driver_path: str, entry: LOLDriverEntry) -> AnalysisResult:
    """Run Tier 1 PE scan on a driver binary.

    Returns:
        AnalysisResult with Tier 1 fields populated
    """
    from .scanner import scan_driver
    from .framework_detect import FrameworkClassifier
    from .scoring import AttackSurfaceScorer

    _pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fw_path = os.path.join(_pkg_root, "signatures", "frameworks.yaml")
    cats_path = os.path.join(_pkg_root, "signatures", "api_categories.yaml")
    score_path = os.path.join(_pkg_root, "signatures", "attack_surface.yaml")

    result = AnalysisResult(
        sha256=entry.sha256,
        driver_name=entry.driver_name,
        lol_category=entry.category,
        lol_mitre_id=entry.mitre_id,
        lol_verified=entry.verified,
        lol_company=entry.company,
        analysis_date=datetime.now(timezone.utc).isoformat(),
    )

    try:
        classifier = FrameworkClassifier(fw_path) if os.path.exists(fw_path) else None
        cats = cats_path if os.path.exists(cats_path) else None
        profile = scan_driver(driver_path, classifier=classifier, categories_path=cats)

        result.machine = profile.machine
        result.subsystem = profile.subsystem
        result.size = profile.size
        result.signer = profile.signer or ""
        result.framework = profile.framework
        result.import_count = profile.import_count
        result.imphash = profile.imphash
        result.mitigations_on = profile.mitigations_on
        result.mitigations_off = profile.mitigations_off
        result.device_names = profile.device_names
        result.symbolic_links = profile.symbolic_links
        result.api_categories = profile.api_categories
        result.sections = profile.sections

        # Extract dangerous imports
        from .tier2.yara_generator import DANGEROUS_IMPORTS
        from .tier2.ioctl_analyzer import SENSITIVE_APIS
        all_imports = []
        for funcs in profile.imports.values():
            all_imports.extend(funcs)
        result.dangerous_imports = sorted(set(
            imp for imp in all_imports
            if imp in DANGEROUS_IMPORTS or imp in SENSITIVE_APIS
        ))

        # Score
        if os.path.exists(score_path):
            scorer = AttackSurfaceScorer(score_path)
            score = scorer.score(profile)
            result.score = score.total
            result.risk_level = score.risk_level
            result.score_flags = score.flags

        result.tier1_ok = True

    except Exception as e:
        result.error = f"Tier 1 failed: {e}"
        logger.warning(f"Tier 1 failed for {entry.sha256[:16]}: {e}")

    return result


# ── Phase 3: Tier 2 Ghidra deep analysis ──────────────────────────────

def run_tier2(driver_path: str, result: AnalysisResult,
              ghidra_home: Optional[str] = None,
              timeout: int = 600) -> AnalysisResult:
    """Run Tier 2 Ghidra deep analysis and update the AnalysisResult in place."""
    from .tier2.ghidra_runner import GhidraRunner
    from .tier2.ioctl_analyzer import parse_dispatch_table, deep_dive_all
    from .tier2.taint_analyzer import analyze_taint, analyze_security_checks
    from .tier2.gadget_scanner import scan_gadgets, generate_gadget_summary
    from .tier2.yara_generator import generate_yara
    from .tier2 import Tier2Result

    try:
        runner = GhidraRunner(ghidra_home=ghidra_home, timeout=timeout)
    except FileNotFoundError as e:
        result.error = f"Ghidra not found: {e}"
        return result

    try:
        dispatch_data = runner.analyze(driver_path)

        # IOCTLs
        ioctls = parse_dispatch_table(dispatch_data)
        result.ioctl_count = len(ioctls)
        result.neither_io_count = sum(1 for i in ioctls if i.uses_neither_io)
        result.ioctls = [
            {
                "code_hex": i.code_hex,
                "method": i.method.name,
                "access": i.access.name,
                "label": i.label,
                "api_calls": i.api_calls,
                "neither_io": i.uses_neither_io,
            }
            for i in ioctls
        ]

        # Deep dives
        deep_dives = deep_dive_all(ioctls)
        result.deep_dives = [dd.to_dict() for dd in deep_dives]

        # Taint
        taint_paths = analyze_taint(dispatch_data)
        result.taint_path_count = len(taint_paths)
        result.taint_paths = [t.to_dict() for t in taint_paths]

        # Security checks
        checks = analyze_security_checks(dispatch_data)
        result.missing_checks_count = sum(1 for c in checks if not c.present)

        # Gadgets
        gadget_list = scan_gadgets(driver_path, max_gadgets=500)
        gadget_summary = generate_gadget_summary(gadget_list)
        result.gadget_total = gadget_summary.get("total", 0)
        result.gadget_categories = gadget_summary.get("by_category", {})
        result.high_value_gadgets = gadget_summary.get("high_value", [])

        # YARA
        tier2_result = Tier2Result(
            driver_name=os.path.basename(driver_path),
            sha256=result.sha256,
            ioctls=ioctls,
            taint_paths=taint_paths,
            security_checks=checks,
            gadgets=gadget_list,
        )
        result.yara_rule = generate_yara(tier2_result)

        result.tier2_ok = True

    except Exception as e:
        result.error = f"Tier 2 failed: {e}"
        logger.warning(f"Tier 2 failed for {result.sha256[:16]}: {e}")

    return result


# ── Phase 4: Full pipeline ─────────────────────────────────────────────

def run_pipeline(
    vt_api_key: str,
    work_dir: str = DEFAULT_WORK_DIR,
    ghidra_home: Optional[str] = None,
    max_drivers: int = 0,
    tier2_enabled: bool = True,
    ghidra_timeout: int = 600,
    resume: bool = True,
) -> list:
    """Run the full LOLDrivers analysis pipeline.

    Args:
        vt_api_key: VirusTotal API key
        work_dir: Working directory for downloads and results
        ghidra_home: Ghidra install directory
        max_drivers: Limit number of drivers (0 = all)
        tier2_enabled: Run Tier 2 Ghidra analysis
        ghidra_timeout: Ghidra timeout per driver
        resume: Resume from previous run (skip already analyzed)

    Returns:
        List of AnalysisResult
    """
    os.makedirs(work_dir, exist_ok=True)
    download_dir = os.path.join(work_dir, "binaries")
    results_path = os.path.join(work_dir, "results.json")

    # Load previous results for resume
    previous = {}
    if resume and os.path.exists(results_path):
        with open(results_path, "r") as f:
            for r in json.load(f):
                previous[r["sha256"]] = r
        logger.info(f"Resuming: {len(previous)} previous results loaded")

    # Fetch catalog
    entries = fetch_loldrivers_catalog(work_dir)
    logger.info(f"LOLDrivers catalog: {len(entries)} unique hashes")

    # Download
    downloaded = batch_download(
        entries, vt_api_key, download_dir,
        max_drivers=max_drivers,
    )
    logger.info(f"Binaries available: {len(downloaded)}")

    # Analyze
    results = []
    entry_map = {e.sha256: e for e in entries}
    to_analyze = list(downloaded.items())
    total = len(to_analyze)

    for i, (sha256, driver_path) in enumerate(to_analyze):
        entry = entry_map[sha256]

        # Skip if already analyzed with required tier
        if sha256 in previous:
            prev = previous[sha256]
            if prev.get("tier1_ok"):
                if not tier2_enabled or prev.get("tier2_ok"):
                    results.append(prev)
                    continue

        logger.info(f"[{i+1}/{total}] Analyzing {entry.driver_name or sha256[:16]}...")

        # Tier 1
        result = run_tier1(driver_path, entry)

        # Tier 2
        if tier2_enabled and result.tier1_ok:
            result = run_tier2(driver_path, result,
                              ghidra_home=ghidra_home,
                              timeout=ghidra_timeout)

        results.append(result.to_dict() if isinstance(result, AnalysisResult) else result)

        # Save progress after each driver
        _save_results(results, results_path)

    _save_results(results, results_path)
    logger.info(f"Pipeline complete: {len(results)} drivers analyzed")
    return results


def _save_results(results: list, path: str):
    """Save results to JSON, atomic write."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(results, f, indent=2, default=str)
    os.replace(tmp, path)


# ── Phase 5: Export for KernelSight ────────────────────────────────────

def export_kernelsight_markdown(
    results_path: str,
    output_path: str,
) -> str:
    """Generate KernelSight markdown page from analysis results.

    Args:
        results_path: Path to results.json
        output_path: Path to write the markdown file

    Returns:
        Path to generated markdown
    """
    with open(results_path, "r") as f:
        results = json.load(f)

    # Filter to successfully analyzed drivers
    analyzed = [r for r in results if r.get("tier1_ok")]
    tier2_done = [r for r in analyzed if r.get("tier2_ok")]

    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = []
    lines.append("# LOLDrivers Deep Analysis")
    lines.append("")
    lines.append("> Automated deep analysis of every driver in the "
                 "[LOLDrivers.io](https://www.loldrivers.io/) catalog, "
                 "powered by [DriverAtlas](https://github.com/splintersfury/DriverAtlas).")
    lines.append("")
    lines.append(f"**Last updated:** {date}  ")
    lines.append(f"**Drivers analyzed:** {len(analyzed)} (Tier 1) / "
                 f"{len(tier2_done)} (Tier 2 deep)  ")

    # Stats
    vuln_count = sum(1 for r in analyzed if r.get("lol_category") == "vulnerable driver")
    mal_count = sum(1 for r in analyzed if r.get("lol_category") == "malicious")
    neither_count = sum(1 for r in tier2_done if r.get("neither_io_count", 0) > 0)
    no_cfg = sum(1 for r in analyzed if "GUARD_CF" in r.get("mitigations_off", []))
    no_integrity = sum(1 for r in analyzed if "FORCE_INTEGRITY" in r.get("mitigations_off", []))
    high_score = sum(1 for r in analyzed if r.get("score", 0) >= 8.0)

    lines.append("")
    lines.append("## Key Statistics")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Vulnerable drivers | {vuln_count} |")
    lines.append(f"| Malicious drivers | {mal_count} |")
    lines.append(f"| Missing CFG | {no_cfg} |")
    lines.append(f"| Missing FORCE_INTEGRITY | {no_integrity} |")
    lines.append(f"| NEITHER I/O (raw user ptrs) | {neither_count} |")
    lines.append(f"| High risk (score >= 8.0) | {high_score} |")

    # Sort by score descending
    analyzed.sort(key=lambda r: r.get("score", 0), reverse=True)

    # Main table
    lines.append("")
    lines.append("## Driver Analysis Table")
    lines.append("")
    lines.append("| Driver | Category | Score | Arch | Mitigations OFF | IOCTLs | "
                 "NEITHER | Gadgets | Dangerous Imports | Signer |")
    lines.append("|--------|----------|-------|------|-----------------|--------|"
                 "---------|---------|-------------------|--------|")

    for r in analyzed:
        name = r.get("driver_name", r["sha256"][:12])
        cat = r.get("lol_category", "")[:12]
        score = r.get("score", 0)
        arch = r.get("machine", "?")
        mits_off = ", ".join(r.get("mitigations_off", []))
        ioctl_count = r.get("ioctl_count", "-")
        neither = r.get("neither_io_count", "-")
        gadget_total = r.get("gadget_total", "-")
        dangerous = ", ".join(r.get("dangerous_imports", [])[:3])
        if len(r.get("dangerous_imports", [])) > 3:
            dangerous += "..."
        signer = (r.get("signer", "") or "unsigned")[:25]

        score_str = f"**{score:.1f}**" if score >= 8.0 else f"{score:.1f}"
        lines.append(
            f"| {name} | {cat} | {score_str} | {arch} | {mits_off} | "
            f"{ioctl_count} | {neither} | {gadget_total} | {dangerous} | {signer} |"
        )

    # Per-driver detail sections (for top 20 highest scored)
    top_drivers = [r for r in analyzed if r.get("tier2_ok")][:20]
    if top_drivers:
        lines.append("")
        lines.append("## Deep Dive: Top Drivers by Attack Surface Score")
        lines.append("")

        for r in top_drivers:
            name = r.get("driver_name", r["sha256"][:12])
            lines.append(f"### {name}")
            lines.append("")
            lines.append(f"**SHA256:** `{r['sha256']}`  ")
            lines.append(f"**Score:** {r.get('score', 0):.1f} | "
                         f"**Category:** {r.get('lol_category', '')} | "
                         f"**Signer:** {r.get('signer', 'unsigned')}  ")
            lines.append(f"**Mitigations ON:** {', '.join(r.get('mitigations_on', []))}  ")
            lines.append(f"**Mitigations OFF:** {', '.join(r.get('mitigations_off', []))}  ")

            if r.get("device_names"):
                lines.append(f"**Devices:** {', '.join(r['device_names'])}  ")

            if r.get("dangerous_imports"):
                lines.append(f"**Dangerous imports:** `{'`, `'.join(r['dangerous_imports'])}`  ")

            # IOCTLs
            if r.get("ioctls"):
                lines.append("")
                lines.append("| IOCTL | Method | Access | Label |")
                lines.append("|-------|--------|--------|-------|")
                for ioctl in r["ioctls"]:
                    method = ioctl.get("method", "")
                    if ioctl.get("neither_io"):
                        method = "**NEITHER**"
                    lines.append(
                        f"| `{ioctl.get('code_hex', '')}` | {method} | "
                        f"{ioctl.get('access', '')} | {ioctl.get('label', '')} |"
                    )

            # Deep dive highlights
            if r.get("deep_dives"):
                risky = [dd for dd in r["deep_dives"]
                         if dd.get("risk") and "No sensitive" not in dd.get("risk", "")]
                if risky:
                    lines.append("")
                    lines.append("**Risk highlights:**")
                    lines.append("")
                    for dd in risky[:5]:
                        lines.append(f"- `{dd.get('code_hex', '')}`: {dd.get('risk', '')}")

            # Gadgets
            if r.get("gadget_total", 0) > 0:
                cats = r.get("gadget_categories", {})
                cat_str = ", ".join(f"{k}: {v}" for k, v in cats.items())
                lines.append(f"\n**Gadgets:** {r['gadget_total']} ({cat_str})")

            lines.append("")
            lines.append("---")
            lines.append("")

    output = "\n".join(lines)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(output)

    logger.info(f"KernelSight page written to {output_path}")
    return output_path


def export_kdu_markdown(
    results_path: str,
    output_path: str,
) -> str:
    """Generate KDU compatibility analysis page from analysis results.

    Args:
        results_path: Path to results.json
        output_path: Path to write the markdown file

    Returns:
        Path to generated markdown
    """
    from .tier2.kdu_scorer import score_batch

    with open(results_path, "r") as f:
        results = json.load(f)

    scores = score_batch(results)
    compatible = [s for s in scores if s.kdu_compatible]
    confirmed = [s for s in compatible if s.confidence == "confirmed"]
    likely = [s for s in compatible if s.confidence == "likely"]

    # Group by action type
    from collections import Counter
    action_counts = Counter(s.best_action for s in compatible)

    # Separate by action type for tables
    map_driver = [s for s in compatible if s.best_action == "MapDriver"]
    map_brute = [s for s in compatible if s.best_action == "MapDriver (physical brute-force)"]
    dkom = [s for s in compatible if s.best_action in ("DKOM", "DSECorruption")]
    dump = [s for s in compatible if s.best_action == "DumpProcess"]

    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = []
    w = lines.append

    w("---")
    w("title: KDU Provider Compatibility Analysis")
    w("description: Which LOLDrivers could be weaponized as KDU providers? Automated analysis of 1,775 drivers.")
    w("---")
    w("")
    w("# KDU Provider Compatibility Analysis")
    w("")
    w("Which [LOLDrivers](https://loldrivers.io) could be weaponized as "
      "[KDU](https://github.com/hfiref0x/KDU) providers? This page answers that question "
      "by mapping each driver's confirmed IOCTL-reachable primitives to KDU's provider requirements.")
    w("")
    w(f"**Last updated:** {date}  ")
    w(f"**Drivers analyzed:** {len(results)} (Tier 1) / "
      f"{sum(1 for r in results if r.get('tier2_ok'))} (Tier 2 Ghidra)  ")
    w("")

    w("## Key Findings")
    w("")
    w("| Metric | Count |")
    w("|--------|-------|")
    w(f"| Total drivers analyzed | {len(results):,} |")
    w(f"| **KDU-compatible** | **{len(compatible)}** ({100*len(compatible)/len(results):.0f}%) |")
    w(f"| Tier 2 confirmed | {len(confirmed)} |")
    w(f"| Tier 1 likely | {len(likely)} |")
    w(f"| MapDriver capable | {len(map_driver)} |")
    w(f"| MapDriver (physical brute-force) | {len(map_brute)} |")
    w(f"| DKOM / DSECorruption | {len(dkom)} |")
    w(f"| DumpProcess | {len(dump)} |")
    w("")

    w("## What This Means")
    w("")
    w("KDU uses vulnerable signed drivers to load unsigned kernel code. "
      "A driver is \"KDU-compatible\" if it exposes memory primitives through its IOCTL handlers "
      "that an attacker can chain into kernel code execution.")
    w("")
    w("- **Confirmed**: Ghidra analysis verified the dangerous API is reachable from an IOCTL handler")
    w("- **Likely**: The driver imports the API, but we haven't confirmed IOCTL reachability yet")
    w("")
    w("KDU supports these actions, from most to least powerful:")
    w("")
    w("1. **MapDriver** - Load arbitrary unsigned code into the kernel (needs physical + virtual memory R/W)")
    w("2. **MapDriver (physical brute-force)** - Same, but uses only physical memory with PML4 brute-forcing")
    w("3. **DKOM** - Direct Kernel Object Manipulation, e.g. hiding processes (needs virtual memory write)")
    w("4. **DSECorruption** - Patch `ci.dll!g_CiOptions` to disable driver signature enforcement")
    w("5. **DumpProcess** - Read arbitrary process memory (needs process handle + virtual memory read)")
    w("")

    # MapDriver confirmed table
    map_confirmed = [s for s in map_driver if s.confidence == "confirmed"]
    if map_confirmed:
        w("## Confirmed MapDriver Candidates")
        w("")
        w(f"These {len(map_confirmed)} drivers have Ghidra-confirmed physical + virtual memory "
          "primitives reachable from IOCTL handlers. They could load unsigned kernel code.")
        w("")
        w("| # | Driver | Primitives (confirmed IOCTLs) | NEITHER I/O | Mitigations OFF |")
        w("|---|--------|------------------------------|-------------|-----------------|")
        for i, s in enumerate(map_confirmed, 1):
            name = s.driver_name or s.sha256[:16]
            # Show unique IOCTL codes with confirmed primitives
            confirmed_ioctls = set()
            for p in s.primitives:
                if p.confidence == "high" and p.ioctl_code != "unknown":
                    confirmed_ioctls.add(p.ioctl_code)
            ioctl_str = ", ".join(sorted(confirmed_ioctls)[:4])
            if len(confirmed_ioctls) > 4:
                ioctl_str += f" (+{len(confirmed_ioctls)-4})"
            prim_types = sorted(set(p.primitive_type for p in s.primitives if p.confidence == "high"))
            prim_short = ", ".join(p.replace("Physical", "Phys").replace("Memory", "Mem")
                                    .replace("Kernel", "K").replace("Virtual", "V")
                                    for p in prim_types)
            neither = "YES" if s.has_neither_io else ""
            mits = ", ".join(s.missing_mitigations[:3])
            w(f"| {i} | `{name}` | {prim_short} | {neither} | {mits} |")
        w("")

    # Physical brute-force table
    brute_confirmed = [s for s in map_brute if s.confidence == "confirmed"]
    if brute_confirmed:
        w("## Confirmed Physical Brute-Force Candidates")
        w("")
        w(f"These {len(brute_confirmed)} drivers have confirmed physical memory R/W but lack virtual memory. "
          "KDU can brute-force PML4 via physical scanning to achieve MapDriver.")
        w("")
        w("| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |")
        w("|---|--------|---------------|-------------|-----------------|")
        for i, s in enumerate(brute_confirmed[:30], 1):
            name = s.driver_name or s.sha256[:16]
            apis = set()
            for p in s.primitives:
                if p.confidence == "high":
                    apis.update(p.confirming_apis)
            apis_str = ", ".join(sorted(apis)[:4])
            neither = "YES" if s.has_neither_io else ""
            mits = ", ".join(s.missing_mitigations[:3])
            w(f"| {i} | `{name}` | `{apis_str}` | {neither} | {mits} |")
        if len(brute_confirmed) > 30:
            w(f"| ... | *{len(brute_confirmed)-30} more* | | | |")
        w("")

    # DKOM/DSE table
    dkom_confirmed = [s for s in dkom if s.confidence == "confirmed"]
    if dkom_confirmed:
        w("## Confirmed DKOM / DSECorruption Candidates")
        w("")
        w(f"These {len(dkom_confirmed)} drivers have confirmed virtual memory write primitives. "
          "They can manipulate kernel objects or patch `ci.dll` to disable signature enforcement.")
        w("")
        w("| # | Driver | Confirmed APIs | NEITHER I/O | Mitigations OFF |")
        w("|---|--------|---------------|-------------|-----------------|")
        for i, s in enumerate(dkom_confirmed[:30], 1):
            name = s.driver_name or s.sha256[:16]
            apis = set()
            for p in s.primitives:
                if p.confidence == "high":
                    apis.update(p.confirming_apis)
            apis_str = ", ".join(sorted(apis)[:4])
            neither = "YES" if s.has_neither_io else ""
            mits = ", ".join(s.missing_mitigations[:3])
            w(f"| {i} | `{name}` | `{apis_str}` | {neither} | {mits} |")
        if len(dkom_confirmed) > 30:
            w(f"| ... | *{len(dkom_confirmed)-30} more* | | | |")
        w("")

    # Likely candidates (Tier 1 only)
    likely_map = [s for s in map_driver if s.confidence == "likely"]
    if likely_map:
        w("## Likely MapDriver Candidates (Tier 1 only)")
        w("")
        w(f"These {len(likely_map)} drivers import the right APIs but haven't been Ghidra-confirmed yet. "
          "The dangerous imports may be used internally rather than exposed through IOCTLs.")
        w("")
        w("| # | Driver | Imported Primitives | Mitigations OFF |")
        w("|---|--------|-------------------|-----------------|")
        for i, s in enumerate(likely_map[:30], 1):
            name = s.driver_name or s.sha256[:16]
            prim_types = sorted(set(p.primitive_type for p in s.primitives))
            prim_short = ", ".join(p.replace("Physical", "Phys").replace("Memory", "Mem")
                                    .replace("Kernel", "K").replace("Virtual", "V")
                                    for p in prim_types)
            mits = ", ".join(s.missing_mitigations[:3])
            w(f"| {i} | `{name}` | {prim_short} | {mits} |")
        if len(likely_map) > 30:
            w(f"| ... | *{len(likely_map)-30} more* | | |")
        w("")

    # Methodology
    w("## Methodology")
    w("")
    w("1. **Tier 1** (all drivers): PE parsing extracts imports, device names, IOCTLs, and mitigations")
    w("2. **Tier 2** (Ghidra): Headless decompilation traces which imports are called from which IOCTL handlers")
    w("3. **KDU scoring**: Maps confirmed IOCTL-reachable APIs to KDU primitive types "
      "(ReadPhysicalMemory, WriteKernelVM, OpenProcess, etc.)")
    w("4. **Action assessment**: Determines which KDU actions the primitives support "
      "(MapDriver > DKOM > DSECorruption > DumpProcess)")
    w("")
    w("**Confirmed** = Ghidra verified the API call exists inside an IOCTL dispatch handler  ")
    w("**Likely** = The driver imports the API, but IOCTL reachability is unverified")
    w("")
    w("---")
    w("")
    w("*Generated by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) "
      "× [KernelSight](https://splintersfury.github.io/KernelSight/)*")

    output = "\n".join(lines)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(output)

    logger.info(f"KDU analysis page written to {output_path} "
                f"({len(compatible)} compatible, {len(confirmed)} confirmed)")
    return output_path
