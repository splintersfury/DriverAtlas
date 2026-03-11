# DriverAtlas

Windows kernel driver attack surface analysis toolkit. Two-tier static analysis
(PE imports + Ghidra headless decompilation) with KDU provider compatibility
scoring. Built for BYOVD research, driver triage, and large-scale corpus analysis.

Ran against all 1,775 [LOLDrivers](https://www.loldrivers.io/) — results published
on [KernelSight](https://splintersfury.github.io/KernelSight/reference/kdu-compatibility/).

## Quick Start

```bash
pip install -e ".[all]"

# Tier 1: fast PE scan and attack surface score
driveratlas scan /path/to/driver.sys
driveratlas rank /path/to/drivers/ -r --min-score 8.0

# Tier 2: Ghidra headless deep analysis (IOCTL dispatch, taint, gadgets)
driveratlas deep /path/to/driver.sys --ghidra-home /opt/ghidra --gadgets --yara

# KDU assessment: can this driver load unsigned kernel code?
driveratlas kdu /path/to/results.json --top 20

# Full LOLDrivers pipeline: download → Tier 1 → Tier 2 → KDU score
driveratlas loldrivers --vt-key $VT_API_KEY --tier2 --ghidra-home /opt/ghidra

# Hunt for high-risk drivers on VT or locally
driveratlas hunt --vt-key $VT_API_KEY --min-score 6
driveratlas hunt -d /path/to/drivers/ --min-score 6

# Blocklist check (LOLDrivers + WDAC)
driveratlas check <sha256>
```

## How It Works

### Tier 1 — PE Analysis (seconds per driver)

Parses the PE binary to extract:
- Imports, device names, symbolic links, IOCTL codes, I/O methods
- Security mitigations: ASLR, CFG, GS (stack cookies), NX, FORCE_INTEGRITY
- Driver framework classification (minifilter, KMDF, WDM, NDIS, etc.)
- Signer certificate chain (via `cryptography.x509`)

Then evaluates 22 weighted rules from
[`signatures/attack_surface.yaml`](signatures/attack_surface.yaml) to produce a
**0–15 attack surface score**. A driver that imports `MmMapIoSpace` with no
`ProbeForRead`, exposes a symbolic link, and has all mitigations off will score
high. A minifilter with `IoCreateDeviceSecure` and stack cookies will score low.

### Tier 2 — Ghidra Headless Decompilation (minutes per driver)

Runs Ghidra headless analysis with
[`ExportDriverDispatch.py`](ghidra_scripts/ExportDriverDispatch.py) to:
- Locate the `IRP_MJ_DEVICE_CONTROL` handler
- Extract every IOCTL code and its handler function
- Decompile each handler and identify which dangerous APIs are reachable
- Run heuristic taint analysis (user input buffer → sensitive sink)
- Check for security validations (`ProbeForRead`, `SeAccessCheck`, `try/except`)
- Scan `.text` section for ROP/JOP gadgets (stack pivots, memory R/W, jmp-reg)
- Generate YARA rules from analysis artifacts

This is the step that answers: **does the IOCTL handler actually call the
dangerous API, or does the driver just import it for internal use?**

### KDU Scoring — Exploitation Primitive Assessment

Maps Tier 2 IOCTL-reachable APIs to the exploitation primitives that
[KDU](https://github.com/hfiref0x/KDU) needs:

| Primitive | Example API |
|-----------|-------------|
| ReadPhysicalMemory | `MmMapIoSpace` (read path) |
| WritePhysicalMemory | `MmMapIoSpace` (write path) |
| ReadKernelVM | `MmCopyMemory`, `ZwReadVirtualMemory` |
| WriteKernelVM | `ZwWriteVirtualMemory` |
| VirtualToPhysical | `MmGetPhysicalAddress` |
| MSRAccess | `__readmsr`, `__writemsr` |
| OpenProcess | `ZwOpenProcess`, `PsLookupProcessByProcessId` |

These primitives map to KDU actions:

| Action | What it does | Required primitives |
|--------|-------------|-------------------|
| **MapDriver** | Load unsigned code into kernel | Physical + virtual memory R/W |
| **MapDriver (brute)** | Same, via PML4 brute-force | Physical memory R/W only |
| **DKOM** | Hide processes, manipulate kernel objects | Virtual memory write |
| **DSECorruption** | Disable driver signature enforcement | Virtual memory write to `ci.dll` |
| **DumpProcess** | Read arbitrary process memory | Process handle + virtual read |

Confidence is **"confirmed"** if Tier 2 verified the API is reachable from an
IOCTL handler, **"likely"** if only Tier 1 imports suggest it.

## Results: 1,775 LOLDrivers

| Category | Count | % |
|----------|------:|---:|
| Confirmed MapDriver (physical + virtual in IOCTLs) | 122 | 6.9% |
| Confirmed physical brute-force only | 157 | 8.8% |
| Confirmed DKOM / DSE corruption | 75 | 4.2% |
| Likely KDU-compatible (Tier 1 imports only) | 1,050 | 59.2% |
| **Total KDU-compatible** | **1,404** | **79.2%** |

354 drivers have Ghidra-confirmed dangerous APIs in their IOCTL handlers.
1,050 more are "likely" based on imports alone. Full results:
[KernelSight KDU Compatibility](https://splintersfury.github.io/KernelSight/reference/kdu-compatibility/).

## Attack Surface Scoring

**Risk levels:**

| Level | Score Range |
|-------|------------|
| Critical | >= 10.0 |
| High | >= 8.0 |
| Medium | >= 5.0 |
| Low | >= 2.0 |
| Minimal | < 2.0 |

**Key positive signals** (increase score):

| Rule | Weight | What it catches |
|------|--------|----------------|
| `mmmapiospace_import` | +4.0 | Physical memory mapping via MmMapIoSpace |
| `device_name_exposed` | +3.0 | Usermode-accessible device path |
| `register_port_io` | +3.0 | Direct register/port I/O |
| `no_probe_functions` | +2.5 | Missing ProbeForRead/ProbeForWrite |
| `symbolic_link_present` | +2.0 | DosDevices symbolic link |
| `ioctl_strings_present` | +2.0 | IOCTL_ strings in binary |
| `insecure_device_creation` | +2.0 | IoCreateDevice without IoCreateDeviceSecure |
| `dma_operations` | +2.0 | DMA buffer allocation |
| `no_access_checks` | +1.5 | Missing SeAccessCheck/SeSinglePrivilegeCheck |

**Key negative signals** (reduce score):

| Rule | Weight | What it recognizes |
|------|--------|--------------------|
| `no_device_names` | -3.0 | Not directly usermode-accessible |
| `has_probe_functions` | -2.0 | Proper input validation |
| `secure_device_creation` | -2.0 | IoCreateDeviceSecure present |
| `has_access_check` | -1.5 | Authorization enforcement |
| `kmdf_framework` | -1.0 | Built-in KMDF safety mechanisms |

Tier 2 adds additional rule types: `tier2_neither_io_count`, `tier2_ioctl_count_above`,
`tier2_has_taint_sink`, `tier2_missing_check_type`, `tier2_gadget_count_above`.

## CLI Reference

### `driveratlas scan`

Tier 1 PE scan. Single file or recursive directory.

```bash
driveratlas scan driver.sys
driveratlas scan /path/to/drivers/ -r -f table
driveratlas scan driver.sys -f json -o report.json
```

### `driveratlas rank`

Score and rank drivers by attack surface.

```bash
driveratlas rank /path/to/drivers/ -r
driveratlas rank /path/to/drivers/ -r --min-score 8.0 -f json
```

### `driveratlas deep`

Tier 2 Ghidra headless analysis. Requires Ghidra installed.

```bash
driveratlas deep driver.sys --ghidra-home /opt/ghidra
driveratlas deep driver.sys --ghidra-home /opt/ghidra --gadgets --yara --json-output report.json
driveratlas deep driver.sys --pdb driver.pdb  # with symbols
```

Output includes: IOCTL dispatch table, I/O methods, per-handler API calls, taint
paths, security validations, ROP/JOP gadget counts, and optionally YARA rules.

### `driveratlas kdu`

KDU provider compatibility assessment from Tier 2 results.

```bash
driveratlas kdu results.json --top 20
driveratlas kdu results.json --json-output kdu_scores.json
driveratlas kdu driver.sys  # runs Tier 1 only (lower confidence)
```

### `driveratlas loldrivers`

Full pipeline: download LOLDrivers corpus from VT, run Tier 1 + Tier 2, export results.

```bash
driveratlas loldrivers --vt-key $VT_API_KEY --work-dir ./loldrivers_run
driveratlas loldrivers --vt-key $VT_API_KEY --tier2 --ghidra-home /opt/ghidra
driveratlas loldrivers --resume --work-dir ./loldrivers_run  # resume interrupted run
driveratlas loldrivers --export-md  # export Markdown for KernelSight
```

### `driveratlas hunt`

Autonomous driver discovery and scoring from VT Intelligence or local directories.

```bash
driveratlas hunt --vt-key $VT_API_KEY --min-score 6
driveratlas hunt -d /path/to/drivers/ --min-score 6
driveratlas hunt --vt-key $VT_API_KEY --interval 3600  # daemon mode
driveratlas hunt --telegram-token $TOKEN --telegram-chat $CHAT  # with alerts
```

Features:
- VT Intelligence queries for recently submitted signed `.sys` files
- Deduplication across runs (`~/.driveratlas/seen.json`)
- Telegram alerts (Markdown-formatted) for drivers scoring >= 8.0
- `--import-to-corpus` auto-imports high-scoring finds
- `--interval N` for daemon mode

### `driveratlas check`

Blocklist lookup against LOLDrivers and Microsoft WDAC recommended block rules.

```bash
driveratlas check <sha256>
driveratlas check driver.sys  # computes hash automatically
```

### `driveratlas corpus`

Reference corpus management.

```bash
driveratlas corpus list
driveratlas import driver.sys -c minifilter -v Microsoft
```

## Detected Frameworks

minifilter, ndis_miniport, ndis_filter, ndis_protocol, wfp_callout,
kmdf, storport, portclass_audio, ks_minidriver, class_video, wdm_raw

Framework detection uses weighted import anchors defined in
[`signatures/frameworks.yaml`](signatures/frameworks.yaml).

## Installation

```bash
# Base (scan, rank, corpus)
pip install -e .

# With Ghidra deep analysis (adds capstone for gadget scanning)
pip install -e ".[deep]"

# With VT hunting
pip install -e ".[hunt]"

# Everything
pip install -e ".[all]"

# Development
pip install -e ".[dev]"
```

**Requirements:** Python 3.10+. Ghidra 10.x+ for Tier 2 analysis (set `GHIDRA_HOME`
or pass `--ghidra-home`).

## Karton Integration

DriverAtlas powers the `karton.driveratlas.triage` stage in
[AutoPiff](https://github.com/splintersfury/AutoPiff). The triage stage scores
every incoming driver sample, tags it in MWDB with `attack_surface_score`, `risk`,
and `framework`, and sends Telegram alerts for high-scoring drivers.

## Related

- [KernelSight](https://splintersfury.github.io/KernelSight/) — knowledge base with full LOLDrivers analysis results
- [AutoPiff](https://github.com/splintersfury/AutoPiff) — binary diffing pipeline for tracking driver family evolution
- [Blog series](https://threatunpacked.com/2026/01/21/building-a-scalable-windows-driver-vulnerability-analyzer-part-1/) — three-part writeup covering the research behind these tools

## Tests

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -v
```
