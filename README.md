# DriverAtlas

Windows kernel driver structural analysis toolkit. Fingerprints drivers by
framework, imports, API usage, and strings to enable "canonical skeleton"
analysis per category. Scores attack surface exposure to prioritize drivers
for security research.

## Quick Start

```bash
pip install -e .

# Scan and classify drivers
driveratlas scan /path/to/driver.sys
driveratlas scan /path/to/drivers/ -r -f table

# Rank drivers by attack surface score
driveratlas rank /path/to/drivers/ -r
driveratlas rank /path/to/drivers/ -r --min-score 8.0 -f json

# Hunt for high-risk drivers (VirusTotal or local)
driveratlas hunt --min-score 6
driveratlas hunt -d /path/to/drivers/ --min-score 6

# Corpus management
driveratlas import /path/to/driver.sys -c minifilter -v Microsoft
driveratlas corpus list
```

## Architecture

- **Tier 1** (implemented): Fast PE import scan producing `DriverProfile`, plus
  attack surface scoring via weighted rules (see [`signatures/attack_surface.yaml`](signatures/attack_surface.yaml))
- **Tier 2** (future): Deep Ghidra pass on representative samples

## Attack Surface Scoring

Every scanned driver receives a **0–15 attack surface score** computed from
22 weighted rules in [`signatures/attack_surface.yaml`](signatures/attack_surface.yaml).

**Risk Levels:**

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
| `symbolic_link_present` | +2.0 | DosDevices/Global?? symbolic link |
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

## Autonomous Hunting

The `hunt` command continuously discovers and scores drivers from VirusTotal
Intelligence or a local directory.

```bash
# One-shot: query VT for recent signed drivers, score them
driveratlas hunt --vt-key $VT_API_KEY --min-score 6

# Daemon mode: re-run every 3600 seconds
driveratlas hunt --vt-key $VT_API_KEY --interval 3600 --min-score 6

# Local directory scan
driveratlas hunt -d /path/to/drivers/ --min-score 6

# With Telegram alerts for critical findings
driveratlas hunt --vt-key $VT_API_KEY --min-score 6 \
  --telegram-token $TELEGRAM_BOT_TOKEN \
  --telegram-chat $TELEGRAM_CHAT_ID
```

**Features:**
- Queries VT Intelligence for recently submitted signed `.sys` files
- Deduplicates across runs via `~/.driveratlas/seen.json`
- Sends Telegram alerts (Markdown-formatted) for drivers scoring >= 8.0
- `--import-to-corpus` flag auto-imports high-scoring finds
- `--interval N` enables daemon mode (re-runs every N seconds)

## Installation

```bash
# Base install (scan, rank, corpus)
pip install -e .

# With VirusTotal hunting support
pip install -e ".[hunt]"

# Development (adds pytest)
pip install -e ".[dev]"
```

The `[hunt]` extra adds `vt-py` and `requests` for VirusTotal Intelligence queries.

## Detected Frameworks

minifilter, ndis_miniport, ndis_filter, ndis_protocol, wfp_callout,
kmdf, storport, portclass_audio, ks_minidriver, class_video, wdm_raw

## Karton Integration

DriverAtlas powers the `karton.driveratlas.triage` stage in [AutoPiff](https://github.com/splintersfury/AutoPiff).
The triage stage scores every incoming driver sample, tags it in MWDB with
`attack_surface_score`, `risk`, and `framework`, and sends Telegram alerts
for high-scoring drivers. See AutoPiff's README for pipeline details.

## Tests

```bash
python3 -m pytest tests/ -v
```
