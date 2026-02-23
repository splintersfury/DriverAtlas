# DriverAtlas

Windows kernel driver structural analysis toolkit. Fingerprints drivers by
framework, imports, API usage, and strings to enable "canonical skeleton"
analysis per category.

## Quick Start

```bash
pip install -e .
driveratlas scan /path/to/driver.sys
driveratlas scan /path/to/drivers/ -r -f table
driveratlas import /path/to/driver.sys -c minifilter -v Microsoft
driveratlas corpus list
```

## Architecture

- **Tier 1** (implemented): Fast PE import scan producing `DriverProfile`
- **Tier 2** (future): Deep Ghidra pass on representative samples

## Detected Frameworks

minifilter, ndis_miniport, ndis_filter, ndis_protocol, wfp_callout,
kmdf, storport, portclass_audio, ks_minidriver, class_video, wdm_raw

## Tests

```bash
python3 -m pytest tests/ -v
```
