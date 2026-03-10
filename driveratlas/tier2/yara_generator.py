"""YARA rule generator — creates detection rules from Tier 2 analysis results.

Generates YARA rules for:
- IOCTL code patterns (detect drivers handling specific IOCTLs)
- Vulnerable patterns (NEITHER I/O + sensitive API combos)
- Device name patterns (detect drivers exposing specific device paths)
"""

import logging
import os
import re
import struct
from datetime import datetime, timezone
from typing import Optional

from . import Tier2Result, IOCTLInfo

logger = logging.getLogger("driveratlas.tier2.yara_generator")

# Imports considered dangerous/interesting for YARA detection.
# These map closely to TheDebugger's output format.
DANGEROUS_IMPORTS = {
    "MmProbeAndLockPages",
    "MmMapLockedPagesSpecifyCache",
    "MmMapLockedPages",
    "MmMapIoSpace",
    "MmIsAddressValid",
    "IoGetCurrentProcess",
    "ObRegisterCallbacks",
    "ObOpenObjectByPointer",
    "ZwOpenProcess",
    "ZwDuplicateObject",
    "ZwTerminateProcess",
    "KeStackAttachProcess",
    "KeInsertQueueApc",
    "PsCreateSystemThread",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "ZwDeleteFile",
    "ZwSetInformationFile",
    "ZwQuerySystemInformation",
    "NtQuerySystemInformation",
    "ZwAllocateVirtualMemory",
    "ZwProtectVirtualMemory",
    "ZwFreeVirtualMemory",
    "ZwMapViewOfSection",
    "ZwUnmapViewOfSection",
    "__writemsr",
    "__readmsr",
    "HalGetBusDataByOffset",
    "IoGetDeviceObjectPointer",
    "MmCopyMemory",
    "MmCopyVirtualMemory",
    "RtlCopyMemory",
}


def generate_yara(result: Tier2Result, output_path: Optional[str] = None,
                   profile=None) -> str:
    """Generate YARA rules from a Tier2Result.

    Args:
        result: Complete Tier 2 analysis result
        output_path: Optional path to write the .yar file
        profile: Optional DriverProfile for device names and import enrichment

    Returns:
        YARA rule text
    """
    rules = []

    # Rule 1: IOCTL fingerprint (enriched with profile data when available)
    if result.ioctls:
        rule = _generate_ioctl_rule(result, profile=profile)
        if rule:
            rules.append(rule)

    # Rule 2: Vulnerable patterns
    vuln_rule = _generate_vuln_pattern_rule(result)
    if vuln_rule:
        rules.append(vuln_rule)

    output = "\n\n".join(rules)

    if output_path and output:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            f.write(output)
        logger.info(f"YARA rules written to {output_path}")

    return output


def _sanitize_name(name: str) -> str:
    """Convert a driver name to a valid YARA identifier."""
    base = os.path.splitext(name)[0]
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", base)
    if sanitized[0:1].isdigit():
        sanitized = "_" + sanitized
    return sanitized


def _ioctl_to_le_hex(code: int) -> str:
    """Convert IOCTL code to little-endian hex string for YARA."""
    packed = struct.pack("<I", code & 0xFFFFFFFF)
    return " ".join(f"{b:02X}" for b in packed)


def _collect_capabilities(ioctls) -> list:
    """Collect unique IOCTL auto-labels as a sorted capability list."""
    caps = set()
    for ioctl in ioctls:
        if ioctl.label:
            caps.add(ioctl.label.strip())
    return sorted(caps)


def _get_dangerous_imports_from_profile(profile) -> list:
    """Extract dangerous imports from a DriverProfile's ntoskrnl imports."""
    if profile is None:
        return []
    found = []
    for imp in getattr(profile, "ntoskrnl_imports", []):
        if imp in DANGEROUS_IMPORTS:
            found.append(imp)
    return sorted(set(found))


def _generate_ioctl_rule(result: Tier2Result, profile=None) -> str:
    """Generate a YARA rule matching the driver's IOCTL codes.

    When *profile* is provided, the rule follows TheDebugger's output format:
    - $dev strings for device names
    - $imp strings for dangerous imports
    - $ioctl strings for IOCTL codes in LE hex
    - capabilities meta field from IOCTL auto-labels
    """
    name = _sanitize_name(result.driver_name)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Use up to 10 most interesting IOCTLs (NEITHER first, then custom)
    sorted_ioctls = sorted(
        result.ioctls,
        key=lambda i: (not i.uses_neither_io, not i.is_custom_function, i.code),
    )[:10]

    if not sorted_ioctls:
        return ""

    # ── Meta ──
    capabilities = _collect_capabilities(result.ioctls)
    meta_lines = [
        f'        description = "DriverAtlas: IOCTL codes for {result.driver_name}"',
        f'        author = "DriverAtlas auto-generator"',
        f'        date = "{date}"',
        f'        sha256 = "{result.sha256}"',
        f'        ioctl_count = {len(result.ioctls)}',
    ]
    if capabilities:
        meta_lines.append(
            f'        capabilities = "{", ".join(capabilities)}"'
        )

    # ── Strings ──
    strings = []
    idx_counter = 1  # TheDebugger uses 1-based numbering

    # Device name strings (from profile)
    dev_vars = []
    if profile is not None:
        device_names = getattr(profile, "device_names", [])
        for dev_name in device_names:
            var_name = f"$dev{idx_counter}"
            strings.append(f'        {var_name} = "{dev_name}" ascii wide')
            dev_vars.append(var_name)
            idx_counter += 1

    # Dangerous import strings (from profile)
    imp_vars = []
    if profile is not None:
        dangerous = _get_dangerous_imports_from_profile(profile)
        for imp_name in dangerous:
            var_name = f"$imp{idx_counter}"
            strings.append(f'        {var_name} = "{imp_name}" ascii')
            imp_vars.append(var_name)
            idx_counter += 1

    # IOCTL codes as LE hex
    ioctl_vars = []
    for ioctl in sorted_ioctls:
        var_name = f"$ioctl{idx_counter}"
        hex_str = _ioctl_to_le_hex(ioctl.code)
        comment = f"// {ioctl.code_hex}"
        if ioctl.label:
            comment += f" ({ioctl.label})"
        strings.append(f"        {var_name} = {{ {hex_str} }} {comment}")
        ioctl_vars.append(var_name)
        idx_counter += 1

    # ── Condition ──
    cond_parts = ["uint16(0) == 0x5A4D"]

    if profile is not None and dev_vars:
        # Require all device names
        cond_parts.extend(dev_vars)

    if profile is not None and imp_vars:
        # Require any dangerous import
        cond_parts.append(
            "(" + " or ".join(imp_vars) + ")"
        )

    if ioctl_vars:
        if profile is not None:
            # TheDebugger style: any IOCTL match
            cond_parts.append(
                "(" + " or ".join(ioctl_vars) + ")"
            )
        else:
            # Original behavior: require minimum N matches
            min_match = min(2, len(ioctl_vars))
            cond_parts.append(f"{min_match} of ($ioctl*)")

    strings_block = "\n".join(strings)
    meta_block = "\n".join(meta_lines)
    condition_block = " and ".join(cond_parts)

    return f"""rule DriverAtlas_{name}_IOCTLs
{{
    meta:
{meta_block}

    strings:
{strings_block}

    condition:
        {condition_block}
}}"""


def _generate_vuln_pattern_rule(result: Tier2Result) -> str:
    """Generate a YARA rule for vulnerable patterns found in the driver."""
    name = _sanitize_name(result.driver_name)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    strings = []
    notes = []

    # NEITHER I/O IOCTLs
    neither_ioctls = [i for i in result.ioctls if i.uses_neither_io]
    for idx, ioctl in enumerate(neither_ioctls[:5]):
        hex_str = _ioctl_to_le_hex(ioctl.code)
        strings.append(
            f"        $neither_{idx} = {{ {hex_str} }} "
            f"// {ioctl.code_hex} NEITHER I/O"
        )
        notes.append(f"NEITHER I/O: {ioctl.code_hex}")

    # Taint paths with high confidence
    high_taint = [t for t in result.taint_paths if t.confidence >= 0.7]
    if high_taint:
        notes.append(f"{len(high_taint)} high-confidence taint paths")

    # Sensitive API strings
    sensitive_apis = set()
    for ioctl in result.ioctls:
        for api in (ioctl.api_calls or []):
            if api in ("MmMapIoSpace", "ZwOpenProcess", "__writemsr",
                       "ZwDuplicateObject", "KeStackAttachProcess"):
                sensitive_apis.add(api)

    for idx, api in enumerate(sorted(sensitive_apis)):
        strings.append(f'        $api_{idx} = "{api}" ascii wide')

    if not strings:
        return ""

    strings_block = "\n".join(strings)

    # Build condition
    cond_parts = ["uint16(0) == 0x5A4D"]
    if neither_ioctls:
        cond_parts.append("any of ($neither_*)")
    if sensitive_apis:
        cond_parts.append("any of ($api_*)")

    condition_block = " and ".join(cond_parts)

    return f"""rule DriverAtlas_{name}_VulnPatterns
{{
    meta:
        description = "DriverAtlas: Vulnerable patterns in {result.driver_name}"
        author = "DriverAtlas auto-generator"
        date = "{date}"
        sha256 = "{result.sha256}"
        notes = "{'; '.join(notes)}"

    strings:
{strings_block}

    condition:
        {condition_block}
}}"""
