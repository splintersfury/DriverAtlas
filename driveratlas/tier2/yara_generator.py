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


def generate_yara(result: Tier2Result, output_path: Optional[str] = None) -> str:
    """Generate YARA rules from a Tier2Result.

    Args:
        result: Complete Tier 2 analysis result
        output_path: Optional path to write the .yar file

    Returns:
        YARA rule text
    """
    rules = []

    # Rule 1: IOCTL fingerprint
    if result.ioctls:
        rule = _generate_ioctl_rule(result)
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


def _generate_ioctl_rule(result: Tier2Result) -> str:
    """Generate a YARA rule matching the driver's IOCTL codes."""
    name = _sanitize_name(result.driver_name)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Use up to 10 most interesting IOCTLs (NEITHER first, then custom)
    sorted_ioctls = sorted(
        result.ioctls,
        key=lambda i: (not i.uses_neither_io, not i.is_custom_function, i.code),
    )[:10]

    if not sorted_ioctls:
        return ""

    conditions = []
    strings = []

    for idx, ioctl in enumerate(sorted_ioctls):
        var_name = f"$ioctl_{idx}"
        hex_str = _ioctl_to_le_hex(ioctl.code)
        comment = f"// {ioctl.code_hex}"
        if ioctl.label:
            comment += f" ({ioctl.label})"
        strings.append(f"        {var_name} = {{ {hex_str} }} {comment}")

    # Require at least 2 IOCTLs to match (reduce FPs)
    min_match = min(2, len(sorted_ioctls))
    conditions.append(f"{min_match} of ($ioctl_*)")

    strings_block = "\n".join(strings)
    condition_block = " and ".join(conditions)

    return f"""rule DriverAtlas_{name}_IOCTLs
{{
    meta:
        description = "DriverAtlas: IOCTL codes for {result.driver_name}"
        author = "DriverAtlas auto-generator"
        date = "{date}"
        sha256 = "{result.sha256}"
        ioctl_count = {len(result.ioctls)}

    strings:
{strings_block}

    condition:
        uint16(0) == 0x5A4D and {condition_block}
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
