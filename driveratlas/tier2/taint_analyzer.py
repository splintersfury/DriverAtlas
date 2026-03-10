"""Taint analyzer — traces user-controlled input to sensitive kernel APIs.

Operates on decompiled C output from Ghidra. Uses pattern matching on
decompiled code to identify data flows from IRP buffers to dangerous sinks.

This is a static heuristic approach (not full symbolic execution), but catches
the most common vulnerability patterns in Windows kernel drivers.
"""

import logging
import re
from typing import Optional

from . import TaintPath, SecurityCheck

logger = logging.getLogger("driveratlas.tier2.taint_analyzer")

# User-controlled input sources (from IRP)
TAINT_SOURCES = {
    # Buffered I/O
    "SystemBuffer": "IRP SystemBuffer (buffered I/O)",
    "AssociatedIrp.SystemBuffer": "IRP SystemBuffer (buffered I/O)",
    # Direct I/O
    "MdlAddress": "IRP MDL address (direct I/O)",
    # Neither I/O — raw user pointers
    "Type3InputBuffer": "Type3InputBuffer (raw user pointer)",
    "UserBuffer": "IRP UserBuffer (raw user pointer)",
    # Buffer lengths
    "InputBufferLength": "Input buffer length",
    "OutputBufferLength": "Output buffer length",
    "IoControlCode": "IOCTL control code",
}

# Dangerous sinks — functions that can cause security issues when called
# with user-controlled data
TAINT_SINKS = {
    # Physical memory mapping — arbitrary physical read/write
    "MmMapIoSpace": ("critical", "Physical memory mapping with user-controlled address"),
    "MmMapIoSpaceEx": ("critical", "Physical memory mapping with user-controlled address"),
    "MmMapLockedPages": ("high", "Locked pages mapping"),
    "MmMapLockedPagesSpecifyCache": ("high", "Locked pages mapping with cache control"),
    "ZwMapViewOfSection": ("high", "Section mapping"),

    # Memory copy — buffer overflow if length is user-controlled
    "memcpy": ("high", "Memory copy with potentially user-controlled length"),
    "memmove": ("high", "Memory move with potentially user-controlled length"),
    "RtlCopyMemory": ("high", "Kernel memory copy"),
    "RtlMoveMemory": ("high", "Kernel memory move"),
    "RtlCopyBytes": ("high", "Kernel byte copy"),

    # Process/thread manipulation — privilege escalation
    "ZwOpenProcess": ("critical", "Process handle acquisition"),
    "PsLookupProcessByProcessId": ("high", "Process lookup by PID"),
    "KeStackAttachProcess": ("critical", "Process context attachment"),
    "ZwDuplicateObject": ("critical", "Handle duplication"),
    "ObReferenceObjectByHandle": ("high", "Object reference by handle"),

    # Registry — persistent system modification
    "ZwSetValueKey": ("medium", "Registry value write"),
    "ZwDeleteKey": ("medium", "Registry key deletion"),
    "ZwCreateKey": ("medium", "Registry key creation"),

    # I/O ports — hardware access
    "WRITE_PORT_UCHAR": ("high", "I/O port write (byte)"),
    "WRITE_PORT_USHORT": ("high", "I/O port write (word)"),
    "WRITE_PORT_ULONG": ("high", "I/O port write (dword)"),

    # MSR — model-specific register access
    "__writemsr": ("critical", "MSR write — arbitrary code execution possible"),
    "__readmsr": ("high", "MSR read — information disclosure"),

    # Pool operations — overflow targets
    "ExAllocatePool": ("medium", "Pool allocation (deprecated, no tag)"),
    "ExAllocatePoolWithTag": ("low", "Pool allocation"),
}

# Security checks that should be present in IOCTL handlers
EXPECTED_CHECKS = [
    {
        "id": "input_length_validation",
        "description": "Input buffer length validation",
        "patterns": [
            r"InputBufferLength\s*[<>=!]+",
            r"nInBufferSize\s*[<>=!]+",
            r"param_\d\s*<\s*(?:0x)?\d+",
            r"cbInput\s*[<>=!]+",
        ],
        "severity": "high",
    },
    {
        "id": "output_length_validation",
        "description": "Output buffer length validation",
        "patterns": [
            r"OutputBufferLength\s*[<>=!]+",
            r"nOutBufferSize\s*[<>=!]+",
            r"cbOutput\s*[<>=!]+",
        ],
        "severity": "high",
    },
    {
        "id": "probe_for_read",
        "description": "ProbeForRead on user buffer",
        "patterns": [r"ProbeForRead\s*\("],
        "severity": "high",
    },
    {
        "id": "probe_for_write",
        "description": "ProbeForWrite on user buffer",
        "patterns": [r"ProbeForWrite\s*\("],
        "severity": "high",
    },
    {
        "id": "try_except",
        "description": "Exception handling around user buffer access",
        "patterns": [
            r"__try",
            r"_SEH_prolog",
            r"ExceptionRecord",
        ],
        "severity": "medium",
    },
    {
        "id": "access_check",
        "description": "Caller privilege/access check",
        "patterns": [
            r"SeAccessCheck\s*\(",
            r"SeSinglePrivilegeCheck\s*\(",
            r"IoIsOperationSynchronous",
            r"Irp->RequestorMode\s*==\s*(?:1|KernelMode)",
            r"ExGetPreviousMode",
            r"PreviousMode",
        ],
        "severity": "medium",
    },
]


def analyze_taint(dispatch_data: dict) -> list:
    """Analyze dispatch table for taint paths from user input to sensitive sinks.

    Args:
        dispatch_data: Raw dict from dispatch_table.json

    Returns:
        List of TaintPath objects
    """
    ioctl_dispatch = dispatch_data.get("ioctl_dispatch", {})
    paths = []

    for code_hex, info in ioctl_dispatch.items():
        snippet = info.get("decompiled_snippet", "")
        handler_name = info.get("handler_name", "")
        if not snippet:
            continue

        # Find which sources appear in the snippet
        active_sources = []
        for source_key, source_desc in TAINT_SOURCES.items():
            if source_key in snippet:
                active_sources.append(source_key)

        # Find which sinks appear in the snippet
        for sink_name, (severity, sink_desc) in TAINT_SINKS.items():
            if sink_name not in snippet:
                continue

            # Check if any taint source also appears (heuristic co-occurrence)
            for source in active_sources:
                confidence = _estimate_confidence(snippet, source, sink_name)
                if confidence > 0.0:
                    paths.append(TaintPath(
                        source=source,
                        sink=sink_name,
                        ioctl_code=code_hex,
                        handler_name=handler_name,
                        confidence=confidence,
                        path_description=(
                            f"{TAINT_SOURCES[source]} → {sink_desc}"
                        ),
                    ))

            # Even without explicit source, if NEITHER I/O method and sink present,
            # flag it — the entire buffer is a raw user pointer
            if not active_sources and _is_neither_io(int(code_hex, 16)):
                paths.append(TaintPath(
                    source="raw_user_pointer",
                    sink=sink_name,
                    ioctl_code=code_hex,
                    handler_name=handler_name,
                    confidence=0.6,
                    path_description=(
                        f"NEITHER I/O method — raw user pointer → {sink_desc}"
                    ),
                ))

    logger.info(f"Taint analysis: {len(paths)} potential paths found")
    return paths


def analyze_security_checks(dispatch_data: dict) -> list:
    """Check each IOCTL handler for expected security validations.

    Args:
        dispatch_data: Raw dict from dispatch_table.json

    Returns:
        List of SecurityCheck objects (both present and missing)
    """
    ioctl_dispatch = dispatch_data.get("ioctl_dispatch", {})
    checks = []

    for code_hex, info in ioctl_dispatch.items():
        snippet = info.get("decompiled_snippet", "")
        handler_name = info.get("handler_name", "")

        for check_def in EXPECTED_CHECKS:
            present = False
            if snippet:
                for pattern in check_def["patterns"]:
                    if re.search(pattern, snippet):
                        present = True
                        break

            checks.append(SecurityCheck(
                check_type=check_def["id"],
                present=present,
                ioctl_code=code_hex,
                handler_name=handler_name,
                details=check_def["description"],
                severity=check_def["severity"],
            ))

    missing = sum(1 for c in checks if not c.present)
    present = sum(1 for c in checks if c.present)
    logger.info(f"Security checks: {present} present, {missing} missing across {len(ioctl_dispatch)} IOCTLs")
    return checks


def _estimate_confidence(snippet: str, source: str, sink: str) -> float:
    """Estimate confidence that a source-to-sink flow exists.

    Uses heuristic proximity and co-occurrence analysis.
    """
    source_pos = snippet.find(source)
    sink_pos = snippet.find(sink)

    if source_pos < 0 or sink_pos < 0:
        return 0.0

    # Both present in same snippet — base confidence
    confidence = 0.5

    # Source appears before sink — more likely a forward data flow
    if source_pos < sink_pos:
        confidence += 0.2

    # Close proximity (within 200 chars) — stronger signal
    distance = abs(sink_pos - source_pos)
    if distance < 200:
        confidence += 0.2
    elif distance < 500:
        confidence += 0.1

    # If the source is used as a function argument near the sink
    # (look for source name within 50 chars before sink call)
    if source_pos < sink_pos and (sink_pos - source_pos) < 80:
        confidence += 0.1

    return min(confidence, 1.0)


def _is_neither_io(ioctl_code: int) -> bool:
    """Check if an IOCTL code uses METHOD_NEITHER."""
    return (ioctl_code & 0x3) == 3
