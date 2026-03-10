"""IOCTL analyzer — parses Ghidra dispatch_table.json into structured IOCTLInfo objects."""

import logging
from typing import Optional

from . import IOCTLInfo, IOCTLAccess, IOCTLMethod

logger = logging.getLogger("driveratlas.tier2.ioctl_analyzer")

# Known device types for labeling
DEVICE_TYPES = {
    0x0001: "FILE_DEVICE_BEEP",
    0x0002: "FILE_DEVICE_CD_ROM",
    0x0003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    0x0004: "FILE_DEVICE_CONTROLLER",
    0x0005: "FILE_DEVICE_DATALINK",
    0x0006: "FILE_DEVICE_DFS",
    0x0007: "FILE_DEVICE_DISK",
    0x0008: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x0009: "FILE_DEVICE_FILE_SYSTEM",
    0x000B: "FILE_DEVICE_KEYBOARD",
    0x000C: "FILE_DEVICE_MAILSLOT",
    0x000D: "FILE_DEVICE_MIDI_IN",
    0x000E: "FILE_DEVICE_MIDI_OUT",
    0x000F: "FILE_DEVICE_MOUSE",
    0x0012: "FILE_DEVICE_NETWORK",
    0x0013: "FILE_DEVICE_NETWORK_BROWSER",
    0x0014: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
    0x0015: "FILE_DEVICE_NULL",
    0x0016: "FILE_DEVICE_PARALLEL_PORT",
    0x0017: "FILE_DEVICE_PHYSICAL_NETCARD",
    0x0018: "FILE_DEVICE_PRINTER",
    0x0019: "FILE_DEVICE_SCANNER",
    0x001A: "FILE_DEVICE_SERIAL_MOUSE_PORT",
    0x001B: "FILE_DEVICE_SERIAL_PORT",
    0x001C: "FILE_DEVICE_SCREEN",
    0x001D: "FILE_DEVICE_SOUND",
    0x001E: "FILE_DEVICE_STREAMS",
    0x001F: "FILE_DEVICE_TAPE",
    0x0020: "FILE_DEVICE_TAPE_FILE_SYSTEM",
    0x0021: "FILE_DEVICE_TRANSPORT",
    0x0022: "FILE_DEVICE_UNKNOWN",
    0x0023: "FILE_DEVICE_VIDEO",
    0x0024: "FILE_DEVICE_VIRTUAL_DISK",
    0x0025: "FILE_DEVICE_WAVE_IN",
    0x0026: "FILE_DEVICE_WAVE_OUT",
    0x0027: "FILE_DEVICE_8042_PORT",
    0x0028: "FILE_DEVICE_NETWORK_REDIRECTOR",
    0x0029: "FILE_DEVICE_BATTERY",
    0x002A: "FILE_DEVICE_BUS_EXTENDER",
    0x002B: "FILE_DEVICE_MODEM",
    0x002C: "FILE_DEVICE_VDM",
    0x002D: "FILE_DEVICE_MASS_STORAGE",
    0x002F: "FILE_DEVICE_FIPS",
    0x0030: "FILE_DEVICE_SMARTCARD",
    0x0034: "FILE_DEVICE_KS",
    0x003D: "FILE_DEVICE_AVIO",
}

# Sensitive API calls that indicate security-relevant operations
SENSITIVE_APIS = {
    # Physical memory / MMIO
    "MmMapIoSpace": "mmio_map",
    "MmMapLockedPages": "mmio_map",
    "MmMapLockedPagesSpecifyCache": "mmio_map",
    "ZwMapViewOfSection": "memory_map",
    "MmMapMemoryDumpMdl": "memory_map",

    # Memory copy (potential overflow)
    "memcpy": "memory_copy",
    "memmove": "memory_copy",
    "RtlCopyMemory": "memory_copy",
    "RtlMoveMemory": "memory_copy",
    "RtlCopyBytes": "memory_copy",

    # Process/thread manipulation
    "ZwOpenProcess": "process_access",
    "PsLookupProcessByProcessId": "process_access",
    "KeStackAttachProcess": "process_access",
    "ZwDuplicateObject": "handle_dup",
    "ObReferenceObjectByHandle": "handle_access",

    # Registry
    "ZwSetValueKey": "registry_write",
    "ZwDeleteKey": "registry_write",
    "ZwCreateKey": "registry_write",

    # I/O ports
    "READ_PORT_UCHAR": "port_io",
    "WRITE_PORT_UCHAR": "port_io",
    "READ_PORT_ULONG": "port_io",
    "WRITE_PORT_ULONG": "port_io",

    # MSR access
    "__readmsr": "msr_access",
    "__writemsr": "msr_access",

    # File operations
    "ZwCreateFile": "file_ops",
    "ZwWriteFile": "file_ops",
    "ZwReadFile": "file_ops",

    # Allocations (overflow targets)
    "ExAllocatePool": "pool_alloc",
    "ExAllocatePool2": "pool_alloc",
    "ExAllocatePoolWithTag": "pool_alloc",
}

# Labels auto-assigned based on API call categories
AUTO_LABELS = {
    "mmio_map": "Physical Memory Map",
    "memory_copy": "Memory Copy",
    "process_access": "Process Manipulation",
    "handle_dup": "Handle Duplication",
    "handle_access": "Handle Access",
    "registry_write": "Registry Write",
    "port_io": "I/O Port Access",
    "msr_access": "MSR Read/Write",
    "file_ops": "File Operations",
    "pool_alloc": "Pool Allocation",
    "memory_map": "Memory Mapping",
}


def parse_dispatch_table(dispatch_data: dict) -> list:
    """Parse Ghidra dispatch_table.json into IOCTLInfo objects.

    Args:
        dispatch_data: Raw dict from dispatch_table.json

    Returns:
        List of IOCTLInfo objects with CTL_CODE decomposition and auto-labels
    """
    ioctl_dispatch = dispatch_data.get("ioctl_dispatch", {})
    results = []

    for code_hex, info in ioctl_dispatch.items():
        try:
            code = int(code_hex, 16)
        except ValueError:
            logger.warning(f"Skipping invalid IOCTL code: {code_hex}")
            continue

        ioctl = IOCTLInfo.from_code(
            code,
            handler_name=info.get("handler_name", ""),
            handler_addr=info.get("handler_addr", ""),
            decompiled_snippet=info.get("decompiled_snippet", ""),
        )

        # Extract API calls from decompiled snippet
        if ioctl.decompiled_snippet:
            ioctl.api_calls = _extract_api_calls(ioctl.decompiled_snippet)
            ioctl.label = _auto_label(ioctl.api_calls)

        results.append(ioctl)

    # Sort by IOCTL code
    results.sort(key=lambda i: i.code)

    logger.info(
        f"Parsed {len(results)} IOCTLs: "
        f"{sum(1 for i in results if i.uses_neither_io)} NEITHER, "
        f"{sum(1 for i in results if i.is_custom_device_type)} custom device type"
    )

    return results


def _extract_api_calls(snippet: str) -> list:
    """Extract known sensitive API calls from a decompiled code snippet."""
    found = []
    for api in SENSITIVE_APIS:
        if api in snippet:
            found.append(api)
    return found


def _auto_label(api_calls: list) -> str:
    """Generate a human-readable label from API calls found in an IOCTL handler."""
    if not api_calls:
        return ""

    categories = set()
    for api in api_calls:
        cat = SENSITIVE_APIS.get(api)
        if cat:
            categories.add(cat)

    labels = [AUTO_LABELS.get(c, c) for c in sorted(categories)]
    return " + ".join(labels)


def device_type_name(device_type: int) -> str:
    """Get human-readable device type name."""
    if device_type in DEVICE_TYPES:
        return DEVICE_TYPES[device_type]
    if device_type >= 0x8000:
        return f"VENDOR_DEFINED(0x{device_type:04X})"
    return f"UNKNOWN(0x{device_type:04X})"


def summarize_ioctls(ioctls: list) -> dict:
    """Generate a summary of IOCTL analysis results.

    Args:
        ioctls: List of IOCTLInfo objects

    Returns:
        Summary dict with counts, risk indicators, and notable findings
    """
    if not ioctls:
        return {"total": 0}

    methods = {"BUFFERED": 0, "IN_DIRECT": 0, "OUT_DIRECT": 0, "NEITHER": 0}
    device_types = set()
    sensitive_ioctls = []

    for ioctl in ioctls:
        methods[ioctl.method.name] += 1
        device_types.add(ioctl.device_type)

        if ioctl.uses_neither_io or ioctl.api_calls:
            sensitive_ioctls.append({
                "code": ioctl.code_hex,
                "method": ioctl.method.name,
                "label": ioctl.label,
                "api_calls": ioctl.api_calls,
                "neither_io": ioctl.uses_neither_io,
            })

    return {
        "total": len(ioctls),
        "methods": methods,
        "device_types": [
            {"type": dt, "name": device_type_name(dt)} for dt in sorted(device_types)
        ],
        "custom_device_types": sum(1 for dt in device_types if dt >= 0x8000),
        "custom_functions": sum(1 for i in ioctls if i.is_custom_function),
        "sensitive_ioctls": sensitive_ioctls,
        "risk_indicators": {
            "neither_io": methods["NEITHER"],
            "has_mmio": any("MmMapIoSpace" in (i.api_calls or []) for i in ioctls),
            "has_process_access": any(
                api in SENSITIVE_APIS and SENSITIVE_APIS[api] == "process_access"
                for i in ioctls for api in (i.api_calls or [])
            ),
            "has_msr": any(
                api in SENSITIVE_APIS and SENSITIVE_APIS[api] == "msr_access"
                for i in ioctls for api in (i.api_calls or [])
            ),
        },
    }
