"""IOCTL analyzer — parses Ghidra dispatch_table.json into structured IOCTLInfo objects."""

import logging
from typing import Optional

from . import IOCTLInfo, IOCTLAccess, IOCTLMethod, IOCTLDeepDive

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

# Categorized API calls for deep dive analysis
API_CATEGORIES = {
    "PROCESS": [
        "PsLookupProcessByProcessId", "KeStackAttachProcess",
        "ZwTerminateProcess", "KeUnstackDetachProcess",
        "ZwOpenProcess", "ObOpenObjectByPointer",
    ],
    "MEMORY": [
        "MmMapIoSpace", "MmMapLockedPages", "MmMapLockedPagesSpecifyCache",
        "MmCopyVirtualMemory", "ZwMapViewOfSection", "MmGetPhysicalAddress",
        "MmAllocateContiguousMemory", "MmAllocateNonCachedMemory",
    ],
    "FILE": ["ZwCreateFile", "ZwWriteFile", "ZwReadFile", "ZwDeleteFile"],
    "REGISTRY": ["ZwSetValueKey", "ZwDeleteKey", "ZwCreateKey", "ZwOpenKey"],
    "PORT_IO": [
        "READ_PORT_UCHAR", "WRITE_PORT_UCHAR",
        "READ_PORT_ULONG", "WRITE_PORT_ULONG",
    ],
    "MSR": ["__readmsr", "__writemsr"],
    "ALLOC": [
        "ExAllocatePool", "ExAllocatePool2",
        "ExAllocatePoolWithTag", "ExFreePoolWithTag",
    ],
    "CALLBACK": [
        "ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutine",
        "PsSetLoadImageNotifyRoutine",
    ],
}

# Build flat SENSITIVE_APIS lookup from API_CATEGORIES
SENSITIVE_APIS = {}
_CATEGORY_MAP = {
    "PROCESS": "process_access",
    "MEMORY": "mmio_map",
    "FILE": "file_ops",
    "REGISTRY": "registry_write",
    "PORT_IO": "port_io",
    "MSR": "msr_access",
    "ALLOC": "pool_alloc",
    "CALLBACK": "callback_reg",
}
for _cat, _apis in API_CATEGORIES.items():
    _tag = _CATEGORY_MAP.get(_cat, _cat.lower())
    for _api in _apis:
        SENSITIVE_APIS[_api] = _tag

# Add extra APIs that don't fit neatly into categories but are still sensitive
SENSITIVE_APIS.update({
    "memcpy": "memory_copy",
    "memmove": "memory_copy",
    "RtlCopyMemory": "memory_copy",
    "RtlMoveMemory": "memory_copy",
    "RtlCopyBytes": "memory_copy",
    "ZwDuplicateObject": "handle_dup",
    "ObReferenceObjectByHandle": "handle_access",
    "MmMapMemoryDumpMdl": "memory_map",
})

# Concise auto-labels (TheDebugger-style short names)
AUTO_LABELS = {
    "mmio_map": "map pages",
    "memory_copy": "mem copy",
    "memory_map": "map section",
    "process_access": "process attach",
    "handle_dup": "dup handle",
    "handle_access": "ref handle",
    "registry_write": "reg write",
    "port_io": "port I/O",
    "msr_access": "msr r/w",
    "file_ops": "file ops",
    "pool_alloc": "alloc mem",
    "callback_reg": "set callback",
}

# Per-API concise labels for deep dive output
_API_LABELS = {
    "MmCopyVirtualMemory": "mem copy",
    "MmMapIoSpace": "map pages",
    "MmMapLockedPages": "map pages",
    "MmMapLockedPagesSpecifyCache": "map pages",
    "MmGetPhysicalAddress": "phys addr",
    "MmAllocateContiguousMemory": "alloc contig",
    "MmAllocateNonCachedMemory": "alloc nocache",
    "ZwMapViewOfSection": "map section",
    "PsLookupProcessByProcessId": "lookup pid",
    "KeStackAttachProcess": "process attach",
    "KeUnstackDetachProcess": "process detach",
    "ZwTerminateProcess": "process kill",
    "ZwOpenProcess": "open process",
    "ObOpenObjectByPointer": "obj by ptr",
    "ExAllocatePool": "alloc mem",
    "ExAllocatePool2": "alloc mem",
    "ExAllocatePoolWithTag": "alloc mem",
    "ExFreePoolWithTag": "free mem",
    "ZwCreateFile": "create file",
    "ZwWriteFile": "write file",
    "ZwReadFile": "read file",
    "ZwDeleteFile": "delete file",
    "ZwSetValueKey": "reg set",
    "ZwDeleteKey": "reg delete",
    "ZwCreateKey": "reg create",
    "ZwOpenKey": "reg open",
    "READ_PORT_UCHAR": "read port",
    "WRITE_PORT_UCHAR": "write port",
    "READ_PORT_ULONG": "read port",
    "WRITE_PORT_ULONG": "write port",
    "__readmsr": "read msr",
    "__writemsr": "write msr",
    "ObRegisterCallbacks": "reg callbacks",
    "PsSetCreateProcessNotifyRoutine": "proc notify",
    "PsSetLoadImageNotifyRoutine": "img notify",
    "memcpy": "mem copy",
    "memmove": "mem copy",
    "RtlCopyMemory": "mem copy",
    "RtlMoveMemory": "mem copy",
    "RtlCopyBytes": "mem copy",
    "ZwDuplicateObject": "dup handle",
    "ObReferenceObjectByHandle": "ref handle",
}

# Validation APIs to check for security posture
_VALIDATION_APIS = {
    "ProbeForRead", "ProbeForWrite", "SeAccessCheck",
}

# IRP completion APIs
_IRP_COMPLETION_APIS = {"IofCompleteRequest", "IoCompleteRequest"}


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


def deep_dive_ioctl(ioctl: IOCTLInfo,
                    handler_irp_completion: bool = False) -> IOCTLDeepDive:
    """Produce a per-IOCTL deep dive with categorized APIs, validation, and risk.

    Args:
        ioctl: A parsed IOCTLInfo object (with decompiled_snippet populated)
        handler_irp_completion: Whether the parent DeviceControl handler (full
            decompilation) contains IofCompleteRequest/IoCompleteRequest.
            Used as fallback when the per-IOCTL snippet is too narrow to
            capture the completion call.

    Returns:
        IOCTLDeepDive with categorized API calls, security validation status,
        IRP completion check, risk assessment, and concise auto-label.
    """
    snippet = ioctl.decompiled_snippet or ""

    # --- 1. Categorized API calls ---
    api_categories: dict[str, list[str]] = {}
    all_found_apis: list[str] = []

    for category, apis in API_CATEGORIES.items():
        found = [api for api in apis if api in snippet]
        if found:
            api_categories[category] = found
            all_found_apis.extend(found)

    # Check for OTHER known APIs not in the categories above
    other_apis = []
    for api, tag in SENSITIVE_APIS.items():
        if api in snippet and api not in all_found_apis:
            other_apis.append(api)
            all_found_apis.append(api)
    if other_apis:
        api_categories["OTHER"] = other_apis

    # --- 2. Security validation status ---
    has_probe_read = "ProbeForRead" in snippet
    has_probe_write = "ProbeForWrite" in snippet
    has_access_check = "SeAccessCheck" in snippet
    has_try_except = ("try {" in snippet or "__try" in snippet
                      or "_SEH_" in snippet or "except (" in snippet)

    checks_found = []
    if has_probe_read:
        checks_found.append("ProbeForRead")
    if has_probe_write:
        checks_found.append("ProbeForWrite")
    if has_access_check:
        checks_found.append("SeAccessCheck")
    if has_try_except:
        checks_found.append("try/except")

    validation_status = ", ".join(checks_found) if checks_found else "NONE"

    # --- 3. IRP completion check ---
    # First check the per-IOCTL snippet (most specific).
    # Fall back to the parent handler flag — IofCompleteRequest is almost
    # always called AFTER the switch/case, outside any individual case body,
    # so the narrow 500-char snippet rarely captures it.
    has_irp_completion = any(api in snippet for api in _IRP_COMPLETION_APIS)
    if not has_irp_completion and handler_irp_completion:
        has_irp_completion = True
    irp_completion_risk = "" if has_irp_completion else \
        "No IRP completion detected (may leak IRP or cause hang)"

    # --- 4. Risk assessment ---
    risk = _assess_risk(ioctl, api_categories, validation_status,
                        has_irp_completion)

    # --- 5. Concise auto-label ---
    label_parts = []
    seen_labels = set()
    for api in all_found_apis:
        lbl = _API_LABELS.get(api)
        if lbl and lbl not in seen_labels:
            seen_labels.add(lbl)
            label_parts.append(lbl)
    label = " + ".join(label_parts) if label_parts else ioctl.label

    return IOCTLDeepDive(
        code_hex=ioctl.code_hex,
        method=ioctl.method.name,
        access=ioctl.access.name,
        label=label,
        api_categories=api_categories,
        has_probe_for_read=has_probe_read,
        has_probe_for_write=has_probe_write,
        has_access_check=has_access_check,
        has_try_except=has_try_except,
        validation_status=validation_status,
        has_irp_completion=has_irp_completion,
        irp_completion_risk=irp_completion_risk,
        risk=risk,
    )


def deep_dive_all(ioctls: list,
                  handler_irp_completion: bool = False) -> list:
    """Run deep_dive_ioctl on every IOCTL in a list.

    Args:
        ioctls: List of IOCTLInfo objects
        handler_irp_completion: Whether the parent DeviceControl handler
            contains IRP completion calls (passed through to each deep dive)

    Returns:
        List of IOCTLDeepDive objects, sorted by IOCTL code
    """
    return [deep_dive_ioctl(ioctl, handler_irp_completion=handler_irp_completion)
            for ioctl in ioctls]


def _assess_risk(ioctl: IOCTLInfo, api_categories: dict,
                 validation_status: str, has_irp_completion: bool) -> str:
    """Generate a one-line risk string based on what's found in the handler."""
    risks = []

    # NEITHER I/O with no validation is the highest risk
    if ioctl.uses_neither_io and validation_status == "NONE":
        risks.append("NEITHER I/O with no buffer validation")
    elif ioctl.uses_neither_io:
        risks.append("NEITHER I/O (raw user pointers)")

    # Dangerous API combos
    if "MEMORY" in api_categories:
        mem_apis = api_categories["MEMORY"]
        if any(a in mem_apis for a in ("MmMapIoSpace", "MmMapLockedPages",
                                        "MmMapLockedPagesSpecifyCache")):
            risks.append("maps physical/locked pages to usermode")
        if "MmCopyVirtualMemory" in mem_apis:
            risks.append("cross-process memory copy")

    if "PROCESS" in api_categories:
        proc_apis = api_categories["PROCESS"]
        if "ZwTerminateProcess" in proc_apis:
            risks.append("can terminate arbitrary process")
        if "KeStackAttachProcess" in proc_apis:
            risks.append("attaches to arbitrary process context")

    if "MSR" in api_categories:
        msr_apis = api_categories["MSR"]
        if "__writemsr" in msr_apis:
            risks.append("writes arbitrary MSR (code exec risk)")
        elif "__readmsr" in msr_apis:
            risks.append("reads arbitrary MSR")

    if "PORT_IO" in api_categories:
        risks.append("direct I/O port access")

    if not has_irp_completion:
        risks.append("no IRP completion")

    if not risks:
        if not api_categories:
            return "No sensitive APIs detected"
        return "Low — standard kernel APIs only"

    return "; ".join(risks)
