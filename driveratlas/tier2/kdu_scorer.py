"""KDU Provider Compatibility Scorer.

Analyzes Tier 1 + Tier 2 results to determine if a driver could serve as a
KDU (Kernel Driver Utility) provider and what action types it supports.

KDU action types:
  - MapDriver: Load unsigned kernel code (needs physical + virtual memory)
  - DKOM: Direct Kernel Object Manipulation (needs virtual memory write)
  - DSECorruption: Patch ci.dll (needs virtual memory write)
  - DumpProcess: Read process memory (needs process + virtual memory)

Reference: https://github.com/hfiref0x/KDU
"""

from dataclasses import dataclass, field, asdict
from typing import Optional


# KDU primitive categories mapped to API names
# These are the APIs that, when reachable from an IOCTL handler,
# indicate a driver exposes the corresponding KDU primitive.

PHYS_READ_APIS = {
    "MmMapIoSpace", "MmGetPhysicalAddress", "MmGetVirtualForPhysical",
    "HalTranslateBusAddress", "MmAllocateContiguousMemory",
}

PHYS_WRITE_APIS = PHYS_READ_APIS  # same APIs, write = map + memcpy

VIRT_READ_APIS = {
    "MmCopyVirtualMemory", "ZwMapViewOfSection",
    "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
    "KeStackAttachProcess",  # attach + read pattern
}

VIRT_WRITE_APIS = VIRT_READ_APIS  # same APIs for write

MSR_APIS = {"__readmsr", "__writemsr"}

PORT_IO_APIS = {
    "READ_PORT_UCHAR", "READ_PORT_ULONG",
    "WRITE_PORT_UCHAR", "WRITE_PORT_ULONG",
}

PROCESS_APIS = {
    "PsLookupProcessByProcessId", "ZwOpenProcess",
    "ObOpenObjectByPointer", "ObReferenceObjectByHandle",
    "ZwDuplicateObject",
}

DSE_APIS = VIRT_WRITE_APIS  # DSE corruption = write ci.dll!g_CiOptions

PML4_APIS = PHYS_READ_APIS  # PML4 discovery = scan low physical stub


@dataclass
class KDUPrimitive:
    """A confirmed KDU-usable primitive from a specific IOCTL."""
    primitive_type: str  # "ReadPhysicalMemory", "WriteKernelVM", etc.
    ioctl_code: str      # "0x80862007"
    ioctl_method: str    # "NEITHER", "BUFFERED", etc.
    confirming_apis: list = field(default_factory=list)
    confidence: str = "high"  # "high" (Tier 2 confirmed), "medium" (Tier 1 only)


@dataclass
class KDUAction:
    """A KDU action type this driver could support."""
    action: str          # "MapDriver", "DKOM", "DSECorruption", "DumpProcess"
    supported: bool = False
    reason: str = ""
    required_primitives: list = field(default_factory=list)
    missing_primitives: list = field(default_factory=list)


@dataclass
class KDUScore:
    """Complete KDU provider compatibility assessment for a driver."""
    driver_name: str
    sha256: str

    # Overall
    kdu_compatible: bool = False
    best_action: str = ""  # best supported action type
    confidence: str = ""   # "confirmed" (Tier 2) or "likely" (Tier 1 only)

    # Confirmed primitives
    primitives: list = field(default_factory=list)  # List[KDUPrimitive]

    # Action compatibility
    actions: list = field(default_factory=list)  # List[KDUAction]

    # Risk factors
    has_neither_io: bool = False
    missing_mitigations: list = field(default_factory=list)

    # Summary
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "driver_name": self.driver_name,
            "sha256": self.sha256,
            "kdu_compatible": self.kdu_compatible,
            "best_action": self.best_action,
            "confidence": self.confidence,
            "primitives": [asdict(p) for p in self.primitives],
            "actions": [asdict(a) for a in self.actions],
            "has_neither_io": self.has_neither_io,
            "missing_mitigations": self.missing_mitigations,
            "summary": self.summary,
        }


def _check_ioctl_primitives(deep_dive: dict) -> list:
    """Extract KDU primitives from a single IOCTL deep dive."""
    primitives = []
    apis_found = set()

    # Collect all APIs from categories
    for cat, api_list in deep_dive.get("api_categories", {}).items():
        for api in api_list:
            apis_found.add(api)

    code = deep_dive.get("code_hex", "?")
    method = deep_dive.get("method", "?")

    # Check each primitive type
    phys_r = apis_found & PHYS_READ_APIS
    if phys_r:
        primitives.append(KDUPrimitive(
            primitive_type="ReadPhysicalMemory",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(phys_r),
        ))
        primitives.append(KDUPrimitive(
            primitive_type="WritePhysicalMemory",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(phys_r),
        ))

    virt_r = apis_found & VIRT_READ_APIS
    if virt_r:
        primitives.append(KDUPrimitive(
            primitive_type="ReadKernelVM",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(virt_r),
        ))
        primitives.append(KDUPrimitive(
            primitive_type="WriteKernelVM",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(virt_r),
        ))

    pml4 = apis_found & PML4_APIS
    if pml4:
        primitives.append(KDUPrimitive(
            primitive_type="QueryPML4Value",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(pml4),
        ))
        primitives.append(KDUPrimitive(
            primitive_type="VirtualToPhysical",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(pml4),
        ))

    msr = apis_found & MSR_APIS
    if msr:
        primitives.append(KDUPrimitive(
            primitive_type="MSRAccess",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(msr),
        ))

    port = apis_found & PORT_IO_APIS
    if port:
        primitives.append(KDUPrimitive(
            primitive_type="PortIO",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(port),
        ))

    proc = apis_found & PROCESS_APIS
    if proc:
        primitives.append(KDUPrimitive(
            primitive_type="OpenProcess",
            ioctl_code=code, ioctl_method=method,
            confirming_apis=sorted(proc),
        ))

    return primitives


def _check_import_primitives(dangerous_imports: list) -> list:
    """Fall back to Tier 1 import analysis (lower confidence)."""
    primitives = []
    dimps = set(dangerous_imports)

    if dimps & PHYS_READ_APIS:
        primitives.append(KDUPrimitive(
            primitive_type="ReadPhysicalMemory",
            ioctl_code="unknown", ioctl_method="unknown",
            confirming_apis=sorted(dimps & PHYS_READ_APIS),
            confidence="medium",
        ))
        primitives.append(KDUPrimitive(
            primitive_type="WritePhysicalMemory",
            ioctl_code="unknown", ioctl_method="unknown",
            confirming_apis=sorted(dimps & PHYS_WRITE_APIS),
            confidence="medium",
        ))

    if dimps & VIRT_READ_APIS:
        primitives.append(KDUPrimitive(
            primitive_type="ReadKernelVM",
            ioctl_code="unknown", ioctl_method="unknown",
            confirming_apis=sorted(dimps & VIRT_READ_APIS),
            confidence="medium",
        ))
        primitives.append(KDUPrimitive(
            primitive_type="WriteKernelVM",
            ioctl_code="unknown", ioctl_method="unknown",
            confirming_apis=sorted(dimps & VIRT_WRITE_APIS),
            confidence="medium",
        ))

    if dimps & PROCESS_APIS:
        primitives.append(KDUPrimitive(
            primitive_type="OpenProcess",
            ioctl_code="unknown", ioctl_method="unknown",
            confirming_apis=sorted(dimps & PROCESS_APIS),
            confidence="medium",
        ))

    if dimps & MSR_APIS:
        primitives.append(KDUPrimitive(
            primitive_type="MSRAccess",
            ioctl_code="unknown", ioctl_method="unknown",
            confirming_apis=sorted(dimps & MSR_APIS),
            confidence="medium",
        ))

    if dimps & PORT_IO_APIS:
        primitives.append(KDUPrimitive(
            primitive_type="PortIO",
            ioctl_code="unknown", ioctl_method="unknown",
            confirming_apis=sorted(dimps & PORT_IO_APIS),
            confidence="medium",
        ))

    return primitives


def _assess_actions(prim_types: set) -> list:
    """Determine which KDU action types are supported by the primitives."""
    actions = []

    # MapDriver: needs physical + virtual + PML4 (or just physical with brute force)
    map_required = {"ReadPhysicalMemory", "WritePhysicalMemory", "ReadKernelVM", "WriteKernelVM"}
    map_have = prim_types & map_required
    map_missing = map_required - prim_types
    actions.append(KDUAction(
        action="MapDriver",
        supported=len(map_missing) == 0,
        reason="Full physical + virtual memory primitives" if not map_missing else f"Missing: {', '.join(sorted(map_missing))}",
        required_primitives=sorted(map_required),
        missing_primitives=sorted(map_missing),
    ))

    # MapDriver (physical brute force): only needs physical memory
    phys_required = {"ReadPhysicalMemory", "WritePhysicalMemory"}
    phys_have = prim_types & phys_required
    if phys_have == phys_required and map_missing:
        actions.append(KDUAction(
            action="MapDriver (physical brute-force)",
            supported=True,
            reason="Physical memory R/W available, can brute-force PML4",
            required_primitives=sorted(phys_required),
        ))

    # DKOM: needs virtual memory write
    dkom_required = {"WriteKernelVM"}
    dkom_missing = dkom_required - prim_types
    actions.append(KDUAction(
        action="DKOM",
        supported=len(dkom_missing) == 0,
        reason="Kernel virtual memory write available" if not dkom_missing else f"Missing: {', '.join(sorted(dkom_missing))}",
        required_primitives=sorted(dkom_required),
        missing_primitives=sorted(dkom_missing),
    ))

    # DSECorruption: needs virtual memory write to ci.dll
    dse_required = {"WriteKernelVM"}
    dse_missing = dse_required - prim_types
    actions.append(KDUAction(
        action="DSECorruption",
        supported=len(dse_missing) == 0,
        reason="Can write ci.dll!g_CiOptions via virtual memory" if not dse_missing else f"Missing: {', '.join(sorted(dse_missing))}",
        required_primitives=sorted(dse_required),
        missing_primitives=sorted(dse_missing),
    ))

    # DumpProcess: needs process + virtual memory read
    dump_required = {"OpenProcess", "ReadKernelVM"}
    dump_missing = dump_required - prim_types
    actions.append(KDUAction(
        action="DumpProcess",
        supported=len(dump_missing) == 0,
        reason="Process handle + virtual memory read available" if not dump_missing else f"Missing: {', '.join(sorted(dump_missing))}",
        required_primitives=sorted(dump_required),
        missing_primitives=sorted(dump_missing),
    ))

    return actions


def score_driver(result: dict) -> KDUScore:
    """Score a driver's KDU provider compatibility from Tier 1 + Tier 2 results.

    Args:
        result: A single driver entry from results.json (has both T1 and T2 fields)

    Returns:
        KDUScore with primitives, actions, and overall assessment
    """
    score = KDUScore(
        driver_name=result.get("driver_name", ""),
        sha256=result.get("sha256", ""),
        missing_mitigations=result.get("mitigations_off", []),
    )

    # Phase 1: Check Tier 2 deep dives (high confidence)
    tier2_primitives = []
    for dd in result.get("deep_dives", []):
        tier2_primitives.extend(_check_ioctl_primitives(dd))

    # Phase 2: Fall back to Tier 1 imports for primitives not found in Tier 2
    tier2_types = {p.primitive_type for p in tier2_primitives}
    tier1_primitives = []
    if not result.get("tier2_ok"):
        # No Tier 2 — use imports only (medium confidence)
        tier1_primitives = _check_import_primitives(
            result.get("dangerous_imports", [])
        )
    else:
        # Have Tier 2 but some primitives might only show in imports
        # (Ghidra may miss deeply nested calls)
        import_prims = _check_import_primitives(
            result.get("dangerous_imports", [])
        )
        for p in import_prims:
            if p.primitive_type not in tier2_types:
                p.confidence = "low"  # imported but not confirmed in IOCTL
                tier1_primitives.append(p)

    # Merge: Tier 2 primitives take priority
    all_primitives = tier2_primitives + tier1_primitives
    score.primitives = all_primitives

    # Determine confidence level
    if tier2_primitives:
        score.confidence = "confirmed"
    elif tier1_primitives:
        score.confidence = "likely"
    else:
        score.confidence = "none"

    # Check NEITHER I/O
    score.has_neither_io = result.get("neither_io_count", 0) > 0

    # Assess action types
    prim_types = {p.primitive_type for p in all_primitives}
    score.actions = _assess_actions(prim_types)

    # Overall compatibility
    supported_actions = [a for a in score.actions if a.supported]
    if supported_actions:
        score.kdu_compatible = True
        # Pick best action (MapDriver > DKOM > DSE > DumpProcess)
        priority = ["MapDriver", "MapDriver (physical brute-force)",
                     "DKOM", "DSECorruption", "DumpProcess"]
        for p in priority:
            if any(a.action == p and a.supported for a in score.actions):
                score.best_action = p
                break

    # Build summary
    if score.kdu_compatible:
        confirmed = [p for p in all_primitives if p.confidence == "high"]
        likely = [p for p in all_primitives if p.confidence != "high"]
        parts = []
        if confirmed:
            ctypes = sorted(set(p.primitive_type for p in confirmed))
            parts.append(f"Confirmed: {', '.join(ctypes)}")
        if likely:
            ltypes = sorted(set(p.primitive_type for p in likely))
            parts.append(f"Likely: {', '.join(ltypes)}")
        actions_str = ", ".join(a.action for a in supported_actions)
        score.summary = f"KDU-compatible ({actions_str}). {'; '.join(parts)}"
    else:
        score.summary = "Not KDU-compatible: no exploitable primitives found in IOCTL handlers"

    return score


def score_batch(results: list) -> list:
    """Score all drivers in a results list.

    Returns:
        List of KDUScore, sorted by compatibility (best first)
    """
    scores = [score_driver(r) for r in results]

    # Sort: compatible first, then by action priority, then by primitive count
    action_rank = {
        "MapDriver": 0,
        "MapDriver (physical brute-force)": 1,
        "DKOM": 2,
        "DSECorruption": 3,
        "DumpProcess": 4,
        "": 99,
    }

    scores.sort(key=lambda s: (
        0 if s.kdu_compatible else 1,
        action_rank.get(s.best_action, 99),
        -len(s.primitives),
    ))

    return scores


def format_kdu_report(score: KDUScore) -> str:
    """Format a KDU score as a terminal-style report."""
    lines = []

    if score.kdu_compatible:
        lines.append(f"[!] KDU PROVIDER CANDIDATE: {score.driver_name}")
        lines.append(f"    Best action: {score.best_action}")
        lines.append(f"    Confidence: {score.confidence}")
    else:
        lines.append(f"[-] {score.driver_name}: not KDU-compatible")
        return "\n".join(lines)

    lines.append("")
    lines.append("[*] Confirmed Primitives:")
    for p in score.primitives:
        conf = "CONFIRMED" if p.confidence == "high" else "LIKELY" if p.confidence == "medium" else "UNCONFIRMED"
        apis = ", ".join(p.confirming_apis)
        lines.append(f"    [{conf}] {p.primitive_type} via IOCTL {p.ioctl_code} ({p.ioctl_method})")
        lines.append(f"             APIs: {apis}")

    lines.append("")
    lines.append("[*] Supported Actions:")
    for a in score.actions:
        marker = "[+]" if a.supported else "[-]"
        lines.append(f"    {marker} {a.action}: {a.reason}")

    if score.missing_mitigations:
        lines.append("")
        lines.append(f"[*] Missing mitigations: {', '.join(score.missing_mitigations)}")

    return "\n".join(lines)
