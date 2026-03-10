"""ROP/JOP gadget scanner — finds useful gadgets in driver .text sections.

Uses Capstone disassembly engine (no JVM needed, faster than Ghidra for
byte-level scanning). Searches for instruction sequences ending in ret/jmp/call
that could be used in exploit chains.
"""

import logging
import os
import re
import struct
from typing import Optional

import pefile

from . import Gadget

logger = logging.getLogger("driveratlas.tier2.gadget_scanner")

# Maximum gadget length (bytes before the terminator)
MAX_GADGET_LEN = 20

# Minimum useful gadget instructions
MIN_GADGET_INSNS = 1

# x64 terminators
RET_BYTES = [
    b"\xc3",         # ret
    b"\xc2",         # ret imm16 (first byte, 2 more follow)
    b"\xcb",         # retf
]

JMP_REG_PATTERNS = [
    b"\xff\xe0",  # jmp rax
    b"\xff\xe1",  # jmp rcx
    b"\xff\xe2",  # jmp rdx
    b"\xff\xe3",  # jmp rbx
    b"\xff\xe4",  # jmp rsp
    b"\xff\xe6",  # jmp rsi
    b"\xff\xe7",  # jmp rdi
]

CALL_REG_PATTERNS = [
    b"\xff\xd0",  # call rax
    b"\xff\xd1",  # call rcx
    b"\xff\xd2",  # call rdx
    b"\xff\xd3",  # call rbx
    b"\xff\xd4",  # call rsp
    b"\xff\xd6",  # call rsi
    b"\xff\xd7",  # call rdi
]


def scan_gadgets(
    driver_path: str,
    max_gadgets: int = 500,
    include_jop: bool = True,
    include_cop: bool = False,
) -> list:
    """Scan a driver binary for ROP/JOP gadgets.

    Args:
        driver_path: Path to the .sys file
        max_gadgets: Maximum number of gadgets to return
        include_jop: Include JOP gadgets (jmp reg)
        include_cop: Include COP gadgets (call reg)

    Returns:
        List of Gadget objects
    """
    try:
        import capstone
    except ImportError:
        logger.error("capstone not installed. Install with: pip install capstone")
        return []

    if not os.path.isfile(driver_path):
        logger.error(f"Driver not found: {driver_path}")
        return []

    try:
        pe = pefile.PE(driver_path)
    except pefile.PEFormatError as e:
        logger.error(f"Invalid PE: {e}")
        return []

    # Determine architecture
    if pe.FILE_HEADER.Machine == 0x8664:
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif pe.FILE_HEADER.Machine == 0x014C:
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    else:
        logger.warning(f"Unsupported architecture: 0x{pe.FILE_HEADER.Machine:04X}")
        pe.close()
        return []

    cs.detail = False  # Faster without detailed instruction info

    image_base = pe.OPTIONAL_HEADER.ImageBase
    gadgets = []

    # Find .text section(s)
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        if not (section.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue

        data = section.get_data()
        section_rva = section.VirtualAddress

        logger.info(f"Scanning {name} ({len(data)} bytes) for gadgets...")

        # Find ROP gadgets (ending in ret)
        gadgets.extend(_find_gadgets_at_terminators(
            data, section_rva, image_base, cs,
            [b"\xc3"], "rop", max_gadgets - len(gadgets),
        ))

        # Find JOP gadgets (ending in jmp reg)
        if include_jop and len(gadgets) < max_gadgets:
            gadgets.extend(_find_gadgets_at_terminators(
                data, section_rva, image_base, cs,
                JMP_REG_PATTERNS, "jop", max_gadgets - len(gadgets),
            ))

        # Find COP gadgets (ending in call reg)
        if include_cop and len(gadgets) < max_gadgets:
            gadgets.extend(_find_gadgets_at_terminators(
                data, section_rva, image_base, cs,
                CALL_REG_PATTERNS, "cop", max_gadgets - len(gadgets),
            ))

        if len(gadgets) >= max_gadgets:
            break

    pe.close()
    logger.info(f"Found {len(gadgets)} gadgets")
    return gadgets[:max_gadgets]


def _classify_gadget(disassembly: str) -> str:
    """Classify a gadget into a functional category matching TheDebugger output.

    Categories: stack-pivot, memory-read, memory-write, reg-control, jmp-reg, syscall, misc
    """
    d = disassembly.lower()

    # stack-pivot: xchg with rsp/esp, mov rsp/esp, pop rsp/esp, leave
    if any(pat in d for pat in [
        "xchg rsp", "xchg esp", "xchg rax, rsp", "xchg rcx, rsp",
        "xchg rdx, rsp", "xchg rbx, rsp", "xchg rsi, rsp", "xchg rdi, rsp",
        "mov rsp", "mov esp", "pop rsp", "pop esp", "leave",
    ]):
        return "stack-pivot"

    # syscall: syscall instruction or int 0x2e (Windows fast syscall)
    if "syscall" in d or "int 0x2e" in d:
        return "syscall"

    # memory-write: mov [reg], reg / stos / mov dword ptr [
    if any(pat in d for pat in ["stos", "mov dword ptr [", "mov qword ptr [", "mov word ptr [", "mov byte ptr ["]):
        return "memory-write"
    # Pattern: mov [rXX], rXX (store to memory via register indirect)
    if re.search(r'mov\s+\[r\w+', d):
        return "memory-write"

    # memory-read: mov rXX, [rXX] / movzx / lods
    if any(pat in d for pat in ["movzx", "lods"]):
        return "memory-read"
    if re.search(r'mov\s+r\w+,\s*\[', d) or re.search(r'mov\s+e\w+,\s*\[', d):
        return "memory-read"

    # jmp-reg: jmp to register (already identified by terminator, but classify explicitly)
    if re.search(r'jmp\s+(rax|rcx|rdx|rbx|rsp|rbp|rsi|rdi|r\d+|eax|ecx|edx|ebx|esp|ebp|esi|edi)', d):
        return "jmp-reg"

    # reg-control: pop rXX (any register), xchg (non-rsp)
    if re.search(r'pop\s+(rax|rcx|rdx|rbx|rbp|rsi|rdi|r\d+|eax|ecx|edx|ebx|ebp|esi|edi)', d):
        return "reg-control"
    if "xchg" in d:
        return "reg-control"

    return "misc"


def _find_gadgets_at_terminators(
    data: bytes,
    section_rva: int,
    image_base: int,
    cs,
    terminators: list,
    gadget_type: str,
    remaining: int,
) -> list:
    """Find gadgets ending at each terminator location."""
    gadgets = []
    seen = set()

    for terminator in terminators:
        term_len = len(terminator)
        offset = 0

        while offset < len(data) and len(gadgets) < remaining:
            pos = data.find(terminator, offset)
            if pos < 0:
                break
            offset = pos + 1

            # Try different start offsets before the terminator
            for back in range(1, MAX_GADGET_LEN + 1):
                start = pos - back
                if start < 0:
                    continue

                candidate = data[start:pos + term_len]
                addr = image_base + section_rva + start

                # Skip duplicates
                if candidate in seen:
                    continue

                # Disassemble and validate
                instructions = list(cs.disasm(candidate, addr))
                if len(instructions) < MIN_GADGET_INSNS:
                    continue

                # Verify the disassembly covers the full candidate
                # (last instruction should end at the terminator)
                last = instructions[-1]
                last_end = last.address + last.size
                expected_end = addr + len(candidate)
                if last_end != expected_end:
                    continue

                disasm = "; ".join(
                    f"{i.mnemonic} {i.op_str}".strip() for i in instructions
                )

                seen.add(candidate)
                gadgets.append(Gadget(
                    address=addr,
                    address_hex="0x%X" % addr,
                    instruction_bytes=candidate,
                    disassembly=disasm,
                    gadget_type=gadget_type,
                    category=_classify_gadget(disasm),
                ))

                if len(gadgets) >= remaining:
                    return gadgets

    return gadgets


def generate_gadget_summary(gadgets: list) -> dict:
    """Generate a summary of found gadgets for reporting.

    Categorizes gadgets functionally (matching TheDebugger output):
    reg-control, misc, memory-read, memory-write, jmp-reg, stack-pivot, syscall
    """
    if not gadgets:
        return {"total": 0}

    # Category ordering matches TheDebugger convention
    CATEGORY_ORDER = [
        "reg-control", "misc", "memory-read",
        "jmp-reg", "memory-write", "stack-pivot", "syscall",
    ]

    by_category = {}
    for g in gadgets:
        by_category.setdefault(g.category, []).append(g)

    # Build ordered category counts
    category_counts = {}
    for cat in CATEGORY_ORDER:
        if cat in by_category:
            category_counts[cat] = len(by_category[cat])
    # Include any categories not in the predefined order
    for cat in sorted(by_category.keys()):
        if cat not in category_counts:
            category_counts[cat] = len(by_category[cat])

    # Build the one-line summary string
    parts = [f"{cat}: {count}" for cat, count in category_counts.items()]
    summary_line = f"ROP/JOP Gadgets: {len(gadgets)} ({', '.join(parts)})"

    # Group interesting gadgets by category with examples
    # "Interesting" = non-misc categories (functional gadgets are more useful for exploit dev)
    interesting_by_category = {}
    for cat in CATEGORY_ORDER:
        if cat == "misc":
            continue
        cat_gadgets = by_category.get(cat, [])
        if cat_gadgets:
            # Include up to 5 examples per category
            interesting_by_category[cat] = [
                {
                    "address": g.address_hex,
                    "disassembly": g.disassembly,
                    "type": g.gadget_type,
                }
                for g in cat_gadgets[:5]
            ]

    # Also flag high-value gadgets: MSR, I/O, wrmsr/rdmsr
    high_value = []
    for g in gadgets:
        d = g.disassembly.lower()
        if any(pat in d for pat in ["wrmsr", "rdmsr", "in ", "out "]):
            high_value.append({
                "address": g.address_hex,
                "disassembly": g.disassembly,
                "category": g.category,
            })

    return {
        "total": len(gadgets),
        "summary_line": summary_line,
        "by_category": category_counts,
        "interesting_by_category": interesting_by_category,
        "high_value": high_value[:20],
    }
