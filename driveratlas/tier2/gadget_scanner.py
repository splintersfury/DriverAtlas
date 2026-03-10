"""ROP/JOP gadget scanner — finds useful gadgets in driver .text sections.

Uses Capstone disassembly engine (no JVM needed, faster than Ghidra for
byte-level scanning). Searches for instruction sequences ending in ret/jmp/call
that could be used in exploit chains.
"""

import logging
import os
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
                ))

                if len(gadgets) >= remaining:
                    return gadgets

    return gadgets


def generate_gadget_summary(gadgets: list) -> dict:
    """Generate a summary of found gadgets for reporting."""
    if not gadgets:
        return {"total": 0}

    by_type = {}
    for g in gadgets:
        by_type.setdefault(g.gadget_type, []).append(g)

    # Find interesting gadgets (stack pivots, syscall, etc.)
    interesting = []
    for g in gadgets:
        d = g.disassembly.lower()
        if any(pat in d for pat in [
            "xchg", "mov rsp", "mov esp",  # Stack pivots
            "pop rsp", "pop esp",
            "syscall", "int 0x2e",  # Syscall
            "wrmsr", "rdmsr",  # MSR access
            "in ", "out ",  # I/O ports
        ]):
            interesting.append({
                "address": g.address_hex,
                "disassembly": g.disassembly,
                "type": g.gadget_type,
            })

    return {
        "total": len(gadgets),
        "by_type": {k: len(v) for k, v in by_type.items()},
        "interesting": interesting[:50],
    }
