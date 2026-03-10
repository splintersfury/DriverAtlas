"""Tier 2 deep analysis — Ghidra-powered dispatch extraction and security assessment."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class IOCTLMethod(Enum):
    """I/O transfer method from CTL_CODE."""
    BUFFERED = 0
    IN_DIRECT = 1
    OUT_DIRECT = 2
    NEITHER = 3


class IOCTLAccess(Enum):
    """Required access from CTL_CODE."""
    ANY = 0
    READ = 1
    WRITE = 2
    READ_WRITE = 3


@dataclass
class IOCTLInfo:
    """Parsed IOCTL code with CTL_CODE decomposition and handler details."""

    code: int  # Raw IOCTL value
    code_hex: str  # "0x22200C"

    # CTL_CODE decomposition
    device_type: int = 0
    function: int = 0
    method: IOCTLMethod = IOCTLMethod.BUFFERED
    access: IOCTLAccess = IOCTLAccess.ANY

    # Handler info from Ghidra
    handler_name: str = ""
    handler_addr: str = ""
    decompiled_snippet: str = ""

    # API calls made within this IOCTL handler
    api_calls: list = field(default_factory=list)

    # Auto-generated label from API call analysis
    label: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["method"] = self.method.name
        d["access"] = self.access.name
        return d

    @staticmethod
    def from_code(code: int, **kwargs) -> "IOCTLInfo":
        """Parse a raw IOCTL code into its CTL_CODE components."""
        return IOCTLInfo(
            code=code,
            code_hex="0x%X" % code,
            device_type=(code >> 16) & 0xFFFF,
            function=(code >> 2) & 0xFFF,
            method=IOCTLMethod(code & 0x3),
            access=IOCTLAccess((code >> 14) & 0x3),
            **kwargs,
        )

    @property
    def uses_neither_io(self) -> bool:
        """NEITHER method = raw user pointers, highest risk."""
        return self.method == IOCTLMethod.NEITHER

    @property
    def is_custom_device_type(self) -> bool:
        """Device types >= 0x8000 are vendor-defined."""
        return self.device_type >= 0x8000

    @property
    def is_custom_function(self) -> bool:
        """Function codes >= 0x800 are vendor-defined."""
        return self.function >= 0x800


@dataclass
class TaintPath:
    """A data flow from user-controlled input to a sensitive API."""

    source: str  # e.g., "SystemBuffer", "Type3InputBuffer", "InputBufferLength"
    sink: str  # e.g., "MmMapIoSpace", "memcpy", "RtlCopyMemory"
    ioctl_code: str = ""  # Which IOCTL this path lives in
    handler_name: str = ""
    confidence: float = 0.0  # 0.0-1.0
    path_description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SecurityCheck:
    """A missing or present security validation in an IOCTL handler."""

    check_type: str  # e.g., "input_length_validation", "probe_for_read", "access_check"
    present: bool = False
    ioctl_code: str = ""
    handler_name: str = ""
    details: str = ""
    severity: str = "medium"  # low, medium, high, critical

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Gadget:
    """ROP/JOP gadget found in driver .text section."""

    address: int
    address_hex: str
    instruction_bytes: bytes = b""
    disassembly: str = ""
    gadget_type: str = ""  # "rop", "jop", "cop"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["instruction_bytes"] = self.instruction_bytes.hex()
        return d


@dataclass
class Tier2Result:
    """Complete Tier 2 deep analysis result for a driver."""

    driver_name: str
    sha256: str

    # Ghidra analysis
    driver_entry_addr: str = ""
    irp_handlers: dict = field(default_factory=dict)  # IRP_MJ_NAME -> handler info
    ioctls: list = field(default_factory=list)  # List[IOCTLInfo]

    # Security assessment
    taint_paths: list = field(default_factory=list)  # List[TaintPath]
    security_checks: list = field(default_factory=list)  # List[SecurityCheck]

    # Artifacts
    gadgets: list = field(default_factory=list)  # List[Gadget]

    # Metadata
    ghidra_version: str = ""
    analysis_seconds: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "driver_name": self.driver_name,
            "sha256": self.sha256,
            "driver_entry_addr": self.driver_entry_addr,
            "irp_handlers": self.irp_handlers,
            "ioctls": [i.to_dict() for i in self.ioctls],
            "taint_paths": [t.to_dict() for t in self.taint_paths],
            "security_checks": [s.to_dict() for s in self.security_checks],
            "gadgets": [g.to_dict() for g in self.gadgets],
            "ghidra_version": self.ghidra_version,
            "analysis_seconds": self.analysis_seconds,
            "error": self.error,
        }

    @property
    def ioctl_count(self) -> int:
        return len(self.ioctls)

    @property
    def neither_io_count(self) -> int:
        return sum(1 for i in self.ioctls if i.uses_neither_io)

    @property
    def taint_path_count(self) -> int:
        return len(self.taint_paths)

    @property
    def missing_checks_count(self) -> int:
        return sum(1 for s in self.security_checks if not s.present)
