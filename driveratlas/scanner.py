"""Core PE scanner — produces DriverProfile from a Windows driver binary."""

import hashlib
import logging
import os
import re
import struct
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import pefile
import yaml

logger = logging.getLogger("driveratlas.scanner")

# Suppress cryptography BER warnings from malformed certs
warnings.filterwarnings("ignore", message=".*BER.*")


@dataclass
class DriverProfile:
    """Structural fingerprint of a Windows kernel driver."""

    # Identity
    name: str
    sha256: str
    size: int

    # PE metadata
    timestamp: Optional[datetime] = None
    machine: str = "unknown"
    subsystem: str = "unknown"
    linker_version: str = ""

    # Signing
    signer: Optional[str] = None

    # Version info
    product_name: Optional[str] = None
    file_description: Optional[str] = None
    company_name: Optional[str] = None
    file_version: Optional[str] = None
    original_filename: Optional[str] = None
    internal_name: Optional[str] = None

    # Framework
    framework: str = "unknown"
    framework_confidence: float = 0.0
    framework_evidence: list = field(default_factory=list)
    secondary_frameworks: list = field(default_factory=list)

    # Imports
    imports: dict = field(default_factory=dict)
    import_count: int = 0
    ntoskrnl_imports: list = field(default_factory=list)
    fltmgr_imports: list = field(default_factory=list)
    ndis_imports: list = field(default_factory=list)
    wdf_imports: list = field(default_factory=list)
    fwp_imports: list = field(default_factory=list)

    # Strings
    device_names: list = field(default_factory=list)
    symbolic_links: list = field(default_factory=list)
    registry_paths: list = field(default_factory=list)
    notable_strings: list = field(default_factory=list)

    # API fingerprint
    api_categories: dict = field(default_factory=dict)

    # Sections
    sections: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        if d.get("timestamp"):
            d["timestamp"] = d["timestamp"].isoformat()
        return d


# ── Machine type mapping ──────────────────────────────────────────────

_MACHINE_MAP = {
    0x8664: "x64",
    0x014C: "x86",
    0xAA64: "arm64",
}

_SUBSYSTEM_MAP = {
    1: "native",
    2: "windows_gui",
    3: "windows_console",
}


def scan_driver(path: str, classifier=None, categories_path: str | None = None) -> DriverProfile:
    """Scan a PE driver file and return its structural profile."""
    raw = open(path, "rb").read()
    sha256 = hashlib.sha256(raw).hexdigest()
    size = len(raw)
    name = os.path.basename(path)

    pe = pefile.PE(path, fast_load=False)

    meta = _extract_pe_metadata(pe)
    version = _extract_version_info(pe)
    imports = _extract_imports(pe)
    signer = _extract_signer(path, pe)
    strings = _extract_strings(raw)
    sections = _extract_sections(pe)

    # Categorize imports if we have the categories file
    api_cats = {}
    if categories_path and os.path.exists(categories_path):
        api_cats = _categorize_imports(imports, categories_path)

    # Classify framework
    fw_name, fw_conf, fw_evidence, secondary = "unknown", 0.0, [], []
    if classifier:
        primary, sec = classifier.classify(imports)
        if primary:
            fw_name = primary.name
            fw_conf = primary.confidence
            fw_evidence = primary.matched_symbols
        secondary = [s.name for s in sec]

    # Partition imports by DLL
    all_funcs = {dll: funcs for dll, funcs in imports.items()}
    ntoskrnl = all_funcs.get("ntoskrnl.exe", [])
    fltmgr = all_funcs.get("fltmgr.sys", [])
    ndis = all_funcs.get("ndis.sys", [])
    wdf = all_funcs.get("wdfldr.sys", [])
    fwp = all_funcs.get("fwpkclnt.sys", [])

    import_count = sum(len(v) for v in imports.values())

    pe.close()

    return DriverProfile(
        name=name,
        sha256=sha256,
        size=size,
        timestamp=meta.get("timestamp"),
        machine=meta.get("machine", "unknown"),
        subsystem=meta.get("subsystem", "unknown"),
        linker_version=meta.get("linker_version", ""),
        signer=signer,
        product_name=version.get("ProductName"),
        file_description=version.get("FileDescription"),
        company_name=version.get("CompanyName"),
        file_version=version.get("FileVersion"),
        original_filename=version.get("OriginalFilename"),
        internal_name=version.get("InternalName"),
        framework=fw_name,
        framework_confidence=fw_conf,
        framework_evidence=fw_evidence,
        secondary_frameworks=secondary,
        imports=imports,
        import_count=import_count,
        ntoskrnl_imports=ntoskrnl,
        fltmgr_imports=fltmgr,
        ndis_imports=ndis,
        wdf_imports=wdf,
        fwp_imports=fwp,
        device_names=strings.get("device_names", []),
        symbolic_links=strings.get("symbolic_links", []),
        registry_paths=strings.get("registry_paths", []),
        notable_strings=strings.get("notable_strings", []),
        api_categories=api_cats,
        sections=sections,
    )


def _extract_pe_metadata(pe: pefile.PE) -> dict:
    """Extract machine type, timestamp, subsystem, linker version."""
    machine = _MACHINE_MAP.get(pe.FILE_HEADER.Machine, "unknown")

    ts = None
    raw_ts = pe.FILE_HEADER.TimeDateStamp
    if raw_ts and raw_ts != 0 and raw_ts != 0xFFFFFFFF:
        try:
            ts = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
        except (OSError, ValueError):
            pass

    subsystem = _SUBSYSTEM_MAP.get(
        pe.OPTIONAL_HEADER.Subsystem, f"0x{pe.OPTIONAL_HEADER.Subsystem:X}"
    )

    major = pe.OPTIONAL_HEADER.MajorLinkerVersion
    minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
    linker = f"{major}.{minor}"

    return {
        "machine": machine,
        "timestamp": ts,
        "subsystem": subsystem,
        "linker_version": linker,
    }


def _extract_version_info(pe: pefile.PE) -> dict:
    """Extract version info from PE StringTable (ProductName, FileVersion, etc.)."""
    result = {}
    wanted = {
        "ProductName", "FileDescription", "CompanyName",
        "FileVersion", "OriginalFilename", "InternalName",
    }
    if not hasattr(pe, "FileInfo"):
        return result
    for entry in pe.FileInfo:
        for child in entry:
            if hasattr(child, "StringTable"):
                for st in child.StringTable:
                    for key, val in st.entries.items():
                        k = key.decode("utf-8", errors="ignore")
                        v = val.decode("utf-8", errors="ignore")
                        if k in wanted:
                            result[k] = v
    return result


def _extract_imports(pe: pefile.PE) -> dict:
    """Extract full import table: dll (lowercased) → list of function names."""
    imports = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("utf-8", errors="ignore").lower()
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("utf-8", errors="ignore"))
            elif imp.ordinal is not None:
                funcs.append(f"ord_{imp.ordinal}")
        imports[dll] = funcs
    return imports


def _extract_signer(path: str, pe: pefile.PE) -> Optional[str]:
    """Extract Authenticode signer (leaf cert CN) from PE security directory."""
    try:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
            return None

        with open(path, "rb") as f:
            f.seek(security_dir.VirtualAddress)
            cert_data = f.read(security_dir.Size)

        if len(cert_data) < 8:
            return None

        # Skip 8-byte WIN_CERTIFICATE header (dwLength:4, wRevision:2, wCertificateType:2)
        pkcs7_der = cert_data[8:]

        from cryptography.hazmat.primitives.serialization.pkcs7 import (
            load_der_pkcs7_certificates,
        )
        from cryptography.x509.oid import ExtendedKeyUsageOID

        certs = load_der_pkcs7_certificates(pkcs7_der)

        # Find the code-signing leaf cert
        for cert in certs:
            try:
                eku = cert.extensions.get_extension_for_oid(
                    cert.extensions.get_extension_for_class(
                        type(None)  # dummy — use direct OID below
                    ).oid
                )
            except Exception:
                pass

            # Check for code signing EKU
            try:
                from cryptography.x509 import ExtensionOID, ExtendedKeyUsage
                eku_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.EXTENDED_KEY_USAGE
                )
                eku_val = eku_ext.value
                if ExtendedKeyUsageOID.CODE_SIGNING in eku_val:
                    return cert.subject.rfc4514_string().split("CN=")[-1].split(",")[0]
            except Exception:
                continue

        # Fallback: return first cert's CN (often the signer in simple chains)
        if certs:
            cn_parts = certs[0].subject.rfc4514_string().split("CN=")
            if len(cn_parts) > 1:
                return cn_parts[-1].split(",")[0]

    except Exception as e:
        logger.debug(f"Signer extraction failed for {path}: {e}")

    return None


# ── String extraction ─────────────────────────────────────────────────

_DEVICE_RE = re.compile(r"\\Device\\[\w.]+", re.IGNORECASE)
_SYMLINK_RE = re.compile(r"\\DosDevices\\[\w.]+|\\Global\?\?\\[\w.]+", re.IGNORECASE)
_REGISTRY_RE = re.compile(
    r"\\Registry\\Machine\\[\w\\]+|HKLM\\[\w\\]+|"
    r"\\REGISTRY\\MACHINE\\[\w\\]+",
    re.IGNORECASE,
)
_NOTABLE_PATTERNS = [
    re.compile(r"\\Driver\\[\w.]+", re.IGNORECASE),
    re.compile(r"\\FileSystem\\[\w.]+", re.IGNORECASE),
    re.compile(r"IOCTL_\w+", re.IGNORECASE),
    re.compile(r"\\BaseNamedObjects\\[\w.]+", re.IGNORECASE),
]


def _extract_strings(raw: bytes) -> dict:
    """Extract classified strings from raw binary data (ASCII + UTF-16LE)."""
    device_names = set()
    symbolic_links = set()
    registry_paths = set()
    notable = set()

    # ASCII strings (min length 6)
    ascii_strs = re.findall(rb"[\x20-\x7E]{6,}", raw)
    # UTF-16LE strings (min 6 chars)
    utf16_strs = re.findall(rb"(?:[\x20-\x7E]\x00){6,}", raw)

    all_strings = []
    for s in ascii_strs:
        all_strings.append(s.decode("ascii", errors="ignore"))
    for s in utf16_strs:
        all_strings.append(s.decode("utf-16-le", errors="ignore"))

    for s in all_strings:
        for m in _DEVICE_RE.finditer(s):
            device_names.add(m.group())
        for m in _SYMLINK_RE.finditer(s):
            symbolic_links.add(m.group())
        for m in _REGISTRY_RE.finditer(s):
            registry_paths.add(m.group())
        for pat in _NOTABLE_PATTERNS:
            for m in pat.finditer(s):
                notable.add(m.group())

    return {
        "device_names": sorted(device_names),
        "symbolic_links": sorted(symbolic_links),
        "registry_paths": sorted(registry_paths),
        "notable_strings": sorted(notable),
    }


def _extract_sections(pe: pefile.PE) -> list:
    """Extract section info (name, virtual size, raw size, characteristics)."""
    sections = []
    for s in pe.sections:
        name = s.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        sections.append({
            "name": name,
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "characteristics": f"0x{s.Characteristics:08X}",
        })
    return sections


def _categorize_imports(imports: dict, categories_path: str) -> dict:
    """Reverse-lookup imports against api_categories.yaml → category → matched symbols."""
    with open(categories_path, "r") as f:
        cat_data = yaml.safe_load(f)

    # Build reverse map: symbol → category
    sym_to_cat = {}
    for cat_name, cat_info in cat_data.get("categories", {}).items():
        for sym in cat_info.get("symbols", []):
            sym_to_cat[sym] = cat_name

    result = {}
    for dll, funcs in imports.items():
        for func in funcs:
            if func in sym_to_cat:
                cat = sym_to_cat[func]
                result.setdefault(cat, []).append(func)

    # Deduplicate
    for cat in result:
        result[cat] = sorted(set(result[cat]))

    return result
