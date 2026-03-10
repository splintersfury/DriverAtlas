"""Tests for DriverAtlas Tier 2 deep analysis module."""

import json
import os
import struct
import tempfile

import pytest


# ── Dataclass tests ──────────────────────────────────────────────────

class TestIOCTLInfo:
    def test_from_code_buffered(self):
        from driveratlas.tier2 import IOCTLInfo, IOCTLMethod, IOCTLAccess

        # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
        # = (0x22 << 16) | (0 << 14) | (0x803 << 2) | 0 = 0x22200C
        ioctl = IOCTLInfo.from_code(0x22200C)
        assert ioctl.device_type == 0x0022
        assert ioctl.function == 0x803
        assert ioctl.method == IOCTLMethod.BUFFERED
        assert ioctl.access == IOCTLAccess.ANY
        assert ioctl.code_hex == "0x22200C"
        assert not ioctl.uses_neither_io
        assert not ioctl.is_custom_device_type
        assert ioctl.is_custom_function  # >= 0x800

    def test_from_code_neither(self):
        from driveratlas.tier2 import IOCTLInfo, IOCTLMethod

        # METHOD_NEITHER = 3
        ioctl = IOCTLInfo.from_code(0x22200F)
        assert ioctl.method == IOCTLMethod.NEITHER
        assert ioctl.uses_neither_io

    def test_from_code_vendor_device(self):
        from driveratlas.tier2 import IOCTLInfo

        # Vendor-defined device type (>= 0x8000)
        code = (0x8000 << 16) | (0 << 14) | (1 << 2) | 0
        ioctl = IOCTLInfo.from_code(code)
        assert ioctl.is_custom_device_type
        assert ioctl.device_type == 0x8000

    def test_from_code_direct_in(self):
        from driveratlas.tier2 import IOCTLInfo, IOCTLMethod, IOCTLAccess

        # METHOD_IN_DIRECT = 1, FILE_READ_ACCESS = 1
        code = (0x22 << 16) | (1 << 14) | (0x800 << 2) | 1
        ioctl = IOCTLInfo.from_code(code)
        assert ioctl.method == IOCTLMethod.IN_DIRECT
        assert ioctl.access == IOCTLAccess.READ

    def test_to_dict(self):
        from driveratlas.tier2 import IOCTLInfo

        ioctl = IOCTLInfo.from_code(0x22200C, handler_name="TestHandler")
        d = ioctl.to_dict()
        assert d["method"] == "BUFFERED"
        assert d["access"] == "ANY"
        assert d["handler_name"] == "TestHandler"
        assert d["code_hex"] == "0x22200C"


class TestTier2Result:
    def test_empty_result(self):
        from driveratlas.tier2 import Tier2Result

        result = Tier2Result(driver_name="test.sys", sha256="abc123")
        assert result.ioctl_count == 0
        assert result.neither_io_count == 0
        assert result.taint_path_count == 0
        assert result.missing_checks_count == 0

    def test_with_ioctls(self):
        from driveratlas.tier2 import Tier2Result, IOCTLInfo

        result = Tier2Result(driver_name="test.sys", sha256="abc123")
        result.ioctls = [
            IOCTLInfo.from_code(0x22200C),  # BUFFERED
            IOCTLInfo.from_code(0x22200F),  # NEITHER
            IOCTLInfo.from_code(0x222013),  # NEITHER
        ]
        assert result.ioctl_count == 3
        assert result.neither_io_count == 2

    def test_to_dict_serializable(self):
        from driveratlas.tier2 import Tier2Result, IOCTLInfo, TaintPath, SecurityCheck, Gadget

        result = Tier2Result(
            driver_name="test.sys",
            sha256="abc123",
            ioctls=[IOCTLInfo.from_code(0x22200C)],
            taint_paths=[TaintPath(source="SystemBuffer", sink="memcpy", confidence=0.8)],
            security_checks=[SecurityCheck(check_type="input_length_validation", present=False)],
            gadgets=[Gadget(address=0x140001000, address_hex="0x140001000",
                           instruction_bytes=b"\x58\xc3", disassembly="pop rax; ret",
                           gadget_type="rop")],
        )
        d = result.to_dict()
        # Verify it's JSON-serializable
        text = json.dumps(d)
        assert "0x22200C" in text
        assert "memcpy" in text
        assert "58c3" in text  # hex bytes


# ── IOCTL Analyzer tests ────────────────────────────────────────────

class TestIOCTLAnalyzer:
    def _make_dispatch(self, ioctls=None):
        return {
            "driver_name": "test.sys",
            "driver_entry": "0x140001000",
            "irp_handlers": {},
            "ioctl_dispatch": ioctls or {},
        }

    def test_parse_empty(self):
        from driveratlas.tier2.ioctl_analyzer import parse_dispatch_table
        result = parse_dispatch_table(self._make_dispatch())
        assert result == []

    def test_parse_single_ioctl(self):
        from driveratlas.tier2.ioctl_analyzer import parse_dispatch_table

        data = self._make_dispatch({
            "0x22200C": {
                "handler_name": "HandleIoctl",
                "handler_addr": "0x140003000",
                "decompiled_snippet": "MmMapIoSpace(addr, size, cache);",
            }
        })
        ioctls = parse_dispatch_table(data)
        assert len(ioctls) == 1
        assert ioctls[0].code == 0x22200C
        assert "MmMapIoSpace" in ioctls[0].api_calls
        assert "Physical Memory Map" in ioctls[0].label

    def test_parse_multiple_sorted(self):
        from driveratlas.tier2.ioctl_analyzer import parse_dispatch_table

        data = self._make_dispatch({
            "0x332000": {"handler_name": "H2", "handler_addr": "", "decompiled_snippet": ""},
            "0x222000": {"handler_name": "H1", "handler_addr": "", "decompiled_snippet": ""},
        })
        ioctls = parse_dispatch_table(data)
        assert ioctls[0].code < ioctls[1].code

    def test_api_extraction(self):
        from driveratlas.tier2.ioctl_analyzer import parse_dispatch_table

        snippet = "ZwOpenProcess(handle, access, &oa, &cid); memcpy(dst, src, len);"
        data = self._make_dispatch({
            "0x22200F": {
                "handler_name": "H",
                "handler_addr": "",
                "decompiled_snippet": snippet,
            }
        })
        ioctls = parse_dispatch_table(data)
        assert "ZwOpenProcess" in ioctls[0].api_calls
        assert "memcpy" in ioctls[0].api_calls

    def test_device_type_name(self):
        from driveratlas.tier2.ioctl_analyzer import device_type_name

        assert device_type_name(0x0022) == "FILE_DEVICE_UNKNOWN"
        assert device_type_name(0x0007) == "FILE_DEVICE_DISK"
        assert "VENDOR" in device_type_name(0x8000)
        assert "UNKNOWN" in device_type_name(0x0099)

    def test_summarize(self):
        from driveratlas.tier2.ioctl_analyzer import parse_dispatch_table, summarize_ioctls

        data = self._make_dispatch({
            "0x22200C": {"handler_name": "H", "handler_addr": "",
                         "decompiled_snippet": "MmMapIoSpace(a,b,c);"},
            "0x22200F": {"handler_name": "H", "handler_addr": "",
                         "decompiled_snippet": "__writemsr(reg, val);"},
        })
        ioctls = parse_dispatch_table(data)
        summary = summarize_ioctls(ioctls)
        assert summary["total"] == 2
        assert summary["risk_indicators"]["has_mmio"] is True
        assert summary["risk_indicators"]["has_msr"] is True
        assert summary["risk_indicators"]["neither_io"] == 1

    def test_summarize_empty(self):
        from driveratlas.tier2.ioctl_analyzer import summarize_ioctls
        assert summarize_ioctls([]) == {"total": 0}


# ── Taint Analyzer tests ────────────────────────────────────────────

class TestTaintAnalyzer:
    def test_basic_taint(self):
        from driveratlas.tier2.taint_analyzer import analyze_taint

        data = {
            "ioctl_dispatch": {
                "0x22200C": {
                    "handler_name": "Handler",
                    "decompiled_snippet": (
                        "buf = Irp->AssociatedIrp.SystemBuffer;\n"
                        "MmMapIoSpace(*(PHYSICAL_ADDRESS *)buf, size, cache);"
                    ),
                }
            }
        }
        paths = analyze_taint(data)
        assert len(paths) > 0
        sinks = [p.sink for p in paths]
        assert "MmMapIoSpace" in sinks

    def test_neither_io_taint(self):
        from driveratlas.tier2.taint_analyzer import analyze_taint

        # NEITHER method (code & 3 == 3) with no explicit source
        data = {
            "ioctl_dispatch": {
                "0x22200F": {
                    "handler_name": "Handler",
                    "decompiled_snippet": "memcpy(kernel_buf, user_ptr, len);",
                }
            }
        }
        paths = analyze_taint(data)
        # Should flag raw_user_pointer → memcpy
        assert any(p.source == "raw_user_pointer" for p in paths)

    def test_no_taint_clean(self):
        from driveratlas.tier2.taint_analyzer import analyze_taint

        data = {
            "ioctl_dispatch": {
                "0x22200C": {
                    "handler_name": "Handler",
                    "decompiled_snippet": "return STATUS_SUCCESS;",
                }
            }
        }
        paths = analyze_taint(data)
        assert len(paths) == 0

    def test_security_checks_present(self):
        from driveratlas.tier2.taint_analyzer import analyze_security_checks

        data = {
            "ioctl_dispatch": {
                "0x22200C": {
                    "handler_name": "Handler",
                    "decompiled_snippet": (
                        "if (InputBufferLength < sizeof(MY_STRUCT)) return STATUS_BUFFER_TOO_SMALL;\n"
                        "ProbeForRead(buf, len, 1);\n"
                        "ProbeForWrite(outbuf, outlen, 1);"
                    ),
                }
            }
        }
        checks = analyze_security_checks(data)
        input_val = [c for c in checks if c.check_type == "input_length_validation"]
        assert len(input_val) == 1
        assert input_val[0].present is True

        probe_r = [c for c in checks if c.check_type == "probe_for_read"]
        assert probe_r[0].present is True

    def test_security_checks_missing(self):
        from driveratlas.tier2.taint_analyzer import analyze_security_checks

        data = {
            "ioctl_dispatch": {
                "0x22200C": {
                    "handler_name": "Handler",
                    "decompiled_snippet": "memcpy(dst, src, len);",
                }
            }
        }
        checks = analyze_security_checks(data)
        missing = [c for c in checks if not c.present]
        assert len(missing) > 0
        missing_types = {c.check_type for c in missing}
        assert "input_length_validation" in missing_types
        assert "probe_for_read" in missing_types


# ── Gadget Scanner tests ────────────────────────────────────────────

class TestGadgetScanner:
    def _make_minimal_pe(self, code_bytes: bytes) -> str:
        """Create a minimal x64 PE with the given bytes in .text section."""
        # Minimal PE headers for x64
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 60, 64)  # e_lfanew

        pe_sig = b"PE\x00\x00"

        # COFF header: x64, 1 section
        coff = struct.pack("<HHIIIHH",
            0x8664,  # Machine: AMD64
            1,       # NumberOfSections
            0,       # TimeDateStamp
            0,       # PointerToSymbolTable
            0,       # NumberOfSymbols
            112,     # SizeOfOptionalHeader (PE32+)
            0x22,    # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        )

        # Optional header (PE32+) - minimal
        opt = bytearray(112)
        struct.pack_into("<H", opt, 0, 0x20B)  # Magic: PE32+
        struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
        struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
        struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", opt, 36, 0x200)   # FileAlignment
        struct.pack_into("<I", opt, 56, 0x3000)  # SizeOfImage
        struct.pack_into("<I", opt, 60, 0x200)   # SizeOfHeaders
        struct.pack_into("<I", opt, 76, 16)      # NumberOfRvaAndSizes

        # Section header: .text
        section = bytearray(40)
        section[0:6] = b".text\x00"
        code_size = len(code_bytes)
        aligned = (code_size + 0x1FF) & ~0x1FF
        struct.pack_into("<I", section, 8, code_size)   # VirtualSize
        struct.pack_into("<I", section, 12, 0x1000)     # VirtualAddress
        struct.pack_into("<I", section, 16, aligned)    # SizeOfRawData
        struct.pack_into("<I", section, 20, 0x200)      # PointerToRawData
        struct.pack_into("<I", section, 36, 0x60000020) # Characteristics: CODE|EXECUTE|READ

        # Assemble PE
        headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + bytes(section)
        headers_padded = headers + b"\x00" * (0x200 - len(headers))
        code_padded = code_bytes + b"\x00" * (aligned - code_size)

        pe_data = headers_padded + code_padded

        tmp = tempfile.NamedTemporaryFile(suffix=".sys", delete=False)
        tmp.write(pe_data)
        tmp.close()
        return tmp.name

    def test_find_rop_gadget(self):
        from driveratlas.tier2.gadget_scanner import scan_gadgets

        # pop rax; ret
        code = b"\x90" * 16 + b"\x58\xc3" + b"\x90" * 16
        pe_path = self._make_minimal_pe(code)
        try:
            gadgets = scan_gadgets(pe_path, max_gadgets=100)
            rop_gadgets = [g for g in gadgets if g.gadget_type == "rop"]
            assert len(rop_gadgets) > 0
            assert any("pop rax" in g.disassembly for g in rop_gadgets)
        finally:
            os.unlink(pe_path)

    def test_find_jop_gadget(self):
        from driveratlas.tier2.gadget_scanner import scan_gadgets

        # pop rcx; jmp rax
        code = b"\x90" * 16 + b"\x59\xff\xe0" + b"\x90" * 16
        pe_path = self._make_minimal_pe(code)
        try:
            gadgets = scan_gadgets(pe_path, max_gadgets=100, include_jop=True)
            jop_gadgets = [g for g in gadgets if g.gadget_type == "jop"]
            assert len(jop_gadgets) > 0
        finally:
            os.unlink(pe_path)

    def test_no_file(self):
        from driveratlas.tier2.gadget_scanner import scan_gadgets
        gadgets = scan_gadgets("/nonexistent/path.sys")
        assert gadgets == []

    def test_gadget_summary(self):
        from driveratlas.tier2.gadget_scanner import scan_gadgets, generate_gadget_summary

        # xchg rax, rsp; ret (interesting - stack pivot)
        code = b"\x90" * 16 + b"\x48\x94\xc3" + b"\x90" * 16
        pe_path = self._make_minimal_pe(code)
        try:
            gadgets = scan_gadgets(pe_path, max_gadgets=100)
            summary = generate_gadget_summary(gadgets)
            assert summary["total"] > 0
            assert "rop" in summary.get("by_type", {})
        finally:
            os.unlink(pe_path)


# ── YARA Generator tests ────────────────────────────────────────────

class TestYARAGenerator:
    def test_ioctl_rule(self):
        from driveratlas.tier2 import Tier2Result, IOCTLInfo
        from driveratlas.tier2.yara_generator import generate_yara

        result = Tier2Result(
            driver_name="test.sys",
            sha256="a" * 64,
            ioctls=[
                IOCTLInfo.from_code(0x22200C),
                IOCTLInfo.from_code(0x22200F),
            ],
        )
        yara_text = generate_yara(result)
        assert "rule DriverAtlas_test_IOCTLs" in yara_text
        assert "0C 20 22 00" in yara_text  # 0x22200C little-endian
        assert "0F 20 22 00" in yara_text

    def test_vuln_pattern_rule(self):
        from driveratlas.tier2 import Tier2Result, IOCTLInfo
        from driveratlas.tier2.yara_generator import generate_yara

        ioctl = IOCTLInfo.from_code(0x22200F)  # NEITHER
        ioctl.api_calls = ["MmMapIoSpace", "ZwOpenProcess"]

        result = Tier2Result(
            driver_name="vuln.sys",
            sha256="b" * 64,
            ioctls=[ioctl],
        )
        yara_text = generate_yara(result)
        assert "VulnPatterns" in yara_text
        assert "MmMapIoSpace" in yara_text
        assert "NEITHER" in yara_text

    def test_write_to_file(self):
        from driveratlas.tier2 import Tier2Result, IOCTLInfo
        from driveratlas.tier2.yara_generator import generate_yara

        result = Tier2Result(
            driver_name="test.sys",
            sha256="c" * 64,
            ioctls=[IOCTLInfo.from_code(0x22200C)],
        )

        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False) as f:
            path = f.name

        try:
            generate_yara(result, output_path=path)
            assert os.path.isfile(path)
            with open(path) as f:
                content = f.read()
            assert "DriverAtlas_test_IOCTLs" in content
        finally:
            os.unlink(path)

    def test_empty_result_no_rules(self):
        from driveratlas.tier2 import Tier2Result
        from driveratlas.tier2.yara_generator import generate_yara

        result = Tier2Result(driver_name="empty.sys", sha256="d" * 64)
        yara_text = generate_yara(result)
        assert yara_text == ""


# ── Scoring integration tests ───────────────────────────────────────

class TestTier2Scoring:
    def test_tier2_rules_loaded(self):
        from driveratlas.scoring import AttackSurfaceScorer

        scorer = AttackSurfaceScorer()
        rule_ids = [r["id"] for r in scorer.rules]
        assert "tier2_neither_io" in rule_ids
        assert "tier2_taint_mmio" in rule_ids
        assert "tier2_missing_checks" in rule_ids

    def test_tier2_score_with_data(self):
        from driveratlas.scoring import AttackSurfaceScorer
        from driveratlas.scanner import DriverProfile

        profile = DriverProfile(
            name="vuln.sys",
            sha256="abc",
            size=50000,
            device_names=["\\Device\\VulnDev"],
            tier2={
                "ioctl_count": 25,
                "neither_io_count": 3,
                "taint_paths": [
                    {"sink": "MmMapIoSpace", "source": "SystemBuffer", "confidence": 0.8},
                ],
                "security_checks": [
                    {"check_type": "input_length_validation", "present": False},
                ],
                "gadget_count": 100,
            },
        )

        scorer = AttackSurfaceScorer()
        score = scorer.score(profile)

        # Should have contributions from Tier 2 rules
        tier2_matched = [c for c in score.contributions if c.rule_id.startswith("tier2_") and c.matched]
        assert len(tier2_matched) >= 3  # neither_io, many_ioctls, taint_mmio, missing_checks, gadgets

    def test_tier2_score_without_data(self):
        from driveratlas.scoring import AttackSurfaceScorer
        from driveratlas.scanner import DriverProfile

        profile = DriverProfile(name="clean.sys", sha256="abc", size=50000)

        scorer = AttackSurfaceScorer()
        score = scorer.score(profile)

        # Tier 2 rules should not match when no tier2 data
        tier2_matched = [c for c in score.contributions if c.rule_id.startswith("tier2_") and c.matched]
        assert len(tier2_matched) == 0


# ── Ghidra Runner tests ─────────────────────────────────────────────

class TestGhidraRunner:
    def test_find_ghidra_home_missing(self):
        from driveratlas.tier2.ghidra_runner import find_ghidra_home
        # On CI/test machines, Ghidra likely isn't installed
        # Just verify it returns None or a valid path
        result = find_ghidra_home()
        if result is not None:
            assert os.path.isdir(result)

    def test_runner_raises_without_ghidra(self):
        from driveratlas.tier2.ghidra_runner import GhidraRunner
        # Should raise FileNotFoundError if Ghidra isn't installed
        try:
            runner = GhidraRunner(ghidra_home="/nonexistent/ghidra")
            pytest.fail("Should have raised FileNotFoundError")
        except FileNotFoundError:
            pass


# ── CLI command registration test ────────────────────────────────────

class TestCLI:
    def test_deep_command_registered(self):
        from driveratlas.cli import main
        assert "deep" in main.commands
