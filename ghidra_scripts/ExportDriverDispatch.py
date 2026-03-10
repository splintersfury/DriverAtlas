# ExportDriverDispatch.py
# Ghidra headless Jython script (Python 2)
#
# Finds DriverEntry, extracts IRP MajorFunction dispatch table,
# traces IRP_MJ_DEVICE_CONTROL handler to map IOCTL codes to handlers.
#
# Enhanced for DriverAtlas Tier 2: also extracts per-IOCTL API call lists
# for auto-labeling and taint path seeding.
#
# Supports:
# - Direct MajorFunction[N] = func assignments (standard drivers)
# - Offset-based assignments *(DriverObject + 0x70 + N*8) = func (common pattern)
# - C++ class-based dispatch via PDB symbol names (e.g., CLFS, NTFS)
# - Symbol-aware handler detection: *::Create, *::Close, *::Cleanup, *::Dispatch
# - IOCTL/FSCTL code extraction from if-else chains and switch/case
# - Per-IOCTL API call extraction for security assessment
#
# Usage: analyzeHeadless ... -postScript ExportDriverDispatch.py <output_dir>

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json
import os
import re

# IRP major function names by index
IRP_MJ_NAMES = {
    0: "IRP_MJ_CREATE",
    1: "IRP_MJ_CREATE_NAMED_PIPE",
    2: "IRP_MJ_CLOSE",
    3: "IRP_MJ_READ",
    4: "IRP_MJ_WRITE",
    5: "IRP_MJ_QUERY_INFORMATION",
    6: "IRP_MJ_SET_INFORMATION",
    7: "IRP_MJ_QUERY_EA",
    8: "IRP_MJ_SET_EA",
    9: "IRP_MJ_FLUSH_BUFFERS",
    10: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    11: "IRP_MJ_SET_VOLUME_INFORMATION",
    12: "IRP_MJ_DIRECTORY_CONTROL",
    13: "IRP_MJ_FILE_SYSTEM_CONTROL",
    14: "IRP_MJ_DEVICE_CONTROL",
    15: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    16: "IRP_MJ_SHUTDOWN",
    17: "IRP_MJ_LOCK_CONTROL",
    18: "IRP_MJ_CLEANUP",
    19: "IRP_MJ_CREATE_MAILSLOT",
    20: "IRP_MJ_QUERY_SECURITY",
    21: "IRP_MJ_SET_SECURITY",
    22: "IRP_MJ_POWER",
    23: "IRP_MJ_SYSTEM_CONTROL",
    24: "IRP_MJ_DEVICE_CHANGE",
    25: "IRP_MJ_QUERY_QUOTA",
    26: "IRP_MJ_SET_QUOTA",
    27: "IRP_MJ_PNP",
}

IRP_MJ_NAMES_REVERSE = {}
for _k, _v in IRP_MJ_NAMES.items():
    IRP_MJ_NAMES_REVERSE[_v] = _k

# Offset of MajorFunction array in DRIVER_OBJECT for x64
DRIVER_OBJECT_MJ_OFFSET_X64 = 0x70
POINTER_SIZE_X64 = 8

# Symbol name patterns for IRP handler detection (C++ drivers)
SYMBOL_IRP_PATTERNS = [
    ("::Create(", "IRP_MJ_CREATE"),
    ("::Close(", "IRP_MJ_CLOSE"),
    ("::Cleanup(", "IRP_MJ_CLEANUP"),
    ("::Read(", "IRP_MJ_READ"),
    ("::Write(", "IRP_MJ_WRITE"),
    ("::DeviceControl(", "IRP_MJ_DEVICE_CONTROL"),
    ("::InternalDeviceControl(", "IRP_MJ_INTERNAL_DEVICE_CONTROL"),
    ("::Shutdown(", "IRP_MJ_SHUTDOWN"),
    ("::Power(", "IRP_MJ_POWER"),
    ("::SystemControl(", "IRP_MJ_SYSTEM_CONTROL"),
    ("::Pnp(", "IRP_MJ_PNP"),
    ("::QueryInformation(", "IRP_MJ_QUERY_INFORMATION"),
    ("::SetInformation(", "IRP_MJ_SET_INFORMATION"),
    ("::QuerySecurity", "IRP_MJ_QUERY_SECURITY"),
    ("::SetSecurity", "IRP_MJ_SET_SECURITY"),
    ("::FlushBuffers(", "IRP_MJ_FLUSH_BUFFERS"),
    ("::LockControl(", "IRP_MJ_LOCK_CONTROL"),
    ("::DirectoryControl(", "IRP_MJ_DIRECTORY_CONTROL"),
    ("::FileSystemControl(", "IRP_MJ_FILE_SYSTEM_CONTROL"),
]

IRP_DISPATCH_PATTERNS = [
    "Dispatch",
    "LogIoDispatch",
    "DispatchIoRequest",
    "DispatchRequest",
    "IrpDispatch",
]

# Sensitive APIs to extract from IOCTL handler decompilation (DriverAtlas Tier 2)
SENSITIVE_API_LIST = [
    # Physical memory / MMIO
    "MmMapIoSpace", "MmMapLockedPages", "MmMapLockedPagesSpecifyCache",
    "ZwMapViewOfSection", "MmMapMemoryDumpMdl",
    # Memory copy
    "memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory", "RtlCopyBytes",
    # Process/thread
    "ZwOpenProcess", "PsLookupProcessByProcessId", "KeStackAttachProcess",
    "ZwDuplicateObject", "ObReferenceObjectByHandle",
    # Registry
    "ZwSetValueKey", "ZwDeleteKey", "ZwCreateKey",
    # I/O ports
    "READ_PORT_UCHAR", "WRITE_PORT_UCHAR", "READ_PORT_ULONG", "WRITE_PORT_ULONG",
    # MSR
    "__readmsr", "__writemsr",
    # File ops
    "ZwCreateFile", "ZwWriteFile", "ZwReadFile",
    # Pool alloc
    "ExAllocatePool", "ExAllocatePool2", "ExAllocatePoolWithTag",
    # Buffer validation
    "ProbeForRead", "ProbeForWrite",
    # MDL
    "IoAllocateMdl", "MmProbeAndLockPages", "MmGetSystemAddressForMdlSafe",
]


def find_driver_entry(program):
    """Find DriverEntry or GsDriverEntry function."""
    fm = program.getFunctionManager()
    st = program.getSymbolTable()

    for name in ["DriverEntry", "GsDriverEntry", "FxDriverEntry"]:
        syms = list(st.getSymbols(name))
        if syms:
            addr = syms[0].getAddress()
            func = fm.getFunctionAt(addr)
            if func:
                return func

    entry = program.getSymbolTable().getExternalEntryPointIterator()
    while entry.hasNext():
        addr = entry.next()
        func = fm.getFunctionAt(addr)
        if func:
            return func

    syms = list(st.getSymbols("entry"))
    if syms:
        addr = syms[0].getAddress()
        func = fm.getFunctionAt(addr)
        if func:
            return func

    return None


def decompile_function(decomplib, func):
    """Decompile a function and return C code string."""
    monitor = ConsoleTaskMonitor()
    result = decomplib.decompileFunction(func, 120, monitor)
    if result.decompileCompleted():
        decomp_func = result.getDecompiledFunction()
        if decomp_func:
            return decomp_func.getC()
    return ""


def extract_irp_handlers_direct(decompiled_code, program):
    """Extract IRP MajorFunction assignments from decompiled code."""
    handlers = {}

    # Pattern 1: MajorFunction[index] = func_ptr
    p1 = re.findall(
        r'MajorFunction\[(\w+)\]\s*=\s*(\w+)',
        decompiled_code
    )
    for idx_str, func_name in p1:
        try:
            idx = int(idx_str, 0)
        except ValueError:
            continue
        irp_name = IRP_MJ_NAMES.get(idx, "IRP_MJ_%d" % idx)
        handler_addr = _resolve_func_addr(func_name, program)
        handlers[irp_name] = {
            "index": idx,
            "handler_addr": handler_addr,
            "handler_name": func_name,
        }

    # Pattern 2: *(type *)(var + offset) = handler
    p2 = re.findall(
        r'\*\([^)]*\)\s*\([^)]*\+\s*(0x[0-9a-fA-F]+)\s*\)\s*=\s*(\w+)',
        decompiled_code
    )
    for offset_str, func_name in p2:
        try:
            offset = int(offset_str, 16)
        except ValueError:
            continue
        if offset >= DRIVER_OBJECT_MJ_OFFSET_X64:
            idx = (offset - DRIVER_OBJECT_MJ_OFFSET_X64) // POINTER_SIZE_X64
            if 0 <= idx <= 27:
                irp_name = IRP_MJ_NAMES.get(idx, "IRP_MJ_%d" % idx)
                if irp_name not in handlers:
                    handler_addr = _resolve_func_addr(func_name, program)
                    handlers[irp_name] = {
                        "index": idx,
                        "handler_addr": handler_addr,
                        "handler_name": func_name,
                    }

    # Pattern 3: *(code **)(expr + 0xNN) = handler  (C++ class dispatch)
    p3 = re.findall(
        r'\*\(code\s*\*\*\)\([^+]+\+\s*(0x[0-9a-fA-F]+)\s*\)\s*=\s*(\w+)',
        decompiled_code
    )
    for offset_str, func_name in p3:
        try:
            offset = int(offset_str, 16)
        except ValueError:
            continue
        if offset >= DRIVER_OBJECT_MJ_OFFSET_X64:
            idx = (offset - DRIVER_OBJECT_MJ_OFFSET_X64) // POINTER_SIZE_X64
            if 0 <= idx <= 27:
                irp_name = IRP_MJ_NAMES.get(idx, "IRP_MJ_%d" % idx)
                if irp_name not in handlers:
                    handler_addr = _resolve_func_addr(func_name, program)
                    handlers[irp_name] = {
                        "index": idx,
                        "handler_addr": handler_addr,
                        "handler_name": func_name,
                    }

    return handlers


def extract_irp_handlers_from_symbols(program, decomplib):
    """Extract IRP handler mappings using PDB symbol names."""
    handlers = {}
    fm = program.getFunctionManager()

    # Phase 1: Direct symbol name matching
    for func in fm.getFunctions(True):
        full_name = func.getName(True)

        for pattern, irp_name in SYMBOL_IRP_PATTERNS:
            pattern_base = pattern.rstrip("(")
            if pattern_base in full_name:
                code = decompile_function(decomplib, func)
                if code and ("_IRP" in code or "param_1" in code):
                    idx = IRP_MJ_NAMES_REVERSE.get(irp_name, -1)
                    if irp_name not in handlers:
                        handlers[irp_name] = {
                            "index": idx,
                            "handler_addr": func.getEntryPoint().toString(),
                            "handler_name": full_name,
                        }
                break

    # Phase 2: Find dispatch functions that switch on IRP major function index
    for func in fm.getFunctions(True):
        name = func.getName()
        full_name = func.getName(True)

        is_dispatch = False
        for dp in IRP_DISPATCH_PATTERNS:
            if dp.lower() in name.lower():
                is_dispatch = True
                break
        if not is_dispatch:
            continue

        code = decompile_function(decomplib, func)
        if not code:
            continue

        irp_index_matches = set()

        for m in re.finditer(r"==\s*'\\x([0-9a-fA-F]{2})'", code):
            try:
                val = int(m.group(1), 16)
                if 0 <= val <= 27:
                    irp_index_matches.add(val)
            except ValueError:
                pass

        for m in re.finditer(r'==\s*(?:\([^)]*\))?\s*0x([0-9a-fA-F]{1,2})(?![0-9a-fA-F])', code):
            try:
                val = int(m.group(1), 16)
                if 0 <= val <= 27:
                    irp_index_matches.add(val)
            except ValueError:
                pass

        if len(irp_index_matches) >= 2:
            print("[ExportDriverDispatch] Found IRP dispatch in %s: indices %s"
                  % (full_name, sorted(irp_index_matches)))

            for idx in irp_index_matches:
                irp_name = IRP_MJ_NAMES.get(idx, "IRP_MJ_%d" % idx)
                if irp_name in handlers:
                    continue

                handler_func = _find_handler_for_irp_index(code, idx, program)
                if handler_func:
                    handlers[irp_name] = {
                        "index": idx,
                        "handler_addr": _resolve_func_addr(handler_func, program),
                        "handler_name": handler_func,
                        "dispatch_function": full_name,
                    }

    return handlers


def _find_handler_for_irp_index(code, irp_index, program):
    """Find the handler function called for a specific IRP major function index."""
    patterns = [
        r"==\s*'\\x%02x'" % irp_index,
        r"==\s*(?:\([^)]*\))?\s*0x%x(?![0-9a-fA-F])" % irp_index,
    ]

    for pattern in patterns:
        m = re.search(pattern, code)
        if not m:
            continue

        after = code[m.end():m.end() + 500]
        calls = re.findall(r'\b([A-Za-z_][A-Za-z0-9_:]+)\s*\(', after[:300])
        for call_name in calls:
            if call_name in ("if", "else", "while", "for", "switch", "return",
                             "case", "goto", "sizeof", "LOCK", "UNLOCK",
                             "KeBugCheckEx", "WPP_SF_sdD", "WPP_SF_sl",
                             "IofCompleteRequest", "CONCAT35"):
                continue
            st = program.getSymbolTable()
            syms = list(st.getSymbols(call_name))
            if syms:
                return call_name
            if call_name.startswith("FUN_"):
                return call_name

    return ""


def _resolve_func_addr(func_name, program):
    """Resolve a function name to its address string."""
    st = program.getSymbolTable()
    syms = list(st.getSymbols(func_name))
    if syms:
        return syms[0].getAddress().toString()
    fm = program.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getName() == func_name:
            return func.getEntryPoint().toString()
    return ""


def extract_ioctl_dispatch(handler_name, handler_addr, program, decomplib):
    """Trace a handler function to extract IOCTL/FSCTL code dispatch."""
    fm = program.getFunctionManager()
    ioctl_dispatch = {}

    func = None
    if handler_addr:
        try:
            addr_obj = program.getAddressFactory().getAddress(handler_addr)
            func = fm.getFunctionAt(addr_obj)
        except Exception:
            pass

    if not func:
        st = program.getSymbolTable()
        syms = list(st.getSymbols(handler_name))
        if syms:
            func = fm.getFunctionAt(syms[0].getAddress())

    if not func:
        return ioctl_dispatch

    code = decompile_function(decomplib, func)
    if not code:
        return ioctl_dispatch

    # Extract IOCTL/FSCTL codes from various comparison patterns
    all_codes = set()

    cases = re.findall(r'case\s+(0x[0-9a-fA-F]+)\s*:', code)
    for c in cases:
        try:
            all_codes.add(int(c, 16))
        except ValueError:
            pass

    ifs = re.findall(r'==\s*(0x[0-9a-fA-F]{5,8})', code)
    for c in ifs:
        try:
            all_codes.add(int(c, 16))
        except ValueError:
            pass

    io_cmp = re.findall(r'IoControlCode\s*(?:==|!=)\s*(0x[0-9a-fA-F]+)', code)
    for c in io_cmp:
        try:
            all_codes.add(int(c, 16))
        except ValueError:
            pass

    filtered_codes = set()
    for val in all_codes:
        if 0x10000 <= val <= 0xFFFFFFFF:
            filtered_codes.add(val)

    print("[ExportDriverDispatch] Found %d IOCTL/FSCTL code candidates in %s"
          % (len(filtered_codes), handler_name))

    for ioctl_code in sorted(filtered_codes):
        code_hex = "0x%X" % ioctl_code
        snippet = _extract_snippet(code, code_hex)
        handler_func = _find_case_handler(code, code_hex, program)

        # DriverAtlas Tier 2: extract API calls from the IOCTL handler
        api_calls = _extract_api_calls_from_snippet(snippet)

        # If we found the specific handler function, decompile it for deeper API extraction
        if handler_func and handler_func != handler_name:
            handler_code = _decompile_named_function(handler_func, program, decomplib)
            if handler_code:
                api_calls = list(set(api_calls + _extract_api_calls_from_code(handler_code)))

        ioctl_dispatch[code_hex] = {
            "handler_addr": handler_addr,
            "handler_name": handler_func or handler_name,
            "decompiled_snippet": snippet[:500] if snippet else "",
            "api_calls": sorted(api_calls),
        }

    return ioctl_dispatch


def extract_ioctl_from_all_dispatch_functions(program, decomplib, irp_handlers):
    """Scan functions named *Dispatch* for IOCTL code dispatch."""
    ioctl_dispatch = {}
    fm = program.getFunctionManager()

    candidate_funcs = []

    dc_handler = irp_handlers.get("IRP_MJ_DEVICE_CONTROL")
    if dc_handler:
        candidate_funcs.append((dc_handler["handler_name"], dc_handler["handler_addr"]))

    for key in irp_handlers:
        info = irp_handlers[key]
        name = info.get("handler_name", "")
        for dp in IRP_DISPATCH_PATTERNS:
            if dp.lower() in name.lower():
                if (name, info.get("handler_addr", "")) not in candidate_funcs:
                    candidate_funcs.append((name, info.get("handler_addr", "")))

    for func in fm.getFunctions(True):
        name = func.getName()
        full_name = func.getName(True)
        for dp in IRP_DISPATCH_PATTERNS:
            if dp.lower() in name.lower() or dp.lower() in full_name.lower():
                entry = (full_name, func.getEntryPoint().toString())
                if entry not in candidate_funcs:
                    candidate_funcs.append(entry)
                break

    for func_name, func_addr in candidate_funcs:
        result = extract_ioctl_dispatch(func_name, func_addr, program, decomplib)
        if result:
            print("[ExportDriverDispatch] Found %d IOCTLs in %s" % (len(result), func_name))
            for code_hex, info in result.items():
                if code_hex not in ioctl_dispatch:
                    ioctl_dispatch[code_hex] = info

    return ioctl_dispatch


def _extract_snippet(code, ioctl_hex):
    """Extract a code snippet around an IOCTL code reference."""
    idx = code.find(ioctl_hex)
    if idx < 0:
        idx = code.lower().find(ioctl_hex.lower())
    if idx < 0:
        return ""
    start = max(0, idx - 200)
    end = min(len(code), idx + 300)
    return code[start:end]


def _find_case_handler(code, ioctl_hex, program):
    """Try to find the function called in a case block for an IOCTL code."""
    idx = code.find(ioctl_hex)
    if idx < 0:
        idx = code.lower().find(ioctl_hex.lower())
    if idx < 0:
        return ""

    block = code[idx:idx + 400]
    calls = re.findall(r'\b([A-Za-z_][A-Za-z0-9_:]+)\s*\(', block)
    for n in calls:
        if n in ("if", "else", "while", "for", "switch", "return", "case",
                 "goto", "sizeof", "LOCK", "UNLOCK", "CONCAT35",
                 "WPP_SF_sdD", "WPP_SF_sl", "IofCompleteRequest"):
            continue
        st = program.getSymbolTable()
        syms = list(st.getSymbols(n))
        if syms:
            return n
        if n.startswith("FUN_"):
            return n

    return ""


def _extract_api_calls_from_snippet(snippet):
    """Extract sensitive API calls from a code snippet."""
    found = []
    for api in SENSITIVE_API_LIST:
        if api in snippet:
            found.append(api)
    return found


def _extract_api_calls_from_code(code):
    """Extract sensitive API calls from full decompiled function code."""
    found = []
    for api in SENSITIVE_API_LIST:
        if api in code:
            found.append(api)
    return found


def _decompile_named_function(func_name, program, decomplib):
    """Decompile a function by name. Returns code string or empty."""
    fm = program.getFunctionManager()
    st = program.getSymbolTable()

    syms = list(st.getSymbols(func_name))
    if syms:
        func = fm.getFunctionAt(syms[0].getAddress())
        if func:
            return decompile_function(decomplib, func)

    # Try FUN_ pattern
    if func_name.startswith("FUN_"):
        try:
            addr_str = func_name[4:]
            addr = program.getAddressFactory().getAddress(addr_str)
            func = fm.getFunctionAt(addr)
            if func:
                return decompile_function(decomplib, func)
        except Exception:
            pass

    return ""


def run():
    program = currentProgram
    args = getScriptArgs()

    if len(args) > 0:
        output_dir = args[0]
    else:
        output_dir = os.getcwd()

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    out_path = os.path.join(output_dir, "dispatch_table.json")
    print("[ExportDriverDispatch] Output: " + out_path)

    decomplib = DecompInterface()
    decomplib.openProgram(program)

    # Find DriverEntry
    driver_entry = find_driver_entry(program)
    if not driver_entry:
        print("[ExportDriverDispatch] ERROR: Could not find DriverEntry")
        result = {
            "driver_name": program.getName(),
            "driver_entry": "",
            "irp_handlers": {},
            "ioctl_dispatch": {},
            "error": "DriverEntry not found",
        }
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        return

    entry_addr = driver_entry.getEntryPoint().toString()
    print("[ExportDriverDispatch] Found DriverEntry at " + entry_addr)

    # Phase 1: Direct extraction from DriverEntry decompiled code
    entry_code = decompile_function(decomplib, driver_entry)
    irp_handlers = {}
    if entry_code:
        irp_handlers = extract_irp_handlers_direct(entry_code, program)
        print("[ExportDriverDispatch] Direct extraction: %d IRP handlers" % len(irp_handlers))

    # Phase 2: Scan functions called BY DriverEntry
    if len(irp_handlers) < 3:
        print("[ExportDriverDispatch] Scanning DriverEntry callees for dispatch setup...")
        called = driver_entry.getCalledFunctions(ConsoleTaskMonitor())
        for callee in called:
            callee_code = decompile_function(decomplib, callee)
            if callee_code:
                more = extract_irp_handlers_direct(callee_code, program)
                if more:
                    print("[ExportDriverDispatch]   Found %d handlers in %s"
                          % (len(more), callee.getName(True)))
                    for k, v in more.items():
                        if k not in irp_handlers:
                            irp_handlers[k] = v

            if len(irp_handlers) < 3:
                sub_called = callee.getCalledFunctions(ConsoleTaskMonitor())
                for sub in sub_called:
                    sub_code = decompile_function(decomplib, sub)
                    if sub_code and ("0x70" in sub_code or "MajorFunction" in sub_code):
                        more2 = extract_irp_handlers_direct(sub_code, program)
                        if more2:
                            print("[ExportDriverDispatch]   Found %d handlers in %s"
                                  % (len(more2), sub.getName(True)))
                            for k, v in more2.items():
                                if k not in irp_handlers:
                                    irp_handlers[k] = v

    print("[ExportDriverDispatch] After call graph scan: %d IRP handlers" % len(irp_handlers))

    # Phase 3: Symbol-aware detection using PDB names
    if len(irp_handlers) < 3:
        print("[ExportDriverDispatch] Trying symbol-aware IRP detection...")
        symbol_handlers = extract_irp_handlers_from_symbols(program, decomplib)
        for k, v in symbol_handlers.items():
            if k not in irp_handlers:
                irp_handlers[k] = v
        print("[ExportDriverDispatch] After symbol scan: %d IRP handlers" % len(irp_handlers))

    # Phase 4: Extract IOCTL dispatch
    ioctl_dispatch = {}

    dc_handler = irp_handlers.get("IRP_MJ_DEVICE_CONTROL")
    if dc_handler:
        print("[ExportDriverDispatch] Tracing IRP_MJ_DEVICE_CONTROL: %s"
              % dc_handler["handler_name"])
        ioctl_dispatch = extract_ioctl_dispatch(
            dc_handler["handler_name"],
            dc_handler["handler_addr"],
            program,
            decomplib,
        )

    more_ioctls = extract_ioctl_from_all_dispatch_functions(
        program, decomplib, irp_handlers
    )
    for k, v in more_ioctls.items():
        if k not in ioctl_dispatch:
            ioctl_dispatch[k] = v

    # Phase 5: Final fallback — scan ALL functions for IOCTL patterns
    if not ioctl_dispatch:
        print("[ExportDriverDispatch] No IOCTLs found yet, scanning all functions...")
        fm = program.getFunctionManager()
        scanned = 0
        for func in fm.getFunctions(True):
            code = decompile_function(decomplib, func)
            if not code:
                continue
            if re.search(r'==\s*0x[0-9a-fA-F]{5,8}', code):
                fallback = extract_ioctl_dispatch(
                    func.getName(True),
                    func.getEntryPoint().toString(),
                    program,
                    decomplib,
                )
                for k, v in fallback.items():
                    if k not in ioctl_dispatch:
                        ioctl_dispatch[k] = v
            scanned += 1
            if scanned % 200 == 0:
                print("[ExportDriverDispatch]   Scanned %d functions..." % scanned)

    print("[ExportDriverDispatch] Total: %d IRP handlers, %d IOCTL codes"
          % (len(irp_handlers), len(ioctl_dispatch)))

    result = {
        "driver_name": program.getName(),
        "driver_entry": entry_addr,
        "irp_handlers": irp_handlers,
        "ioctl_dispatch": ioctl_dispatch,
    }

    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print("[ExportDriverDispatch] Wrote " + out_path)


if __name__ == "__main__":
    run()
