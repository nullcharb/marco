"""Ghidra disassembler adapter using pyghidra."""

from __future__ import annotations

import ctypes
import logging
import sys
import threading
from contextlib import contextmanager
from ctypes import wintypes
from typing import Any

from ..utils.module_resolution import resolve_module_name, symbol_module_from_filename
from . import DisassemblerAdapter, InstructionToken

logger = logging.getLogger(__name__)

# Ghidra JVM lifecycle lock — pyghidra.start() must only be called once.
_GHIDRA_LOCK = threading.Lock()
_ghidra_started = False


def _ensure_ghidra() -> None:
    """Start the Ghidra/pyghidra JVM if it hasn't been started yet."""
    global _ghidra_started
    if _ghidra_started:
        return
    with _GHIDRA_LOCK:
        if _ghidra_started:
            return
        import pyghidra

        pyghidra.start()
        _ghidra_started = True


class GhidraAdapter(DisassemblerAdapter):
    """Adapter for Ghidra via the ``pyghidra`` package."""

    source_name = "ghidra"

    def __init__(
        self,
        *,
        project_dir: str | None = None,
        analyze: bool = True,
    ):
        self._project_dir = project_dir
        self._analyze = analyze

    @contextmanager
    def open_binary(self, path: str):
        _ensure_ghidra()

        import os
        from pathlib import Path as _Path

        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        binary_name = os.path.basename(path)

        # Determine project location and name
        project_dir = _Path(self._project_dir) if self._project_dir else _Path(path).parent
        project_name = f"{binary_name}_ghidra"
        project_location = project_dir / project_name
        project_location.mkdir(parents=True, exist_ok=True)

        project = None
        program = None
        try:
            with _GHIDRA_LOCK:
                logger.debug("Opening Ghidra project for %s", path)

                # Open or create the project
                if ProjectLocator(project_location, project_name).exists():
                    project = GhidraProject.openProject(project_location, project_name, True)
                else:
                    project = GhidraProject.createProject(project_location, project_name, False)

                # Open existing program or import the binary
                if project.getRootFolder().getFile(binary_name):
                    program = project.openProgram("/", binary_name, False)
                else:
                    from java.io import File as JFile
                    program = project.importProgram(JFile(path))
                    if program is None:
                        raise RuntimeError(f"Ghidra failed to import '{path}'")
                    project.saveAs(program, "/", binary_name, True)

                # Run analysis if needed
                if self._analyze:
                    from ghidra.program.util import GhidraProgramUtilities
                    if GhidraProgramUtilities.shouldAskToAnalyze(program):
                        from ghidra.app.script import GhidraScriptUtil
                        from ghidra.program.flatapi import FlatProgramAPI
                        GhidraScriptUtil.acquireBundleHostReference()
                        try:
                            flat = FlatProgramAPI(program)
                            flat.analyzeAll(program)
                            GhidraProgramUtilities.markProgramAnalyzed(program)
                        finally:
                            GhidraScriptUtil.releaseBundleHostReference()

            yield program
        finally:
            if project is not None:
                try:
                    if program is not None:
                        project.save(program)
                    project.close()
                except Exception:
                    logger.debug("Failed to close Ghidra project for %s", path, exc_info=True)

    def get_module_name(self, program: Any) -> str:
        try:
            name = program.getName()
        except Exception:
            name = str(program)
        return symbol_module_from_filename(name)

    def get_file_version(self, program: Any) -> str | None:
        # Try PE property extraction from Ghidra
        try:
            options = program.getOptions("Program Information")
            if options is not None:
                for key in ("FileVersion", "ProductVersion"):
                    val = options.getString(key, None)
                    if val:
                        return val
        except Exception:
            pass
        # Windows WinAPI fallback
        if sys.platform == "win32":
            try:
                path = program.getExecutablePath()
                if path:
                    return _get_file_version_winapi(path)
            except Exception:
                pass
        return None

    def iter_functions(self, program: Any):
        fm = program.getFunctionManager()
        return list(fm.getFunctions(True))

    def function_name(self, fn: Any) -> str:
        return fn.getName()

    def function_address(self, fn: Any) -> int:
        return int(fn.getEntryPoint().getOffset())

    def function_callees_symbols(self, program: Any, fn: Any) -> list[str]:
        symbols: set[str] = set()
        module = self.get_module_name(program)

        try:
            for callee in fn.getCalledFunctions(None):
                if callee.isExternal():
                    ext_loc = callee.getExternalLocation()
                    lib_name = ext_loc.getLibraryName() if ext_loc else ""
                    if lib_name:
                        resolved = resolve_module_name(lib_name)
                        sym_module = symbol_module_from_filename(resolved)
                        symbols.add(f"{sym_module}!{callee.getName()}")
                else:
                    symbols.add(f"{module}!{callee.getName()}")
        except Exception:
            logger.debug("Error getting callees for %s", fn.getName(), exc_info=True)

        return list(symbols)

    def imported_modules(self, program: Any) -> set[str]:
        modules: set[str] = set()
        try:
            sym_table = program.getSymbolTable()
            for sym in sym_table.getExternalSymbols():
                ns = sym.getParentNamespace()
                if ns is not None:
                    lib_name = ns.getName()
                    if lib_name and lib_name != "<EXTERNAL>":
                        modules.add(resolve_module_name(lib_name))
        except Exception:
            logger.debug("Error enumerating imported modules", exc_info=True)
        return modules

    def read_memory(self, program: Any, address: int, size: int) -> bytes | None:
        try:

            memory = program.getMemory()
            addr_factory = program.getAddressFactory()
            addr = addr_factory.getDefaultAddressSpace().getAddress(address)
            buf = bytearray(size)
            n_read = memory.getBytes(addr, buf)
            if n_read == size:
                return bytes(buf)
        except Exception:
            pass
        return None

    def iter_instructions(self, fn: Any):
        """Yield ``(address, length, list[InstructionToken])`` for each instruction."""
        try:
            program = fn.getProgram()
            listing = program.getListing()
            body = fn.getBody()
            instr_iter = listing.getInstructions(body, True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                addr = int(instr.getAddress().getOffset())
                length = instr.getLength()
                tokens = [InstructionToken(text=instr.getMnemonicString(), value=0, type=0)]
                for i in range(instr.getNumOperands()):
                    op_text = instr.getDefaultOperandRepresentation(i)
                    op_value = 0
                    try:
                        scalar = instr.getScalar(i)
                        if scalar is not None:
                            op_value = int(scalar.getValue())
                    except Exception:
                        pass
                    tokens.append(InstructionToken(text=op_text, value=op_value, type=i + 1))
                yield (addr, length, tokens)
        except Exception:
            logger.debug("Error iterating instructions for function", exc_info=True)

    def get_call_parameter(self, program: Any, fn: Any, call_addr: int, param_idx: int) -> int | None:
        """Resolve a call parameter constant via the Ghidra decompiler."""
        try:
            from ghidra.app.decompiler import DecompInterface

            decomp = DecompInterface()
            decomp.openProgram(program)
            try:
                result = decomp.decompileFunction(fn, 60, None)
                if result and result.decompileCompleted():
                    hfunc = result.getHighFunction()
                    if hfunc is not None:
                        for op in hfunc.getPcodeOps():
                            op_addr = op.getSeqnum().getTarget().getOffset()
                            if (
                                call_addr >= op_addr
                                and call_addr < op_addr + 10
                                and op.getOpcode() == 4  # CALL opcode in PCode
                            ):
                                inputs = op.getInputs()
                                # Input 0 is the call target; params start at index 1
                                actual_idx = param_idx + 1
                                if len(inputs) > actual_idx:
                                    vn = inputs[actual_idx]
                                    if vn.isConstant():
                                        return int(vn.getOffset())
            finally:
                decomp.dispose()
        except Exception:
            pass

        # Fallback: backward register scan
        try:
            from ..utils.binary_analysis import find_register_value_asm

            return find_register_value_asm(self, program, fn, call_addr, param_idx)
        except Exception:
            pass

        return None


def _get_file_version_winapi(path: str) -> str | None:
    """Extract file version via Windows API."""
    try:
        get_size = ctypes.windll.version.GetFileVersionInfoSizeW
        get_info = ctypes.windll.version.GetFileVersionInfoW
        query_value = ctypes.windll.version.VerQueryValueW

        dummy = wintypes.DWORD(0)
        size = get_size(path, ctypes.byref(dummy))
        if not size:
            return None
        data = ctypes.create_string_buffer(size)
        if not get_info(path, 0, size, data):
            return None
        lp_buffer = ctypes.c_void_p()
        u_len = wintypes.UINT()
        if not query_value(data, "\\", ctypes.byref(lp_buffer), ctypes.byref(u_len)) or not lp_buffer.value:
            return None

        class FixedFileInfo(ctypes.Structure):
            _fields_ = [
                ("dwSignature", wintypes.DWORD),
                ("dwStrucVersion", wintypes.DWORD),
                ("dwFileVersionMS", wintypes.DWORD),
                ("dwFileVersionLS", wintypes.DWORD),
                ("dwProductVersionMS", wintypes.DWORD),
                ("dwProductVersionLS", wintypes.DWORD),
                ("dwFileFlagsMask", wintypes.DWORD),
                ("dwFileFlags", wintypes.DWORD),
                ("dwFileOS", wintypes.DWORD),
                ("dwFileType", wintypes.DWORD),
                ("dwFileSubtype", wintypes.DWORD),
                ("dwFileDateMS", wintypes.DWORD),
                ("dwFileDateLS", wintypes.DWORD),
            ]

        info = ctypes.cast(lp_buffer.value, ctypes.POINTER(FixedFileInfo)).contents
        major = (info.dwFileVersionMS >> 16) & 0xFFFF
        minor = info.dwFileVersionMS & 0xFFFF
        build = (info.dwFileVersionLS >> 16) & 0xFFFF
        revision = info.dwFileVersionLS & 0xFFFF
        return f"{major}.{minor}.{build}.{revision}"
    except Exception:
        return None
