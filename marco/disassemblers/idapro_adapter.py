"""IDA Pro disassembler adapter using ida_domain."""

from __future__ import annotations

import contextlib
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


class IDAProAdapter(DisassemblerAdapter):
    """Adapter for IDA Pro 9.0+ via the ``ida_domain`` package.

    All calls MUST happen on the main thread — the orchestrator
    enforces this via ``_run_sequential``.  Only one database may be
    open at a time (mirroring ReConductor's SessionManager pattern).

    Real API shapes (verified via introspection):
        Database.open(path, args=IdaCommandOptions, save_on_close=True)
        db.path -> str, db.module -> str
        db.functions.get_callees(fn) -> List[func_t]
        db.functions.get_instructions(fn) -> Iterator[insn_t]
            insn_t: .ea, .size, .get_canon_mnem(), .Op1..Op8 (op.type==0 is void)
        db.imports.get_module_names() -> list of str
        db.imports.get_all_imports() -> List[ImportInfo]
            ImportInfo: .name, .module_name, .address, .ordinal
        db.imports.get_import_at(ea) -> ImportInfo | None
        db.bytes.get_bytes_at(addr, size) -> bytes
        db.bytes.get_disassembly_at(ea) -> str
        db.functions.get_pseudocode(fn) -> List[str]
    """

    source_name = "idapro"

    def __init__(
        self,
        *,
        auto_analysis: bool = True,
        processor: str = "",
        output_dir: str | None = None,
    ):
        self._auto_analysis = auto_analysis
        self._processor = processor
        self._output_dir = output_dir
        self._db: Any | None = None  # Track active database

    @contextmanager
    def open_binary(self, path: str):
        # idapro init may mutate sys.path via ida_domain imports; keep the
        # process import path stable for the rest of the app.
        _saved_path = sys.path[:]
        from ida_domain.database import Database, IdaCommandOptions
        sys.path = _saved_path

        # Enforce single-session: close any dangling database first
        if self._db is not None:
            logger.warning("Closing previously-open IDA database before opening %s", path)
            with contextlib.suppress(Exception):
                self._db.close()
            self._db = None

        try:
            logger.debug("Opening IDA database for %s", path)
            opts: dict[str, Any] = {"auto_analysis": self._auto_analysis}
            if self._processor:
                opts["processor"] = self._processor
            if self._output_dir:
                import os
                from pathlib import Path as _Path
                _Path(self._output_dir).mkdir(parents=True, exist_ok=True)
                basename = os.path.splitext(os.path.basename(path))[0]
                opts["output_database"] = os.path.join(self._output_dir, basename + ".i64")
            logger.debug("IDA open_binary: path=%s thread=%s", path, threading.current_thread().name)
            args = IdaCommandOptions(**opts)
            self._db = Database.open(path, args=args, save_on_close=True)
            yield self._db
        finally:
            if self._db is not None:
                try:
                    self._db.close()
                except Exception:
                    logger.debug("Failed to close IDA database for %s", path, exc_info=True)
                self._db = None

    def get_module_name(self, db: Any) -> str:
        # db.module is the short name (e.g. "kernel32.dll"),
        # db.path is the full path
        try:
            return symbol_module_from_filename(db.path)
        except Exception:
            return symbol_module_from_filename(str(db))

    def get_file_version(self, db: Any) -> str | None:
        # IDA doesn't expose PE version info directly — use WinAPI fallback
        if sys.platform == "win32":
            try:
                return _get_file_version_winapi(db.path)
            except Exception:
                pass
        return None

    def iter_functions(self, db: Any):
        return list(db.functions.get_all())

    def function_name(self, fn: Any) -> str:
        return fn.name

    def function_address(self, fn: Any) -> int:
        return int(fn.start_ea)

    def function_callees_symbols(self, db: Any, fn: Any) -> list[str]:
        symbols: set[str] = set()
        module = self.get_module_name(db)

        # Internal callees via db.functions.get_callees(fn) -> List[func_t]
        try:
            for callee_fn in db.functions.get_callees(fn):
                symbols.add(f"{module}!{callee_fn.name}")
        except Exception:
            logger.debug("Error getting internal callees for %s", fn.name, exc_info=True)

        # External callees: walk call xrefs and resolve imports
        try:
            for ins in db.functions.get_instructions(fn):
                if ins.get_canon_mnem() != "call":
                    continue
                # Call target is in Op1.addr or Op1.value
                op = ins.Op1
                target = op.addr if op.addr else op.value
                if not target:
                    continue
                imp = db.imports.get_import_at(target)
                if imp is not None:
                    resolved = resolve_module_name(imp.module_name)
                    sym_module = symbol_module_from_filename(resolved)
                    symbols.add(f"{sym_module}!{imp.name}")
        except Exception:
            logger.debug("Error getting external callees for %s", fn.name, exc_info=True)

        return list(symbols)

    def imported_modules(self, db: Any) -> set[str]:
        modules: set[str] = set()
        try:
            for name in db.imports.get_module_names():
                modules.add(resolve_module_name(name))
        except Exception:
            logger.debug("Error enumerating imported modules", exc_info=True)
        return modules

    def read_memory(self, db: Any, address: int, size: int) -> bytes | None:
        try:
            data = db.bytes.get_bytes_at(address, size)
            if data and len(data) == size:
                return bytes(data)
        except Exception:
            pass
        return None

    def iter_instructions(self, fn: Any):
        """Yield ``(address, length, list[InstructionToken])`` for each instruction.

        Uses ``self._db`` (the active database) to call
        ``db.functions.get_instructions(fn)`` since the IDA ``func_t``
        object doesn't carry a back-reference to the database.
        """
        db = self._db
        if db is None:
            return

        try:
            for ins in db.functions.get_instructions(fn):
                mnemonic = ins.get_canon_mnem()
                tokens = [InstructionToken(text=mnemonic, value=0, type=0)]

                # Iterate Op1..Op8; op.type == 0 means void (no operand)
                for i in range(1, 9):
                    op = getattr(ins, f"Op{i}")
                    if op.type == 0:
                        break
                    # Use disassembly text for the operand representation
                    op_text = db.bytes.get_disassembly_at(ins.ea) if i == 1 else ""
                    op_value = op.value if op.value else op.addr
                    tokens.append(InstructionToken(
                        text=op_text if op_text else str(op_value),
                        value=op_value,
                        type=op.type,
                    ))

                yield (int(ins.ea), int(ins.size), tokens)
        except Exception:
            logger.debug("Error iterating instructions for function", exc_info=True)

    def get_call_parameter(self, db: Any, fn: Any, call_addr: int, param_idx: int) -> int | None:
        """Resolve a call parameter constant via pseudocode or register scan."""
        # Try pseudocode via db.functions.get_pseudocode(fn) -> List[str]
        try:
            lines = db.functions.get_pseudocode(fn)
            if lines:
                import re
                for line in lines:
                    # Look for call-like patterns matching the address
                    # and extract the Nth argument
                    if f"0x{call_addr:X}" in line.upper() or f"0x{call_addr:x}" in line:
                        # Try to extract arguments from function call syntax
                        m = re.search(r"\(([^)]+)\)", line)
                        if m:
                            args = [a.strip() for a in m.group(1).split(",")]
                            if len(args) > param_idx:
                                arg = args[param_idx]
                                # Try to parse as integer
                                try:
                                    return int(arg, 0)
                                except ValueError:
                                    pass
        except Exception:
            pass

        # Fallback: backward register scan for immediate values
        try:
            from ..utils.binary_analysis import find_register_value_asm

            return find_register_value_asm(self, db, fn, call_addr, param_idx)
        except Exception:
            pass

        return None


def _get_file_version_winapi(path: str) -> str | None:
    """Extract file version via Windows API — shared helper."""
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
