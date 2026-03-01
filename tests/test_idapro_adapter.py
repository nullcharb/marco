"""Tests for IDAProAdapter with mocked ida_domain."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_ida_domain():
    """Create a complete mock of ida_domain matching the real API shapes.

    Real API verified via introspection:
        Database.open(path, args=IdaCommandOptions, save_on_close=True) -> Database
        db.path -> str, db.module -> str
        db.functions.get_all() -> List[func_t]
        db.functions.get_callees(fn) -> List[func_t]
        db.functions.get_instructions(fn) -> Iterator[insn_t]
        db.imports.get_module_names() -> list[str]
        db.imports.get_all_imports() -> List[ImportInfo]
        db.imports.get_import_at(ea) -> ImportInfo | None
        db.bytes.get_bytes_at(addr, size) -> bytes
        db.bytes.get_disassembly_at(ea) -> str
        db.functions.get_pseudocode(fn) -> List[str]
    """
    mod = MagicMock()

    # Mock IdaCommandOptions
    ida_db_mod = MagicMock()
    mod.database = ida_db_mod

    # Mock function (func_t)
    fn = MagicMock()
    fn.name = "TestFunc"
    fn.start_ea = 0x401000
    fn.end_ea = 0x401020

    # Mock callee function
    callee_fn = MagicMock()
    callee_fn.name = "HelperFunc"
    callee_fn.start_ea = 0x402000

    # Mock instruction (insn_t)
    ins = MagicMock()
    ins.ea = 0x401000
    ins.size = 3
    ins.get_canon_mnem.return_value = "mov"
    # Operands: Op1 = register (type=1), Op2 = immediate (type=5), Op3..Op8 = void (type=0)
    op1 = MagicMock()
    op1.type = 1
    op1.value = 0
    op1.addr = 0
    op1.reg = 0
    ins.Op1 = op1
    op2 = MagicMock()
    op2.type = 5
    op2.value = 56
    op2.addr = 0
    ins.Op2 = op2
    for i in range(3, 9):
        void_op = MagicMock()
        void_op.type = 0
        void_op.value = 0
        void_op.addr = 0
        setattr(ins, f"Op{i}", void_op)

    # Mock database
    db = MagicMock()
    db.path = "C:\\test\\sample.dll"
    db.module = "sample.dll"
    db.functions.get_all.return_value = [fn]
    db.functions.get_callees.return_value = [callee_fn]
    db.functions.get_instructions.return_value = [ins]
    db.functions.get_pseudocode.return_value = ["v1 = SomeFunc(0x42, 0x10);"]
    db.bytes.get_bytes_at.return_value = b"\x00" * 16
    db.bytes.get_disassembly_at.return_value = "mov     eax, 38h"
    db.close.return_value = None

    # Mock imports
    db.imports.get_module_names.return_value = ["kernel32", "ntdll"]
    imp = MagicMock()
    imp.name = "CreateFileW"
    imp.module_name = "kernel32"
    imp.address = 0x500000
    imp.ordinal = 0
    db.imports.get_all_imports.return_value = [imp]
    db.imports.get_import_at.return_value = None  # Default: no import at address

    mod.database.Database.open.return_value = db
    mod.database.IdaCommandOptions.return_value = MagicMock()
    return mod, db, fn


class TestIDAProAdapter:
    @patch.dict("sys.modules", {"ida_domain": MagicMock(), "ida_domain.database": MagicMock()})
    def test_importable(self):
        from marco.disassemblers.idapro_adapter import IDAProAdapter
        assert IDAProAdapter is not None

    @patch.dict("sys.modules", {"ida_domain": MagicMock(), "ida_domain.database": MagicMock()})
    def test_source_name(self):
        from marco.disassemblers.idapro_adapter import IDAProAdapter
        adapter = IDAProAdapter()
        assert adapter.source_name == "idapro"

    def test_open_binary(self, mock_ida_domain):
        mod, db, _ = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            with adapter.open_binary("test.dll") as result:
                assert result is db
            db.close.assert_called_once()

    def test_get_module_name(self, mock_ida_domain):
        mod, db, _ = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            assert adapter.get_module_name(db) == "sample"

    def test_iter_functions(self, mock_ida_domain):
        mod, db, fn = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            funcs = adapter.iter_functions(db)
            assert len(funcs) == 1

    def test_function_name(self, mock_ida_domain):
        mod, _, fn = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            assert adapter.function_name(fn) == "TestFunc"

    def test_function_address(self, mock_ida_domain):
        mod, _, fn = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            assert adapter.function_address(fn) == 0x401000

    def test_function_callees_symbols(self, mock_ida_domain):
        """get_callees returns func_t objects for internal callees."""
        mod, db, fn = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            callees = adapter.function_callees_symbols(db, fn)
            assert isinstance(callees, list)
            assert any("HelperFunc" in c for c in callees)

    def test_function_callees_with_import(self, mock_ida_domain):
        """External callees resolved via call instructions + get_import_at."""
        mod, db, fn = mock_ida_domain
        # Set up a call instruction pointing to an import
        call_ins = MagicMock()
        call_ins.get_canon_mnem.return_value = "call"
        call_op = MagicMock()
        call_op.addr = 0x500000
        call_op.value = 0
        call_ins.Op1 = call_op
        db.functions.get_instructions.return_value = [call_ins]

        imp = MagicMock()
        imp.name = "CreateFileW"
        imp.module_name = "kernel32"
        db.imports.get_import_at.return_value = imp

        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            callees = adapter.function_callees_symbols(db, fn)
            assert any("kernel32" in c and "CreateFileW" in c for c in callees)

    def test_imported_modules(self, mock_ida_domain):
        """get_module_names returns plain strings."""
        mod, db, _ = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            modules = adapter.imported_modules(db)
            assert "kernel32.dll" in modules
            assert "ntdll.dll" in modules

    def test_read_memory(self, mock_ida_domain):
        mod, db, _ = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            data = adapter.read_memory(db, 0x401000, 16)
            assert data == b"\x00" * 16

    def test_read_memory_none(self, mock_ida_domain):
        mod, db, _ = mock_ida_domain
        db.bytes.get_bytes_at.return_value = None
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            assert adapter.read_memory(db, 0x401000, 16) is None

    def test_iter_instructions_tuple_format(self, mock_ida_domain):
        """get_instructions returns insn_t with .ea, .size, .get_canon_mnem(), .Op1..Op8."""
        mod, db, fn = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            # Must set _db for iter_instructions to work
            adapter._db = db
            instrs = list(adapter.iter_instructions(fn))
            assert len(instrs) == 1
            addr, length, tokens = instrs[0]
            assert addr == 0x401000
            assert length == 3
            assert isinstance(tokens, list)
            # Should have mnemonic + 2 operands (Op1.type=1, Op2.type=5, Op3.type=0 stops)
            assert tokens[0].text == "mov"
            assert len(tokens) == 3  # mnemonic + 2 operands

    def test_iter_instructions_without_db(self, mock_ida_domain):
        """iter_instructions returns nothing if _db is not set."""
        mod, _, fn = mock_ida_domain
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            instrs = list(adapter.iter_instructions(fn))
            assert instrs == []

    def test_get_call_parameter_returns_none(self, mock_ida_domain):
        mod, db, fn = mock_ida_domain
        db.functions.get_pseudocode.return_value = []
        with patch.dict("sys.modules", {
            "ida_domain": mod,
            "ida_domain.database": mod.database,
        }):
            from marco.disassemblers.idapro_adapter import IDAProAdapter
            adapter = IDAProAdapter()
            result = adapter.get_call_parameter(db, fn, 0x401000, 0)
            assert result is None
