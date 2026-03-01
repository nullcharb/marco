"""Tests for GhidraAdapter with mocked pyghidra."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_pyghidra():
    """Create a complete mock of pyghidra and Ghidra Java objects."""
    mod = MagicMock()

    # Mock function
    fn = MagicMock()
    fn.getName.return_value = "TestFunc"
    entry_point = MagicMock()
    entry_point.getOffset.return_value = 0x401000
    fn.getEntryPoint.return_value = entry_point
    fn.isExternal.return_value = False

    # External callee
    ext_fn = MagicMock()
    ext_fn.getName.return_value = "CreateFileW"
    ext_fn.isExternal.return_value = True
    ext_loc = MagicMock()
    ext_loc.getLibraryName.return_value = "kernel32"
    ext_fn.getExternalLocation.return_value = ext_loc

    fn.getCalledFunctions.return_value = [ext_fn]

    # Mock instruction
    instr = MagicMock()
    instr_addr = MagicMock()
    instr_addr.getOffset.return_value = 0x401000
    instr.getAddress.return_value = instr_addr
    instr.getLength.return_value = 3
    instr.getMnemonicString.return_value = "mov"
    instr.getNumOperands.return_value = 1
    instr.getDefaultOperandRepresentation.return_value = "eax"
    scalar = MagicMock()
    scalar.getValue.return_value = 0
    instr.getScalar.return_value = scalar

    # Mock instruction iterator
    instr_iter = MagicMock()
    instr_iter.hasNext.side_effect = [True, False]
    instr_iter.next.return_value = instr

    # Mock program
    program = MagicMock()
    program.getName.return_value = "sample.dll"
    program.getExecutablePath.return_value = "C:\\test\\sample.dll"

    # Function manager
    fm = MagicMock()
    fm.getFunctions.return_value = [fn]
    program.getFunctionManager.return_value = fm

    # Memory
    memory = MagicMock()
    memory.getBytes.return_value = 16
    program.getMemory.return_value = memory

    # Listing
    listing = MagicMock()
    listing.getInstructions.return_value = instr_iter
    program.getListing.return_value = listing
    fn.getProgram.return_value = program
    fn.getBody.return_value = MagicMock()

    # Symbol table
    ext_sym = MagicMock()
    ns = MagicMock()
    ns.getName.return_value = "kernel32"
    ext_sym.getParentNamespace.return_value = ns
    sym_table = MagicMock()
    sym_table.getExternalSymbols.return_value = [ext_sym]
    program.getSymbolTable.return_value = sym_table

    # Mock GhidraProject (new non-deprecated API)
    mock_project = MagicMock()
    root_folder = MagicMock()
    root_folder.getFile.return_value = None  # Binary not yet imported
    mock_project.getRootFolder.return_value = root_folder
    mock_project.importProgram.return_value = program

    # Mock ProjectLocator
    mock_locator = MagicMock()
    mock_locator_instance = MagicMock()
    mock_locator_instance.exists.return_value = False
    mock_locator.return_value = mock_locator_instance

    # Mock GhidraProgramUtilities
    mock_gpu = MagicMock()
    mock_gpu.shouldAskToAnalyze.return_value = False  # Skip analysis in tests

    mod.start.return_value = None

    return mod, program, fn, mock_project, mock_locator, mock_gpu


class TestGhidraAdapter:
    @patch.dict("sys.modules", {"pyghidra": MagicMock()})
    def test_importable(self):
        from marco.disassemblers.ghidra_adapter import GhidraAdapter
        assert GhidraAdapter is not None

    @patch.dict("sys.modules", {"pyghidra": MagicMock()})
    def test_source_name(self):
        from marco.disassemblers.ghidra_adapter import GhidraAdapter
        adapter = GhidraAdapter()
        assert adapter.source_name == "ghidra"

    def test_open_binary(self, mock_pyghidra, tmp_path):
        mod, program, _, mock_project, mock_locator, mock_gpu = mock_pyghidra
        mock_jfile = MagicMock()
        ghidra_mocks = {
            "pyghidra": mod,
            "ghidra": MagicMock(),
            "ghidra.base": MagicMock(),
            "ghidra.base.project": MagicMock(GhidraProject=MagicMock(
                openProject=MagicMock(return_value=mock_project),
                createProject=MagicMock(return_value=mock_project),
            )),
            "ghidra.framework": MagicMock(),
            "ghidra.framework.model": MagicMock(ProjectLocator=mock_locator),
            "ghidra.program": MagicMock(),
            "ghidra.program.util": MagicMock(GhidraProgramUtilities=mock_gpu),
            "java": MagicMock(),
            "java.io": MagicMock(File=mock_jfile),
        }
        with patch.dict("sys.modules", ghidra_mocks):
            import marco.disassemblers.ghidra_adapter as ga
            ga._ghidra_started = True  # Skip actual JVM start
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter(project_dir=str(tmp_path))
            with adapter.open_binary("test.dll") as result:
                assert result is program

    def test_get_module_name(self, mock_pyghidra):
        mod, program, _, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            assert adapter.get_module_name(program) == "sample"

    def test_iter_functions(self, mock_pyghidra):
        mod, program, fn, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            funcs = adapter.iter_functions(program)
            assert len(funcs) == 1

    def test_function_name(self, mock_pyghidra):
        mod, _, fn, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            assert adapter.function_name(fn) == "TestFunc"

    def test_function_address(self, mock_pyghidra):
        mod, _, fn, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            assert adapter.function_address(fn) == 0x401000

    def test_function_callees_symbols(self, mock_pyghidra):
        mod, program, fn, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            callees = adapter.function_callees_symbols(program, fn)
            assert isinstance(callees, list)
            assert any("CreateFileW" in c for c in callees)
            assert any("kernel32" in c for c in callees)

    def test_imported_modules(self, mock_pyghidra):
        mod, program, _, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            modules = adapter.imported_modules(program)
            assert "kernel32.dll" in modules

    def test_iter_instructions_tuple_format(self, mock_pyghidra):
        mod, _, fn, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            instrs = list(adapter.iter_instructions(fn))
            assert len(instrs) == 1
            addr, length, tokens = instrs[0]
            assert isinstance(addr, int)
            assert isinstance(length, int)
            assert isinstance(tokens, list)
            assert len(tokens) >= 1

    def test_get_call_parameter_returns_none(self, mock_pyghidra):
        mod, program, fn, _, _, _ = mock_pyghidra
        with patch.dict("sys.modules", {"pyghidra": mod}):
            from marco.disassemblers.ghidra_adapter import GhidraAdapter
            adapter = GhidraAdapter()
            result = adapter.get_call_parameter(program, fn, 0x401000, 0)
            assert result is None
