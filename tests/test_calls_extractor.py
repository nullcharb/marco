"""Tests for CallsExtractor source_name propagation."""

from unittest.mock import MagicMock

from marco.extractors.calls import CallsExtractor


def _make_mock_adapter(source_name: str):
    """Create a mock adapter with the given source_name."""
    adapter = MagicMock()
    adapter.source_name = source_name
    adapter.get_module_name.return_value = "testmod"
    adapter.get_file_version.return_value = "1.0.0"

    fn = MagicMock()
    adapter.iter_functions.return_value = [fn]
    adapter.function_name.return_value = "TestFunc"
    adapter.function_address.return_value = 0x1000
    adapter.function_callees_symbols.return_value = []

    adapter.imported_modules.return_value = set()

    return adapter


def _make_mock_bv():
    """Create a minimal mock BinaryView-like object."""
    bv = MagicMock()
    bv.arch = None
    bv.platform = None
    return bv


class TestCallsSourceName:
    def test_idapro_source(self):
        adapter = _make_mock_adapter("idapro")
        bv = _make_mock_bv()
        result = CallsExtractor().extract(bv=bv, adapter=adapter)
        assert len(result.nodes) >= 1
        assert result.nodes[0].props["source"] == "idapro"

    def test_ghidra_source(self):
        adapter = _make_mock_adapter("ghidra")
        bv = _make_mock_bv()
        result = CallsExtractor().extract(bv=bv, adapter=adapter)
        assert len(result.nodes) >= 1
        assert result.nodes[0].props["source"] == "ghidra"

    def test_binaryninja_source(self):
        adapter = _make_mock_adapter("binaryninja")
        bv = _make_mock_bv()
        result = CallsExtractor().extract(bv=bv, adapter=adapter)
        assert len(result.nodes) >= 1
        assert result.nodes[0].props["source"] == "binaryninja"

    def test_placeholder_nodes_use_import_source(self):
        adapter = _make_mock_adapter("idapro")
        adapter.function_callees_symbols.return_value = ["kernel32!CreateFileW"]
        bv = _make_mock_bv()
        result = CallsExtractor().extract(bv=bv, adapter=adapter)
        placeholders = [n for n in result.nodes if n.props.get("placeholder")]
        assert len(placeholders) == 1
        assert placeholders[0].props["source"] == "import"
