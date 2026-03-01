"""Tests for the disassembler adapter factory."""

import pytest

from marco.disassemblers import BACKENDS, InstructionToken, create_adapter


class TestInstructionToken:
    def test_defaults(self):
        t = InstructionToken(text="mov")
        assert t.text == "mov"
        assert t.value == 0
        assert t.type == 0

    def test_custom_values(self):
        t = InstructionToken(text="eax", value=0x10, type=5)
        assert t.text == "eax"
        assert t.value == 0x10
        assert t.type == 5


class TestCreateAdapter:
    def test_create_ida_returns_adapter(self):
        adapter = create_adapter("ida")
        assert adapter.source_name == "idapro"

    def test_create_ghidra_returns_adapter(self):
        adapter = create_adapter("ghidra")
        assert adapter.source_name == "ghidra"

    def test_create_invalid_raises(self):
        with pytest.raises(ValueError, match="Unknown backend"):
            create_adapter("invalid")


class TestBackendsList:
    def test_backends_contains_all(self):
        assert "binja" in BACKENDS
        assert "ida" in BACKENDS
        assert "ghidra" in BACKENDS
