"""Tests for the disassembler adapter factory."""

from unittest.mock import MagicMock, patch

import pytest

from marco.disassemblers import BACKENDS, InstructionToken, create_adapter, _detect_backend


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


class TestDetectBackend:
    def test_detect_binja_first(self):
        with patch("builtins.__import__", side_effect=lambda name, *a, **kw: (
            MagicMock() if name == "binaryninja" else __import__(name, *a, **kw)
        )):
            assert _detect_backend() == "binja"

    def test_detect_ida_when_no_binja(self):
        def fake_import(name, *args, **kwargs):
            if name == "binaryninja":
                raise ImportError("no binja")
            if name == "ida_domain":
                return MagicMock()
            return __import__(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            assert _detect_backend() == "ida"

    def test_detect_ghidra_when_no_others(self):
        def fake_import(name, *args, **kwargs):
            if name in ("binaryninja", "ida_domain"):
                raise ImportError("not available")
            if name == "pyghidra":
                return MagicMock()
            return __import__(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            assert _detect_backend() == "ghidra"

    def test_no_backend_raises(self):
        def fake_import(name, *args, **kwargs):
            if name in ("binaryninja", "ida_domain", "pyghidra"):
                raise ImportError("not available")
            return __import__(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            with pytest.raises(RuntimeError, match="No disassembler backend found"):
                _detect_backend()


class TestBackendsList:
    def test_backends_contains_all(self):
        assert "binja" in BACKENDS
        assert "ida" in BACKENDS
        assert "ghidra" in BACKENDS
