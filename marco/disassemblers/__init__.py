from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class BinaryViewLike(Protocol): ...


@dataclass
class InstructionToken:
    """Cross-backend instruction token abstraction."""

    text: str
    value: int = 0
    type: int = 0


class DisassemblerAdapter(Protocol):
    source_name: str

    def open_binary(self, path: str): ...

    def get_module_name(self, bv: BinaryViewLike) -> str: ...

    def get_file_version(self, bv: BinaryViewLike) -> str | None: ...

    def iter_functions(self, bv: BinaryViewLike): ...

    def function_name(self, fn: Any) -> str: ...

    def function_address(self, fn: Any) -> int: ...

    def function_callees_symbols(self, bv: BinaryViewLike, fn: Any) -> list[str]: ...

    def imported_modules(self, bv: BinaryViewLike) -> set[str]: ...

    def read_memory(self, bv: BinaryViewLike, address: int, size: int) -> bytes | None: ...

    def iter_instructions(self, fn: Any) -> Any: ...

    def get_call_parameter(self, bv: BinaryViewLike, fn: Any, call_addr: int, param_idx: int) -> int | None: ...


BACKENDS = ["binja", "ida", "ghidra"]


def _detect_backend() -> str:
    for name, mod in [("binja", "binaryninja"), ("ida", "ida_domain"), ("ghidra", "pyghidra")]:
        try:
            __import__(mod)
            return name
        except ImportError:
            continue
    raise RuntimeError("No disassembler backend found. Install binaryninja, ida_domain, or pyghidra.")


def create_adapter(backend: str = "auto", **kwargs: Any) -> DisassemblerAdapter:
    """Create a disassembler adapter for the specified backend.

    Args:
        backend: One of ``"auto"``, ``"binja"``, ``"ida"``, ``"ghidra"``.
        **kwargs: Backend-specific constructor arguments.
    """
    if backend == "auto":
        backend = _detect_backend()
    if backend == "binja":
        from .binaryninja_adapter import BinaryNinjaAdapter

        return BinaryNinjaAdapter(**kwargs)
    elif backend == "ida":
        from .idapro_adapter import IDAProAdapter

        return IDAProAdapter(**kwargs)
    elif backend == "ghidra":
        from .ghidra_adapter import GhidraAdapter

        return GhidraAdapter(**kwargs)
    else:
        raise ValueError(f"Unknown backend: {backend!r}. Expected one of: {BACKENDS}")
