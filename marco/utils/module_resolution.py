"""Shared module-name resolution utilities used by all disassembler adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyjectify import ApiSetSchema

_apiset_schema: ApiSetSchema | None = None


def resolve_module_name(module_name: str) -> str:
    """Return a normalized filename for a module (ensures extension).

    Resolves Windows API-set pseudo-DLLs (``api-ms-win-*``, ``ext-ms-win-*``)
    to the real implementing DLL via *pyjectify* when available.
    """
    global _apiset_schema
    name = module_name.lower()
    if name.startswith("api-ms-win") or name.startswith("ext-ms-win"):
        try:
            from pyjectify import ApiSetSchema

            query = name if name.endswith(".dll") else f"{name}.dll"
            if _apiset_schema is None:
                _apiset_schema = ApiSetSchema()
            resolved = _apiset_schema.resolve(query)
            if resolved:
                name = resolved
        except Exception:
            pass
    if not name.endswith((".dll", ".sys", ".exe")):
        name += ".dll"
    return name


def symbol_module_from_filename(filename: str) -> str:
    """Extract a base module name (no extension, lowercase) from a path or filename."""
    base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." in base:
        base = base.split(".")[0]
    return base.lower()
