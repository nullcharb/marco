"""Tests for shared module resolution utilities."""

from marco.utils.module_resolution import resolve_module_name, symbol_module_from_filename


class TestResolveModuleName:
    def test_apiset_resolution(self):
        result = resolve_module_name("api-ms-win-core-libraryloader-l1-2-0.dll")
        assert result == "kernelbase.dll"

    def test_apiset_no_extension(self):
        result = resolve_module_name("api-ms-win-core-libraryloader-l1-2-0")
        assert result == "kernelbase.dll"

    def test_normal_dll_passthrough(self):
        assert resolve_module_name("kernel32.dll") == "kernel32.dll"
        assert resolve_module_name("ntdll.dll") == "ntdll.dll"

    def test_adds_dll_extension(self):
        assert resolve_module_name("kernelbase") == "kernelbase.dll"
        assert resolve_module_name("user32") == "user32.dll"

    def test_sys_extension_preserved(self):
        assert resolve_module_name("ntoskrnl.sys") == "ntoskrnl.sys"

    def test_exe_extension_preserved(self):
        assert resolve_module_name("ntoskrnl.exe") == "ntoskrnl.exe"

    def test_lowercased(self):
        assert resolve_module_name("KERNEL32.DLL") == "kernel32.dll"
        assert resolve_module_name("NtDll") == "ntdll.dll"

    def test_ext_ms_win_prefix(self):
        result = resolve_module_name("ext-ms-win-ntuser-window-l1-1-0")
        assert result.endswith(".dll")


class TestSymbolModuleFromFilename:
    def test_simple_filename(self):
        assert symbol_module_from_filename("kernel32.dll") == "kernel32"

    def test_path_with_backslash(self):
        assert symbol_module_from_filename("C:\\Windows\\System32\\ntdll.dll") == "ntdll"

    def test_path_with_slash(self):
        assert symbol_module_from_filename("/usr/lib/test.so") == "test"

    def test_no_extension(self):
        assert symbol_module_from_filename("mymodule") == "mymodule"

    def test_lowercased(self):
        assert symbol_module_from_filename("KERNEL32.DLL") == "kernel32"
