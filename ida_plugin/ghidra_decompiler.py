"""
Ghidra Decompiler Plugin for IDA 9.0
=====================================

Press Alt+F1 on any function to decompile it using the PyGhidra engine
and display pseudocode in a custom viewer window (like Hex-Rays).
Press Alt+F2 on any function to display raw PCode in a viewer.

Architecture is auto-detected from the IDA database (x86/x64/ARM/MIPS/PPC).

Requirements:
- IDA 9.0+ with IDAPython
- PyGhidra engine
- sleigh_native.pyd built for your Python version
- Matching .sla specification file(s)

Installation:
- Copy this file to IDA's plugins/ directory
- Or load via File -> Script file
"""

import sys
import os
import traceback

import ida_kernwin
import ida_funcs
import ida_bytes
import ida_segment
import ida_idaapi
import ida_ida
import ida_name
import ida_ua
import idautils
import idc

# Add PyGhidra to path (supports both source and deployed layout)
_plugin_dir = os.path.dirname(os.path.abspath(__file__))
_source_path = os.path.join(os.path.dirname(_plugin_dir), "python")
_deploy_path = os.path.join(_plugin_dir, "pyghidra")
if os.path.isdir(os.path.join(_deploy_path, "ghidra")):
    PYGHIDRA_PATH = _deploy_path
elif os.path.isdir(os.path.join(_source_path, "ghidra")):
    PYGHIDRA_PATH = _source_path
else:
    PYGHIDRA_PATH = _deploy_path  # fallback
if PYGHIDRA_PATH not in sys.path:
    sys.path.insert(0, PYGHIDRA_PATH)

PLUGIN_NAME = "Ghidra Decompiler"
PLUGIN_HOTKEY_DECOMPILE = "Alt+F1"
PLUGIN_HOTKEY_PCODE = "Alt+F2"
PLUGIN_COMMENT = "Decompile current function using Ghidra engine"


class GhidraDecompilerViewer(ida_kernwin.simplecustviewer_t):
    """Custom viewer to display Ghidra decompiled pseudocode."""

    def __init__(self, title, lines, func_ea):
        super().__init__()
        self._title = title
        self._lines = lines
        self._func_ea = func_ea

    def Create(self):
        if not ida_kernwin.simplecustviewer_t.Create(self, self._title):
            return False
        for line in self._lines:
            colored = self._colorize(line)
            self.AddLine(colored)
        return True

    def _colorize(self, line):
        """Apply IDA-style syntax highlighting to a line of C code."""
        import ida_lines
        # Keywords
        KEYWORDS = {
            'if', 'else', 'while', 'for', 'do', 'return', 'break', 'continue',
            'goto', 'switch', 'case', 'default', 'void', 'int', 'char', 'short',
            'long', 'unsigned', 'signed', 'float', 'double', 'struct', 'union',
            'enum', 'typedef', 'const', 'static', 'extern', 'true', 'false',
            'NULL', 'bool', 'uint', 'undefined', 'byte', 'word', 'dword', 'qword',
            'new', 'delete', 'sizeof',
        }
        result = ""
        i = 0
        while i < len(line):
            ch = line[i]
            # String literal
            if ch == '"':
                j = i + 1
                while j < len(line) and line[j] != '"':
                    if line[j] == '\\':
                        j += 1
                    j += 1
                j = min(j + 1, len(line))
                result += ida_lines.COLSTR(line[i:j], ida_lines.SCOLOR_DSTR)
                i = j
                continue
            # Character literal
            if ch == "'":
                j = i + 1
                while j < len(line) and line[j] != "'":
                    if line[j] == '\\':
                        j += 1
                    j += 1
                j = min(j + 1, len(line))
                result += ida_lines.COLSTR(line[i:j], ida_lines.SCOLOR_CHAR)
                i = j
                continue
            # Comment
            if ch == '/' and i + 1 < len(line):
                if line[i + 1] == '/':
                    result += ida_lines.COLSTR(line[i:], ida_lines.SCOLOR_RPTCMT)
                    break
                if line[i + 1] == '*':
                    j = line.find('*/', i + 2)
                    if j < 0:
                        j = len(line)
                    else:
                        j += 2
                    result += ida_lines.COLSTR(line[i:j], ida_lines.SCOLOR_RPTCMT)
                    i = j
                    continue
            # Number
            if ch.isdigit() or (ch == '0' and i + 1 < len(line) and line[i + 1] in 'xXbB'):
                j = i
                if ch == '0' and j + 1 < len(line) and line[j + 1] in 'xX':
                    j += 2
                    while j < len(line) and (line[j].isalnum() or line[j] == '_'):
                        j += 1
                else:
                    while j < len(line) and (line[j].isdigit() or line[j] == '.'):
                        j += 1
                    if j < len(line) and line[j] in 'uUlLfF':
                        j += 1
                result += ida_lines.COLSTR(line[i:j], ida_lines.SCOLOR_NUMBER)
                i = j
                continue
            # Identifier or keyword
            if ch.isalpha() or ch == '_':
                j = i
                while j < len(line) and (line[j].isalnum() or line[j] == '_'):
                    j += 1
                word = line[i:j]
                if word in KEYWORDS:
                    result += ida_lines.COLSTR(word, ida_lines.SCOLOR_KEYWORD)
                elif word[0].isupper() or '_t' in word:
                    # Type-like names
                    result += ida_lines.COLSTR(word, ida_lines.SCOLOR_SEGNAME)
                else:
                    result += ida_lines.COLSTR(word, ida_lines.SCOLOR_DEFAULT)
                i = j
                continue
            # Operators and punctuation
            result += ch
            i += 1
        return result

    def OnKeydown(self, vkey, shift):
        if vkey == ord('G') and shift == 0:
            # Go to address
            ea = ida_kernwin.ask_addr(self._func_ea, "Jump to address")
            if ea is not None:
                ida_kernwin.jumpto(ea)
            return True
        if vkey == 27:  # ESC
            self.Close()
            return True
        return False


def get_function_bytes(func_ea):
    """Extract bytes for the function at func_ea from the IDA database."""
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return None, 0, 0
    start = func.start_ea
    end = func.end_ea
    size = end - start
    data = ida_bytes.get_bytes(start, size)
    return data, start, size


def get_arch_info():
    """Determine architecture parameters from the IDA database."""
    procname = ida_ida.inf_get_procname().lower()
    if ida_ida.inf_is_64bit():
        bitness = 64
    elif not ida_ida.inf_is_16bit():
        bitness = 32
    else:
        bitness = 16
    is_be = ida_ida.inf_is_be()
    return procname, bitness, is_be


def create_lifter(start_addr, data):
    """Create a Lifter with correct SLA and context for the current binary."""
    from ghidra.sleigh.lifter import Lifter
    from ghidra.sleigh.arch_map import resolve_arch

    procname, bitness, is_be = get_arch_info()
    arch_info = resolve_arch(procname, bitness, is_be)

    lifter = Lifter(arch_info["sla_path"], arch_info["context"])
    lifter.set_image(start_addr, data)
    return lifter


def _get_native_decompiler():
    """Get or create the singleton native decompiler instance."""
    global _native_decompiler
    if '_native_decompiler' not in globals() or _native_decompiler is None:
        import ghidra.sleigh.decompiler_native as _dnmod
        from ghidra.sleigh.decompiler_native import DecompilerNative
        _native_decompiler = DecompilerNative()
        # Find Ghidra spec directory (standard layout: Ghidra/<proc>/data/languages/)
        # decompiler_native.pyd is at <root>/python/ghidra/sleigh/
        mod_dir = os.path.dirname(os.path.abspath(_dnmod.__file__))
        project_root = os.path.normpath(os.path.join(mod_dir, "..", "..", ".."))
        candidates = [
            project_root,
            os.path.normpath(os.path.join(PYGHIDRA_PATH, "..")),
            os.environ.get("PYGHIDRA_GHIDRA_ROOT", ""),
        ]
        found = False
        for candidate in candidates:
            if not candidate:
                continue
            ghidra_dir = os.path.join(candidate, "Ghidra")
            if os.path.isdir(ghidra_dir):
                _native_decompiler.add_ghidra_root(candidate)
                found = True
                break
        if not found:
            print(f"[{PLUGIN_NAME}] WARNING: Ghidra/ spec directory not found. Searched: {candidates}")
        _native_decompiler.initialize()
    return _native_decompiler


def decompile_function(func_ea):
    """Decompile the function at func_ea using the native Ghidra C++ decompiler."""
    data, start_addr, size = get_function_bytes(func_ea)
    if data is None or size == 0:
        return None, "No function at this address"

    try:
        from ghidra.sleigh.arch_map import resolve_arch

        procname, bitness, is_be = get_arch_info()
        arch_info = resolve_arch(procname, bitness, is_be)

        decomp = _get_native_decompiler()
        c_code = decomp.decompile(
            arch_info["sla_path"],
            arch_info["target"],
            bytes(data),
            start_addr,
            start_addr,
            size
        )

        if not c_code or not c_code.strip():
            return None, "Decompilation produced no output"

        return c_code, None

    except Exception as e:
        return None, f"Decompilation error: {str(e)}\n{traceback.format_exc()}"


def get_pcode_text(func_ea):
    """Lift the function at func_ea and return formatted PCode text."""
    data, start_addr, size = get_function_bytes(func_ea)
    if data is None or size == 0:
        return None, "No function at this address"

    try:
        lifter = create_lifter(start_addr, data)

        func_name = ida_name.get_name(func_ea)
        if not func_name:
            func_name = f"sub_{func_ea:X}"

        procname, bitness, _ = get_arch_info()
        header = f"// PCode for {func_name} @ 0x{func_ea:X}\n"
        header += f"// Arch: {procname} {bitness}-bit, Size: {size} bytes\n\n"

        pcode = lifter.pcode_text(start_addr, size)
        return header + pcode, None

    except Exception as e:
        return None, f"PCode lift error: {str(e)}\n{traceback.format_exc()}"


def show_decompiled(func_ea):
    """Decompile and show the result in a custom viewer."""
    ida_kernwin.show_wait_box("Decompiling with Ghidra engine...")
    try:
        c_code, error = decompile_function(func_ea)
    finally:
        ida_kernwin.hide_wait_box()

    if error:
        ida_kernwin.warning(f"Ghidra Decompiler: {error}")
        return

    if not c_code:
        ida_kernwin.warning("Ghidra Decompiler: No output generated")
        return

    # Get function name for title
    func_name = ida_name.get_name(func_ea)
    if not func_name:
        func_name = f"sub_{func_ea:X}"

    title = f"Ghidra: {func_name}"
    lines = c_code.split('\n')

    # Close existing viewer with same title
    widget = ida_kernwin.find_widget(title)
    if widget:
        ida_kernwin.close_widget(widget, 0)

    # Create and show the viewer
    viewer = GhidraDecompilerViewer(title, lines, func_ea)
    if viewer.Create():
        viewer.Show()
    else:
        ida_kernwin.warning("Failed to create decompiler viewer")


def show_pcode(func_ea):
    """Lift and show PCode in a custom viewer."""
    ida_kernwin.show_wait_box("Lifting to PCode with Ghidra SLEIGH...")
    try:
        pcode_text, error = get_pcode_text(func_ea)
    finally:
        ida_kernwin.hide_wait_box()

    if error:
        ida_kernwin.warning(f"Ghidra PCode: {error}")
        return

    func_name = ida_name.get_name(func_ea)
    if not func_name:
        func_name = f"sub_{func_ea:X}"

    title = f"PCode: {func_name}"
    lines = pcode_text.split('\n')

    widget = ida_kernwin.find_widget(title)
    if widget:
        ida_kernwin.close_widget(widget, 0)

    viewer = GhidraDecompilerViewer(title, lines, func_ea)
    if viewer.Create():
        viewer.Show()
    else:
        ida_kernwin.warning("Failed to create PCode viewer")


class GhidraDecompilerHandler(ida_kernwin.action_handler_t):
    """Action handler for the Ghidra decompile action (Alt+F1)."""

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is None:
            ida_kernwin.warning("No function at current address")
            return 0
        show_decompiled(func.start_ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class GhidraPcodeHandler(ida_kernwin.action_handler_t):
    """Action handler for the Ghidra PCode viewer action (Alt+F2)."""

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is None:
            ida_kernwin.warning("No function at current address")
            return 0
        show_pcode(func.start_ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class GhidraDecompilerPlugin(ida_idaapi.plugin_t):
    """IDA Plugin class for the Ghidra Decompiler."""

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = PLUGIN_COMMENT
    help = "Decompile functions using the Ghidra decompilation engine"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    ACTION_DECOMPILE = "ghidra:decompile"
    ACTION_PCODE = "ghidra:pcode"

    def init(self):
        # Register decompile action (Alt+F1)
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            self.ACTION_DECOMPILE,
            "Decompile with Ghidra",
            GhidraDecompilerHandler(),
            PLUGIN_HOTKEY_DECOMPILE,
            "Decompile current function using Ghidra engine",
            -1
        ))

        # Register PCode action (Alt+F2)
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            self.ACTION_PCODE,
            "Show PCode (Ghidra)",
            GhidraPcodeHandler(),
            PLUGIN_HOTKEY_PCODE,
            "Lift current function to PCode using Ghidra SLEIGH",
            -1
        ))

        # Add to Edit menu
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", self.ACTION_DECOMPILE, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", self.ACTION_PCODE, ida_kernwin.SETMENU_APP)

        print(f"[{PLUGIN_NAME}] Loaded. "
              f"{PLUGIN_HOTKEY_DECOMPILE}=Decompile, {PLUGIN_HOTKEY_PCODE}=PCode")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            show_decompiled(func.start_ea)

    def term(self):
        ida_kernwin.unregister_action(self.ACTION_DECOMPILE)
        ida_kernwin.unregister_action(self.ACTION_PCODE)
        print(f"[{PLUGIN_NAME}] Unloaded.")


def PLUGIN_ENTRY():
    return GhidraDecompilerPlugin()


# Allow running as a script too
if __name__ == "__main__":
    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func:
        show_decompiled(func.start_ea)
    else:
        print("No function at current address")

