"""
Ghidra Decompiler Plugin for IDA 9.0
=====================================

Press Alt+F1 on any function to decompile it using the PyGhidra engine
and display pseudocode in a custom viewer window (like Hex-Rays).

Requirements:
- IDA 9.0+ with IDAPython
- PyGhidra engine (d:\BIGAI\pyghidra\python)
- sleigh_native.pyd built for your Python version
- x86.sla specification file

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
import ida_name
import ida_ua
import idautils
import idc

# Add PyGhidra to path
PYGHIDRA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "python")
if PYGHIDRA_PATH not in sys.path:
    sys.path.insert(0, PYGHIDRA_PATH)

# SLA file path
SLA_PATH = r"d:\BIGAI\XGhidra\native\specs\x86.sla"

PLUGIN_NAME = "Ghidra Decompiler"
PLUGIN_HOTKEY = "Alt+F1"
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
    info = ida_idaapi.get_inf_structure()
    procname = info.procname.lower()
    bitness = 64 if info.is_64bit() else (32 if info.is_32bit() else 16)
    is_be = info.is_be()
    return procname, bitness, is_be


def decompile_function(func_ea):
    """Decompile the function at func_ea using the PyGhidra engine."""
    data, start_addr, size = get_function_bytes(func_ea)
    if data is None or size == 0:
        return None, "No function at this address"

    procname, bitness, is_be = get_arch_info()

    try:
        from ghidra.sleigh.lifter import Lifter
        from ghidra.arch.architecture import Architecture

        # Create the lifter with the SLA file
        lifter = Lifter(SLA_PATH)

        # Set up context for x86
        if 'x86' in procname or '80386' in procname or 'metapc' in procname:
            if bitness == 32:
                lifter.native.set_context_default('addrsize', 1)
                lifter.native.set_context_default('opsize', 1)
            elif bitness == 64:
                lifter.native.set_context_default('longMode', 1)
                lifter.native.set_context_default('addrsize', 2)
                lifter.native.set_context_default('opsize', 2)

        # Lift the function to P-code
        fd = lifter.lift_function(data, start_addr)
        if fd is None:
            return None, "Failed to lift function to P-code"

        # Create architecture and run decompilation pipeline
        arch = Architecture()
        arch.init()
        fd.setArch(arch)

        # Run the full decompilation pipeline
        c_code = arch.decompileFunction(fd)

        # Get the function name from IDA
        func_name = ida_name.get_name(func_ea)
        if not func_name:
            func_name = f"sub_{func_ea:X}"

        # Replace the generic function name with the IDA name
        if c_code:
            c_code = c_code.replace("func_unknown", func_name)
            c_code = c_code.replace("FUN_", func_name + "_")

        return c_code, None

    except Exception as e:
        return None, f"Decompilation error: {str(e)}\n{traceback.format_exc()}"


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


class GhidraDecompilerHandler(ida_kernwin.action_handler_t):
    """Action handler for the Ghidra decompile action."""

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


class GhidraDecompilerPlugin(ida_idaapi.plugin_t):
    """IDA Plugin class for the Ghidra Decompiler."""

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = PLUGIN_COMMENT
    help = "Decompile functions using the Ghidra decompilation engine"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    ACTION_NAME = "ghidra:decompile"
    ACTION_LABEL = "Decompile with Ghidra"
    ACTION_SHORTCUT = PLUGIN_HOTKEY

    def init(self):
        # Register the action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_NAME,
            self.ACTION_LABEL,
            GhidraDecompilerHandler(),
            self.ACTION_SHORTCUT,
            PLUGIN_COMMENT,
            -1
        )
        ida_kernwin.register_action(action_desc)

        # Add to Edit menu
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/",
            self.ACTION_NAME,
            ida_kernwin.SETMENU_APP
        )

        print(f"[{PLUGIN_NAME}] Loaded. Press {PLUGIN_HOTKEY} to decompile.")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            show_decompiled(func.start_ea)

    def term(self):
        ida_kernwin.unregister_action(self.ACTION_NAME)
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
