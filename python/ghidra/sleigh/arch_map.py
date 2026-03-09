"""
Architecture mapping: resolves IDA processor info to SLEIGH SLA file and context settings.

Maps (processor_name, bitness, endianness) → {"sla": filename, "context": {key: val, ...}}
"""

from __future__ import annotations

import os
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Architecture registry
# Keys: (procname_pattern, bitness, is_big_endian)
#   procname_pattern: lowercase substring matched against IDA's inf_get_procname()
#   bitness: 16 | 32 | 64
#   is_big_endian: True | False
# Values: dict with "sla" (filename) and "context" (context variable defaults)
# ---------------------------------------------------------------------------

ARCH_TABLE = [
    # x86 family
    {"match": ("metapc", 64, False), "sla": "x86-64.sla",  "target": "x86:LE:64:default", "context": {}},
    {"match": ("metapc", 32, False), "sla": "x86.sla",     "target": "x86:LE:32:default", "context": {"addrsize": 1, "opsize": 1}},
    {"match": ("metapc", 16, False), "sla": "x86.sla",     "target": "x86:LE:16:Real Mode", "context": {}},

    # ARM family
    {"match": ("arm",    64, False), "sla": "AARCH64.sla",  "target": "AARCH64:LE:64:v8A", "context": {}},
    {"match": ("arm",    32, False), "sla": "ARM8_le.sla",  "target": "ARM:LE:32:v8", "context": {}},
    {"match": ("arm",    32, True),  "sla": "ARM8_be.sla",  "target": "ARM:BE:32:v8", "context": {}},

    # MIPS family
    {"match": ("mips",   64, False), "sla": "mips64le.sla", "target": "MIPS:LE:64:default", "context": {}},
    {"match": ("mips",   64, True),  "sla": "mips64be.sla", "target": "MIPS:BE:64:default", "context": {}},
    {"match": ("mips",   32, False), "sla": "mips32le.sla", "target": "MIPS:LE:32:default", "context": {}},
    {"match": ("mips",   32, True),  "sla": "mips32be.sla", "target": "MIPS:BE:32:default", "context": {}},

    # PowerPC
    {"match": ("ppc",    64, True),  "sla": "ppc_64_be.sla", "target": "PowerPC:BE:64:default", "context": {}},
    {"match": ("ppc",    32, True),  "sla": "ppc_32_be.sla", "target": "PowerPC:BE:32:default", "context": {}},
    {"match": ("ppc",    64, False), "sla": "ppc_64_le.sla", "target": "PowerPC:LE:64:default", "context": {}},
    {"match": ("ppc",    32, False), "sla": "ppc_32_le.sla", "target": "PowerPC:LE:32:default", "context": {}},
]


# ---------------------------------------------------------------------------
# SLA file search paths (ordered by priority)
# ---------------------------------------------------------------------------

_SLA_SEARCH_DIRS: list = []


def add_sla_search_dir(path: str) -> None:
    """Add a directory to the SLA search path."""
    if path and path not in _SLA_SEARCH_DIRS:
        _SLA_SEARCH_DIRS.append(path)


def _get_search_dirs() -> list:
    """Build the ordered list of directories to search for SLA files."""
    dirs = list(_SLA_SEARCH_DIRS)

    # Environment variable
    env_dir = os.environ.get("PYGHIDRA_SLA_DIR")
    if env_dir and env_dir not in dirs:
        dirs.append(env_dir)

    # Relative to this file: ghidra/sleigh/arch_map.py
    here = os.path.dirname(os.path.abspath(__file__))
    # Source layout:   <root>/python/ghidra/sleigh/ -> 3 levels up = <root>
    # Deployed layout: <dst>/ghidra/sleigh/         -> 2 levels up = <dst>
    roots = [
        os.path.normpath(os.path.join(here, "..", "..", "..")),  # source
        os.path.normpath(os.path.join(here, "..", "..")),        # deployed
    ]

    for root in roots:
        # Scan Ghidra/Processors/<proc>/data/languages/ (standard Ghidra layout)
        proc_dir = os.path.join(root, "Ghidra", "Processors")
        if os.path.isdir(proc_dir):
            for proc in os.listdir(proc_dir):
                lang_dir = os.path.join(proc_dir, proc, "data", "languages")
                if os.path.isdir(lang_dir) and lang_dir not in dirs:
                    dirs.append(lang_dir)
        # Legacy flat specs/ directory
        rel_specs = os.path.join(root, "specs")
        if os.path.isdir(rel_specs) and rel_specs not in dirs:
            dirs.append(rel_specs)

    return dirs


def find_sla(filename: str) -> Optional[str]:
    """Find the full path to a .sla file by searching known directories."""
    for d in _get_search_dirs():
        candidate = os.path.join(d, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def resolve_arch(procname: str, bitness: int, is_be: bool) -> Dict:
    """Resolve architecture parameters to SLA file path and context dict.

    Args:
        procname: IDA processor name (lowercase), e.g. "metapc", "arm", "mips"
        bitness: 16, 32, or 64
        is_be: True for big-endian

    Returns:
        {"sla_path": "/full/path/to/file.sla", "context": {key: val, ...}}

    Raises:
        FileNotFoundError: if no matching SLA file can be found
        ValueError: if the architecture is not recognized
    """
    procname = procname.lower().strip()

    for entry in ARCH_TABLE:
        pat_proc, pat_bits, pat_be = entry["match"]
        if pat_proc in procname and pat_bits == bitness and pat_be == is_be:
            sla_file = entry["sla"]
            sla_path = find_sla(sla_file)
            if sla_path is None:
                raise FileNotFoundError(
                    f"SLA file '{sla_file}' not found for {procname}/{bitness}bit. "
                    f"Search dirs: {_get_search_dirs()}"
                )
            return {
                "sla_path": sla_path,
                "target": entry.get("target", ""),
                "context": dict(entry["context"]),
            }

    raise ValueError(
        f"Unsupported architecture: procname={procname!r}, bitness={bitness}, "
        f"big_endian={is_be}. Add an entry to ARCH_TABLE in arch_map.py."
    )


def get_opcode_name(opcode: int) -> str:
    """Return human-readable PCode opcode name."""
    _NAMES = {
        0: "BLANK", 1: "COPY", 2: "LOAD", 3: "STORE",
        4: "BRANCH", 5: "CBRANCH", 6: "BRANCHIND",
        7: "CALL", 8: "CALLIND", 9: "CALLOTHER", 10: "RETURN",
        11: "INT_EQUAL", 12: "INT_NOTEQUAL", 13: "INT_SLESS",
        14: "INT_SLESSEQUAL", 15: "INT_LESS", 16: "INT_LESSEQUAL",
        17: "INT_ZEXT", 18: "INT_SEXT", 19: "INT_ADD", 20: "INT_SUB",
        21: "INT_CARRY", 22: "INT_SCARRY", 23: "INT_SBORROW",
        24: "INT_2COMP", 25: "INT_NEGATE", 26: "INT_XOR",
        27: "INT_AND", 28: "INT_OR", 29: "INT_LEFT", 30: "INT_RIGHT",
        31: "INT_SRIGHT", 32: "INT_MULT", 33: "INT_DIV", 34: "INT_SDIV",
        35: "INT_REM", 36: "INT_SREM",
        37: "BOOL_NEGATE", 38: "BOOL_XOR", 39: "BOOL_AND", 40: "BOOL_OR",
        41: "FLOAT_EQUAL", 42: "FLOAT_NOTEQUAL", 43: "FLOAT_LESS",
        44: "FLOAT_LESSEQUAL", 46: "FLOAT_NAN",
        47: "FLOAT_ADD", 48: "FLOAT_DIV", 49: "FLOAT_MULT", 50: "FLOAT_SUB",
        51: "FLOAT_NEG", 52: "FLOAT_ABS", 53: "FLOAT_SQRT",
        54: "FLOAT_INT2FLOAT", 55: "FLOAT_FLOAT2FLOAT", 56: "FLOAT_TRUNC",
        57: "FLOAT_CEIL", 58: "FLOAT_FLOOR", 59: "FLOAT_ROUND",
        60: "MULTIEQUAL", 61: "INDIRECT", 62: "PIECE", 63: "SUBPIECE",
        64: "CAST", 65: "PTRADD", 66: "PTRSUB", 67: "SEGMENTOP",
        68: "CPOOLREF", 69: "NEW", 70: "INSERT", 71: "EXTRACT",
        72: "POPCOUNT", 73: "LZCOUNT",
    }
    return _NAMES.get(opcode, f"OP_{opcode}")
