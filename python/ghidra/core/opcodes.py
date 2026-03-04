"""
Corresponds to: opcodes.hh / opcodes.cc

All the individual p-code operations, defined as an IntEnum.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Tuple


class OpCode(IntEnum):
    """The op-code defining a specific p-code operation (PcodeOp).

    These break up into categories:
      - Branching operations
      - Load and Store
      - Comparison operations
      - Arithmetic operations
      - Logical operations
      - Extension and truncation operations
    """
    CPUI_BLANK = 0

    CPUI_COPY = 1
    CPUI_LOAD = 2
    CPUI_STORE = 3

    CPUI_BRANCH = 4
    CPUI_CBRANCH = 5
    CPUI_BRANCHIND = 6

    CPUI_CALL = 7
    CPUI_CALLIND = 8
    CPUI_CALLOTHER = 9
    CPUI_RETURN = 10

    # Integer/bit operations
    CPUI_INT_EQUAL = 11
    CPUI_INT_NOTEQUAL = 12
    CPUI_INT_SLESS = 13
    CPUI_INT_SLESSEQUAL = 14
    CPUI_INT_LESS = 15
    CPUI_INT_LESSEQUAL = 16
    CPUI_INT_ZEXT = 17
    CPUI_INT_SEXT = 18
    CPUI_INT_ADD = 19
    CPUI_INT_SUB = 20
    CPUI_INT_CARRY = 21
    CPUI_INT_SCARRY = 22
    CPUI_INT_SBORROW = 23
    CPUI_INT_2COMP = 24
    CPUI_INT_NEGATE = 25
    CPUI_INT_XOR = 26
    CPUI_INT_AND = 27
    CPUI_INT_OR = 28
    CPUI_INT_LEFT = 29
    CPUI_INT_RIGHT = 30
    CPUI_INT_SRIGHT = 31
    CPUI_INT_MULT = 32
    CPUI_INT_DIV = 33
    CPUI_INT_SDIV = 34
    CPUI_INT_REM = 35
    CPUI_INT_SREM = 36

    CPUI_BOOL_NEGATE = 37
    CPUI_BOOL_XOR = 38
    CPUI_BOOL_AND = 39
    CPUI_BOOL_OR = 40

    # Floating point operations
    CPUI_FLOAT_EQUAL = 41
    CPUI_FLOAT_NOTEQUAL = 42
    CPUI_FLOAT_LESS = 43
    CPUI_FLOAT_LESSEQUAL = 44
    CPUI_UNUSED1 = 45  # Slot 45 is currently unused
    CPUI_FLOAT_NAN = 46

    CPUI_FLOAT_ADD = 47
    CPUI_FLOAT_DIV = 48
    CPUI_FLOAT_MULT = 49
    CPUI_FLOAT_SUB = 50
    CPUI_FLOAT_NEG = 51
    CPUI_FLOAT_ABS = 52
    CPUI_FLOAT_SQRT = 53

    CPUI_FLOAT_INT2FLOAT = 54
    CPUI_FLOAT_FLOAT2FLOAT = 55
    CPUI_FLOAT_TRUNC = 56
    CPUI_FLOAT_CEIL = 57
    CPUI_FLOAT_FLOOR = 58
    CPUI_FLOAT_ROUND = 59

    # Internal opcodes for simplification
    # Data-flow operations
    CPUI_MULTIEQUAL = 60
    CPUI_INDIRECT = 61
    CPUI_PIECE = 62
    CPUI_SUBPIECE = 63

    CPUI_CAST = 64
    CPUI_PTRADD = 65
    CPUI_PTRSUB = 66
    CPUI_SEGMENTOP = 67
    CPUI_CPOOLREF = 68
    CPUI_NEW = 69
    CPUI_INSERT = 70
    CPUI_EXTRACT = 71
    CPUI_POPCOUNT = 72
    CPUI_LZCOUNT = 73

    CPUI_MAX = 74


# --------------------------------------------------------------------------
# Opcode name table (indexed by OpCode value)
# Some names are replaced with special placeholder ops for the sleigh
# compiler and interpreter:
#   MULTIEQUAL = BUILD
#   INDIRECT   = DELAY_SLOT
#   PTRADD     = LABEL
#   PTRSUB     = CROSSBUILD
# --------------------------------------------------------------------------
_OPCODE_NAMES: list[str] = [
    "BLANK", "COPY", "LOAD", "STORE",
    "BRANCH", "CBRANCH", "BRANCHIND", "CALL",
    "CALLIND", "CALLOTHER", "RETURN", "INT_EQUAL",
    "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS",
    "INT_LESSEQUAL", "INT_ZEXT", "INT_SEXT", "INT_ADD",
    "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "INT_2COMP", "INT_NEGATE", "INT_XOR", "INT_AND",
    "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
    "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM",
    "INT_SREM", "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND",
    "BOOL_OR", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS",
    "FLOAT_LESSEQUAL", "UNUSED1", "FLOAT_NAN", "FLOAT_ADD",
    "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB", "FLOAT_NEG",
    "FLOAT_ABS", "FLOAT_SQRT", "INT2FLOAT", "FLOAT2FLOAT",
    "TRUNC", "CEIL", "FLOOR", "ROUND",
    "BUILD", "DELAY_SLOT", "PIECE", "SUBPIECE", "CAST",
    "LABEL", "CROSSBUILD", "SEGMENTOP", "CPOOLREF", "NEW",
    "INSERT", "EXTRACT", "POPCOUNT", "LZCOUNT",
]

# Pre-built reverse lookup: name -> OpCode
_NAME_TO_OPCODE: dict[str, OpCode] = {}
for _i, _nm in enumerate(_OPCODE_NAMES):
    try:
        _NAME_TO_OPCODE[_nm] = OpCode(_i)
    except ValueError:
        pass  # Skip unused slots


def get_opname(opc: OpCode) -> str:
    """Convert an OpCode to its name string.

    Corresponds to: get_opname() in opcodes.cc
    """
    return _OPCODE_NAMES[int(opc)]


def get_opcode(nm: str) -> OpCode:
    """Convert a name string to the matching OpCode.

    Corresponds to: get_opcode() in opcodes.cc
    Returns CPUI_BLANK (0) if the name is not recognised.
    """
    return _NAME_TO_OPCODE.get(nm, OpCode.CPUI_BLANK)


def get_booleanflip(opc: OpCode) -> Tuple[OpCode, bool]:
    """Get the complementary OpCode for comparison operations.

    Corresponds to: get_booleanflip() in opcodes.cc
    Returns (complementary_opcode, reorder).
    *reorder* is True if the complementary operation involves
    reordering the input parameters.
    Returns (CPUI_MAX, False) if *opc* is not a comparison.
    """
    _map: dict[OpCode, Tuple[OpCode, bool]] = {
        OpCode.CPUI_INT_EQUAL:       (OpCode.CPUI_INT_NOTEQUAL,   False),
        OpCode.CPUI_INT_NOTEQUAL:    (OpCode.CPUI_INT_EQUAL,      False),
        OpCode.CPUI_INT_SLESS:       (OpCode.CPUI_INT_SLESSEQUAL, True),
        OpCode.CPUI_INT_SLESSEQUAL:  (OpCode.CPUI_INT_SLESS,      True),
        OpCode.CPUI_INT_LESS:        (OpCode.CPUI_INT_LESSEQUAL,   True),
        OpCode.CPUI_INT_LESSEQUAL:   (OpCode.CPUI_INT_LESS,        True),
        OpCode.CPUI_BOOL_NEGATE:     (OpCode.CPUI_COPY,            False),
        OpCode.CPUI_FLOAT_EQUAL:     (OpCode.CPUI_FLOAT_NOTEQUAL,  False),
        OpCode.CPUI_FLOAT_NOTEQUAL:  (OpCode.CPUI_FLOAT_EQUAL,     False),
        OpCode.CPUI_FLOAT_LESS:      (OpCode.CPUI_FLOAT_LESSEQUAL, True),
        OpCode.CPUI_FLOAT_LESSEQUAL: (OpCode.CPUI_FLOAT_LESS,      True),
    }
    return _map.get(opc, (OpCode.CPUI_MAX, False))
