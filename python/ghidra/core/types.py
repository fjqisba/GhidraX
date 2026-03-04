"""
Corresponds to: types.h

Basic type definitions for the decompiler.
In C++ these are fixed-width integer typedefs. In Python, integers are
arbitrary precision, so we define masks and helper functions to simulate
fixed-width behavior where needed.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# Width masks – used to clamp Python ints to C++ fixed widths
# --------------------------------------------------------------------------
UINT1_MAX: int = 0xFF
UINT2_MAX: int = 0xFFFF
UINT4_MAX: int = 0xFFFFFFFF
UINT8_MAX: int = 0xFFFFFFFFFFFFFFFF

INT1_MIN: int = -0x80
INT1_MAX: int = 0x7F
INT2_MIN: int = -0x8000
INT2_MAX: int = 0x7FFF
INT4_MIN: int = -0x80000000
INT4_MAX: int = 0x7FFFFFFF
INT8_MIN: int = -0x8000000000000000
INT8_MAX: int = 0x7FFFFFFFFFFFFFFF

# Type aliases (documentation-only in Python, but useful for grep / readability)
# uint1, int1 = 8-bit
# uint2, int2 = 16-bit
# uint4, int4 = 32-bit
# uint8, int8 = 64-bit  (NOTE: Python's int is already arbitrary)
# uintb, intb = "big" integer – 64-bit in C++
# uintm, intm = 32-bit (deprecated in C++)
# uintp       = pointer-sized unsigned int

# --------------------------------------------------------------------------
# Utility helpers
# --------------------------------------------------------------------------

def mask_uint1(val: int) -> int:
    return val & UINT1_MAX

def mask_uint2(val: int) -> int:
    return val & UINT2_MAX

def mask_uint4(val: int) -> int:
    return val & UINT4_MAX

def mask_uint8(val: int) -> int:
    return val & UINT8_MAX

def to_signed(val: int, size: int) -> int:
    """Convert an unsigned value to signed given *size* in bytes."""
    bits = size * 8
    mask = (1 << bits) - 1
    val &= mask
    if val >= (1 << (bits - 1)):
        val -= (1 << bits)
    return val

def to_unsigned(val: int, size: int) -> int:
    """Convert a (possibly negative) value to unsigned given *size* in bytes."""
    mask = (1 << (size * 8)) - 1
    return val & mask

# Host endianness indicator (0 = little-endian on x86)
HOST_ENDIAN: int = 0
