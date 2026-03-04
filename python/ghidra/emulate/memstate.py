"""
Corresponds to: memstate.hh / memstate.cc

Classes for a pcode machine state that can be operated on by the emulator.
"""

from __future__ import annotations

from typing import Optional, Dict, Tuple

from ghidra.core.space import AddrSpace, IPTR_CONSTANT
from ghidra.core.address import Address


class MemoryBank:
    """A byte-addressable bank of memory for a specific address space."""

    def __init__(self, spc: AddrSpace, pagesize: int = 4096) -> None:
        self._space: AddrSpace = spc
        self._pagesize: int = pagesize
        self._pages: Dict[int, bytearray] = {}

    def getSpace(self) -> AddrSpace:
        return self._space

    def _pageIndex(self, offset: int) -> Tuple[int, int]:
        page = offset // self._pagesize
        off = offset % self._pagesize
        return page, off

    def setValue(self, offset: int, size: int, val: int) -> None:
        """Write a value (little-endian by default) at the given offset."""
        is_big = self._space.isBigEndian()
        for i in range(size):
            if is_big:
                b = (val >> ((size - 1 - i) * 8)) & 0xFF
            else:
                b = (val >> (i * 8)) & 0xFF
            self._setByte(offset + i, b)

    def getValue(self, offset: int, size: int) -> int:
        """Read a value from the given offset."""
        is_big = self._space.isBigEndian()
        val = 0
        for i in range(size):
            b = self._getByte(offset + i)
            if is_big:
                val = (val << 8) | b
            else:
                val |= (b << (i * 8))
        return val

    def _setByte(self, offset: int, val: int) -> None:
        page, off = self._pageIndex(offset)
        if page not in self._pages:
            self._pages[page] = bytearray(self._pagesize)
        self._pages[page][off] = val & 0xFF

    def _getByte(self, offset: int) -> int:
        page, off = self._pageIndex(offset)
        if page not in self._pages:
            return 0
        return self._pages[page][off]

    def setChunk(self, offset: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self._setByte(offset + i, b)

    def getChunk(self, offset: int, size: int) -> bytes:
        return bytes(self._getByte(offset + i) for i in range(size))

    def clear(self) -> None:
        self._pages.clear()


class MemoryState:
    """All memory state needed by a pcode emulator.

    Manages a set of MemoryBanks, one per address space.
    """

    def __init__(self, trans) -> None:
        self._trans = trans  # Translate
        self._banks: Dict[int, MemoryBank] = {}

    def setMemoryBank(self, bank: MemoryBank) -> None:
        self._banks[bank.getSpace().getIndex()] = bank

    def getMemoryBank(self, spc: AddrSpace) -> Optional[MemoryBank]:
        return self._banks.get(spc.getIndex())

    def _ensureBank(self, spc: AddrSpace) -> MemoryBank:
        bank = self._banks.get(spc.getIndex())
        if bank is None:
            bank = MemoryBank(spc)
            self._banks[spc.getIndex()] = bank
        return bank

    def setValue(self, spc: AddrSpace, offset: int, size: int, val: int) -> None:
        if spc.getType() == IPTR_CONSTANT:
            return
        bank = self._ensureBank(spc)
        bank.setValue(offset, size, val)

    def getValue(self, spc: AddrSpace, offset: int, size: int) -> int:
        if spc.getType() == IPTR_CONSTANT:
            return offset
        bank = self._banks.get(spc.getIndex())
        if bank is None:
            return 0
        return bank.getValue(offset, size)

    def setVarnodeValue(self, vn_space: AddrSpace, vn_offset: int, vn_size: int, val: int) -> None:
        self.setValue(vn_space, vn_offset, vn_size, val)

    def getVarnodeValue(self, vn_space: AddrSpace, vn_offset: int, vn_size: int) -> int:
        return self.getValue(vn_space, vn_offset, vn_size)

    def clear(self) -> None:
        for bank in self._banks.values():
            bank.clear()
