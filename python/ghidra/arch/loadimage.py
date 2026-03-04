"""
Corresponds to: loadimage.hh / loadimage.cc / loadimage_xml.hh

LoadImage: interface for accessing the binary being analyzed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace


class LoadImageFunc:
    """A record indicating a function symbol."""
    def __init__(self, addr: Address = None, name: str = ""):
        self.address = addr if addr is not None else Address()
        self.name = name


class LoadImageSection:
    """A record describing a section of bytes in the executable."""
    unalloc = 1
    noload = 2
    code = 4
    data = 8
    readonly = 16

    def __init__(self, addr: Address = None, size: int = 0, flags: int = 0):
        self.address = addr if addr is not None else Address()
        self.size = size
        self.flags = flags


class DataUnavailError(Exception):
    """Exception indicating data was not available."""
    pass


class LoadImage(ABC):
    """An interface into a binary image being analyzed.

    The image is byte-addressable through an arbitrary number of address spaces.
    """

    def __init__(self, nm: str = "") -> None:
        self._filename: str = nm

    def getFileName(self) -> str:
        return self._filename

    @abstractmethod
    def loadFill(self, buf: bytearray, size: int, addr: Address) -> None:
        """Load *size* bytes at *addr* into *buf*. Pad with zero if unavailable."""
        ...

    @abstractmethod
    def getArchType(self) -> str:
        """Get a string describing the architecture type."""
        ...

    def adjustVma(self, adjust: int) -> None:
        """Adjust load addresses by a given amount."""
        pass

    def openSymbols(self) -> None:
        """Prepare to read symbols."""
        pass

    def closeSymbols(self) -> None:
        """Stop reading symbols."""
        pass

    def getNextSymbol(self, record: LoadImageFunc) -> bool:
        """Get the next symbol record. Returns False when done."""
        return False

    def openSectionInfo(self) -> None:
        """Prepare to read section info."""
        pass

    def closeSectionInfo(self) -> None:
        """Stop reading section info."""
        pass

    def getNextSection(self, sec: LoadImageSection) -> bool:
        """Get info on the next section. Returns False when done."""
        return False

    def getReadonly(self, rnglist) -> None:
        """Return list of readonly address ranges."""
        pass

    def load(self, size: int, addr: Address) -> bytes:
        """Load a chunk of image."""
        buf = bytearray(size)
        self.loadFill(buf, size, addr)
        return bytes(buf)


class LoadImageBytes(LoadImage):
    """A LoadImage backed by raw bytes in memory."""

    def __init__(self, data: bytes, base_addr: Address, nm: str = "memory") -> None:
        super().__init__(nm)
        self._data: bytes = data
        self._base: Address = base_addr

    def loadFill(self, buf: bytearray, size: int, addr: Address) -> None:
        if addr.getSpace() is not self._base.getSpace():
            for i in range(size):
                buf[i] = 0
            return
        off = addr.getOffset() - self._base.getOffset()
        for i in range(size):
            idx = off + i
            if 0 <= idx < len(self._data):
                buf[i] = self._data[idx]
            else:
                buf[i] = 0

    def getArchType(self) -> str:
        return "raw-bytes"

    def getData(self) -> bytes:
        return self._data

    def getBaseAddress(self) -> Address:
        return self._base
