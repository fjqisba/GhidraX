"""
Corresponds to: stringmanage.hh / stringmanage.cc

Classes for decoding and storing string data.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Optional, Dict, List

from ghidra.core.address import Address
from ghidra.types.datatype import Datatype, TYPE_INT


class StringData:
    """String data (a sequence of bytes) stored by StringManager."""

    def __init__(self) -> None:
        self.isTruncated: bool = False
        self.byteData: bytes = b""


class StringManager:
    """Storage for decoding and storing strings associated with an address.

    Looks at data in the loadimage to determine if it represents a "string".
    """

    def __init__(self, max_chars: int = 256) -> None:
        self._stringMap: Dict[int, StringData] = {}  # addr_hash -> StringData
        self.maximumChars: int = max_chars

    def clear(self) -> None:
        self._stringMap.clear()

    @abstractmethod
    def getStringData(self, addr: Address, charType: Datatype) -> tuple[bytes, bool]:
        """Retrieve string data at the given address as UTF8 bytes.

        Returns (byte_data, is_truncated). Empty bytes if no string.
        """
        ...

    def getString(self, addr: Address, charType=None) -> Optional[str]:
        """Get a quoted string representation at the given address."""
        if charType is None:
            from ghidra.types.datatype import Datatype
            charType = Datatype("char", 1, TYPE_INT)
        data, trunc = self.getStringData(addr, charType)
        if not data:
            return None
        try:
            s = data.decode('utf-8', errors='replace')
            if s.endswith('\x00'):
                s = s[:-1]
            result = '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t') + '"'
            return result
        except Exception:
            return None

    def isString(self, addr: Address, charType: Datatype) -> bool:
        data, _ = self.getStringData(addr, charType)
        return len(data) > 0

    @staticmethod
    def hasCharTerminator(buffer: bytes, size: int, charsize: int) -> bool:
        for i in range(0, size, charsize):
            chunk = buffer[i:i + charsize]
            if all(b == 0 for b in chunk):
                return True
        return False

    @staticmethod
    def writeUtf8(codepoint: int) -> bytes:
        return chr(codepoint).encode("utf-8", errors="replace")

    @staticmethod
    def getCodepoint(buf: bytes, charsize: int, bigend: bool) -> tuple[int, int]:
        if charsize == 1:
            return buf[0], 1
        elif charsize == 2:
            if bigend:
                return (buf[0] << 8) | buf[1], 2
            return buf[0] | (buf[1] << 8), 2
        elif charsize == 4:
            if bigend:
                return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3], 4
            return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24), 4
        return 0, charsize


    def setMaxChars(self, val: int) -> None:
        self.maximumChars = val

    def getMaxChars(self) -> int:
        return self.maximumChars

    def encode(self, encoder) -> None:
        """Encode all cached strings to a stream."""
        pass

    def decode(self, decoder) -> None:
        """Decode cached strings from a stream."""
        pass

    def testForString(self, addr: Address, charType: Datatype, buf: bytes, sz: int) -> bool:
        """Quick test if the given data could be a string."""
        if sz < 1:
            return False
        charsize = charType.getSize() if hasattr(charType, 'getSize') else 1
        return self.hasCharTerminator(buf, sz, charsize)

    def getCharType(self, size: int):
        """Get the character data-type for the given element size."""
        return None


class StringManagerUnicode(StringManager):
    """An implementation that understands terminated unicode strings."""

    def __init__(self, glb=None, max_chars: int = 256) -> None:
        super().__init__(max_chars)
        self.glb = glb  # Architecture

    def getStringData(self, addr: Address, charType: Datatype) -> tuple[bytes, bool]:
        """Retrieve string data by reading from the load image."""
        if self.glb is None or not hasattr(self.glb, 'loader') or self.glb.loader is None:
            return b"", False
        charsize = charType.getSize() if hasattr(charType, 'getSize') else 1
        maxbytes = self.maximumChars * charsize
        buf = bytearray(maxbytes)
        try:
            self.glb.loader.loadFill(buf, maxbytes, addr)
        except Exception:
            return b"", False
        # Find null terminator
        result = bytearray()
        truncated = True
        for i in range(0, maxbytes, charsize):
            chunk = buf[i:i + charsize]
            if all(b == 0 for b in chunk):
                truncated = False
                break
            result.extend(chunk)
        if not result:
            return b"", False
        # Convert to UTF-8
        if charsize == 1:
            return bytes(result), truncated
        elif charsize == 2:
            try:
                text = result.decode('utf-16-le' if not self._isBigEndian() else 'utf-16-be')
                return text.encode('utf-8'), truncated
            except Exception:
                return bytes(result), truncated
        elif charsize == 4:
            try:
                text = result.decode('utf-32-le' if not self._isBigEndian() else 'utf-32-be')
                return text.encode('utf-8'), truncated
            except Exception:
                return bytes(result), truncated
        return bytes(result), truncated

    def _isBigEndian(self) -> bool:
        if self.glb is not None and hasattr(self.glb, 'translate') and self.glb.translate is not None:
            return self.glb.translate.isBigEndian() if hasattr(self.glb.translate, 'isBigEndian') else False
        return False

    def isUTF8(self) -> bool:
        return True

    def getGlb(self):
        return self.glb

    def readString(self, addr: Address, charType: Datatype) -> Optional[str]:
        """Read a string from the load image, returning None if not a string."""
        data, trunc = self.getStringData(addr, charType)
        if not data:
            return None
        try:
            return data.decode('utf-8', errors='replace')
        except Exception:
            return None
