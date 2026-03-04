"""
Corresponds to: slaformat.hh / slaformat.cc + marshal.hh PackedDecode/PackedEncode

Binary .sla file format reader/writer and the PackedDecode protocol.
The .sla file uses a compressed packed binary encoding for all SLEIGH data.
"""

from __future__ import annotations

import zlib
import struct
from typing import Optional, List, TYPE_CHECKING

from ghidra.core.error import DecoderError, LowlevelError
from ghidra.core.marshal import (
    Decoder, Encoder, AttributeId, ElementId,
    ATTRIB_UNKNOWN, ATTRIB_CONTENT, ELEM_UNKNOWN,
)
from ghidra.core.opcodes import OpCode, get_opcode

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace, AddrSpaceManager


# =========================================================================
# PackedFormat constants
# =========================================================================

HEADER_MASK = 0xC0
ELEMENT_START = 0x40
ELEMENT_END = 0x80
ATTRIBUTE = 0xC0
HEADEREXTEND_MASK = 0x20
ELEMENTID_MASK = 0x1F
RAWDATA_MASK = 0x7F
RAWDATA_BITSPERBYTE = 7
RAWDATA_MARKER = 0x80
TYPECODE_SHIFT = 4
LENGTHCODE_MASK = 0x0F
TYPECODE_BOOLEAN = 1
TYPECODE_SIGNEDINT_POSITIVE = 2
TYPECODE_SIGNEDINT_NEGATIVE = 3
TYPECODE_UNSIGNEDINT = 4
TYPECODE_ADDRESSSPACE = 5
TYPECODE_SPECIALSPACE = 6
TYPECODE_STRING = 7

SPECIALSPACE_STACK = 0
SPECIALSPACE_JOIN = 1
SPECIALSPACE_FSPEC = 2
SPECIALSPACE_IOP = 3
SPECIALSPACE_SPACEBASE = 4

FORMAT_VERSION = 5
SLA_MAGIC = b"sleigh"


# =========================================================================
# PackedDecode - binary protocol decoder
# =========================================================================

class PackedDecode(Decoder):
    """A byte-based decoder for the packed binary protocol used in .sla files.

    Protocol format:
    - 01xiiiii = element start (x=extend bit, iiiii = id low bits)
    - 10xiiiii = element end
    - 11xiiiii = attribute start
    After attribute start: type byte ttttllll where tttt=type code, llll=length code
    Integer values encoded as 7-bits-per-byte with high bit marker.
    """

    BUFFER_SIZE = 1024

    def __init__(self, spc_manager: Optional[AddrSpaceManager] = None) -> None:
        super().__init__(spc_manager)
        self._data: bytes = b""
        self._pos: int = 0
        self._startStack: List[int] = []  # Stack of element start positions
        self._endStack: List[int] = []    # Stack of element end positions (for attributes)
        self._attrPos: int = 0            # Current attribute read position

    def ingestStream(self, s: str) -> None:
        """Ingest raw bytes (as string or bytes)."""
        if isinstance(s, bytes):
            self._data = s
        else:
            self._data = s.encode('latin-1')
        self._pos = 0

    def ingestBytes(self, data: bytes) -> None:
        """Ingest raw bytes directly."""
        self._data = data
        self._pos = 0

    def _getByte(self) -> int:
        if self._pos >= len(self._data):
            raise DecoderError("Unexpected end of packed stream")
        b = self._data[self._pos]
        self._pos += 1
        return b

    def _peekByte(self) -> int:
        if self._pos >= len(self._data):
            return 0
        return self._data[self._pos]

    def _readHeaderId(self) -> int:
        """Read an element/attribute id from the header byte(s) at current position."""
        header = self._getByte()
        id_ = header & ELEMENTID_MASK
        if header & HEADEREXTEND_MASK:
            ext = self._getByte()
            id_ = (id_ << RAWDATA_BITSPERBYTE) | (ext & RAWDATA_MASK)
        return id_

    def _readPackedInteger(self, length_code: int) -> int:
        """Read a packed integer given its length code (number of 7-bit bytes)."""
        if length_code == 0:
            return 0
        val = 0
        for i in range(length_code):
            b = self._getByte()
            val |= (b & RAWDATA_MASK) << (i * RAWDATA_BITSPERBYTE)
        return val

    def _readPackedString(self, length_code: int) -> str:
        """Read a packed string: first read length as packed int, then raw UTF8 bytes."""
        str_len = self._readPackedInteger(length_code)
        if str_len == 0:
            return ""
        raw = self._data[self._pos:self._pos + str_len]
        self._pos += str_len
        return raw.decode('utf-8', errors='replace')

    def _skipAttribute(self) -> None:
        """Skip over an attribute at current position."""
        type_byte = self._getByte()
        type_code = (type_byte >> TYPECODE_SHIFT) & 0x0F
        length_code = type_byte & LENGTHCODE_MASK
        if type_code == TYPECODE_BOOLEAN:
            pass  # No extra data
        elif type_code == TYPECODE_STRING:
            str_len = self._readPackedInteger(length_code)
            self._pos += str_len
        elif type_code == TYPECODE_SPECIALSPACE:
            pass  # No extra data
        else:
            self._readPackedInteger(length_code)

    def _findElementEnd(self, start_pos: int) -> int:
        """Scan forward from start_pos to find where attributes end for current element."""
        pos = start_pos
        while pos < len(self._data):
            b = self._data[pos]
            header_type = b & HEADER_MASK
            if header_type != ATTRIBUTE:
                return pos  # First non-attribute byte = end of attributes
            # Skip this attribute header + data
            pos += 1
            if b & HEADEREXTEND_MASK:
                pos += 1  # Extended id byte
            # Skip type byte + data
            if pos >= len(self._data):
                return pos
            tb = self._data[pos]
            pos += 1
            tc = (tb >> TYPECODE_SHIFT) & 0x0F
            lc = tb & LENGTHCODE_MASK
            if tc == TYPECODE_BOOLEAN or tc == TYPECODE_SPECIALSPACE:
                pass
            elif tc == TYPECODE_STRING:
                # Read string length
                slen = 0
                for i in range(lc):
                    if pos >= len(self._data):
                        return pos
                    slen |= (self._data[pos] & RAWDATA_MASK) << (i * RAWDATA_BITSPERBYTE)
                    pos += 1
                pos += slen
            else:
                pos += lc  # Integer bytes
        return pos

    # --- Decoder interface ---

    def peekElement(self) -> int:
        if self._pos >= len(self._data):
            return 0
        b = self._data[self._pos]
        if (b & HEADER_MASK) != ELEMENT_START:
            return 0
        id_ = b & ELEMENTID_MASK
        if b & HEADEREXTEND_MASK:
            if self._pos + 1 < len(self._data):
                ext = self._data[self._pos + 1]
                id_ = (id_ << RAWDATA_BITSPERBYTE) | (ext & RAWDATA_MASK)
        return id_

    def openElement(self, elemId: Optional[ElementId] = None) -> int:
        if self._pos >= len(self._data):
            raise DecoderError("No element to open")
        b = self._data[self._pos]
        if (b & HEADER_MASK) != ELEMENT_START:
            raise DecoderError(f"Expected element start, got 0x{b:02x}")
        save_pos = self._pos
        self._pos += 1
        id_ = b & ELEMENTID_MASK
        if b & HEADEREXTEND_MASK:
            ext = self._getByte()
            id_ = (id_ << RAWDATA_BITSPERBYTE) | (ext & RAWDATA_MASK)

        self._startStack.append(save_pos)
        self._attrPos = self._pos
        # Find where attributes end
        end = self._findElementEnd(self._pos)
        self._endStack.append(end)
        self._pos = end  # Skip past attributes, ready for child elements

        if elemId is not None and id_ != elemId.id:
            raise DecoderError(f"Expected element {elemId.name} (id={elemId.id}), got id={id_}")
        return id_

    def closeElement(self, id_: int) -> None:
        if self._pos >= len(self._data):
            self._startStack.pop()
            self._endStack.pop()
            return
        b = self._data[self._pos]
        if (b & HEADER_MASK) == ELEMENT_END:
            self._pos += 1
            if b & HEADEREXTEND_MASK:
                self._pos += 1  # Skip extended byte
        self._startStack.pop()
        self._endStack.pop()

    def closeElementSkipping(self, id_: int) -> None:
        # Skip any remaining children + close tag
        depth = 1
        while depth > 0 and self._pos < len(self._data):
            b = self._data[self._pos]
            ht = b & HEADER_MASK
            if ht == ELEMENT_START:
                depth += 1
                self._pos += 1
                if b & HEADEREXTEND_MASK:
                    self._pos += 1
                # Skip attributes
                self._pos = self._findElementEnd(self._pos)
            elif ht == ELEMENT_END:
                depth -= 1
                self._pos += 1
                if b & HEADEREXTEND_MASK:
                    self._pos += 1
            else:
                self._pos += 1
        self._startStack.pop()
        self._endStack.pop()

    def getNextAttributeId(self) -> int:
        if not self._endStack:
            return 0
        attr_end = self._endStack[-1]
        if self._attrPos >= attr_end:
            return 0
        b = self._data[self._attrPos]
        if (b & HEADER_MASK) != ATTRIBUTE:
            return 0
        id_ = b & ELEMENTID_MASK
        self._attrPos += 1
        if b & HEADEREXTEND_MASK:
            ext = self._data[self._attrPos]
            self._attrPos += 1
            id_ = (id_ << RAWDATA_BITSPERBYTE) | (ext & RAWDATA_MASK)
        return id_

    def getIndexedAttributeId(self, attribId: AttributeId) -> int:
        return 0

    def rewindAttributes(self) -> None:
        if self._startStack:
            start = self._startStack[-1]
            # Re-calculate attribute start position
            b = self._data[start]
            skip = 1
            if b & HEADEREXTEND_MASK:
                skip = 2
            self._attrPos = start + skip

    def _readCurrentAttribute(self):
        """Read type byte and return (type_code, length_code, raw_pos)."""
        type_byte = self._data[self._attrPos]
        self._attrPos += 1
        type_code = (type_byte >> TYPECODE_SHIFT) & 0x0F
        length_code = type_byte & LENGTHCODE_MASK
        return type_code, length_code

    def readBool(self, attribId: Optional[AttributeId] = None) -> bool:
        if attribId is not None:
            self.rewindAttributes()
            self._findAttribute(attribId)
        tc, lc = self._readCurrentAttribute()
        if tc != TYPECODE_BOOLEAN:
            raise DecoderError("Expected boolean attribute")
        return lc != 0

    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        if attribId is not None:
            self.rewindAttributes()
            self._findAttribute(attribId)
        tc, lc = self._readCurrentAttribute()
        val = self._readPackedIntegerFromAttr(lc)
        if tc == TYPECODE_SIGNEDINT_NEGATIVE:
            val = -val
        return val

    def readSignedIntegerExpectString(self, expect_or_attribId, expect_str=None, expectval=0):
        tc, lc = self._readCurrentAttribute()
        if tc == TYPECODE_STRING:
            s = self._readPackedStringFromAttr(lc)
            if isinstance(expect_or_attribId, str) and s == expect_or_attribId:
                return expect_str if expect_str is not None else expectval
            if expect_str is not None and s == expect_str:
                return expectval
            return 0
        val = self._readPackedIntegerFromAttr(lc)
        if tc == TYPECODE_SIGNEDINT_NEGATIVE:
            val = -val
        return val

    def readUnsignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        if attribId is not None:
            self.rewindAttributes()
            self._findAttribute(attribId)
        tc, lc = self._readCurrentAttribute()
        return self._readPackedIntegerFromAttr(lc)

    def readString(self, attribId: Optional[AttributeId] = None) -> str:
        if attribId is not None:
            self.rewindAttributes()
            self._findAttribute(attribId)
        tc, lc = self._readCurrentAttribute()
        if tc != TYPECODE_STRING:
            raise DecoderError("Expected string attribute")
        return self._readPackedStringFromAttr(lc)

    def readSpace(self, attribId: Optional[AttributeId] = None) -> AddrSpace:
        if attribId is not None:
            self.rewindAttributes()
            self._findAttribute(attribId)
        tc, lc = self._readCurrentAttribute()
        if tc == TYPECODE_SPECIALSPACE:
            return self._resolveSpecialSpace(lc)
        idx = self._readPackedIntegerFromAttr(lc)
        if self.spcManager is None:
            raise DecoderError("No space manager for readSpace")
        spc = self.spcManager.getSpaceByIndex(idx)
        if spc is None:
            raise DecoderError(f"Unknown space index: {idx}")
        return spc

    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode:
        if attribId is not None:
            self.rewindAttributes()
            self._findAttribute(attribId)
        tc, lc = self._readCurrentAttribute()
        val = self._readPackedIntegerFromAttr(lc)
        return OpCode(val)

    def _readPackedIntegerFromAttr(self, length_code: int) -> int:
        if length_code == 0:
            return 0
        val = 0
        for i in range(length_code):
            b = self._data[self._attrPos]
            self._attrPos += 1
            val |= (b & RAWDATA_MASK) << (i * RAWDATA_BITSPERBYTE)
        return val

    def _readPackedStringFromAttr(self, length_code: int) -> str:
        str_len = self._readPackedIntegerFromAttr(length_code)
        if str_len == 0:
            return ""
        raw = self._data[self._attrPos:self._attrPos + str_len]
        self._attrPos += str_len
        return raw.decode('utf-8', errors='replace')

    def _findAttribute(self, attribId: AttributeId) -> None:
        """Scan attributes to find one matching the given id."""
        self.rewindAttributes()
        while True:
            aid = self.getNextAttributeId()
            if aid == 0:
                raise DecoderError(f"Attribute '{attribId.name}' not found")
            if aid == attribId.id:
                return

    def _resolveSpecialSpace(self, code: int):
        if self.spcManager is None:
            raise DecoderError("No space manager")
        if code == SPECIALSPACE_STACK:
            return self.spcManager.getStackSpace()
        if code == SPECIALSPACE_JOIN:
            return self.spcManager.getJoinSpace()
        raise DecoderError(f"Unknown special space code: {code}")


# =========================================================================
# PackedEncode - binary protocol encoder
# =========================================================================

class PackedEncode(Encoder):
    """A byte-based encoder for the packed binary protocol."""

    def __init__(self) -> None:
        self._buf: bytearray = bytearray()

    def getBytes(self) -> bytes:
        return bytes(self._buf)

    def _writeHeader(self, header: int, id_: int) -> None:
        if id_ > 0x1F:
            header |= HEADEREXTEND_MASK
            header |= (id_ >> RAWDATA_BITSPERBYTE)
            ext = (id_ & RAWDATA_MASK) | RAWDATA_MARKER
            self._buf.append(header & 0xFF)
            self._buf.append(ext & 0xFF)
        else:
            header |= id_
            self._buf.append(header & 0xFF)

    def _writeInteger(self, type_byte: int, val: int) -> None:
        if val == 0:
            self._buf.append(type_byte & 0xFF)
            return
        # Count bytes needed
        tmp = val
        nbytes = 0
        while tmp > 0:
            nbytes += 1
            tmp >>= RAWDATA_BITSPERBYTE
        self._buf.append((type_byte | nbytes) & 0xFF)
        for i in range(nbytes):
            b = (val >> (i * RAWDATA_BITSPERBYTE)) & RAWDATA_MASK
            b |= RAWDATA_MARKER
            self._buf.append(b & 0xFF)

    def openElement(self, elemId: ElementId) -> None:
        self._writeHeader(ELEMENT_START, elemId.id)

    def closeElement(self, elemId: ElementId) -> None:
        self._writeHeader(ELEMENT_END, elemId.id)

    def writeBool(self, attribId: AttributeId, val: bool) -> None:
        self._writeHeader(ATTRIBUTE, attribId.id)
        tb = (TYPECODE_BOOLEAN << TYPECODE_SHIFT) | (1 if val else 0)
        self._buf.append(tb & 0xFF)

    def writeSignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._writeHeader(ATTRIBUTE, attribId.id)
        if val >= 0:
            self._writeInteger(TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT, val)
        else:
            self._writeInteger(TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT, -val)

    def writeUnsignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._writeHeader(ATTRIBUTE, attribId.id)
        self._writeInteger(TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT, val)

    def writeString(self, attribId: AttributeId, val: str) -> None:
        self._writeHeader(ATTRIBUTE, attribId.id)
        encoded = val.encode('utf-8')
        length = len(encoded)
        # Write string type with length-of-length
        tmp = length
        nbytes = 0
        if tmp == 0:
            nbytes = 0
        else:
            while tmp > 0:
                nbytes += 1
                tmp >>= RAWDATA_BITSPERBYTE
        self._buf.append(((TYPECODE_STRING << TYPECODE_SHIFT) | nbytes) & 0xFF)
        # Write length as packed integer
        for i in range(nbytes):
            b = (length >> (i * RAWDATA_BITSPERBYTE)) & RAWDATA_MASK
            b |= RAWDATA_MARKER
            self._buf.append(b & 0xFF)
        # Write raw string data
        self._buf.extend(encoded)

    def writeStringIndexed(self, attribId: AttributeId, index: int, val: str) -> None:
        self.writeString(attribId, val)

    def writeSpace(self, attribId: AttributeId, spc) -> None:
        self._writeHeader(ATTRIBUTE, attribId.id)
        self._writeInteger(TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT, spc.getIndex())

    def writeOpcode(self, attribId: AttributeId, opc: OpCode) -> None:
        self._writeHeader(ATTRIBUTE, attribId.id)
        self._writeInteger(TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT, int(opc))


# =========================================================================
# .sla file format utilities
# =========================================================================

def isSlaFormat(data: bytes) -> bool:
    """Check if data starts with the .sla file header."""
    return data[:6] == SLA_MAGIC


def readSlaFile(filepath: str, spc_manager: Optional[AddrSpaceManager] = None) -> PackedDecode:
    """Read a .sla file, decompress it, and return a PackedDecode ready for parsing.

    The .sla file format:
    1. 6 bytes: 'sleigh' magic
    2. Remaining bytes: zlib compressed packed binary data
    """
    with open(filepath, 'rb') as f:
        raw = f.read()

    if not isSlaFormat(raw):
        raise LowlevelError(f"Not a valid .sla file: {filepath}")

    compressed = raw[6:]
    try:
        decompressed = zlib.decompress(compressed)
    except zlib.error as e:
        raise LowlevelError(f"Failed to decompress .sla file: {e}")

    decoder = PackedDecode(spc_manager)
    decoder.ingestBytes(decompressed)
    return decoder
