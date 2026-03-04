"""
Corresponds to: address.hh / address.cc

Classes for specifying addresses and other low-level constants.
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Optional, Set

from ghidra.core.error import LowlevelError
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, SpaceType,
    IPTR_CONSTANT, IPTR_JOIN,
)
from ghidra.core.marshal import (
    Encoder, Decoder, AttributeId, ElementId,
    ATTRIB_SPACE, ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_FIRST, ATTRIB_LAST,
    ATTRIB_UNIQ, ATTRIB_NAME,
    ELEM_ADDR, ELEM_RANGE, ELEM_RANGELIST, ELEM_REGISTER, ELEM_SEQNUM, ELEM_VARNODE,
)

if TYPE_CHECKING:
    pass


# =========================================================================
# Precalculated masks indexed by size (0..8)
# =========================================================================

uintbmasks: list[int] = [
    0x0,
    0xFF,
    0xFFFF,
    0xFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFF,
    0xFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]


def calc_mask(size: int) -> int:
    """Return a value appropriate for masking off the first *size* bytes."""
    if size >= 8:
        return uintbmasks[8]
    return uintbmasks[size]


def pcode_right(val: int, sa: int) -> int:
    """Perform a CPUI_INT_RIGHT on the given val."""
    if sa >= 64:
        return 0
    return (val & 0xFFFFFFFFFFFFFFFF) >> sa


def pcode_left(val: int, sa: int) -> int:
    """Perform a CPUI_INT_LEFT on the given val."""
    if sa >= 64:
        return 0
    return (val << sa) & 0xFFFFFFFFFFFFFFFF


def minimalmask(val: int) -> int:
    """Calculate smallest mask that covers the given value."""
    if val > 0xFFFFFFFF:
        return 0xFFFFFFFFFFFFFFFF
    if val > 0xFFFF:
        return 0xFFFFFFFF
    if val > 0xFF:
        return 0xFFFF
    return 0xFF


def sign_extend(val: int, bit: int) -> int:
    """Sign extend *val* starting at *bit* (0=least significant)."""
    sa = 64 - (bit + 1)
    # Simulate C++ arithmetic shift on 64-bit
    val = (val << sa) & 0xFFFFFFFFFFFFFFFF
    # Arithmetic right shift
    if val >= (1 << 63):
        val -= (1 << 64)
    val = val >> sa
    return val


def zero_extend(val: int, bit: int) -> int:
    """Clear all bits above given *bit*."""
    sa = 64 - (bit + 1)
    return ((val << sa) & 0xFFFFFFFFFFFFFFFF) >> sa


def signbit_negative(val: int, size: int) -> bool:
    """Return True if the sign-bit is set for a value of *size* bytes."""
    bit = (size * 8) - 1
    return (val >> bit) & 1 != 0


def uintb_negate(val: int, size: int) -> int:
    """Negate the *sized* value (two's complement)."""
    mask = calc_mask(size)
    return ((~val) + 1) & mask


def sign_extend_sized(val: int, sizein: int, sizeout: int) -> int:
    """Sign-extend a value between two byte sizes."""
    mask_in = calc_mask(sizein)
    val &= mask_in
    if signbit_negative(val, sizein):
        mask_out = calc_mask(sizeout)
        val |= (mask_out ^ mask_in)
    return val


def byte_swap(val: int, size: int) -> int:
    """Return the given value with bytes swapped."""
    result = 0
    for i in range(size):
        result = (result << 8) | (val & 0xFF)
        val >>= 8
    return result


def leastsigbit_set(val: int) -> int:
    """Return index of least significant bit set in given value. -1 if none."""
    if val == 0:
        return -1
    idx = 0
    while (val & 1) == 0:
        val >>= 1
        idx += 1
    return idx


def mostsigbit_set(val: int) -> int:
    """Return index of most significant bit set in given value. -1 if none."""
    if val == 0:
        return -1
    idx = 0
    while val > 1:
        val >>= 1
        idx += 1
    return idx


def popcount(val: int) -> int:
    """Return the number of one bits in the given value."""
    return bin(val).count('1')


def count_leading_zeros(val: int) -> int:
    """Return the number of leading zero bits in a 64-bit value."""
    if val == 0:
        return 64
    n = 0
    if val <= 0x00000000FFFFFFFF:
        n += 32; val <<= 32
    if val <= 0x0000FFFFFFFFFFFF:
        n += 16; val <<= 16
    if val <= 0x00FFFFFFFFFFFFFF:
        n += 8; val <<= 8
    if val <= 0x0FFFFFFFFFFFFFFF:
        n += 4; val <<= 4
    if val <= 0x3FFFFFFFFFFFFFFF:
        n += 2; val <<= 2
    if val <= 0x7FFFFFFFFFFFFFFF:
        n += 1
    return n


def coveringmask(val: int) -> int:
    """Return a mask that covers the given value."""
    idx = mostsigbit_set(val)
    if idx < 0:
        return 0
    return (1 << (idx + 1)) - 1


def bit_transitions(val: int, sz: int) -> int:
    """Calculate the number of bit transitions in the sized value."""
    mask = calc_mask(sz)
    val &= mask
    count = 0
    prev_bit = val & 1
    for i in range(1, sz * 8):
        cur_bit = (val >> i) & 1
        if cur_bit != prev_bit:
            count += 1
        prev_bit = cur_bit
    return count


# =========================================================================
# Address
# =========================================================================

# Sentinel values for extremal addresses
_ADDR_MIN_SENTINEL = object()
_ADDR_MAX_SENTINEL = object()


class Address:
    """A low-level machine address for labelling bytes and data.

    Simply an address space (AddrSpace) and an offset within that space.
    """

    class MachExtreme(IntEnum):
        m_minimal = 0
        m_maximal = 1

    m_minimal = MachExtreme.m_minimal
    m_maximal = MachExtreme.m_maximal

    __slots__ = ('base', 'offset')

    def __init__(self, base: Optional[AddrSpace] = None, offset: int = 0) -> None:
        self.base: Optional[AddrSpace] = base
        self.offset: int = offset

    @classmethod
    def from_extreme(cls, ex: MachExtreme) -> Address:
        """Create an extremal address (minimal or maximal)."""
        addr = cls.__new__(cls)
        if ex == cls.m_minimal:
            addr.base = None
            addr.offset = 0
        else:
            addr.base = _ADDR_MAX_SENTINEL  # type: ignore[assignment]
            addr.offset = 0xFFFFFFFFFFFFFFFF
        return addr

    def isInvalid(self) -> bool:
        return self.base is None

    def getAddrSize(self) -> int:
        assert self.base is not None and self.base is not _ADDR_MAX_SENTINEL
        return self.base.getAddrSize()

    def isBigEndian(self) -> bool:
        assert self.base is not None and self.base is not _ADDR_MAX_SENTINEL
        return self.base.isBigEndian()

    def printRaw(self) -> str:
        if self.base is None:
            return "invalid_addr"
        if self.base is _ADDR_MAX_SENTINEL:
            return "max_addr"
        return self.base.printRaw(self.offset)

    def read(self, s: str) -> int:
        assert self.base is not None
        off, sz = self.base.read(s)
        self.offset = off
        return sz

    def getSpace(self) -> Optional[AddrSpace]:
        return self.base

    def getOffset(self) -> int:
        return self.offset

    def getShortcut(self) -> str:
        assert self.base is not None
        return self.base.getShortcut()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Address):
            return NotImplemented
        return self.base is other.base and self.offset == other.offset

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, Address):
            return NotImplemented
        return not self.__eq__(other)

    def __lt__(self, other: Address) -> bool:
        if self.base is not other.base:
            if self.base is None:
                return True
            if self.base is _ADDR_MAX_SENTINEL:
                return False
            if other.base is None:
                return False
            if other.base is _ADDR_MAX_SENTINEL:
                return True
            return self.base.getIndex() < other.base.getIndex()
        return self.offset < other.offset

    def __le__(self, other: Address) -> bool:
        if self.base is not other.base:
            if self.base is None:
                return True
            if self.base is _ADDR_MAX_SENTINEL:
                return False
            if other.base is None:
                return False
            if other.base is _ADDR_MAX_SENTINEL:
                return True
            return self.base.getIndex() < other.base.getIndex()
        return self.offset <= other.offset

    def __add__(self, off: int) -> Address:
        return Address(self.base, self.base.wrapOffset(self.offset + off))

    def __sub__(self, off: int) -> Address:
        return Address(self.base, self.base.wrapOffset(self.offset - off))

    def __hash__(self) -> int:
        base_id = id(self.base) if self.base is not None else 0
        return hash((base_id, self.offset))

    def __repr__(self) -> str:
        return f"Address({self.printRaw()})"

    def __str__(self) -> str:
        return self.printRaw()

    def containedBy(self, sz: int, op2: Address, sz2: int) -> bool:
        """Return True if the range (op2, sz2) contains (self, sz)."""
        if self.base is not op2.base:
            return False
        if op2.offset > self.offset:
            return False
        off1 = self.offset + (sz - 1)
        off2 = op2.offset + (sz2 - 1)
        return off2 >= off1

    def justifiedContain(self, sz: int, op2: Address, sz2: int, forceleft: bool = False) -> int:
        """Determine if op2 is the least significant part of self.
        Returns endian-aware offset, or -1.
        """
        if self.base is not op2.base:
            return -1
        if op2.offset < self.offset:
            return -1
        off1 = self.offset + (sz - 1)
        off2 = op2.offset + (sz2 - 1)
        if off2 > off1:
            return -1
        if self.base.isBigEndian() and not forceleft:
            return off1 - off2
        return op2.offset - self.offset

    def overlap(self, skip: int, op: Address, size: int) -> int:
        """Determine how self+skip falls in range [op, op+size).
        Returns offset into range, or -1.
        """
        if self.base is not op.base:
            return -1
        if self.base.getType() == IPTR_CONSTANT:
            return -1
        dist = self.base.wrapOffset(self.offset + skip - op.offset)
        if dist >= size:
            return -1
        return dist

    def overlapJoin(self, skip: int, op: Address, size: int) -> int:
        return op.getSpace().overlapJoin(op.getOffset(), size, self.base, self.offset, skip)

    def isContiguous(self, sz: int, loaddr: Address, losz: int) -> bool:
        """Does (self, sz) form a contiguous range with (loaddr, losz)?"""
        if self.base is not loaddr.base:
            return False
        if self.base.isBigEndian():
            nextoff = self.base.wrapOffset(self.offset + sz)
            return nextoff == loaddr.offset
        else:
            nextoff = self.base.wrapOffset(loaddr.offset + losz)
            return nextoff == self.offset

    def isConstant(self) -> bool:
        return self.base is not None and self.base.getType() == IPTR_CONSTANT

    def isJoin(self) -> bool:
        return self.base is not None and self.base.getType() == IPTR_JOIN

    def renormalize(self, size: int) -> None:
        if self.base is not None and self.base.getType() == IPTR_JOIN:
            mgr = self.base.getManager()
            if mgr is not None:
                mgr.renormalizeJoinAddress(self, size)

    def encode(self, encoder: Encoder, size: int = -1) -> None:
        encoder.openElement(ELEM_ADDR)
        if self.base is not None:
            if size >= 0:
                self.base.encodeAttributes(encoder, self.offset, size)
            else:
                self.base.encodeAttributes(encoder, self.offset)
        encoder.closeElement(ELEM_ADDR)

    @staticmethod
    def decode(decoder: Decoder, with_size: bool = False):
        """Decode an address (and optionally size) from a stream.

        If *with_size* is True, returns (Address, size).
        Otherwise returns just Address.
        """
        elem_id = decoder.openElement(ELEM_ADDR)
        spc = None
        offset = 0
        size = 0
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_SPACE.id:
                spc = decoder.readSpace()
            elif attrib_id == ATTRIB_OFFSET.id:
                offset = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_SIZE.id:
                size = decoder.readSignedInteger()
        decoder.closeElement(elem_id)
        addr = Address(spc, offset) if spc is not None else Address()
        if with_size:
            return addr, size
        return addr


# =========================================================================
# SeqNum
# =========================================================================

class SeqNum:
    """A class for uniquely labelling and comparing PcodeOps.

    Extends the address with a time (unique) field and an order field.
    """

    __slots__ = ('pc', 'uniq', 'order')

    def __init__(self, pc: Optional[Address] = None, uniq: int = 0) -> None:
        self.pc: Address = pc if pc is not None else Address()
        self.uniq: int = uniq
        self.order: int = 0

    @classmethod
    def from_extreme(cls, ex: Address.MachExtreme) -> SeqNum:
        sq = cls.__new__(cls)
        sq.pc = Address.from_extreme(ex)
        sq.uniq = 0 if ex == Address.m_minimal else 0xFFFFFFFF
        sq.order = 0
        return sq

    def getAddr(self) -> Address:
        return self.pc

    def getTime(self) -> int:
        return self.uniq

    def getOrder(self) -> int:
        return self.order

    def setOrder(self, ord_: int) -> None:
        self.order = ord_

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SeqNum):
            return NotImplemented
        return self.uniq == other.uniq

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, SeqNum):
            return NotImplemented
        return self.uniq != other.uniq

    def __lt__(self, other: SeqNum) -> bool:
        if self.pc == other.pc:
            return self.uniq < other.uniq
        return self.pc < other.pc

    def __hash__(self) -> int:
        return hash(self.uniq)

    def __repr__(self) -> str:
        return f"{self.pc}:{self.uniq}"

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_SEQNUM)
        self.pc.getSpace().encodeAttributes(encoder, self.pc.getOffset())
        encoder.writeUnsignedInteger(ATTRIB_UNIQ, self.uniq)
        encoder.closeElement(ELEM_SEQNUM)

    @staticmethod
    def decode(decoder: Decoder) -> SeqNum:
        uniq = 0xFFFFFFFF
        elem_id = decoder.openElement(ELEM_SEQNUM)
        pc = Address.decode(decoder)
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_UNIQ.id:
                uniq = decoder.readUnsignedInteger()
                break
        decoder.closeElement(elem_id)
        return SeqNum(pc, uniq)


# =========================================================================
# RangeProperties
# =========================================================================

class RangeProperties:
    """A partially parsed description of a Range."""

    def __init__(self) -> None:
        self.spaceName: str = ""
        self.first: int = 0
        self.last: int = 0
        self.isRegister: bool = False
        self.seenLast: bool = False

    def decode(self, decoder: Decoder) -> None:
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_SPACE.id:
                self.spaceName = decoder.readString()
            elif attrib_id == ATTRIB_FIRST.id:
                self.first = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_LAST.id:
                self.last = decoder.readUnsignedInteger()
                self.seenLast = True
            elif attrib_id == ATTRIB_NAME.id:
                self.spaceName = decoder.readString()
                self.isRegister = True


# =========================================================================
# Range
# =========================================================================

class Range:
    """A contiguous range of bytes in some address space."""

    __slots__ = ('spc', 'first', 'last')

    def __init__(self, spc: Optional[AddrSpace] = None, first: int = 0, last: int = 0) -> None:
        self.spc: Optional[AddrSpace] = spc
        self.first: int = first
        self.last: int = last

    @classmethod
    def from_properties(cls, props: RangeProperties, manage: AddrSpaceManager) -> Range:
        spc = manage.getSpaceByName(props.spaceName)
        r = cls(spc, props.first, props.last)
        if not props.seenLast:
            r.last = spc.getHighest()
        return r

    def getSpace(self) -> Optional[AddrSpace]:
        return self.spc

    def getFirst(self) -> int:
        return self.first

    def getLast(self) -> int:
        return self.last

    def getFirstAddr(self) -> Address:
        return Address(self.spc, self.first)

    def getLastAddr(self) -> Address:
        return Address(self.spc, self.last)

    def contains(self, addr: Address) -> bool:
        if self.spc is not addr.getSpace():
            return False
        if self.first > addr.getOffset():
            return False
        if self.last < addr.getOffset():
            return False
        return True

    def __lt__(self, other: Range) -> bool:
        if self.spc.getIndex() != other.spc.getIndex():
            return self.spc.getIndex() < other.spc.getIndex()
        return self.first < other.first

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Range):
            return NotImplemented
        return (self.spc is other.spc and self.first == other.first
                and self.last == other.last)

    def __hash__(self) -> int:
        return hash((id(self.spc), self.first, self.last))

    def printBounds(self) -> str:
        sname = self.spc.getName() if self.spc else "?"
        return f"[{sname}:{self.first:#x},{self.last:#x}]"

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_RANGE)
        encoder.writeString(ATTRIB_SPACE, self.spc.getName())
        encoder.writeUnsignedInteger(ATTRIB_FIRST, self.first)
        encoder.writeUnsignedInteger(ATTRIB_LAST, self.last)
        encoder.closeElement(ELEM_RANGE)

    def decode(self, decoder: Decoder) -> None:
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_SPACE.id:
                self.spc = decoder.readSpace()
            elif attrib_id == ATTRIB_FIRST.id:
                self.first = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_LAST.id:
                self.last = decoder.readUnsignedInteger()


# =========================================================================
# RangeList
# =========================================================================

class RangeList:
    """A disjoint set of Ranges, possibly across multiple address spaces."""

    def __init__(self, other: Optional[RangeList] = None) -> None:
        if other is not None:
            self._ranges: list[Range] = list(other._ranges)
        else:
            self._ranges: list[Range] = []

    def clear(self) -> None:
        self._ranges.clear()

    def empty(self) -> bool:
        return len(self._ranges) == 0

    def numRanges(self) -> int:
        return len(self._ranges)

    def __iter__(self):
        return iter(self._ranges)

    def getFirstRange(self) -> Optional[Range]:
        return self._ranges[0] if self._ranges else None

    def getLastRange(self) -> Optional[Range]:
        return self._ranges[-1] if self._ranges else None

    def getRange(self, spaceid: AddrSpace, offset: int) -> Optional[Range]:
        for r in self._ranges:
            if r.spc is spaceid and r.first <= offset <= r.last:
                return r
        return None

    def insertRange(self, spc: AddrSpace, first: int, last: int) -> None:
        """Insert a range of addresses, merging overlaps."""
        new_range = Range(spc, first, last)
        merged = []
        inserted = False
        for r in self._ranges:
            if r.spc is not spc:
                merged.append(r)
                continue
            # Check overlap or adjacency
            if r.last + 1 < new_range.first or new_range.last + 1 < r.first:
                merged.append(r)
            else:
                new_range = Range(spc, min(r.first, new_range.first),
                                  max(r.last, new_range.last))
        merged.append(new_range)
        merged.sort()
        self._ranges = merged

    def removeRange(self, spc: AddrSpace, first: int, last: int) -> None:
        """Remove a range of addresses."""
        result = []
        for r in self._ranges:
            if r.spc is not spc:
                result.append(r)
                continue
            if r.last < first or r.first > last:
                result.append(r)
                continue
            if r.first < first:
                result.append(Range(spc, r.first, first - 1))
            if r.last > last:
                result.append(Range(spc, last + 1, r.last))
        result.sort()
        self._ranges = result

    def merge(self, op2: RangeList) -> None:
        for r in op2._ranges:
            self.insertRange(r.spc, r.first, r.last)

    def inRange(self, addr: Address, size: int) -> bool:
        """Check if [addr, addr+size) is contained in some range."""
        for r in self._ranges:
            if r.spc is addr.getSpace():
                if r.first <= addr.getOffset() and (addr.getOffset() + size - 1) <= r.last:
                    return True
        return False

    def longestFit(self, addr: Address, maxsize: int) -> int:
        for r in self._ranges:
            if r.spc is addr.getSpace() and r.first <= addr.getOffset() <= r.last:
                avail = r.last - addr.getOffset() + 1
                return min(avail, maxsize)
        return 0

    def printBounds(self) -> str:
        return " ".join(r.printBounds() for r in self._ranges)

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_RANGELIST)
        for r in self._ranges:
            r.encode(encoder)
        encoder.closeElement(ELEM_RANGELIST)

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_RANGELIST)
        while decoder.peekElement() != 0:
            r = Range()
            sub_id = decoder.openElement(ELEM_RANGE)
            r.decode(decoder)
            decoder.closeElement(sub_id)
            self.insertRange(r.spc, r.first, r.last)
        decoder.closeElement(elem_id)
