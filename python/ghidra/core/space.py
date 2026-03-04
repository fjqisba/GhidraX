"""
Corresponds to: space.hh / space.cc

Classes for describing address spaces.
"""

from __future__ import annotations

from enum import IntEnum, IntFlag
from typing import TYPE_CHECKING, Optional, List

from ghidra.core.error import LowlevelError
from ghidra.core.marshal import (
    AttributeId, ElementId, Encoder, Decoder,
    ATTRIB_NAME, ATTRIB_INDEX, ATTRIB_SIZE, ATTRIB_WORDSIZE,
    ATTRIB_BIGENDIAN, ATTRIB_DELAY, ATTRIB_PHYSICAL,
    ATTRIB_BASE, ATTRIB_DEADCODEDELAY, ATTRIB_LOGICALSIZE,
    ATTRIB_PIECE, ATTRIB_SPACE, ATTRIB_OFFSET,
    ELEM_SPACE, ELEM_SPACE_BASE, ELEM_SPACE_UNIQUE, ELEM_SPACE_OTHER,
    ELEM_SPACE_OVERLAY, ELEM_SPACES,
)

if TYPE_CHECKING:
    from ghidra.core.translate import Translate


# =========================================================================
# spacetype enum
# =========================================================================

class SpaceType(IntEnum):
    """Fundamental address space types."""
    IPTR_CONSTANT = 0
    IPTR_PROCESSOR = 1
    IPTR_SPACEBASE = 2
    IPTR_INTERNAL = 3
    IPTR_FSPEC = 4
    IPTR_IOP = 5
    IPTR_JOIN = 6


# Re-export for C++-style access
IPTR_CONSTANT = SpaceType.IPTR_CONSTANT
IPTR_PROCESSOR = SpaceType.IPTR_PROCESSOR
IPTR_SPACEBASE = SpaceType.IPTR_SPACEBASE
IPTR_INTERNAL = SpaceType.IPTR_INTERNAL
IPTR_FSPEC = SpaceType.IPTR_FSPEC
IPTR_IOP = SpaceType.IPTR_IOP
IPTR_JOIN = SpaceType.IPTR_JOIN


# =========================================================================
# AddrSpace
# =========================================================================

class AddrSpace:
    """A region where processor data is stored.

    An AddrSpace (Address Space) is an arbitrary sequence of bytes where
    a processor can store data. An integer offset paired with an AddrSpace
    forms the address of a byte.
    """

    # Space attribute flags
    big_endian = 1
    heritaged = 2
    does_deadcode = 4
    programspecific = 8
    reverse_justification = 16
    formal_stackspace = 0x20
    overlay = 0x40
    overlaybase = 0x80
    truncated = 0x100
    hasphysical = 0x200
    is_otherspace = 0x400
    has_nearpointers = 0x800

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 tp: SpaceType = IPTR_PROCESSOR,
                 name: str = "",
                 big_end: bool = False,
                 size: int = 0,
                 word_size: int = 1,
                 ind: int = 0,
                 fl: int = 0,
                 dl: int = 0,
                 dead: int = 0) -> None:
        self._type: SpaceType = tp
        self._manage: Optional[AddrSpaceManager] = manager
        self._trans: Optional[Translate] = trans
        self._refcount: int = 0
        self._flags: int = fl
        self._name: str = name
        self._addressSize: int = size
        self._wordsize: int = word_size
        self._minimumPointerSize: int = 0
        self._index: int = ind
        self._delay: int = dl
        self._deadcodedelay: int = dead
        self._shortcut: str = ' '
        self._highest: int = 0
        self._pointerLowerBound: int = 0
        self._pointerUpperBound: int = 0

        if big_end:
            self._flags |= AddrSpace.big_endian

        if size > 0:
            self.calcScaleMask()

    def calcScaleMask(self) -> None:
        """Calculate scale and mask based on addressSize and wordsize."""
        if self._addressSize >= 8:
            self._highest = 0xFFFFFFFFFFFFFFFF
        else:
            self._highest = (1 << (self._addressSize * 8)) - 1
        self._pointerLowerBound = 0x100
        self._pointerUpperBound = self._highest

    # --- Attribute accessors ---

    def getName(self) -> str:
        return self._name

    def getManager(self) -> Optional[AddrSpaceManager]:
        return self._manage

    def getTrans(self) -> Optional[Translate]:
        return self._trans

    def getType(self) -> SpaceType:
        return self._type

    def getDelay(self) -> int:
        return self._delay

    def getDeadcodeDelay(self) -> int:
        return self._deadcodedelay

    def getIndex(self) -> int:
        return self._index

    def getWordSize(self) -> int:
        return self._wordsize

    def getAddrSize(self) -> int:
        return self._addressSize

    def getHighest(self) -> int:
        return self._highest

    def getPointerLowerBound(self) -> int:
        return self._pointerLowerBound

    def getPointerUpperBound(self) -> int:
        return self._pointerUpperBound

    def getMinimumPtrSize(self) -> int:
        return self._minimumPointerSize

    def wrapOffset(self, off: int) -> int:
        """Wrap *off* to the offset that fits into this space."""
        if 0 <= off <= self._highest:
            return off
        mod = self._highest + 1
        if mod == 0:
            return off  # Full 64-bit space
        res = off % mod
        if res < 0:
            res += mod
        return res

    def getShortcut(self) -> str:
        return self._shortcut

    def isHeritaged(self) -> bool:
        return (self._flags & AddrSpace.heritaged) != 0

    def doesDeadcode(self) -> bool:
        return (self._flags & AddrSpace.does_deadcode) != 0

    def hasPhysical(self) -> bool:
        return (self._flags & AddrSpace.hasphysical) != 0

    def isBigEndian(self) -> bool:
        return (self._flags & AddrSpace.big_endian) != 0

    def isReverseJustified(self) -> bool:
        return (self._flags & AddrSpace.reverse_justification) != 0

    def isFormalStackSpace(self) -> bool:
        return (self._flags & AddrSpace.formal_stackspace) != 0

    def isOverlay(self) -> bool:
        return (self._flags & AddrSpace.overlay) != 0

    def isOverlayBase(self) -> bool:
        return (self._flags & AddrSpace.overlaybase) != 0

    def isOtherSpace(self) -> bool:
        return (self._flags & AddrSpace.is_otherspace) != 0

    def isTruncated(self) -> bool:
        return (self._flags & AddrSpace.truncated) != 0

    def hasNearPointers(self) -> bool:
        return (self._flags & AddrSpace.has_nearpointers) != 0

    def setFlags(self, fl: int) -> None:
        self._flags |= fl

    def clearFlags(self, fl: int) -> None:
        self._flags &= ~fl

    def truncateSpace(self, newsize: int) -> None:
        self._flags |= AddrSpace.truncated
        self._addressSize = newsize
        self._minimumPointerSize = newsize
        self.calcScaleMask()

    # --- Virtual methods ---

    def numSpacebase(self) -> int:
        return 0

    def getSpacebase(self, i: int):
        raise LowlevelError(f"{self._name} space is not virtual and has no associated base register")

    def getSpacebaseFull(self, i: int):
        raise LowlevelError(f"{self._name} has no truncated registers")

    def stackGrowsNegative(self) -> bool:
        return True

    def getContain(self) -> Optional[AddrSpace]:
        return None

    def overlapJoin(self, offset: int, size: int,
                    point_space: Optional[AddrSpace], point_off: int, point_skip: int) -> int:
        if point_space != self:
            return -1
        dist = self.wrapOffset(point_off + point_skip - offset)
        if dist >= size:
            return -1
        return dist

    def encodeAttributes(self, encoder: Encoder, offset: int, size: int = -1) -> None:
        """Encode address attributes to a stream."""
        encoder.writeString(ATTRIB_SPACE, self._name)
        encoder.writeUnsignedInteger(ATTRIB_OFFSET, offset)
        if size >= 0:
            encoder.writeSignedInteger(ATTRIB_SIZE, size)

    def decodeAttributes(self, decoder: Decoder) -> tuple[int, int]:
        """Recover an offset and size. Returns (offset, size)."""
        offset = 0
        size = 0
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_OFFSET.id:
                offset = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_SIZE.id:
                size = decoder.readUnsignedInteger()
        return offset, size

    def printRaw(self, offset: int) -> str:
        """Return a raw version of the address as a string."""
        return f"{self._shortcut}{offset:#x}"

    def printOffset(self, offset: int) -> str:
        """Write an address offset as a string."""
        return f"0x{offset:0{self._addressSize * 2}x}"

    def read(self, s: str) -> tuple[int, int]:
        """Read in an address (and possible size) from a string. Returns (offset, size)."""
        return int(s, 0), 0

    def decode(self, decoder: Decoder) -> None:
        """Recover the details of this space from a stream."""
        pass

    def decodeBasicAttributes(self, decoder: Decoder) -> None:
        """Read attributes for this space from an open XML element."""
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_NAME.id:
                self._name = decoder.readString()
            elif attrib_id == ATTRIB_INDEX.id:
                self._index = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_SIZE.id:
                self._addressSize = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_WORDSIZE.id:
                self._wordsize = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_BIGENDIAN.id:
                if decoder.readBool():
                    self._flags |= AddrSpace.big_endian
            elif attrib_id == ATTRIB_DELAY.id:
                self._delay = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_DEADCODEDELAY.id:
                self._deadcodedelay = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_PHYSICAL.id:
                if decoder.readBool():
                    self._flags |= AddrSpace.hasphysical

    # --- Static methods ---

    @staticmethod
    def addressToByte(val: int, ws: int) -> int:
        return val * ws

    @staticmethod
    def byteToAddress(val: int, ws: int) -> int:
        return val // ws

    @staticmethod
    def addressToByteInt(val: int, ws: int) -> int:
        return val * ws

    @staticmethod
    def byteToAddressInt(val: int, ws: int) -> int:
        return val // ws

    @staticmethod
    def compareByIndex(a: AddrSpace, b: AddrSpace) -> bool:
        return a._index < b._index

    def __repr__(self) -> str:
        return f"AddrSpace({self._name!r}, index={self._index}, type={self._type.name})"


# =========================================================================
# ConstantSpace
# =========================================================================

class ConstantSpace(AddrSpace):
    """Special AddrSpace for representing constants during analysis."""

    NAME: str = "const"
    INDEX: int = 0

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None) -> None:
        super().__init__(manager, trans, IPTR_CONSTANT, ConstantSpace.NAME,
                         False, 8, 1, ConstantSpace.INDEX, 0, 0, 0)
        self._shortcut = '#'

    def overlapJoin(self, offset, size, point_space, point_off, point_skip):
        return -1

    def printRaw(self, offset: int) -> str:
        return f"#{offset:#x}"

    def decode(self, decoder: Decoder) -> None:
        pass


# =========================================================================
# OtherSpace
# =========================================================================

class OtherSpace(AddrSpace):
    """Special AddrSpace for special/user-defined address spaces."""

    NAME: str = "OTHER"
    INDEX: int = 1

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int = -1) -> None:
        idx = ind if ind >= 0 else OtherSpace.INDEX
        super().__init__(manager, trans, IPTR_PROCESSOR, OtherSpace.NAME,
                         False, 8, 1, idx,
                         AddrSpace.hasphysical | AddrSpace.does_deadcode | AddrSpace.is_otherspace,
                         0, 0)
        self._shortcut = 'o'

    def printRaw(self, offset: int) -> str:
        return f"o{offset:#x}"


# =========================================================================
# UniqueSpace
# =========================================================================

class UniqueSpace(AddrSpace):
    """The pool of temporary storage registers."""

    NAME: str = "unique"
    SIZE: int = 4

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int = 0,
                 fl: int = 0) -> None:
        super().__init__(manager, trans, IPTR_INTERNAL, UniqueSpace.NAME,
                         False, UniqueSpace.SIZE, 1, ind,
                         AddrSpace.hasphysical | AddrSpace.heritaged | fl,
                         0, 0)
        self._shortcut = 'u'


# =========================================================================
# JoinSpace
# =========================================================================

class JoinSpace(AddrSpace):
    """The pool of logically joined variables."""

    NAME: str = "join"
    MAX_PIECES: int = 64

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int = 0) -> None:
        super().__init__(manager, trans, IPTR_JOIN, JoinSpace.NAME,
                         False, 8, 1, ind, 0, 0, 0)
        self._shortcut = 'j'

    def printRaw(self, offset: int) -> str:
        return f"j{offset:#x}"


# =========================================================================
# OverlaySpace
# =========================================================================

class OverlaySpace(AddrSpace):
    """An overlay space occupying the same memory as another address space."""

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None) -> None:
        super().__init__(manager, trans, IPTR_PROCESSOR)
        self._baseSpace: Optional[AddrSpace] = None

    def getContain(self) -> Optional[AddrSpace]:
        return self._baseSpace

    def decode(self, decoder: Decoder) -> None:
        self.decodeBasicAttributes(decoder)
        self._flags |= AddrSpace.overlay
        # Read base space name from sub-elements or attributes
        # (simplified – full decode would parse child elements)


# =========================================================================
# AddrSpaceManager
# =========================================================================

class AddrSpaceManager:
    """Container and manager for all address spaces.

    Corresponds to the AddrSpaceManager class from space.hh / translate.hh.
    """

    def __init__(self) -> None:
        self._spaces: List[AddrSpace] = []
        self._name2space: dict[str, AddrSpace] = {}
        self._defaultCodeSpace: Optional[AddrSpace] = None
        self._defaultDataSpace: Optional[AddrSpace] = None
        self._constantSpace: Optional[ConstantSpace] = None
        self._uniqueSpace: Optional[UniqueSpace] = None
        self._joinSpace: Optional[JoinSpace] = None
        self._iopSpace: Optional[AddrSpace] = None
        self._fspecSpace: Optional[AddrSpace] = None
        self._stackSpace: Optional[AddrSpace] = None

    # --- Space insertion / lookup ---

    def _insertSpace(self, spc: AddrSpace) -> None:
        """Register an address space with the manager."""
        while len(self._spaces) <= spc.getIndex():
            self._spaces.append(None)  # type: ignore[arg-type]
        self._spaces[spc.getIndex()] = spc
        self._name2space[spc.getName()] = spc

    def getSpaceByName(self, name: str) -> AddrSpace:
        """Get a space by its name. Raises LowlevelError if not found."""
        spc = self._name2space.get(name)
        if spc is None:
            raise LowlevelError(f"Unknown address space: {name}")
        return spc

    def getSpaceByIndex(self, index: int) -> Optional[AddrSpace]:
        """Get a space by its integer index."""
        if 0 <= index < len(self._spaces):
            return self._spaces[index]
        return None

    def getSpaceByShortcut(self, sc: str) -> Optional[AddrSpace]:
        """Get a space by its shortcut character."""
        for spc in self._spaces:
            if spc is not None and spc.getShortcut() == sc:
                return spc
        return None

    def numSpaces(self) -> int:
        return len(self._spaces)

    def getSpace(self, i: int) -> Optional[AddrSpace]:
        if 0 <= i < len(self._spaces):
            return self._spaces[i]
        return None

    def getConstantSpace(self) -> ConstantSpace:
        assert self._constantSpace is not None
        return self._constantSpace

    def getDefaultCodeSpace(self) -> AddrSpace:
        assert self._defaultCodeSpace is not None
        return self._defaultCodeSpace

    def getDefaultDataSpace(self) -> AddrSpace:
        assert self._defaultDataSpace is not None
        return self._defaultDataSpace

    def getUniqueSpace(self) -> UniqueSpace:
        assert self._uniqueSpace is not None
        return self._uniqueSpace

    def getJoinSpace(self) -> JoinSpace:
        assert self._joinSpace is not None
        return self._joinSpace

    def getStackSpace(self) -> Optional[AddrSpace]:
        return self._stackSpace

    def setDefaultCodeSpace(self, spc: AddrSpace) -> None:
        self._defaultCodeSpace = spc

    def setDefaultDataSpace(self, spc: AddrSpace) -> None:
        self._defaultDataSpace = spc

    def renormalizeJoinAddress(self, addr, size: int) -> None:
        """Re-evaluate a join address in terms of its new offset and size."""
        pass  # Placeholder – full implementation requires JoinRecord tracking

    def __repr__(self) -> str:
        names = [s.getName() for s in self._spaces if s is not None]
        return f"AddrSpaceManager(spaces={names})"
