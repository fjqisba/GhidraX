"""
Corresponds to: pcoderaw.hh / pcoderaw.cc

Raw descriptions of varnodes and p-code ops.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List

from ghidra.core.opcodes import OpCode
from ghidra.core.address import Address
from ghidra.core.marshal import Decoder, ATTRIB_SPACE, ATTRIB_OFFSET, ATTRIB_SIZE

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace
    from ghidra.core.opbehavior import OpBehavior


class VarnodeData:
    """Data defining a specific memory location.

    Within the decompiler's model of a processor, any register,
    memory location, or other variable can always be represented
    as an address space, an offset within the space, and the
    size of the sequence of bytes.
    """

    __slots__ = ('space', 'offset', 'size')

    def __init__(self, space: Optional[AddrSpace] = None, offset: int = 0, size: int = 0) -> None:
        self.space: Optional[AddrSpace] = space
        self.offset: int = offset
        self.size: int = size

    def __lt__(self, op2: VarnodeData) -> bool:
        if self.space is not op2.space:
            s_idx = self.space.getIndex() if self.space else -1
            o_idx = op2.space.getIndex() if op2.space else -1
            return s_idx < o_idx
        if self.offset != op2.offset:
            return self.offset < op2.offset
        return self.size > op2.size  # BIG sizes come first

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VarnodeData):
            return NotImplemented
        return (self.space is other.space and
                self.offset == other.offset and
                self.size == other.size)

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, VarnodeData):
            return NotImplemented
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((id(self.space), self.offset, self.size))

    def getAddr(self) -> Address:
        """Get the location of the varnode as an address."""
        return Address(self.space, self.offset)

    def getSpaceFromConst(self) -> Optional[AddrSpace]:
        """Treat this as a constant and recover encoded address space."""
        # In C++ this casts offset to a pointer. In Python, we need
        # to look up via the manager. This is a placeholder.
        return None

    def contains(self, op2: VarnodeData) -> bool:
        """Does this container another given VarnodeData?"""
        if self.space is not op2.space:
            return False
        if op2.offset < self.offset:
            return False
        if (op2.offset + op2.size - 1) > (self.offset + self.size - 1):
            return False
        return True

    def isContiguous(self, lo: VarnodeData) -> bool:
        """Is this contiguous (as the most significant piece) with lo?"""
        if self.space is not lo.space:
            return False
        if self.space.isBigEndian():
            return (self.offset + self.size) == lo.offset
        else:
            return (lo.offset + lo.size) == self.offset

    def decode(self, decoder: Decoder) -> None:
        """Recover this object from a stream."""
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_SPACE.id:
                self.space = decoder.readSpace()
            elif attrib_id == ATTRIB_OFFSET.id:
                self.offset = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_SIZE.id:
                self.size = decoder.readSignedInteger()

    def decodeFromAttributes(self, decoder: Decoder) -> None:
        """Recover this object from attributes of the current open element."""
        self.decode(decoder)

    def __repr__(self) -> str:
        sname = self.space.getName() if self.space else "?"
        return f"VarnodeData({sname}:{self.offset:#x}, size={self.size})"


class PcodeOpRaw:
    """A low-level representation of a single pcode operation.

    Just the minimum amount of data to represent a pcode operation:
    an opcode, sequence number, optional output varnode, and input varnodes.
    """

    def __init__(self) -> None:
        self._behave: Optional[OpBehavior] = None
        from ghidra.core.address import SeqNum
        self._seq: SeqNum = SeqNum()
        self._out: Optional[VarnodeData] = None
        self._in: List[VarnodeData] = []

    def setBehavior(self, be: OpBehavior) -> None:
        self._behave = be

    def getBehavior(self) -> Optional[OpBehavior]:
        return self._behave

    def getOpcode(self) -> OpCode:
        assert self._behave is not None
        return self._behave.getOpcode()

    def setSeqNum(self, a: Address, b: int) -> None:
        from ghidra.core.address import SeqNum
        self._seq = SeqNum(a, b)

    def getSeqNum(self):
        return self._seq

    def getAddr(self) -> Address:
        return self._seq.getAddr()

    def setOutput(self, o: Optional[VarnodeData]) -> None:
        self._out = o

    def getOutput(self) -> Optional[VarnodeData]:
        return self._out

    def addInput(self, i: VarnodeData) -> None:
        self._in.append(i)

    def clearInputs(self) -> None:
        self._in.clear()

    def numInput(self) -> int:
        return len(self._in)

    def getInput(self, i: int) -> VarnodeData:
        return self._in[i]

    @staticmethod
    def decode(decoder: Decoder, invar: List[VarnodeData],
               outvar: List[Optional[VarnodeData]]) -> OpCode:
        """Decode the raw OpCode and input/output Varnode data for a PcodeOp.

        This is a simplified version of the static decode method.
        """
        # Placeholder for full implementation
        return OpCode.CPUI_BLANK
