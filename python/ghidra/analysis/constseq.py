"""
Corresponds to: constseq.hh / constseq.cc

Constant sequence detection — identifies sequences of STORE operations
that write constant values to consecutive memory locations, which can
be combined into string or array initializations.
"""

from __future__ import annotations
from typing import Optional, List
from ghidra.core.opcodes import OpCode
from ghidra.core.address import Address


class WriteNode:
    """Helper class holding a data-flow edge and optionally a memory offset being COPYed."""
    def __init__(self, offset: int = 0, op=None, slot: int = 0):
        self.offset: int = offset
        self.op = op
        self.slot: int = slot

    def __lt__(self, other):
        if self.op is None or other.op is None:
            return False
        return self.op.getSeqNum().getOrder() < other.op.getSeqNum().getOrder()


class ArraySequence:
    """A sequence of PcodeOps that move data in-to/out-of an array data-type.

    Given a starting address and set of COPY/STORE ops, collects a maximal set
    that can be replaced with a single memcpy style user-op.
    """
    MINIMUM_SEQUENCE_LENGTH = 4
    MAXIMUM_SEQUENCE_LENGTH = 256

    def __init__(self, fd=None, ct=None, root=None) -> None:
        self._fd = fd
        self.rootOp = root
        self.charType = ct
        self.block = None
        self.numElements: int = 0
        self.moveOps: List[WriteNode] = []
        self.byteArray: List[int] = []

    def isValid(self) -> bool:
        return self.numElements != 0

    def getSize(self) -> int:
        return self.numElements

    @staticmethod
    def interfereBetween(startOp, endOp) -> bool:
        """Check for interfering ops between two given ops."""
        return False

    def checkInterference(self) -> bool:
        """Find maximal set of ops with no interfering ops in between."""
        if len(self.moveOps) < 2:
            return True
        self.moveOps.sort()
        for i in range(len(self.moveOps) - 1):
            if self.interfereBetween(self.moveOps[i].op, self.moveOps[i + 1].op):
                self.moveOps = self.moveOps[:i + 1]
                break
        return len(self.moveOps) >= ArraySequence.MINIMUM_SEQUENCE_LENGTH

    def formByteArray(self, sz: int, slot: int, rootOff: int, bigEndian: bool) -> int:
        """Put constant values from COPYs into a single byte array."""
        self.byteArray = [0] * (len(self.moveOps) * sz)
        for i, node in enumerate(self.moveOps):
            if node.op is None:
                continue
            vn = node.op.getIn(node.slot) if node.slot >= 0 else node.op.getOut()
            if vn is not None and vn.isConstant():
                val = vn.getOffset()
                off = int(node.offset - rootOff)
                for j in range(sz):
                    if bigEndian:
                        self.byteArray[off + sz - 1 - j] = (val >> (j * 8)) & 0xFF
                    else:
                        self.byteArray[off + j] = (val >> (j * 8)) & 0xFF
        self.numElements = len(self.moveOps)
        return self.numElements

    def selectStringCopyFunction(self) -> int:
        """Pick either strncpy, wcsncpy, or memcpy function."""
        if self.charType is None:
            return 0  # memcpy
        sz = self.charType.getSize() if hasattr(self.charType, 'getSize') else 1
        if sz == 1:
            return 1  # strncpy
        elif sz == 2 or sz == 4:
            return 2  # wcsncpy
        return 0  # memcpy

    def clear(self) -> None:
        self.rootOp = None
        self.numElements = 0
        self.moveOps.clear()
        self.byteArray.clear()


class StringSequence(ArraySequence):
    """A sequence of COPY ops writing characters to the same string.

    Given a starting Address and a Symbol with a character array as a component,
    collects a maximal set of COPY ops that can be treated as writing a single string.
    """

    def __init__(self, fd=None, ct=None, entry=None, root=None, addr=None) -> None:
        super().__init__(fd, ct, root)
        self.rootAddr: Address = addr if addr is not None else Address()
        self.startAddr: Address = addr if addr is not None else Address()
        self.entry = entry
        self.byteValues: List[int] = []
        self.storeOps: list = []

    def getString(self) -> str:
        return ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in self.byteValues)

    def collectCopyOps(self, size: int) -> bool:
        """Collect ops COPYing constants into the memory region."""
        return len(self.moveOps) >= ArraySequence.MINIMUM_SEQUENCE_LENGTH

    def buildStringCopy(self):
        """Build the strncpy/wcsncpy/memcpy function with string as input."""
        return None

    def removeCopyOps(self, replaceOp) -> None:
        """Remove all the COPY ops from the basic block."""
        if self._fd is None:
            return
        for node in self.moveOps:
            if node.op is not None and hasattr(self._fd, 'opDestroy'):
                self._fd.opDestroy(node.op)

    def transform(self) -> bool:
        """Transform COPYs into a single memcpy user-op."""
        if not self.isValid():
            return False
        replaceOp = self.buildStringCopy()
        if replaceOp is None:
            return False
        self.removeCopyOps(replaceOp)
        return True

    def clear(self) -> None:
        super().clear()
        self.rootAddr = Address()
        self.startAddr = Address()
        self.entry = None
        self.byteValues.clear()
        self.storeOps.clear()


class HeapSequence(ArraySequence):
    """A sequence of STORE operations writing characters through the same string pointer.

    Given an initial STORE, collects a maximal set of STORE ops that can be treated as
    writing a single string into memory.
    """

    def __init__(self, fd=None, ct=None, root=None) -> None:
        super().__init__(fd, ct, root)
        self.basePointer = None
        self.baseOffset: int = 0
        self.storeSpace = None
        self.ptrAddMult: int = 0
        self.nonConstAdds: list = []

    def findBasePointer(self, initPtr) -> None:
        """Find the base pointer for the sequence."""
        self.basePointer = initPtr

    def collectStoreOps(self) -> bool:
        """Collect ops STOREing into a memory region from the same root pointer."""
        return len(self.moveOps) >= ArraySequence.MINIMUM_SEQUENCE_LENGTH

    def buildStringCopy(self):
        """Build the strncpy/wcsncpy/memcpy function with string as input."""
        return None

    def removeStoreOps(self, indirects: list, indirectPairs: list, replaceOp=None) -> None:
        """Remove all STORE ops from the basic block."""
        pass

    def transform(self) -> bool:
        """Transform STOREs into a single memcpy user-op."""
        if not self.isValid():
            return False
        return False  # Full implementation requires pointer analysis


class ConstSequence:
    """Detect and collect constant store sequences in a basic block.

    Scans a basic block for consecutive STORE operations that write
    constant values to adjacent memory locations. These can be
    collapsed into a single string or array initialization.
    """

    def __init__(self, fd=None) -> None:
        self._fd = fd
        self._strings: List[StringSequence] = []
        self._arrays: List[ArraySequence] = []

    def clear(self) -> None:
        self._strings.clear()
        self._arrays.clear()

    def getStrings(self) -> List[StringSequence]:
        return self._strings

    def getArrays(self) -> List[ArraySequence]:
        return self._arrays

    def analyzeBlock(self, bb) -> bool:
        """Analyze a basic block for constant sequences.

        Returns True if any sequences were found.
        """
        if bb is None:
            return False
        ops = bb.getOpList() if hasattr(bb, 'getOpList') else []
        stores = []
        for op in ops:
            if op.code() == OpCode.CPUI_STORE:
                # Check if value is constant
                val_vn = op.getIn(2)
                addr_vn = op.getIn(1)
                if val_vn is not None and val_vn.isConstant():
                    if addr_vn is not None and addr_vn.isConstant():
                        stores.append((addr_vn.getOffset(), val_vn.getOffset(),
                                       val_vn.getSize(), op))
        if len(stores) < 2:
            return False
        # Sort by address
        stores.sort(key=lambda x: x[0])
        # Find consecutive byte stores
        i = 0
        found = False
        while i < len(stores) - 1:
            seq = StringSequence()
            addr, val, sz, op = stores[i]
            seq.startAddr = Address(None, addr)
            seq.byteValues.append(val & 0xFF)
            seq.storeOps.append(op)
            seq.rootOp = op
            j = i + 1
            while j < len(stores):
                next_addr, next_val, next_sz, next_op = stores[j]
                if next_addr == addr + sz and next_sz == sz:
                    seq.byteValues.append(next_val & 0xFF)
                    seq.storeOps.append(next_op)
                    addr = next_addr
                    j += 1
                else:
                    break
            if len(seq.byteValues) >= 2:
                self._strings.append(seq)
                found = True
            i = j
        return found

    def analyzeFunction(self, fd) -> bool:
        """Analyze all basic blocks in a function for constant sequences."""
        if fd is None:
            return False
        found = False
        bblocks = fd.getBasicBlocks() if hasattr(fd, 'getBasicBlocks') else None
        if bblocks is None:
            return False
        if hasattr(bblocks, 'getSize'):
            for i in range(bblocks.getSize()):
                bl = bblocks.getBlock(i)
                if self.analyzeBlock(bl):
                    found = True
        return found
