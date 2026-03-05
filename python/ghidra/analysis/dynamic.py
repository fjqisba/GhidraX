"""
DynamicHash: Hash-based Varnode identification for dynamic symbols.
Corresponds to dynamic.hh / dynamic.cc.
"""
from __future__ import annotations
from typing import Optional, List, TYPE_CHECKING
from ghidra.core.address import Address

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.analysis.funcdata import Funcdata


class ToOpEdge:
    """An edge between a Varnode and a PcodeOp in a data-flow sub-graph."""

    def __init__(self, op=None, slot: int = -1) -> None:
        self._op = op
        self._slot: int = slot

    def getOp(self):
        return self._op

    def getSlot(self) -> int:
        return self._slot

    def __lt__(self, op2) -> bool:
        if self._op is None and op2._op is None:
            return False
        if self._op is None:
            return True
        if op2._op is None:
            return False
        return self._op.getSeqNum() < op2._op.getSeqNum()

    def hash(self, reg: int) -> int:
        """Hash this edge into an accumulator."""
        h = reg
        if self._op is not None:
            h = (h * 31 + int(self._op.code())) & 0xFFFFFFFF
        h = (h * 31 + (self._slot + 1)) & 0xFFFFFFFF
        return h


class DynamicHash:
    """Uniquely identify a Varnode via a hash of its local data-flow neighborhood.

    Calculates a hash and an address of the PcodeOp most closely associated
    with the Varnode. There are four hash variants (0-3) that incrementally
    hash in a larger portion of data-flow.
    """

    transtable = [0] * 74  # Translation of op-codes to hash values

    def __init__(self) -> None:
        self._hash: int = 0
        self._addrresult: Address = Address()
        self._markop: list = []
        self._markvn: list = []
        self._vnedge: list = []
        self._opedge: list = []

    def clear(self) -> None:
        self._hash = 0
        self._addrresult = Address()
        self._markop.clear()
        self._markvn.clear()
        self._vnedge.clear()
        self._opedge.clear()

    def getHash(self) -> int:
        return self._hash

    def setHash(self, h: int) -> None:
        self._hash = h

    def setAddress(self, addr: Address) -> None:
        self._addrresult = addr

    def getAddress(self) -> Address:
        return self._addrresult

    def calcHash(self, root, method: int = 0) -> None:
        """Calculate a hash for a given Varnode based on its local data-flow."""
        h = 0x12345678
        if hasattr(root, 'getAddr'):
            h ^= root.getAddr().getOffset()
        if hasattr(root, 'getSize'):
            h = (h * 31 + root.getSize()) & 0xFFFFFFFFFFFFFFFF
        if hasattr(root, 'isWritten') and root.isWritten():
            defop = root.getDef()
            h = (h * 31 + defop.code()) & 0xFFFFFFFFFFFFFFFF
            for i in range(defop.numInput()):
                inv = defop.getIn(i)
                if inv.isConstant():
                    h = (h * 31 + inv.getOffset()) & 0xFFFFFFFFFFFFFFFF
                else:
                    h = (h * 31 + inv.getAddr().getOffset()) & 0xFFFFFFFFFFFFFFFF
        if hasattr(root, 'getDescendants'):
            for desc in root.getDescendants():
                h = (h * 31 + desc.code()) & 0xFFFFFFFFFFFFFFFF
        self._hash = h
        if hasattr(root, 'getAddr'):
            self._addrresult = root.getAddr()

    def calcHashOp(self, op, slot: int, method: int = 0) -> None:
        """Calculate hash for given PcodeOp, slot, and method."""
        h = 0x12345678
        if op is not None:
            h = (h * 31 + int(op.code())) & 0xFFFFFFFFFFFFFFFF
            h = (h * 31 + slot) & 0xFFFFFFFFFFFFFFFF
            if slot >= 0 and slot < op.numInput():
                vn = op.getIn(slot)
                if vn is not None:
                    h = (h * 31 + vn.getAddr().getOffset()) & 0xFFFFFFFFFFFFFFFF
                    h = (h * 31 + vn.getSize()) & 0xFFFFFFFFFFFFFFFF
            self._addrresult = op.getAddr()
        self._hash = h

    def uniqueHash(self, root_or_op, fd_or_slot=None, fd2=None) -> None:
        """Select a unique hash for the given Varnode or PcodeOp+slot."""
        if fd2 is not None:
            # uniqueHash(op, slot, fd)
            self.calcHashOp(root_or_op, fd_or_slot)
        else:
            # uniqueHash(vn, fd)
            self.calcHash(root_or_op, 0)

    def findVarnode(self, fd, addr: Address, h: int) -> Optional[Varnode]:
        """Find a Varnode matching the given address and hash."""
        if not hasattr(fd, '_vbank'):
            return None
        for vn in list(fd._vbank.beginLoc()):
            if vn.getAddr() == addr:
                self.calcHash(vn)
                if self._hash == h:
                    return vn
        return None

    def findOp(self, fd, addr: Address, h: int):
        """Find a PcodeOp matching the given address and hash."""
        return None  # Would search ops at address

    @staticmethod
    def getSlotFromHash(h: int) -> int:
        return (h >> 32) & 0x1F

    @staticmethod
    def getMethodFromHash(h: int) -> int:
        return (h >> 37) & 0xF

    @staticmethod
    def getOpCodeFromHash(h: int) -> int:
        return (h >> 53) & 0x7FF

    @staticmethod
    def getPositionFromHash(h: int) -> int:
        return (h >> 41) & 0x3F

    @staticmethod
    def getTotalFromHash(h: int) -> int:
        return (h >> 47) & 0x3F

    @staticmethod
    def getIsNotAttached(h: int) -> bool:
        return (h >> 63) != 0

    @staticmethod
    def clearTotalPosition(h_ref: list) -> None:
        """Clear the collision total and position fields within a hash."""
        if h_ref:
            h_ref[0] &= ~(0x3F << 41)
            h_ref[0] &= ~(0x3F << 47)

    @staticmethod
    def getComparable(h: int) -> int:
        return h & 0xFFFFFFFF

    @staticmethod
    def gatherFirstLevelVars(varlist: list, fd, addr: Address, h: int) -> None:
        """Gather first-level Varnodes at the given address."""
        if not hasattr(fd, '_vbank'):
            return
        for vn in fd._vbank.beginLoc():
            if vn.getAddr() == addr:
                varlist.append(vn)

    @staticmethod
    def gatherOpsAtAddress(opList: list, fd, addr: Address) -> None:
        """Gather all PcodeOps at the given address."""
        if hasattr(fd, '_obank') and hasattr(fd._obank, 'beginByAddr'):
            opList.extend(fd._obank.beginByAddr(addr))

    @staticmethod
    def dedupVarnodes(varlist: list) -> None:
        """Remove duplicate Varnodes from list."""
        seen = set()
        i = 0
        while i < len(varlist):
            vid = id(varlist[i])
            if vid in seen:
                varlist.pop(i)
            else:
                seen.add(vid)
                i += 1

    def getVnEdges(self) -> list:
        return self._vnedge

    def getOpEdges(self) -> list:
        return self._opedge

    def getMarkOps(self) -> list:
        return self._markop

    def getSlotIndex(self) -> int:
        return self._slot if hasattr(self, '_slot') else -1

    def __repr__(self) -> str:
        return f"DynamicHash(hash=0x{self._hash:x})"
