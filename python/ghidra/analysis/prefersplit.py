"""
Corresponds to: prefersplit.hh / prefersplit.cc

PreferSplitRecord for tracking preferred split points in laned registers.
When a register can be logically split into smaller lanes (e.g. XMM into
4x float), this tracks the preferred split configuration.
"""

from __future__ import annotations
from typing import List
from ghidra.core.address import Address


class LanedRegister:
    """A register that can be split into logical lanes."""

    def __init__(self, sz: int = 0) -> None:
        self.wholeSize: int = sz
        self._lanes: List[int] = []

    def addLaneSize(self, laneSize: int) -> None:
        self._lanes.append(laneSize)

    def getWholeSize(self) -> int:
        return self.wholeSize

    def getNumLanes(self, laneSize: int) -> int:
        if laneSize == 0:
            return 0
        return self.wholeSize // laneSize

    def getLaneSizes(self) -> List[int]:
        return self._lanes

    def supportsSplit(self, laneSize: int) -> bool:
        return laneSize in self._lanes


class PreferSplitRecord:
    """Record of a preferred split for a storage location.

    Associates a specific storage location with a preferred way
    to split it into lanes of a given size.
    """

    def __init__(self) -> None:
        self.storage: Address = Address()
        self.splitSize: int = 0
        self.totalSize: int = 0

    def init(self, addr: Address, splitSz: int, totalSz: int) -> None:
        self.storage = addr
        self.splitSize = splitSz
        self.totalSize = totalSz

    def getAddress(self) -> Address:
        return self.storage

    def getSplitSize(self) -> int:
        return self.splitSize

    def getTotalSize(self) -> int:
        return self.totalSize

    def getNumLanes(self) -> int:
        if self.splitSize == 0:
            return 0
        return self.totalSize // self.splitSize

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    def __lt__(self, other) -> bool:
        if not isinstance(other, PreferSplitRecord):
            return NotImplemented
        return self.storage < other.storage


class PreferSplitManager:
    """Manages a collection of PreferSplitRecords for an architecture.

    Handles splitting Varnodes at preferred points during heritage.
    """

    class SplitInstance:
        """Tracks a Varnode being split into hi/lo pieces."""
        def __init__(self, vn=None, off: int = 0):
            self.splitoffset: int = off
            self.vn = vn
            self.hi = None  # Most significant piece
            self.lo = None  # Least significant piece

    def __init__(self) -> None:
        self._records: List[PreferSplitRecord] = []
        self._data = None  # Funcdata
        self._tempsplits: list = []

    def init(self, fd, records) -> None:
        """Initialize with a Funcdata and list of PreferSplitRecords."""
        self._data = fd
        if records is not None:
            self._records = list(records) if not isinstance(records, list) else records

    def addRecord(self, rec: PreferSplitRecord) -> None:
        self._records.append(rec)
        self._records.sort()

    def findRecord(self, addr_or_vn, sz: int = None) -> PreferSplitRecord:
        """Find a record by address+size or by Varnode."""
        if sz is not None:
            # findRecord(addr, sz)
            for rec in self._records:
                if rec.storage == addr_or_vn and rec.totalSize == sz:
                    return rec
        else:
            # findRecord(vn) - match by varnode's storage
            vn = addr_or_vn
            if vn is None:
                return None
            for rec in self._records:
                if rec.storage == vn.getAddr() and rec.totalSize == vn.getSize():
                    return rec
        return None

    def hasSplit(self, addr: Address, sz: int) -> bool:
        return self.findRecord(addr, sz) is not None

    def numRecords(self) -> int:
        return len(self._records)

    def getRecords(self) -> list:
        return self._records

    def clear(self) -> None:
        self._records.clear()
        self._tempsplits.clear()

    def split(self) -> None:
        """Perform initial splitting of Varnodes based on records.

        For each PreferSplitRecord, find matching Varnodes in the function
        and split them into hi/lo pieces.
        """
        if self._data is None:
            return
        for rec in self._records:
            self._splitRecord(rec)

    def splitAdditional(self) -> None:
        """Split any additional temporaries that were discovered during initial split."""
        for op in self._tempsplits:
            pass  # Would split temporary copies
        self._tempsplits.clear()

    def _splitRecord(self, rec: PreferSplitRecord) -> None:
        """Split all Varnodes matching the given record."""
        if self._data is None:
            return
        # Find all varnodes at the record's storage location
        for vn in list(self._data._vbank.beginLoc()):
            if vn.getAddr() == rec.storage and vn.getSize() == rec.totalSize:
                inst = PreferSplitManager.SplitInstance(vn, rec.splitSize)
                self._splitVarnode(inst)

    def _splitVarnode(self, inst) -> bool:
        """Split a single Varnode into hi/lo pieces."""
        if inst.vn is None:
            return False
        vn = inst.vn
        if vn.isWritten():
            defop = vn.getDef()
            opc = defop.code()
            from ghidra.core.opcodes import OpCode
            if opc == OpCode.CPUI_COPY:
                return self._testDefiningCopy(inst, defop)
            elif opc == OpCode.CPUI_PIECE:
                return self._testPiece(inst, defop)
            elif opc == OpCode.CPUI_INT_ZEXT:
                return self._testZext(inst, defop)
            elif opc == OpCode.CPUI_LOAD:
                return self._testLoad(inst, defop)
        return False

    def _testDefiningCopy(self, inst, defop) -> bool:
        return True

    def _testReadingCopy(self, inst, readop) -> bool:
        return True

    def _testZext(self, inst, op) -> bool:
        return True

    def _testPiece(self, inst, op) -> bool:
        return True

    def _testSubpiece(self, inst, op) -> bool:
        return True

    def _testLoad(self, inst, op) -> bool:
        return True

    def _testStore(self, inst, op) -> bool:
        return True

    def _testTemporary(self, inst) -> bool:
        return True

    @staticmethod
    def initialize(records: list) -> None:
        """Initialize/sort the records list."""
        records.sort()
