"""
Corresponds to: cover.hh / cover.cc

Classes describing the topological scope of variables within a function.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Dict, List

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.block.block import FlowBlock


class PcodeOpSet(ABC):
    """A set of PcodeOps that can be tested for Cover intersections.

    Lazily constructed via populate() at first intersection test time.
    """

    def __init__(self) -> None:
        self._opList: List[PcodeOp] = []
        self._blockStart: List[int] = []
        self._is_pop: bool = False

    def isPopulated(self) -> bool:
        return self._is_pop

    def addOp(self, op: PcodeOp) -> None:
        self._opList.append(op)

    def finalize(self) -> None:
        """Sort ops in the set into blocks."""
        self._opList.sort(key=lambda op: (op.getParent().getIndex() if op.getParent() else -1, op.getSeqNum().getOrder()))
        self._blockStart.clear()
        last_block = -1
        for i, op in enumerate(self._opList):
            parent = op.getParent()
            blk = parent.getIndex() if parent else -1
            while len(self._blockStart) <= blk:
                self._blockStart.append(-1)
            if blk != last_block:
                self._blockStart[blk] = i
                last_block = blk
        self._is_pop = True

    @abstractmethod
    def populate(self) -> None:
        """Call-back to lazily add PcodeOps to this set."""
        ...

    @abstractmethod
    def affectsTest(self, op: PcodeOp, vn: Varnode) -> bool:
        """Secondary test: does the given PcodeOp affect the Varnode?"""
        ...

    def clear(self) -> None:
        self._is_pop = False
        self._opList.clear()
        self._blockStart.clear()


class CoverBlock:
    """The topological scope of a variable within a basic block.

    A contiguous range of p-code operations described with a start and stop.
    Special encodings:
      - start=None, stop=None  =>  empty/uncovered
      - start=None, stop=sentinel  =>  from beginning of block
      - start=sentinel, stop=sentinel  =>  whole block covered
    """

    # Sentinel value representing "whole block" endpoint
    _WHOLE_BLOCK_SENTINEL = object()

    __slots__ = ('start', 'stop')

    def __init__(self) -> None:
        self.start: object = None  # PcodeOp or None or sentinel
        self.stop: object = None   # PcodeOp or None or sentinel

    @staticmethod
    def getUIndex(op) -> int:
        """Get the comparison index for a PcodeOp."""
        if op is None:
            return 0
        if op is CoverBlock._WHOLE_BLOCK_SENTINEL:
            return 0xFFFFFFFF
        return op.getSeqNum().getOrder()

    def getStart(self):
        return self.start

    def getStop(self):
        return self.stop

    def clear(self) -> None:
        self.start = None
        self.stop = None

    def setAll(self) -> None:
        """Mark whole block as covered."""
        self.start = None
        self.stop = CoverBlock._WHOLE_BLOCK_SENTINEL

    def setBegin(self, begin) -> None:
        """Reset start of range."""
        self.start = begin
        if self.stop is None:
            self.stop = CoverBlock._WHOLE_BLOCK_SENTINEL

    def setEnd(self, end) -> None:
        """Reset end of range."""
        self.stop = end

    def empty(self) -> bool:
        """Return True if this is empty/uncovered."""
        return self.start is None and self.stop is None

    def contain(self, point) -> bool:
        """Check containment of given point."""
        if self.empty():
            return False
        if self.stop is CoverBlock._WHOLE_BLOCK_SENTINEL and self.start is None:
            return True  # Whole block
        uind = CoverBlock.getUIndex(point)
        start_ind = CoverBlock.getUIndex(self.start) if self.start is not None else 0
        stop_ind = CoverBlock.getUIndex(self.stop) if self.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL else 0xFFFFFFFF
        if self.stop is None:
            stop_ind = 0
        return start_ind <= uind <= stop_ind

    def boundary(self, point) -> int:
        """Characterize given point as boundary.

        Returns:
          0 = not on boundary
          1 = on start boundary
          2 = on stop boundary
          3 = on both (single-point cover)
        """
        if self.empty():
            return -1
        result = 0
        if self.start is not None and self.start is not CoverBlock._WHOLE_BLOCK_SENTINEL:
            if CoverBlock.getUIndex(point) == CoverBlock.getUIndex(self.start):
                result |= 1
        if self.stop is not None and self.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL:
            if CoverBlock.getUIndex(point) == CoverBlock.getUIndex(self.stop):
                result |= 2
        return result

    def intersect(self, op2: CoverBlock) -> int:
        """Compute intersection with another CoverBlock.

        Returns:
          0 = no intersection
          1 = partial intersection (not at boundary)
          2 = intersection at boundary only
        """
        if self.empty() or op2.empty():
            return 0
        # Simplified intersection test
        s1 = CoverBlock.getUIndex(self.start) if self.start is not None else 0
        e1 = CoverBlock.getUIndex(self.stop) if (self.stop is not None and self.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL) else 0xFFFFFFFF
        s2 = CoverBlock.getUIndex(op2.start) if op2.start is not None else 0
        e2 = CoverBlock.getUIndex(op2.stop) if (op2.stop is not None and op2.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL) else 0xFFFFFFFF
        if self.stop is None:
            e1 = s1
        if op2.stop is None:
            e2 = s2
        if e1 < s2 or e2 < s1:
            return 0
        if e1 == s2 or e2 == s1:
            return 2
        return 1

    def merge(self, op2: CoverBlock) -> None:
        """Merge another CoverBlock into this."""
        if op2.empty():
            return
        if self.empty():
            self.start = op2.start
            self.stop = op2.stop
            return
        # Take the union
        s1 = CoverBlock.getUIndex(self.start) if self.start is not None else 0
        e1 = CoverBlock.getUIndex(self.stop) if (self.stop is not None and self.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL) else 0xFFFFFFFF
        s2 = CoverBlock.getUIndex(op2.start) if op2.start is not None else 0
        e2 = CoverBlock.getUIndex(op2.stop) if (op2.stop is not None and op2.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL) else 0xFFFFFFFF
        if self.stop is None:
            e1 = s1
        if op2.stop is None:
            e2 = s2
        if s2 < s1:
            self.start = op2.start
        if e2 > e1:
            self.stop = op2.stop

    def __repr__(self) -> str:
        if self.empty():
            return "CoverBlock(empty)"
        return f"CoverBlock(start={self.start}, stop={self.stop})"


class Cover:
    """A description of the topological scope of a single variable object.

    Internally implemented as a map from basic block index to non-empty CoverBlock.
    """

    _emptyBlock: CoverBlock = CoverBlock()

    def __init__(self) -> None:
        self._cover: Dict[int, CoverBlock] = {}

    def clear(self) -> None:
        self._cover.clear()

    def compareTo(self, op2: Cover) -> int:
        """Give ordering of this and another Cover."""
        keys1 = sorted(self._cover.keys())
        keys2 = sorted(op2._cover.keys())
        for k1, k2 in zip(keys1, keys2):
            if k1 != k2:
                return -1 if k1 < k2 else 1
        if len(keys1) != len(keys2):
            return -1 if len(keys1) < len(keys2) else 1
        return 0

    def getCoverBlock(self, i: int) -> CoverBlock:
        """Get the CoverBlock corresponding to the i-th block."""
        return self._cover.get(i, Cover._emptyBlock)

    def intersect(self, op2: Cover) -> int:
        """Characterize the intersection between this and another Cover.

        Returns:
          0 = no intersection
          1 = intersection exists (not just at boundary)
          2 = intersection only at a boundary
        """
        result = 0
        for blk, cb1 in self._cover.items():
            cb2 = op2._cover.get(blk)
            if cb2 is None:
                continue
            val = cb1.intersect(cb2)
            if val == 1:
                return 1
            if val == 2:
                result = 2
        return result

    def intersectByBlock(self, blk: int, op2: Cover) -> int:
        """Characterize the intersection on a specific block."""
        cb1 = self._cover.get(blk)
        cb2 = op2._cover.get(blk)
        if cb1 is None or cb2 is None:
            return 0
        return cb1.intersect(cb2)

    def contain(self, op, max_: int) -> bool:
        """Check if a PcodeOp is contained in the cover."""
        parent = op.getParent()
        if parent is None:
            return False
        blk = parent.getIndex()
        cb = self._cover.get(blk)
        if cb is None:
            return False
        return cb.contain(op)

    def merge(self, op2: Cover) -> None:
        """Merge this with another Cover block by block."""
        for blk, cb2 in op2._cover.items():
            if blk in self._cover:
                self._cover[blk].merge(cb2)
            else:
                new_cb = CoverBlock()
                new_cb.merge(cb2)
                self._cover[blk] = new_cb

    def rebuild(self, vn) -> None:
        """Reset this based on def-use of a single Varnode."""
        self.clear()
        self.addDefPoint(vn)
        for op in vn.getDescendants():
            self.addRefPoint(op, vn)

    def addDefPoint(self, vn) -> None:
        """Reset to the single point where the given Varnode is defined."""
        defop = vn.getDef()
        if defop is None:
            return
        parent = defop.getParent()
        if parent is None:
            return
        blk = parent.getIndex()
        if blk not in self._cover:
            self._cover[blk] = CoverBlock()
        self._cover[blk].setBegin(defop)

    def addRefPoint(self, ref, vn) -> None:
        """Add a variable read to this Cover."""
        parent = ref.getParent()
        if parent is None:
            return
        blk = parent.getIndex()
        if blk not in self._cover:
            self._cover[blk] = CoverBlock()
        cb = self._cover[blk]
        if cb.empty():
            cb.setAll()
        else:
            uind = CoverBlock.getUIndex(ref)
            stop_ind = CoverBlock.getUIndex(cb.stop) if (cb.stop is not None and cb.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL) else 0xFFFFFFFF
            if cb.stop is None:
                stop_ind = CoverBlock.getUIndex(cb.start) if cb.start is not None else 0
            if uind > stop_ind:
                cb.setEnd(ref)

    def __iter__(self):
        return iter(self._cover.items())

    def __repr__(self) -> str:
        blocks = [f"blk{k}" for k in sorted(self._cover.keys())]
        return f"Cover({', '.join(blocks)})"
