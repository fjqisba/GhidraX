"""
Corresponds to: unionresolve.hh / unionresolve.cc

ResolvedUnion for tracking which union field is selected at each use point.
When a Varnode has a union data-type, the decompiler must decide which field
is being accessed at each PcodeOp. This module tracks those decisions.
"""

from __future__ import annotations
from typing import Optional, Dict, Tuple


class ResolvedUnion:
    """Record of which union field was selected for a particular access."""

    def __init__(self, fieldNum: int = -1, lockCount: int = 0) -> None:
        self._fieldNum: int = fieldNum
        self._lockCount: int = lockCount

    def getFieldNum(self) -> int:
        return self._fieldNum

    def setFieldNum(self, num: int) -> None:
        self._fieldNum = num

    def getLock(self) -> int:
        return self._lockCount

    def lock(self) -> None:
        self._lockCount += 1

    def isLocked(self) -> bool:
        return self._lockCount > 0


class UnionFacetSymbol:
    """A Symbol that represents a particular facet (field) of a union."""

    def __init__(self, sym=None, fieldNum: int = -1) -> None:
        self.symbol = sym
        self.fieldNum: int = fieldNum

    def getSymbol(self):
        return self.symbol

    def getFieldNum(self) -> int:
        return self.fieldNum


class ResolveEdge:
    """An edge in the data-flow graph where union resolution occurs.

    Identified by (opAddress, slot) where slot=-1 means the output.
    """

    def __init__(self, opAddr: int = 0, slot: int = 0) -> None:
        self.opAddr: int = opAddr
        self.slot: int = slot

    def __hash__(self) -> int:
        return hash((self.opAddr, self.slot))

    def __eq__(self, other) -> bool:
        if not isinstance(other, ResolveEdge):
            return NotImplemented
        return self.opAddr == other.opAddr and self.slot == other.slot


class UnionResolveMap:
    """Map from (Datatype, ResolveEdge) to ResolvedUnion.

    Tracks union field resolution decisions across the function.
    """

    def __init__(self) -> None:
        self._map: Dict[Tuple[int, int, int], ResolvedUnion] = {}

    def setUnionField(self, dt, op, slot: int, res: ResolvedUnion) -> None:
        dtid = id(dt) if dt is not None else 0
        opaddr = op.getSeqNum().getAddr().getOffset() if (op is not None and hasattr(op, 'getSeqNum')) else 0
        key = (dtid, opaddr, slot)
        self._map[key] = res

    def getUnionField(self, dt, op, slot: int) -> Optional[ResolvedUnion]:
        dtid = id(dt) if dt is not None else 0
        opaddr = op.getSeqNum().getAddr().getOffset() if (op is not None and hasattr(op, 'getSeqNum')) else 0
        key = (dtid, opaddr, slot)
        return self._map.get(key)

    def hasUnionField(self, dt, op, slot: int) -> bool:
        return self.getUnionField(dt, op, slot) is not None

    def clear(self) -> None:
        self._map.clear()

    def numResolutions(self) -> int:
        return len(self._map)
