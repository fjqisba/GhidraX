"""
Corresponds to: variable.hh / variable.cc

Definitions for high-level variables (HighVariable, VariableGroup, VariablePiece).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List, Set

from ghidra.ir.cover import Cover

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode


class VariableGroup:
    """A collection of HighVariable objects that overlap.

    For a set of HighVariable objects that mutually overlap, a VariableGroup
    is a central access point for information about the intersections.
    """

    def __init__(self) -> None:
        self._pieceSet: List[VariablePiece] = []
        self._size: int = 0
        self._symbolOffset: int = 0

    def empty(self) -> bool:
        return len(self._pieceSet) == 0

    def addPiece(self, piece: VariablePiece) -> None:
        self._pieceSet.append(piece)
        # Update size to cover the full range
        end = piece._groupOffset + piece._size
        if end > self._size:
            self._size = end

    def removePiece(self, piece: VariablePiece) -> None:
        try:
            self._pieceSet.remove(piece)
        except ValueError:
            pass

    def adjustOffsets(self, amt: int) -> None:
        for p in self._pieceSet:
            p._groupOffset += amt

    def getSize(self) -> int:
        return self._size

    def setSymbolOffset(self, val: int) -> None:
        self._symbolOffset = val

    def getSymbolOffset(self) -> int:
        return self._symbolOffset

    def combineGroups(self, op2: VariableGroup) -> None:
        """Combine given VariableGroup into this."""
        for p in op2._pieceSet:
            p._group = self
            self._pieceSet.append(p)
        op2._pieceSet.clear()
        end = 0
        for p in self._pieceSet:
            e = p._groupOffset + p._size
            if e > end:
                end = e
        self._size = end


class VariablePiece:
    """Information about how a HighVariable fits into a larger group or Symbol.

    Describes overlaps and how they affect the HighVariable Cover.
    """

    def __init__(self, high: HighVariable, offset: int,
                 grp_high: Optional[HighVariable] = None) -> None:
        self._high: HighVariable = high
        self._groupOffset: int = offset
        self._size: int = 0
        self._intersection: List[VariablePiece] = []
        self._cover: Cover = Cover()

        if grp_high is not None and grp_high._piece is not None:
            self._group = grp_high._piece._group
        else:
            self._group = VariableGroup()
        self._group.addPiece(self)

        # Calculate size from the HighVariable's instances
        if high._inst:
            self._size = high._inst[0].getSize()

    def getHigh(self) -> HighVariable:
        return self._high

    def getGroup(self) -> VariableGroup:
        return self._group

    def getOffset(self) -> int:
        return self._groupOffset

    def getSize(self) -> int:
        return self._size

    def getCover(self) -> Cover:
        return self._cover

    def numIntersection(self) -> int:
        return len(self._intersection)

    def getIntersection(self, i: int) -> VariablePiece:
        return self._intersection[i]

    def setHigh(self, newHigh: HighVariable) -> None:
        self._high = newHigh

    def transferGroup(self, newGroup: VariableGroup) -> None:
        self._group.removePiece(self)
        self._group = newGroup
        newGroup.addPiece(self)

    def updateIntersections(self) -> None:
        """Calculate intersections with other pieces in the group."""
        self._intersection.clear()
        my_start = self._groupOffset
        my_end = my_start + self._size
        for p in self._group._pieceSet:
            if p is self:
                continue
            p_start = p._groupOffset
            p_end = p_start + p._size
            if my_start < p_end and p_start < my_end:
                self._intersection.append(p)

    def updateCover(self) -> None:
        """Calculate extended cover based on intersections."""
        self._cover.clear()
        # Start with the high variable's own cover
        for vn in self._high._inst:
            if vn.hasCover() and vn.getCover() is not None:
                self._cover.merge(vn.getCover())
        # Extend with intersecting pieces' covers
        for p in self._intersection:
            for vn in p._high._inst:
                if vn.hasCover() and vn.getCover() is not None:
                    self._cover.merge(vn.getCover())


class HighVariable:
    """A high-level variable modeled as a list of low-level variables, each written once.

    In SSA form, a Varnode is written at most once. A high-level variable
    may be written multiple times, modeled as a list of Varnode objects
    where each holds the value for different parts of the code.
    """

    # Dirtiness flags
    flagsdirty       = 1
    namerepdirty     = 2
    typedirty        = 4
    coverdirty       = 8
    symboldirty      = 0x10
    copy_in1         = 0x20
    copy_in2         = 0x40
    type_finalized   = 0x80
    unmerged         = 0x100
    intersectdirty   = 0x200
    extendcoverdirty = 0x400

    def __init__(self, vn: Varnode) -> None:
        self._inst: List[Varnode] = [vn]
        self._numMergeClasses: int = 1
        self._highflags: int = (HighVariable.flagsdirty | HighVariable.namerepdirty |
                                HighVariable.typedirty | HighVariable.coverdirty)
        self._flags: int = 0
        self._type = None  # Datatype
        self._nameRepresentative: Optional[Varnode] = None
        self._internalCover: Cover = Cover()
        self._piece: Optional[VariablePiece] = None
        self._symbol = None  # Symbol
        self._symboloffset: int = -1

        vn.setHigh(self, 0)

    # --- Accessors ---

    def getType(self):
        self._updateType()
        return self._type

    def getCover(self) -> Cover:
        self._updateCover()
        if self._piece is not None:
            return self._piece.getCover()
        return self._internalCover

    def getSymbol(self):
        return self._symbol

    def getSymbolOffset(self) -> int:
        return self._symboloffset

    def numInstances(self) -> int:
        return len(self._inst)

    def getInstance(self, i: int) -> Varnode:
        return self._inst[i]

    def getNumMergeClasses(self) -> int:
        return self._numMergeClasses

    # --- Flag queries ---

    def isMapped(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.mapped) != 0

    def isPersist(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.persist) != 0

    def isAddrTied(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.addrtied) != 0

    def isInput(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.input) != 0

    def isUnaffected(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.unaffected) != 0

    def isConstant(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.constant) != 0

    def isTypeLock(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.typelock) != 0

    def isNameLock(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.namelock) != 0

    def isImplied(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.implied) != 0

    def isSpacebase(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.spacebase) != 0

    def isExtraOut(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & (VN.indirect_creation | VN.addrtied)) == VN.indirect_creation

    def isProtoPartial(self) -> bool:
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.proto_partial) != 0

    def setMark(self) -> None:
        from ghidra.ir.varnode import Varnode as VN
        self._flags |= VN.mark

    def clearMark(self) -> None:
        from ghidra.ir.varnode import Varnode as VN
        self._flags &= ~VN.mark

    def isMark(self) -> bool:
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & VN.mark) != 0

    def isUnmerged(self) -> bool:
        return (self._highflags & HighVariable.unmerged) != 0

    def isSameGroup(self, op2: HighVariable) -> bool:
        """Test if this and op2 are pieces of the same symbol."""
        if self._piece is None or op2._piece is None:
            return False
        return self._piece.getGroup() is op2._piece.getGroup()

    def hasCover(self) -> bool:
        """Determine if this HighVariable has an associated cover."""
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & (VN.constant | VN.annotation | VN.insert)) == VN.insert

    def isUnattached(self) -> bool:
        return len(self._inst) == 0

    # --- Dirty management ---

    def flagsDirty(self) -> None:
        self._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty)

    def coverDirty(self) -> None:
        self._highflags |= HighVariable.coverdirty
        if self._piece is not None:
            self._highflags |= HighVariable.extendcoverdirty

    def typeDirty(self) -> None:
        self._highflags |= HighVariable.typedirty

    def symbolDirty(self) -> None:
        self._highflags |= HighVariable.symboldirty

    def setUnmerged(self) -> None:
        self._highflags |= HighVariable.unmerged

    def setCopyIn1(self) -> None:
        self._highflags |= HighVariable.copy_in1

    def setCopyIn2(self) -> None:
        self._highflags |= HighVariable.copy_in2

    def clearCopyIns(self) -> None:
        self._highflags &= ~(HighVariable.copy_in1 | HighVariable.copy_in2)

    def hasCopyIn1(self) -> bool:
        return (self._highflags & HighVariable.copy_in1) != 0

    def hasCopyIn2(self) -> bool:
        return (self._highflags & HighVariable.copy_in2) != 0

    def isCoverDirty(self) -> bool:
        return (self._highflags & (HighVariable.coverdirty | HighVariable.extendcoverdirty)) != 0

    # --- Internal update methods ---

    def _updateFlags(self) -> None:
        if (self._highflags & HighVariable.flagsdirty) == 0:
            return
        self._highflags &= ~HighVariable.flagsdirty
        # Derive flags from member Varnodes
        self._flags = 0
        for vn in self._inst:
            self._flags |= vn.getFlags()

    def _updateType(self) -> None:
        if (self._highflags & HighVariable.typedirty) == 0:
            return
        self._highflags &= ~HighVariable.typedirty
        if self._inst:
            self._type = self._inst[0].getType()

    def _updateCover(self) -> None:
        if (self._highflags & HighVariable.coverdirty) == 0:
            return
        self._highflags &= ~HighVariable.coverdirty
        self._internalCover.clear()
        for vn in self._inst:
            if vn.hasCover() and vn.getCover() is not None:
                self._internalCover.merge(vn.getCover())

    # --- Merge operations ---

    def remove(self, vn: Varnode) -> None:
        """Remove a member Varnode from this."""
        try:
            self._inst.remove(vn)
        except ValueError:
            pass

    def mergeInternal(self, tv2: HighVariable, isspeculative: bool = False) -> None:
        """Merge another HighVariable into this."""
        for vn in tv2._inst:
            vn.setHigh(self, vn.getMergeGroup())
            self._inst.append(vn)
        tv2._inst.clear()
        self.flagsDirty()
        self.coverDirty()
        self.typeDirty()

    def setSymbol(self, vn: Varnode) -> None:
        """Update Symbol information for this from the given member Varnode."""
        entry = vn.getSymbolEntry()
        if entry is not None:
            self._symboloffset = 0  # Simplified
            self._highflags &= ~HighVariable.symboldirty

    def setSymbolReference(self, sym, off: int) -> None:
        self._symbol = sym
        self._symboloffset = off

    def merge(self, tv2: HighVariable, testCache=None, isspeculative: bool = False) -> None:
        """Merge with another HighVariable taking into account groups."""
        if self._piece is not None and tv2._piece is not None:
            # Both have pieces - merge groups
            self.transferPiece(tv2)
        elif tv2._piece is not None:
            self.transferPiece(tv2)
        self.mergeInternal(tv2, isspeculative)
        if testCache is not None and hasattr(testCache, 'moveIntersectTests'):
            testCache.moveIntersectTests(self, tv2)

    def transferPiece(self, tv2: HighVariable) -> None:
        """Transfer ownership of another's VariablePiece to this."""
        if tv2._piece is None:
            return
        if self._piece is None:
            self._piece = tv2._piece
            self._piece.setHigh(self)
            tv2._piece = None
        else:
            # Merge the groups
            self._piece.getGroup().combineGroups(tv2._piece.getGroup())
            tv2._piece.setHigh(self)
            tv2._piece = None

    def updateCover(self) -> None:
        """Public method to force cover update."""
        self._updateCover()

    def updateInternalCover(self) -> None:
        """Alias for _updateCover."""
        self._updateCover()

    def getSymbolEntry(self):
        """Get the SymbolEntry mapping to this or None."""
        for vn in self._inst:
            entry = vn.getSymbolEntry()
            if entry is not None:
                return entry
        return None

    def finalizeDatatype(self, typeFactory=None) -> None:
        """Set a final data-type matching the associated Symbol."""
        self._highflags |= HighVariable.type_finalized

    def establishGroupSymbolOffset(self) -> None:
        """Transfer symbol offset of this to the VariableGroup."""
        if self._piece is not None and self._symboloffset >= 0:
            self._piece.getGroup().setSymbolOffset(self._symboloffset)

    def stripType(self) -> None:
        """Take the stripped form of the current data-type."""
        pass

    def updateSymbol(self) -> None:
        """(Re)derive the Symbol and offset from member Varnodes."""
        if (self._highflags & HighVariable.symboldirty) == 0:
            return
        self._highflags &= ~HighVariable.symboldirty
        for vn in self._inst:
            entry = vn.getSymbolEntry()
            if entry is not None:
                if hasattr(entry, 'getSymbol'):
                    self._symbol = entry.getSymbol()
                self._symboloffset = 0
                return

    def encode(self, encoder) -> None:
        """Encode this variable to stream as a <high> element."""
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement('high')
            if self._type is not None and hasattr(self._type, 'encode'):
                self._type.encode(encoder)
            for vn in self._inst:
                vn.encode(encoder)
            encoder.closeElement('high')

    @staticmethod
    def compareName(vn1, vn2) -> bool:
        """Determine which given Varnode is most nameable."""
        if vn1.isInput() and not vn2.isInput():
            return True
        if vn2.isInput() and not vn1.isInput():
            return False
        return vn1.getCreateIndex() < vn2.getCreateIndex()

    @staticmethod
    def compareJustLoc(a, b) -> bool:
        """Compare based on storage location."""
        return a.getAddr() < b.getAddr()

    @staticmethod
    def markExpression(vn, highList: list) -> int:
        """Mark and collect variables in expression."""
        count = 0
        if vn is None:
            return count
        high = vn.getHigh()
        if high is not None and not high.isMark():
            high.setMark()
            highList.append(high)
            count += 1
        if vn.isWritten():
            op = vn.getDef()
            for i in range(op.numInput()):
                count += HighVariable.markExpression(op.getIn(i), highList)
        return count

    # --- Query helpers ---

    def hasName(self) -> bool:
        return self._symbol is not None

    def getTiedVarnode(self) -> Optional[Varnode]:
        """Find the first address-tied member Varnode."""
        for vn in self._inst:
            if vn.isAddrTied():
                return vn
        return None

    def getInputVarnode(self) -> Optional[Varnode]:
        """Find (the) input member Varnode."""
        for vn in self._inst:
            if vn.isInput():
                return vn
        return None

    def getTypeRepresentative(self) -> Optional[Varnode]:
        """Get a member Varnode with the strongest data-type."""
        if not self._inst:
            return None
        return self._inst[0]

    def getNameRepresentative(self) -> Optional[Varnode]:
        """Get a member Varnode that dictates the naming."""
        if self._nameRepresentative is not None and (self._highflags & HighVariable.namerepdirty) == 0:
            return self._nameRepresentative
        self._highflags &= ~HighVariable.namerepdirty
        if self._inst:
            self._nameRepresentative = self._inst[0]
        return self._nameRepresentative

    def groupWith(self, off: int, hi2: HighVariable) -> None:
        """Put this and another HighVariable in the same intersection group."""
        if self._piece is None:
            self._piece = VariablePiece(self, 0)
        if hi2._piece is None:
            hi2._piece = VariablePiece(hi2, off, self)
        else:
            # Merge groups
            self._piece.getGroup().combineGroups(hi2._piece.getGroup())

    def printInfo(self) -> str:
        parts = [f"HighVariable(instances={len(self._inst)}"]
        if self._type is not None:
            parts.append(f", type={self._type}")
        parts.append(")")
        return "".join(parts)

    def printCover(self) -> str:
        if (self._highflags & HighVariable.coverdirty) == 0:
            return str(self._internalCover)
        return "Cover dirty"

    def __repr__(self) -> str:
        return self.printInfo()


# =========================================================================
# HighEdge
# =========================================================================

class HighEdge:
    """A record for caching a Cover intersection test between two HighVariable objects."""

    def __init__(self, a: HighVariable, b: HighVariable) -> None:
        self.a = a
        self.b = b

    def __lt__(self, op2: HighEdge) -> bool:
        if self.a is op2.a:
            return id(self.b) < id(op2.b)
        return id(self.a) < id(op2.a)

    def __eq__(self, other) -> bool:
        return self.a is other.a and self.b is other.b

    def __hash__(self) -> int:
        return hash((id(self.a), id(self.b)))


# =========================================================================
# HighIntersectTest
# =========================================================================

class HighIntersectTest:
    """A cache of Cover intersection tests for HighVariables.

    The intersect() method returns the result of a full Cover intersection test.
    Results are cached so repeated calls don't need the full calculation.
    """

    def __init__(self, affectingOps=None) -> None:
        self._affectingOps = affectingOps
        self._cache: dict = {}

    def updateHigh(self, a: HighVariable) -> bool:
        """Make sure given HighVariable's Cover is up-to-date."""
        if a.isCoverDirty():
            a.updateCover()
            # Purge stale cache entries
            self._purgeHigh(a)
            return True
        return False

    def intersection(self, a: HighVariable, b: HighVariable) -> bool:
        """Test if two HighVariables have intersecting covers.

        Returns True if there IS an intersection.
        """
        if a is b:
            return False
        key = (id(a), id(b)) if id(a) < id(b) else (id(b), id(a))
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        self.updateHigh(a)
        self.updateHigh(b)
        ca = a.getCover()
        cb = b.getCover()
        result = ca.intersect(cb) == 2 if ca is not None and cb is not None else False
        self._cache[key] = result
        return result

    def moveIntersectTests(self, high1: HighVariable, high2: HighVariable) -> None:
        """Update cached tests to reflect a merge of high2 into high1."""
        self._purgeHigh(high2)

    def _purgeHigh(self, high: HighVariable) -> None:
        """Remove cached intersection tests for a given HighVariable."""
        hid = id(high)
        keys_to_remove = [k for k in self._cache if hid in k]
        for k in keys_to_remove:
            del self._cache[k]

    def clear(self) -> None:
        self._cache.clear()
