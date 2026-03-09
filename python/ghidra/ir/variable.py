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
        piece._group = self
        if piece in self._pieceSet:
            raise RuntimeError("Duplicate VariablePiece")
        self._pieceSet.append(piece)
        pieceMax = piece._groupOffset + piece._size
        if pieceMax > self._size:
            self._size = pieceMax

    def removePiece(self, piece: VariablePiece) -> None:
        try:
            self._pieceSet.remove(piece)
        except ValueError:
            pass

    def adjustOffsets(self, amt: int) -> None:
        for p in self._pieceSet:
            p._groupOffset += amt
        self._size += amt

    def getSize(self) -> int:
        return self._size

    def setSymbolOffset(self, val: int) -> None:
        self._symbolOffset = val

    def getSymbolOffset(self) -> int:
        return self._symbolOffset

    def combineGroups(self, op2: VariableGroup) -> None:
        """Combine given VariableGroup into this."""
        for p in list(op2._pieceSet):
            p.transferGroup(self)


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
        oldGroup = self._group
        oldGroup.removePiece(self)
        newGroup.addPiece(self)

    def markIntersectionDirty(self) -> None:
        """Mark all pieces in the group as needing intersection recalculation."""
        for p in self._group._pieceSet:
            p._high._highflags |= (HighVariable.intersectdirty | HighVariable.extendcoverdirty)

    def markExtendCoverDirty(self) -> None:
        """Mark all intersecting pieces as having a dirty extended cover."""
        if (self._high._highflags & HighVariable.intersectdirty) != 0:
            return
        for p in self._intersection:
            p._high._highflags |= HighVariable.extendcoverdirty
        self._high._highflags |= HighVariable.extendcoverdirty

    def updateIntersections(self) -> None:
        """Calculate intersections with other pieces in the group."""
        if (self._high._highflags & HighVariable.intersectdirty) == 0:
            return
        endOffset = self._groupOffset + self._size
        self._intersection.clear()
        for p in self._group._pieceSet:
            if p is self:
                continue
            if endOffset <= p._groupOffset:
                continue
            otherEnd = p._groupOffset + p._size
            if self._groupOffset >= otherEnd:
                continue
            self._intersection.append(p)
        self._high._highflags &= ~HighVariable.intersectdirty

    def updateCover(self) -> None:
        """Calculate extended cover based on intersections."""
        if (self._high._highflags & (HighVariable.coverdirty | HighVariable.extendcoverdirty)) == 0:
            return
        self._high._updateInternalCover()
        self._cover = Cover()
        self._cover.merge(self._high._internalCover)
        for p in self._intersection:
            h = p._high
            h._updateInternalCover()
            self._cover.merge(h._internalCover)
        self._high._highflags &= ~HighVariable.extendcoverdirty

    def mergeGroups(self, op2: VariablePiece, mergePairs: list) -> None:
        """Combine two VariableGroups, returning HighVariable pairs to merge."""
        diff = self._groupOffset - op2._groupOffset
        if diff > 0:
            op2._group.adjustOffsets(diff)
        elif diff < 0:
            self._group.adjustOffsets(-diff)
        for piece in list(op2._group._pieceSet):
            # Check if there's a matching piece in self's group
            match = None
            for sp in self._group._pieceSet:
                if sp._groupOffset == piece._groupOffset and sp._size == piece._size:
                    match = sp
                    break
            if match is not None:
                mergePairs.append(match._high)
                mergePairs.append(piece._high)
                piece._high._piece = None
                op2._group.removePiece(piece)
            else:
                piece.transferGroup(self._group)


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

        vn.setHigh(self, self._numMergeClasses - 1)
        if vn.getSymbolEntry() is not None:
            self.setSymbol(vn)

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
        self._updateSymbol()
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
            self._piece.markExtendCoverDirty()

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

    def updateFlags(self) -> None:
        """Public alias for flag update (matches C++ public method)."""
        self._updateFlags()

    def _updateFlags(self) -> None:
        if (self._highflags & HighVariable.flagsdirty) == 0:
            return
        from ghidra.ir.varnode import Varnode as VN
        fl = 0
        for vn in self._inst:
            fl |= vn.getFlags()
        self._flags &= (VN.mark | VN.typelock)
        self._flags |= fl & ~(VN.mark | VN.directwrite | VN.typelock)
        self._highflags &= ~HighVariable.flagsdirty

    def _updateType(self) -> None:
        if (self._highflags & HighVariable.typedirty) == 0:
            return
        self._highflags &= ~HighVariable.typedirty
        if (self._highflags & HighVariable.type_finalized) != 0:
            return
        from ghidra.ir.varnode import Varnode as VN
        vn = self.getTypeRepresentative()
        if vn is None:
            return
        self._type = vn.getType()
        self.stripType()
        self._flags &= ~VN.typelock
        if vn.isTypeLock():
            self._flags |= VN.typelock

    def _updateInternalCover(self) -> None:
        """(Re)derive the internal cover from member Varnodes."""
        if (self._highflags & HighVariable.coverdirty) == 0:
            return
        self._internalCover.clear()
        if self._inst and self._inst[0].hasCover():
            for vn in self._inst:
                c = vn.getCover()
                if c is not None:
                    self._internalCover.merge(c)
        self._highflags &= ~HighVariable.coverdirty

    def _updateCover(self) -> None:
        if self._piece is None:
            self._updateInternalCover()
        else:
            self._piece.updateIntersections()
            self._piece.updateCover()

    # --- Merge operations ---

    def remove(self, vn: Varnode) -> None:
        """Remove a member Varnode from this."""
        for i, v in enumerate(self._inst):
            if v is vn:
                self._inst.pop(i)
                self._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty |
                                    HighVariable.coverdirty | HighVariable.typedirty)
                if vn.getSymbolEntry() is not None:
                    self._highflags |= HighVariable.symboldirty
                if self._piece is not None:
                    self._piece.markExtendCoverDirty()
                return

    def mergeInternal(self, tv2: HighVariable, isspeculative: bool = False) -> None:
        """Merge another HighVariable into this."""
        self._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty | HighVariable.typedirty)
        if tv2._symbol is not None:
            if (tv2._highflags & HighVariable.symboldirty) == 0:
                self._symbol = tv2._symbol
                self._symboloffset = tv2._symboloffset
                self._highflags &= ~HighVariable.symboldirty
        if isspeculative:
            for vn in tv2._inst:
                vn.setHigh(self, vn.getMergeGroup() + self._numMergeClasses)
            self._numMergeClasses += tv2._numMergeClasses
        else:
            if self._numMergeClasses != 1 or tv2._numMergeClasses != 1:
                raise RuntimeError("Non-speculative merge after speculative merges")
            for vn in tv2._inst:
                vn.setHigh(self, vn.getMergeGroup())
        merged = sorted(self._inst + tv2._inst, key=lambda v: v.getAddr())
        self._inst = merged
        tv2._inst.clear()
        if ((self._highflags & HighVariable.coverdirty) == 0 and
                (tv2._highflags & HighVariable.coverdirty) == 0):
            self._internalCover.merge(tv2._internalCover)
        else:
            self._highflags |= HighVariable.coverdirty

    def setSymbol(self, vn: Varnode) -> None:
        """Update Symbol information for this from the given member Varnode."""
        entry = vn.getSymbolEntry()
        if entry is None:
            return
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if self._symbol is not None and sym is not None and self._symbol is not sym:
            if (self._highflags & HighVariable.symboldirty) == 0:
                raise RuntimeError("Symbols assigned to the same variable")
        if sym is not None:
            self._symbol = sym
        if vn.isProtoPartial() and self._piece is not None:
            self._symboloffset = self._piece.getOffset() + self._piece.getGroup().getSymbolOffset()
        elif hasattr(entry, 'isDynamic') and entry.isDynamic():
            self._symboloffset = -1
        elif (self._symbol is not None and hasattr(self._symbol, 'getType') and
              hasattr(entry, 'getAddr') and
              self._symbol.getType().getSize() == vn.getSize() and
              entry.getAddr() == vn.getAddr() and
              not (hasattr(entry, 'isPiece') and entry.isPiece())):
            self._symboloffset = -1
        else:
            if hasattr(vn, 'getAddr') and hasattr(entry, 'getAddr') and hasattr(entry, 'getOffset'):
                self._symboloffset = vn.getAddr().overlapJoin(
                    0, entry.getAddr(),
                    self._symbol.getType().getSize() if (self._symbol and hasattr(self._symbol, 'getType')) else 0
                ) + entry.getOffset()
            else:
                self._symboloffset = -1
        if (self._type is not None and hasattr(self._type, 'getMetatype') and
                self._type.getMetatype() == 'TYPE_PARTIALUNION'):
            self._highflags |= HighVariable.typedirty
        self._highflags &= ~HighVariable.symboldirty

    def setSymbolReference(self, sym, off: int) -> None:
        self._symbol = sym
        self._symboloffset = off
        self._highflags &= ~HighVariable.symboldirty

    def merge(self, tv2: HighVariable, testCache=None, isspeculative: bool = False) -> None:
        """Merge with another HighVariable taking into account groups."""
        if tv2 is self:
            return
        if testCache is not None and hasattr(testCache, 'moveIntersectTests'):
            testCache.moveIntersectTests(self, tv2)
        if self._piece is None and tv2._piece is None:
            self.mergeInternal(tv2, isspeculative)
            return
        if tv2._piece is None:
            self._piece.markExtendCoverDirty()
            self.mergeInternal(tv2, isspeculative)
            return
        if self._piece is None:
            self.transferPiece(tv2)
            self._piece.markExtendCoverDirty()
            self.mergeInternal(tv2, isspeculative)
            return
        if isspeculative:
            raise RuntimeError("Trying speculatively merge variables in separate groups")
        mergePairs = []
        self._piece.mergeGroups(tv2._piece, mergePairs)
        for i in range(0, len(mergePairs), 2):
            high1 = mergePairs[i]
            high2 = mergePairs[i + 1]
            if testCache is not None and hasattr(testCache, 'moveIntersectTests'):
                testCache.moveIntersectTests(high1, high2)
            high1.mergeInternal(high2, isspeculative)
        self._piece.markIntersectionDirty()

    def transferPiece(self, tv2: HighVariable) -> None:
        """Transfer ownership of another's VariablePiece to this."""
        self._piece = tv2._piece
        tv2._piece = None
        self._piece.setHigh(self)
        self._highflags |= (tv2._highflags & (HighVariable.intersectdirty | HighVariable.extendcoverdirty))
        tv2._highflags &= ~(HighVariable.intersectdirty | HighVariable.extendcoverdirty)

    def updateCover(self) -> None:
        """Public method to force cover update."""
        self._updateCover()

    def updateInternalCover(self) -> None:
        """(Re)derive the internal cover from member Varnodes."""
        self._updateInternalCover()

    def getSymbolEntry(self):
        """Get the SymbolEntry mapping to this or None."""
        for vn in self._inst:
            entry = vn.getSymbolEntry()
            if entry is not None:
                if hasattr(entry, 'getSymbol') and entry.getSymbol() is self._symbol:
                    return entry
        return None

    def finalizeDatatype(self, typeFactory=None) -> None:
        """Set a final data-type matching the associated Symbol."""
        self._highflags |= HighVariable.type_finalized

    def establishGroupSymbolOffset(self) -> None:
        """Transfer symbol offset of this to the VariableGroup."""
        group = self._piece.getGroup()
        off = self._symboloffset
        if off < 0:
            off = 0
        off -= self._piece.getOffset()
        if off < 0:
            raise RuntimeError("Symbol offset is incompatible with VariableGroup")
        group.setSymbolOffset(off)

    def stripType(self) -> None:
        """Take the stripped form of the current data-type."""
        if self._type is None or not hasattr(self._type, 'hasStripped'):
            return
        if not self._type.hasStripped():
            return
        meta = self._type.getMetatype() if hasattr(self._type, 'getMetatype') else None
        if meta in ('TYPE_PARTIALUNION', 'TYPE_PARTIALSTRUCT'):
            if self._symbol is not None and self._symboloffset != -1:
                submeta = self._symbol.getType().getMetatype() if hasattr(self._symbol, 'getType') else None
                if submeta in ('TYPE_STRUCT', 'TYPE_UNION'):
                    return
        elif hasattr(self._type, 'isEnumType') and self._type.isEnumType():
            if len(self._inst) == 1 and self._inst[0].isConstant():
                return
        if hasattr(self._type, 'getStripped'):
            self._type = self._type.getStripped()

    def _updateSymbol(self) -> None:
        """(Re)derive the Symbol and offset from member Varnodes."""
        if (self._highflags & HighVariable.symboldirty) == 0:
            return
        self._highflags &= ~HighVariable.symboldirty
        self._symbol = None
        for vn in self._inst:
            if vn.getSymbolEntry() is not None:
                self.setSymbol(vn)
                return

    def encode(self, encoder) -> None:
        """Encode this variable to stream as a <high> element."""
        if encoder is None or not hasattr(encoder, 'openElement'):
            return
        vn = self.getNameRepresentative()
        encoder.openElement('high')
        if vn is not None:
            encoder.writeUnsignedInteger('repref', vn.getCreateIndex())
        if self.isSpacebase() or self.isImplied():
            encoder.writeString('class', 'other')
        elif self.isPersist() and self.isAddrTied():
            encoder.writeString('class', 'global')
        elif self.isConstant():
            encoder.writeString('class', 'constant')
        elif not self.isPersist() and self._symbol is not None:
            cat = self._symbol.getCategory() if hasattr(self._symbol, 'getCategory') else None
            if cat == 'function_parameter':
                encoder.writeString('class', 'param')
            elif hasattr(self._symbol, 'getScope') and hasattr(self._symbol.getScope(), 'isGlobal') and self._symbol.getScope().isGlobal():
                encoder.writeString('class', 'global')
            else:
                encoder.writeString('class', 'local')
        else:
            encoder.writeString('class', 'other')
        if self.isTypeLock():
            encoder.writeBool('typelock', True)
        if self._symbol is not None:
            if hasattr(self._symbol, 'getId'):
                encoder.writeUnsignedInteger('symref', self._symbol.getId())
            if self._symboloffset >= 0:
                encoder.writeSignedInteger('offset', self._symboloffset)
        tp = self.getType()
        if tp is not None and hasattr(tp, 'encodeRef'):
            tp.encodeRef(encoder)
        for inst_vn in self._inst:
            encoder.openElement('addr')
            encoder.writeUnsignedInteger('ref', inst_vn.getCreateIndex())
            encoder.closeElement('addr')
        encoder.closeElement('high')

    @staticmethod
    def compareName(vn1, vn2) -> bool:
        """Return True if vn2's name would override vn1's."""
        if vn1.isNameLock():
            return False
        if vn2.isNameLock():
            return True
        if vn1.isUnaffected() != vn2.isUnaffected():
            return vn2.isUnaffected()
        if vn1.isPersist() != vn2.isPersist():
            return vn2.isPersist()
        if vn1.isInput() != vn2.isInput():
            return vn2.isInput()
        if vn1.isAddrTied() != vn2.isAddrTied():
            return vn2.isAddrTied()
        if vn1.isProtoPartial() != vn2.isProtoPartial():
            return vn2.isProtoPartial()
        spc1 = vn1.getSpace()
        spc2 = vn2.getSpace()
        if spc1 is not None and spc2 is not None:
            t1 = spc1.getType() if hasattr(spc1, 'getType') else None
            t2 = spc2.getType() if hasattr(spc2, 'getType') else None
            IPTR_INTERNAL = 'IPTR_INTERNAL'
            if t1 != IPTR_INTERNAL and t2 == IPTR_INTERNAL:
                return False
            if t1 == IPTR_INTERNAL and t2 != IPTR_INTERNAL:
                return True
        if vn1.isWritten() != vn2.isWritten():
            return vn2.isWritten()
        if not vn1.isWritten():
            return False
        t1 = vn1.getDef().getTime() if hasattr(vn1.getDef(), 'getTime') else 0
        t2 = vn2.getDef().getTime() if hasattr(vn2.getDef(), 'getTime') else 0
        if t1 != t2:
            return t2 < t1
        return False

    @staticmethod
    def compareJustLoc(a, b) -> bool:
        """Compare based on storage location."""
        return a.getAddr() < b.getAddr()

    @staticmethod
    def markExpression(vn, highList: list) -> int:
        """Mark and collect variables in expression using iterative DFS."""
        from ghidra.core.expression import PcodeOpNode
        from ghidra.core.opcodes import OpCode
        high = vn.getHigh()
        high.setMark()
        highList.append(high)
        retVal = 0
        if not vn.isWritten():
            return retVal
        path = []
        op = vn.getDef()
        if op.isCall():
            retVal |= 1
        if op.code() == OpCode.CPUI_LOAD:
            retVal |= 2
        path.append(PcodeOpNode(op, 0))
        while path:
            node = path[-1]
            if node.op.numInput() <= node.slot:
                path.pop()
                continue
            curVn = node.op.getIn(node.slot)
            node.slot += 1
            if curVn.isAnnotation():
                continue
            if hasattr(curVn, 'isExplicit') and curVn.isExplicit():
                h = curVn.getHigh()
                if h.isMark():
                    continue
                h.setMark()
                highList.append(h)
                continue
            if not curVn.isWritten():
                continue
            op = curVn.getDef()
            if op.isCall():
                retVal |= 1
            if op.code() == OpCode.CPUI_LOAD:
                retVal |= 2
            path.append(PcodeOpNode(op, 0))
        return retVal

    # --- Query helpers ---

    def hasName(self) -> bool:
        """Check if this HighVariable can be named."""
        indirectonly = True
        for vn in self._inst:
            if not vn.hasCover():
                if len(self._inst) > 1:
                    raise RuntimeError("Non-coverable varnode has been merged")
                return False
            if vn.isImplied():
                if len(self._inst) > 1:
                    raise RuntimeError("Implied varnode has been merged")
                return False
            if not vn.isIndirectOnly():
                indirectonly = False
        if self.isUnaffected():
            if not self.isInput():
                return False
            if indirectonly:
                return False
            vn = self.getInputVarnode()
            if vn is not None and not vn.isIllegalInput():
                if vn.isSpacebase():
                    return False
        return True

    def getTiedVarnode(self) -> Optional[Varnode]:
        """Find the first address-tied member Varnode."""
        for vn in self._inst:
            if vn.isAddrTied():
                return vn
        raise RuntimeError("Could not find address-tied varnode")

    def getInputVarnode(self) -> Optional[Varnode]:
        """Find (the) input member Varnode."""
        for vn in self._inst:
            if vn.isInput():
                return vn
        raise RuntimeError("Could not find input varnode")

    def getTypeRepresentative(self) -> Optional[Varnode]:
        """Get a member Varnode with the strongest data-type."""
        if not self._inst:
            return None
        rep = self._inst[0]
        for i in range(1, len(self._inst)):
            vn = self._inst[i]
            if rep.isTypeLock() != vn.isTypeLock():
                if vn.isTypeLock():
                    rep = vn
            elif (hasattr(vn.getType(), 'typeOrderBool') and
                  0 > vn.getType().typeOrderBool(rep.getType())):
                rep = vn
        return rep

    def getNameRepresentative(self) -> Optional[Varnode]:
        """Get a member Varnode that dictates the naming."""
        if (self._highflags & HighVariable.namerepdirty) == 0:
            return self._nameRepresentative
        self._highflags &= ~HighVariable.namerepdirty
        if not self._inst:
            return self._nameRepresentative
        self._nameRepresentative = self._inst[0]
        for i in range(1, len(self._inst)):
            vn = self._inst[i]
            if HighVariable.compareName(self._nameRepresentative, vn):
                self._nameRepresentative = vn
        return self._nameRepresentative

    def groupWith(self, off: int, hi2: HighVariable) -> None:
        """Put this and another HighVariable in the same intersection group."""
        if self._piece is None and hi2._piece is None:
            hi2._piece = VariablePiece(hi2, 0)
            self._piece = VariablePiece(self, off, hi2)
            hi2._piece.markIntersectionDirty()
            return
        if self._piece is None:
            if (hi2._highflags & HighVariable.intersectdirty) == 0:
                hi2._piece.markIntersectionDirty()
            self._highflags |= (HighVariable.intersectdirty | HighVariable.extendcoverdirty)
            off += hi2._piece.getOffset()
            self._piece = VariablePiece(self, off, hi2)
        elif hi2._piece is None:
            hi2Off = self._piece.getOffset() - off
            if hi2Off < 0:
                self._piece.getGroup().adjustOffsets(-hi2Off)
                hi2Off = 0
            if (self._highflags & HighVariable.intersectdirty) == 0:
                self._piece.markIntersectionDirty()
            hi2._highflags |= (HighVariable.intersectdirty | HighVariable.extendcoverdirty)
            hi2._piece = VariablePiece(hi2, hi2Off, self)
        else:
            offDiff = hi2._piece.getOffset() + off - self._piece.getOffset()
            if offDiff != 0:
                self._piece.getGroup().adjustOffsets(offDiff)
            hi2._piece.getGroup().combineGroups(self._piece.getGroup())
            hi2._piece.markIntersectionDirty()

    def printInfo(self) -> str:
        """Print information about this HighVariable."""
        self._updateType()
        parts = []
        if self._symbol is None:
            parts.append("Variable: UNNAMED\n")
        else:
            name = self._symbol.getName() if hasattr(self._symbol, 'getName') else str(self._symbol)
            s = f"Variable: {name}"
            if self._symboloffset != -1:
                s += "(partial)"
            parts.append(s + "\n")
        parts.append(f"Type: {self._type}\n\n")
        for vn in self._inst:
            mg = vn.getMergeGroup() if hasattr(vn, 'getMergeGroup') else 0
            parts.append(f"{mg}: ")
            if hasattr(vn, 'printInfo'):
                parts.append(str(vn.printInfo()))
            parts.append("\n")
        return "".join(parts)

    def printCover(self) -> str:
        if (self._highflags & HighVariable.coverdirty) == 0:
            return str(self._internalCover)
        return "Cover dirty"

    def instanceIndex(self, vn) -> int:
        """Find the index of a specific Varnode member."""
        for i, v in enumerate(self._inst):
            if v is vn:
                return i
        return -1

    def verifyCover(self) -> None:
        """Check that there are no internal Cover intersections (debug)."""
        accumCover = Cover()
        for i, vn in enumerate(self._inst):
            c = vn.getCover()
            if c is not None and accumCover.intersect(c) == 2:
                for j in range(i):
                    otherVn = self._inst[j]
                    oc = otherVn.getCover()
                    if oc is not None and oc.intersect(c) == 2:
                        if not otherVn.copyShadow(vn):
                            raise RuntimeError("HighVariable has internal intersection")
            if c is not None:
                accumCover.merge(c)

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
        self._highedgemap: dict = {}  # HighEdge -> bool

    @staticmethod
    def _gatherBlockVarnodes(a: HighVariable, blk: int, cover, res: list) -> None:
        """Gather Varnode instances that intersect a cover on a specific block."""
        for i in range(a.numInstances()):
            vn = a.getInstance(i)
            c = vn.getCover()
            if c is not None and hasattr(c, 'intersectByBlock'):
                if 1 < c.intersectByBlock(blk, cover):
                    res.append(vn)

    @staticmethod
    def _testBlockIntersection(a: HighVariable, blk: int, cover, relOff: int, blist: list) -> bool:
        """Test instances for intersection on a specific block with copy shadow check."""
        for i in range(a.numInstances()):
            vn = a.getInstance(i)
            c = vn.getCover()
            if c is None or not hasattr(c, 'intersectByBlock'):
                continue
            if 2 > c.intersectByBlock(blk, cover):
                continue
            for vn2 in blist:
                c2 = vn2.getCover()
                if c2 is not None and hasattr(c2, 'intersectByBlock'):
                    if 1 < c2.intersectByBlock(blk, c):
                        if vn.getSize() == vn2.getSize():
                            if not vn.copyShadow(vn2):
                                return True
                        else:
                            if hasattr(vn, 'partialCopyShadow'):
                                if not vn.partialCopyShadow(vn2, relOff):
                                    return True
                            else:
                                return True
        return False

    def _blockIntersection(self, a: HighVariable, b: HighVariable, blk: int) -> bool:
        """Test if two HighVariables intersect on a given block."""
        blist = []
        aCover = a.getCover()
        bCover = b.getCover()
        self._gatherBlockVarnodes(b, blk, aCover, blist)
        if self._testBlockIntersection(a, blk, bCover, 0, blist):
            return True
        if a._piece is not None:
            baseOff = a._piece.getOffset()
            for i in range(a._piece.numIntersection()):
                interPiece = a._piece.getIntersection(i)
                off = interPiece.getOffset() - baseOff
                if self._testBlockIntersection(interPiece.getHigh(), blk, bCover, off, blist):
                    return True
        if b._piece is not None:
            bBaseOff = b._piece.getOffset()
            for i in range(b._piece.numIntersection()):
                blist2 = []
                bPiece = b._piece.getIntersection(i)
                bOff = bPiece.getOffset() - bBaseOff
                self._gatherBlockVarnodes(bPiece.getHigh(), blk, aCover, blist2)
                if self._testBlockIntersection(a, blk, bCover, -bOff, blist2):
                    return True
                if a._piece is not None:
                    aBaseOff = a._piece.getOffset()
                    for j in range(a._piece.numIntersection()):
                        aInterPiece = a._piece.getIntersection(j)
                        aOff = (aInterPiece.getOffset() - aBaseOff) - bOff
                        if aOff > 0 and aOff >= bPiece.getSize():
                            continue
                        if aOff < 0 and -aOff >= aInterPiece.getSize():
                            continue
                        if self._testBlockIntersection(aInterPiece.getHigh(), blk, bCover, aOff, blist2):
                            return True
        return False

    def _purgeHigh(self, high: HighVariable) -> None:
        """Remove cached intersection tests for a given HighVariable."""
        hid = id(high)
        to_remove = []
        reverse_remove = []
        for edge_key, val in self._highedgemap.items():
            if edge_key.a is high:
                to_remove.append(edge_key)
                reverse_remove.append(HighEdge(edge_key.b, edge_key.a))
        for rk in reverse_remove:
            self._highedgemap.pop(rk, None)
        for k in to_remove:
            self._highedgemap.pop(k, None)

    def _testUntiedCallIntersection(self, tied: HighVariable, untied: HighVariable) -> bool:
        """Test if untied HighVariable intersects an address-tied one during a call."""
        if tied.isPersist():
            return False
        try:
            vn = tied.getTiedVarnode()
        except RuntimeError:
            return False
        if hasattr(vn, 'hasNoLocalAlias') and vn.hasNoLocalAlias():
            return False
        if self._affectingOps is not None:
            if hasattr(self._affectingOps, 'isPopulated') and not self._affectingOps.isPopulated():
                self._affectingOps.populate()
            uc = untied.getCover()
            if hasattr(uc, 'intersect') and hasattr(self._affectingOps, '__iter__'):
                return uc.intersect(self._affectingOps, vn)
        return False

    def updateHigh(self, a: HighVariable) -> bool:
        """Make sure given HighVariable's Cover is up-to-date."""
        if not a.isCoverDirty():
            return True
        a.updateCover()
        self._purgeHigh(a)
        return False

    def intersection(self, a: HighVariable, b: HighVariable) -> bool:
        """Test the intersection of two HighVariables and cache the result."""
        if a is b:
            return False
        ares = self.updateHigh(a)
        bres = self.updateHigh(b)
        if ares and bres:
            edge = HighEdge(a, b)
            cached = self._highedgemap.get(edge)
            if cached is not None:
                return cached
        res = False
        aCover = a.getCover()
        bCover = b.getCover()
        if aCover is not None and bCover is not None and hasattr(aCover, 'intersectList'):
            blockisect = []
            aCover.intersectList(blockisect, bCover, 2)
            for blk in blockisect:
                if self._blockIntersection(a, b, blk):
                    res = True
                    break
        if not res:
            aTied = a.isAddrTied()
            bTied = b.isAddrTied()
            if aTied != bTied:
                if aTied:
                    res = self._testUntiedCallIntersection(a, b)
                else:
                    res = self._testUntiedCallIntersection(b, a)
        self._highedgemap[HighEdge(a, b)] = res
        self._highedgemap[HighEdge(b, a)] = res
        return res

    def moveIntersectTests(self, high1: HighVariable, high2: HighVariable) -> None:
        """Translate intersection tests for high2 into tests for high1."""
        yesinter = []
        nointer = []
        for edge_key, val in list(self._highedgemap.items()):
            if edge_key.a is high2:
                b = edge_key.b
                if b is high1:
                    continue
                if val:
                    yesinter.append(b)
                else:
                    nointer.append(b)
                    b.setMark()
        # Purge all high2 tests
        self._purgeHigh(high2)
        # Remove high1 false tests if high2 also had no test with that variable
        to_remove = []
        for edge_key, val in self._highedgemap.items():
            if edge_key.a is high1:
                if not val:
                    if not edge_key.b.isMark():
                        to_remove.append(edge_key)
        for k in to_remove:
            del self._highedgemap[k]
        for h in nointer:
            h.clearMark()
        # Reinsert high2's intersection==true tests for high1
        for h in yesinter:
            self._highedgemap[HighEdge(high1, h)] = True
            self._highedgemap[HighEdge(h, high1)] = True

    def clear(self) -> None:
        """Clear any cached tests."""
        self._highedgemap.clear()
