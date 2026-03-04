"""
Corresponds to: varnode.hh / varnode.cc

The Varnode and VarnodeBank classes.
"""

from __future__ import annotations

from enum import IntFlag
from typing import TYPE_CHECKING, Optional, List, Iterator, Set

from ghidra.core.address import Address, calc_mask
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_JOIN, IPTR_FSPEC, IPTR_IOP, IPTR_INTERNAL, IPTR_PROCESSOR, IPTR_SPACEBASE
from ghidra.core.pcoderaw import VarnodeData

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.variable import HighVariable
    from ghidra.ir.cover import Cover
    from ghidra.analysis.funcdata import Funcdata


class Varnode:
    """A low-level variable or contiguous set of bytes described by an Address and a size.

    A Varnode is the fundamental variable in the p-code language model.
    It represents anything that holds data: registers, stack locations,
    global RAM locations, and constants.
    """

    # ---------- varnode_flags ----------
    mark            = 0x01
    constant        = 0x02
    annotation      = 0x04
    input           = 0x08
    written         = 0x10
    insert          = 0x20
    implied         = 0x40
    explict         = 0x80
    typelock        = 0x100
    namelock        = 0x200
    nolocalalias    = 0x400
    volatil         = 0x800
    externref       = 0x1000
    readonly        = 0x2000
    persist         = 0x4000
    addrtied        = 0x8000
    unaffected      = 0x10000
    spacebase       = 0x20000
    indirectonly    = 0x40000
    directwrite     = 0x80000
    addrforce       = 0x100000
    mapped          = 0x200000
    indirect_creation = 0x400000
    return_address  = 0x800000
    coverdirty      = 0x1000000
    precislo        = 0x2000000
    precishi        = 0x4000000
    indirectstorage = 0x8000000
    hiddenretparm   = 0x10000000
    incidental_copy = 0x20000000
    autolive_hold   = 0x40000000
    proto_partial   = 0x80000000

    # ---------- addl_flags ----------
    activeheritage  = 0x01
    writemask       = 0x02
    vacconsume      = 0x04
    lisconsume      = 0x08
    ptrcheck        = 0x10
    ptrflow         = 0x20
    unsignedprint   = 0x40
    longprint       = 0x80
    stack_store     = 0x100
    locked_input    = 0x200
    spacebase_placeholder = 0x400
    stop_uppropagation = 0x800
    has_implied_field = 0x1000

    def __init__(self, size: int, loc: Address, dt=None) -> None:
        self._flags: int = 0
        self._size: int = size
        self._create_index: int = 0
        self._mergegroup: int = 0
        self._addlflags: int = 0
        self._loc: Address = loc
        self._def: Optional[PcodeOp] = None
        self._high: Optional[HighVariable] = None
        self._mapentry = None  # SymbolEntry
        self._type = dt  # Datatype
        self._descend: List[PcodeOp] = []
        self._cover: Optional[Cover] = None
        self._temp_dataType = None
        self._valueSet = None
        self._consumed: int = ~0 & 0xFFFFFFFFFFFFFFFF
        self._nzm: int = 0

        spc = loc.getSpace()
        if spc is None:
            self._flags = 0
            return
        tp = spc.getType()
        if tp == IPTR_CONSTANT:
            self._flags = Varnode.constant
            self._nzm = loc.getOffset()
        elif tp in (IPTR_FSPEC, IPTR_IOP):
            self._flags = Varnode.annotation | Varnode.coverdirty
            self._nzm = ~0 & 0xFFFFFFFFFFFFFFFF
        else:
            self._flags = Varnode.coverdirty
            self._nzm = ~0 & 0xFFFFFFFFFFFFFFFF

    # --- Basic accessors ---

    def getAddr(self) -> Address:
        return self._loc

    def getSpace(self) -> Optional[AddrSpace]:
        return self._loc.getSpace()

    def getOffset(self) -> int:
        return self._loc.getOffset()

    def getSize(self) -> int:
        return self._size

    def getMergeGroup(self) -> int:
        return self._mergegroup

    def getDef(self) -> Optional[PcodeOp]:
        return self._def

    def getHigh(self) -> Optional[HighVariable]:
        return self._high

    def getSymbolEntry(self):
        return self._mapentry

    def getFlags(self) -> int:
        return self._flags

    def getType(self):
        return self._type

    def getCreateIndex(self) -> int:
        return self._create_index

    def getCover(self) -> Optional[Cover]:
        self.updateCover()
        return self._cover

    def getSpaceFromConst(self) -> Optional[AddrSpace]:
        """Get AddrSpace from this encoded constant Varnode (LOAD/STORE)."""
        # In C++ this casts the offset to an AddrSpace pointer; in Python we store the space ref.
        # The caller must resolve this appropriately.
        return self._loc.getSpace()

    def getTypeDefFacing(self):
        """Return the data-type of this when it is written to."""
        ct = self._type
        if ct is not None and hasattr(ct, 'needsResolution') and ct.needsResolution():
            return ct.findResolve(self._def, -1)
        return ct

    def getTypeReadFacing(self, op: PcodeOp):
        """Get the data-type of this when read by the given PcodeOp."""
        ct = self._type
        if ct is not None and hasattr(ct, 'needsResolution') and ct.needsResolution():
            return ct.findResolve(op, op.getSlot(self))
        return ct

    def getHighTypeDefFacing(self):
        """Return the data-type of the HighVariable when this is written to."""
        if self._high is None:
            return self._type
        ct = self._high.getType()
        if ct is not None and hasattr(ct, 'needsResolution') and ct.needsResolution():
            return ct.findResolve(self._def, -1)
        return ct

    def getHighTypeReadFacing(self, op: PcodeOp):
        """Return data-type of the HighVariable when read by the given PcodeOp."""
        if self._high is None:
            return self._type
        ct = self._high.getType()
        if ct is not None and hasattr(ct, 'needsResolution') and ct.needsResolution():
            return ct.findResolve(op, op.getSlot(self))
        return ct

    def setTempType(self, t) -> None:
        self._temp_dataType = t

    def getTempType(self):
        return self._temp_dataType

    def setValueSet(self, v) -> None:
        self._valueSet = v

    def getValueSet(self):
        return self._valueSet

    def getConsume(self) -> int:
        return self._consumed

    def setConsume(self, val: int) -> None:
        self._consumed = val

    def getNZMask(self) -> int:
        return self._nzm

    def getDescendants(self) -> List[PcodeOp]:
        return list(self._descend)

    def beginDescend(self) -> Iterator[PcodeOp]:
        return iter(self._descend)

    def endDescend(self):
        """Sentinel for iteration (Python: use len check instead)."""
        return None

    def hasNoDescend(self) -> bool:
        return len(self._descend) == 0

    # --- Flag setters/getters ---

    def setFlags(self, fl: int) -> None:
        self._flags |= fl

    def clearFlags(self, fl: int) -> None:
        self._flags &= ~fl

    def isAnnotation(self) -> bool:
        return (self._flags & Varnode.annotation) != 0

    def isImplied(self) -> bool:
        return (self._flags & Varnode.implied) != 0

    def isExplicit(self) -> bool:
        return (self._flags & Varnode.explict) != 0

    def isConstant(self) -> bool:
        return (self._flags & Varnode.constant) != 0

    def isFree(self) -> bool:
        return (self._flags & (Varnode.written | Varnode.input)) == 0

    def isInput(self) -> bool:
        return (self._flags & Varnode.input) != 0

    def isIllegalInput(self) -> bool:
        return (self._flags & (Varnode.input | Varnode.directwrite)) == Varnode.input

    def isIndirectOnly(self) -> bool:
        return (self._flags & Varnode.indirectonly) != 0

    def isExternalRef(self) -> bool:
        return (self._flags & Varnode.externref) != 0

    def hasActionProperty(self) -> bool:
        return (self._flags & (Varnode.readonly | Varnode.volatil)) != 0

    def isReadOnly(self) -> bool:
        return (self._flags & Varnode.readonly) != 0

    def isVolatile(self) -> bool:
        return (self._flags & Varnode.volatil) != 0

    def isPersist(self) -> bool:
        return (self._flags & Varnode.persist) != 0

    def isDirectWrite(self) -> bool:
        return (self._flags & Varnode.directwrite) != 0

    def isAddrTied(self) -> bool:
        return (self._flags & (Varnode.addrtied | Varnode.insert)) == (Varnode.addrtied | Varnode.insert)

    def isAddrForce(self) -> bool:
        return (self._flags & Varnode.addrforce) != 0

    def isAutoLive(self) -> bool:
        return (self._flags & (Varnode.addrforce | Varnode.autolive_hold)) != 0

    def isAutoLiveHold(self) -> bool:
        return (self._flags & Varnode.autolive_hold) != 0

    def isPtrCheck(self) -> bool:
        return (self._addlflags & Varnode.ptrcheck) != 0

    def isPtrFlow(self) -> bool:
        return (self._addlflags & Varnode.ptrflow) != 0

    def isSpacebasePlaceholder(self) -> bool:
        return (self._addlflags & Varnode.spacebase_placeholder) != 0

    def hasNoLocalAlias(self) -> bool:
        return (self._flags & Varnode.nolocalalias) != 0

    def isActiveHeritage(self) -> bool:
        return (self._addlflags & Varnode.activeheritage) != 0

    def isStackStore(self) -> bool:
        return (self._addlflags & Varnode.stack_store) != 0

    def isLockedInput(self) -> bool:
        return (self._addlflags & Varnode.locked_input) != 0

    def stopsUpPropagation(self) -> bool:
        return (self._addlflags & Varnode.stop_uppropagation) != 0

    def hasImpliedField(self) -> bool:
        return (self._addlflags & Varnode.has_implied_field) != 0

    def isWriteMask(self) -> bool:
        return (self._addlflags & Varnode.writemask) != 0

    def isUnsignedPrint(self) -> bool:
        return (self._addlflags & Varnode.unsignedprint) != 0

    def isLongPrint(self) -> bool:
        return (self._addlflags & Varnode.longprint) != 0

    def isConsumeList(self) -> bool:
        return (self._addlflags & Varnode.lisconsume) != 0

    def isConsumeVacuous(self) -> bool:
        return (self._addlflags & Varnode.vacconsume) != 0

    def setConsumeList(self) -> None:
        self._addlflags |= Varnode.lisconsume

    def setConsumeVacuous(self) -> None:
        self._addlflags |= Varnode.vacconsume

    def clearConsumeList(self) -> None:
        self._addlflags &= ~Varnode.lisconsume

    def clearConsumeVacuous(self) -> None:
        self._addlflags &= ~Varnode.vacconsume

    def clearAutoLiveHold(self) -> None:
        self._flags &= ~Varnode.autolive_hold

    def isMapped(self) -> bool:
        return (self._flags & Varnode.mapped) != 0

    def isUnaffected(self) -> bool:
        return (self._flags & Varnode.unaffected) != 0

    def isSpacebase(self) -> bool:
        return (self._flags & Varnode.spacebase) != 0

    def isReturnAddress(self) -> bool:
        return (self._flags & Varnode.return_address) != 0

    def isProtoPartial(self) -> bool:
        return (self._flags & Varnode.proto_partial) != 0

    def isWritten(self) -> bool:
        return (self._flags & Varnode.written) != 0

    def hasCover(self) -> bool:
        return (self._flags & (Varnode.constant | Varnode.annotation | Varnode.insert)) == Varnode.insert

    def isMark(self) -> bool:
        return (self._flags & Varnode.mark) != 0

    def isTypeLock(self) -> bool:
        return (self._flags & Varnode.typelock) != 0

    def isNameLock(self) -> bool:
        return (self._flags & Varnode.namelock) != 0

    def isHeritageKnown(self) -> bool:
        return (self._flags & (Varnode.insert | Varnode.constant | Varnode.annotation)) != 0

    def isIndirectZero(self) -> bool:
        return (self._flags & (Varnode.indirect_creation | Varnode.constant)) == (Varnode.indirect_creation | Varnode.constant)

    def isExtraOut(self) -> bool:
        return (self._flags & (Varnode.indirect_creation | Varnode.addrtied)) == Varnode.indirect_creation

    def isPrecisLo(self) -> bool:
        return (self._flags & Varnode.precislo) != 0

    def isPrecisHi(self) -> bool:
        return (self._flags & Varnode.precishi) != 0

    def isIncidentalCopy(self) -> bool:
        return (self._flags & Varnode.incidental_copy) != 0

    def constantMatch(self, val: int) -> bool:
        if not self.isConstant():
            return False
        return self._loc.getOffset() == val

    def isConstantExtended(self) -> tuple:
        """Is this an (extended) constant? Returns (True, [lo, hi]) or (False, None)."""
        from ghidra.core.opcodes import OpCode
        if self.isConstant():
            return (True, [self.getOffset(), 0])
        if not self.isWritten() or self._size <= 8:
            return (False, None)
        if self._size > 16:
            return (False, None)
        opc = self._def.code()
        if opc == OpCode.CPUI_INT_ZEXT:
            vn0 = self._def.getIn(0)
            if vn0.isConstant():
                return (True, [vn0.getOffset(), 0])
        elif opc == OpCode.CPUI_INT_SEXT:
            vn0 = self._def.getIn(0)
            if vn0.isConstant():
                val0 = vn0.getOffset()
                if vn0.getSize() < 8:
                    # sign extend
                    bits = vn0.getSize() * 8
                    if val0 & (1 << (bits - 1)):
                        val0 |= (~0 & 0xFFFFFFFFFFFFFFFF) << bits
                        val0 &= 0xFFFFFFFFFFFFFFFF
                val1 = 0xFFFFFFFFFFFFFFFF if (val0 & (1 << 63)) else 0
                return (True, [val0, val1])
        elif opc == OpCode.CPUI_PIECE:
            vnlo = self._def.getIn(1)
            if vnlo.isConstant():
                val0 = vnlo.getOffset()
                vnhi = self._def.getIn(0)
                if vnhi.isConstant():
                    val1 = vnhi.getOffset()
                    if vnlo.getSize() == 8:
                        return (True, [val0, val1])
                    val0 |= val1 << (8 * vnlo.getSize())
                    val0 &= 0xFFFFFFFFFFFFFFFF
                    val1 >>= 8 * (8 - vnlo.getSize())
                    val1 &= 0xFFFFFFFFFFFFFFFF
                    return (True, [val0, val1])
        return (False, None)

    def isEventualConstant(self, maxBinary: int, maxLoad: int) -> bool:
        """Will this Varnode ultimately collapse to a constant?"""
        from ghidra.core.opcodes import OpCode
        curVn = self
        while not curVn.isConstant():
            if not curVn.isWritten():
                return False
            op = curVn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_LOAD:
                if maxLoad == 0:
                    return False
                maxLoad -= 1
                curVn = op.getIn(1)
            elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB,
                         OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR,
                         OpCode.CPUI_INT_AND):
                if maxBinary == 0:
                    return False
                if not op.getIn(0).isEventualConstant(maxBinary - 1, maxLoad):
                    return False
                return op.getIn(1).isEventualConstant(maxBinary - 1, maxLoad)
            elif opc in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT, OpCode.CPUI_COPY):
                curVn = op.getIn(0)
            elif opc in (OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT,
                         OpCode.CPUI_INT_SRIGHT, OpCode.CPUI_INT_MULT):
                if not op.getIn(1).isConstant():
                    return False
                curVn = op.getIn(0)
            else:
                return False
        return True

    # --- Mutators (friend-class level) ---

    def setInput(self) -> None:
        self._flags |= (Varnode.input | Varnode.coverdirty)

    def setDef(self, op: PcodeOp) -> None:
        self._def = op
        self._flags |= Varnode.written

    def setHigh(self, tv: HighVariable, mg: int = 0) -> None:
        self._high = tv
        self._mergegroup = mg

    def setMark(self) -> None:
        self._flags |= Varnode.mark

    def clearMark(self) -> None:
        self._flags &= ~Varnode.mark

    def setDirectWrite(self) -> None:
        self._flags |= Varnode.directwrite

    def clearDirectWrite(self) -> None:
        self._flags &= ~Varnode.directwrite

    def setImplied(self) -> None:
        self._flags |= Varnode.implied

    def clearImplied(self) -> None:
        self._flags &= ~Varnode.implied

    def setExplicit(self) -> None:
        self._flags |= Varnode.explict

    def clearExplicit(self) -> None:
        self._flags &= ~Varnode.explict

    def setAddrForce(self) -> None:
        self._flags |= Varnode.addrforce

    def clearAddrForce(self) -> None:
        self._flags &= ~Varnode.addrforce

    def setReturnAddress(self) -> None:
        self._flags |= Varnode.return_address

    def clearReturnAddress(self) -> None:
        self._flags &= ~Varnode.return_address

    def setPtrCheck(self) -> None:
        self._addlflags |= Varnode.ptrcheck

    def clearPtrCheck(self) -> None:
        self._addlflags &= ~Varnode.ptrcheck

    def setPtrFlow(self) -> None:
        self._addlflags |= Varnode.ptrflow

    def clearPtrFlow(self) -> None:
        self._addlflags &= ~Varnode.ptrflow

    def setSpacebasePlaceholder(self) -> None:
        self._addlflags |= Varnode.spacebase_placeholder

    def clearSpacebasePlaceholder(self) -> None:
        self._addlflags &= ~Varnode.spacebase_placeholder

    def setPrecisLo(self) -> None:
        self.setFlags(Varnode.precislo)

    def clearPrecisLo(self) -> None:
        self.clearFlags(Varnode.precislo)

    def setPrecisHi(self) -> None:
        self.setFlags(Varnode.precishi)

    def clearPrecisHi(self) -> None:
        self.clearFlags(Varnode.precishi)

    def setWriteMask(self) -> None:
        self._addlflags |= Varnode.writemask

    def clearWriteMask(self) -> None:
        self._addlflags &= ~Varnode.writemask

    def setAutoLiveHold(self) -> None:
        self._flags |= Varnode.autolive_hold

    def setProtoPartial(self) -> None:
        self._flags |= Varnode.proto_partial

    def clearProtoPartial(self) -> None:
        self._flags &= ~Varnode.proto_partial

    def setUnsignedPrint(self) -> None:
        self._addlflags |= Varnode.unsignedprint

    def setLongPrint(self) -> None:
        self._addlflags |= Varnode.longprint

    def setStopUpPropagation(self) -> None:
        self._addlflags |= Varnode.stop_uppropagation

    def clearStopUpPropagation(self) -> None:
        self._addlflags &= ~Varnode.stop_uppropagation

    def setImpliedField(self) -> None:
        self._addlflags |= Varnode.has_implied_field

    def setActiveHeritage(self) -> None:
        self._addlflags |= Varnode.activeheritage

    def clearActiveHeritage(self) -> None:
        self._addlflags &= ~Varnode.activeheritage

    def setStackStore(self) -> None:
        self._addlflags |= Varnode.stack_store

    def setLockedInput(self) -> None:
        self._addlflags |= Varnode.locked_input

    def setUnaffected(self) -> None:
        self._flags |= Varnode.unaffected

    def updateType(self, ct, lock: bool = None, override: bool = False) -> bool:
        """Set the Datatype if not locked. Two-arg form: updateType(ct). Three-arg: updateType(ct, lock, over)."""
        if lock is None:
            # Simple form: updateType(ct)
            if self._type is ct or self.isTypeLock():
                return False
            self._type = ct
            if self._high is not None and hasattr(self._high, 'typeDirty'):
                self._high.typeDirty()
            return True
        # Extended form: updateType(ct, lock, override)
        if ct is not None and hasattr(ct, 'getMetatype'):
            from ghidra.types.datatypes import TYPE_UNKNOWN
            if ct.getMetatype() == TYPE_UNKNOWN:
                lock = False
        if self.isTypeLock() and not override:
            return False
        if self._type is ct and self.isTypeLock() == lock:
            return False
        self._flags &= ~Varnode.typelock
        if lock:
            self._flags |= Varnode.typelock
        self._type = ct
        if self._high is not None and hasattr(self._high, 'typeDirty'):
            self._high.typeDirty()
        return True

    def copySymbol(self, vn: Varnode) -> None:
        """Copy any symbol and type information from vn into this."""
        self._type = vn._type
        self._mapentry = vn._mapentry
        self._flags &= ~(Varnode.typelock | Varnode.namelock)
        self._flags |= (Varnode.typelock | Varnode.namelock) & vn._flags
        if self._high is not None:
            if hasattr(self._high, 'typeDirty'):
                self._high.typeDirty()
            if self._mapentry is not None and hasattr(self._high, 'setSymbol'):
                self._high.setSymbol(self)

    def copySymbolIfValid(self, vn: Varnode) -> None:
        """Copy symbol info from vn if constant value matches."""
        entry = vn.getSymbolEntry()
        if entry is None:
            return
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if sym is None:
            return
        # Simplified: just copy if both are constants
        if self.isConstant() and vn.isConstant():
            self.copySymbol(vn)

    def setSymbolProperties(self, entry) -> bool:
        """Set properties from the given SymbolEntry to this Varnode."""
        res = False
        if hasattr(entry, 'updateType'):
            res = entry.updateType(self)
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if sym is not None and hasattr(sym, 'isTypeLocked') and sym.isTypeLocked():
            if self._mapentry is not entry:
                self._mapentry = entry
                if self._high is not None and hasattr(self._high, 'setSymbol'):
                    self._high.setSymbol(self)
                res = True
        if hasattr(entry, 'getAllFlags'):
            self.setFlags(entry.getAllFlags() & ~Varnode.typelock)
        return res

    def setSymbolEntry(self, entry) -> None:
        """Attach a Symbol to this Varnode."""
        self._mapentry = entry
        fl = Varnode.mapped
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if sym is not None and hasattr(sym, 'isNameLocked') and sym.isNameLocked():
            fl |= Varnode.namelock
        self.setFlags(fl)
        if self._high is not None and hasattr(self._high, 'setSymbol'):
            self._high.setSymbol(self)

    def setSymbolReference(self, entry, off: int) -> None:
        """Attach a Symbol reference to this."""
        if self._high is not None and hasattr(self._high, 'setSymbolReference'):
            sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
            if sym is not None:
                self._high.setSymbolReference(sym, off)

    def clearSymbolLinks(self) -> None:
        """Clear any Symbol attached to this Varnode (and all in same HighVariable)."""
        if self._high is None:
            self._mapentry = None
            self.clearFlags(Varnode.namelock | Varnode.typelock | Varnode.mapped)
            return
        foundEntry = False
        for i in range(self._high.numInstances()):
            vn = self._high.getInstance(i)
            foundEntry = foundEntry or (vn._mapentry is not None)
            vn._mapentry = None
            vn.clearFlags(Varnode.namelock | Varnode.typelock | Varnode.mapped)
        if foundEntry and hasattr(self._high, 'symbolDirty'):
            self._high.symbolDirty()

    def addDescend(self, op: PcodeOp) -> None:
        self._descend.append(op)

    def eraseDescend(self, op: PcodeOp) -> None:
        try:
            self._descend.remove(op)
        except ValueError:
            pass
        self.setFlags(Varnode.coverdirty)

    def destroyDescend(self) -> None:
        self._descend.clear()

    def loneDescend(self) -> Optional[PcodeOp]:
        """Return unique reading PcodeOp, or None if zero or more than 1."""
        if len(self._descend) != 1:
            return None
        return self._descend[0]

    # --- Cover management (friend-level) ---

    def updateCover(self) -> None:
        """Rebuild variable cover if dirty."""
        if (self._flags & Varnode.coverdirty) != 0:
            if self.hasCoverRaw() and self._cover is not None:
                self._cover.rebuild(self)
            self._flags &= ~Varnode.coverdirty

    def hasCoverRaw(self) -> bool:
        """Internal: check cover eligibility without triggering update."""
        return (self._flags & (Varnode.constant | Varnode.annotation | Varnode.insert)) == Varnode.insert

    def calcCover(self) -> None:
        """Initialize a new Cover and set dirty bit."""
        if self.hasCoverRaw():
            from ghidra.ir.cover import Cover as CoverCls
            self._cover = CoverCls()
            self.setFlags(Varnode.coverdirty)

    def clearCover(self) -> None:
        """Turn off any coverage information."""
        self._cover = None

    # --- Geometric / overlap methods ---

    def intersects(self, op_or_addr, op2size: int = None) -> bool:
        """Return True if the storage locations intersect."""
        if op2size is not None:
            # intersects(Address, int) overload
            addr = op_or_addr
            if self._loc.getSpace() is not addr.getSpace():
                return False
            if self._loc.getSpace().getType() == IPTR_CONSTANT:
                return False
            a = self._loc.getOffset()
            b = addr.getOffset()
            if b < a:
                return a < b + op2size
            return b < a + self._size
        op = op_or_addr
        if isinstance(op, Varnode):
            if self._loc.getSpace() is not op._loc.getSpace():
                return False
            if self._loc.getSpace().getType() == IPTR_CONSTANT:
                return False
            a = self._loc.getOffset()
            b = op._loc.getOffset()
            if b < a:
                return a < b + op._size
            return b < a + self._size
        return False

    def overlap(self, op_or_addr, op2size: int = None) -> int:
        """Return relative point of overlap between two Varnodes, or -1."""
        if op2size is not None:
            addr = op_or_addr
            if not self._loc.isBigEndian():
                return self._loc.overlap(0, addr, op2size)
            else:
                over = self._loc.overlap(self._size - 1, addr, op2size)
                if over != -1:
                    return op2size - 1 - over
            return -1
        if isinstance(op_or_addr, Varnode):
            op = op_or_addr
            if not self._loc.isBigEndian():
                return self._loc.overlap(0, op._loc, op._size)
            else:
                over = self._loc.overlap(self._size - 1, op._loc, op._size)
                if over != -1:
                    return op._size - 1 - over
            return -1
        return -1

    def overlapJoin(self, op: Varnode) -> int:
        """Return relative point of overlap, where the given Varnode may be in the join space."""
        if not self._loc.isBigEndian():
            if hasattr(self._loc, 'overlapJoin'):
                return self._loc.overlapJoin(0, op._loc, op._size)
            return self._loc.overlap(0, op._loc, op._size)
        else:
            if hasattr(self._loc, 'overlapJoin'):
                over = self._loc.overlapJoin(self._size - 1, op._loc, op._size)
            else:
                over = self._loc.overlap(self._size - 1, op._loc, op._size)
            if over != -1:
                return op._size - 1 - over
        return -1

    def characterizeOverlap(self, op: Varnode) -> int:
        """Return 0=no overlap, 1=partial overlap, 2=identical storage."""
        if self._loc.getSpace() is not op._loc.getSpace():
            return 0
        if self._loc.getOffset() == op._loc.getOffset():
            return 2 if self._size == op._size else 1
        elif self._loc.getOffset() < op._loc.getOffset():
            thisright = self._loc.getOffset() + (self._size - 1)
            return 0 if thisright < op._loc.getOffset() else 1
        else:
            opright = op._loc.getOffset() + (op._size - 1)
            return 0 if opright < self._loc.getOffset() else 1

    def contains(self, op: Varnode) -> int:
        """Return info about containment of op in this.
        -1 if op.loc starts before this, 0 contained, 1 op.start contained,
        2 op.loc comes after this, 3 non-comparable spaces."""
        if self._loc.getSpace() is not op._loc.getSpace():
            return 3
        if self._loc.getSpace().getType() == IPTR_CONSTANT:
            return 3
        a = self._loc.getOffset()
        b = op._loc.getOffset()
        if b < a:
            return -1
        if b >= a + self._size:
            return 2
        if b + op._size > a + self._size:
            return 1
        return 0

    def termOrder(self, op: Varnode) -> int:
        """Compare term order. -1 if this before op, 1 if op before this, 0 otherwise."""
        from ghidra.core.opcodes import OpCode
        if self.isConstant():
            if not op.isConstant():
                return 1
        else:
            if op.isConstant():
                return -1
            vn = self
            if vn.isWritten() and vn.getDef().code() == OpCode.CPUI_INT_MULT:
                if vn.getDef().getIn(1).isConstant():
                    vn = vn.getDef().getIn(0)
            if op.isWritten() and op.getDef().code() == OpCode.CPUI_INT_MULT:
                if op.getDef().getIn(1).isConstant():
                    op = op.getDef().getIn(0)
            if vn.getAddr() < op.getAddr():
                return -1
            if op.getAddr() < vn.getAddr():
                return 1
        return 0

    def getUsePoint(self, fd: Funcdata) -> Address:
        """Get Address when this Varnode first comes into scope."""
        if self.isWritten():
            return self._def.getAddr()
        return fd.getAddress()

    def getLocalType(self, blockup_ref: list = None):
        """Calculate type of Varnode based on local information."""
        if self.isTypeLock():
            return self._type
        ct = None
        if self._def is not None:
            ct = self._def.outputTypeLocal() if hasattr(self._def, 'outputTypeLocal') else None
            if ct is not None and hasattr(self._def, 'stopsTypePropagation') and self._def.stopsTypePropagation():
                if blockup_ref is not None:
                    blockup_ref[0] = True
                return ct
        for op in self._descend:
            i = op.getSlot(self)
            newct = op.inputTypeLocal(i) if hasattr(op, 'inputTypeLocal') else None
            if newct is None:
                continue
            if ct is None:
                ct = newct
            else:
                if hasattr(newct, 'typeOrder') and newct.typeOrder(ct) < 0:
                    ct = newct
        return ct

    def isBooleanValue(self, useAnnotation: bool) -> bool:
        """Does this Varnode hold a formal boolean value?"""
        if self.isWritten():
            return self._def.isCalculatedBool() if hasattr(self._def, 'isCalculatedBool') else False
        if not useAnnotation:
            return False
        if (self._flags & (Varnode.input | Varnode.typelock)) == (Varnode.input | Varnode.typelock):
            if self._size == 1 and self._type is not None and hasattr(self._type, 'getMetatype'):
                from ghidra.types.datatypes import TYPE_BOOL
                if self._type.getMetatype() == TYPE_BOOL:
                    return True
        return False

    def isZeroExtended(self, baseSize: int) -> bool:
        """Is this zero extended from something of the given size?"""
        if baseSize >= self._size:
            return False
        from ghidra.core.opcodes import OpCode
        if self._size > 8:
            if not self.isWritten():
                return False
            if self._def.code() != OpCode.CPUI_INT_ZEXT:
                return False
            if self._def.getIn(0).getSize() > baseSize:
                return False
            return True
        mask = self._nzm >> (8 * baseSize)
        return mask == 0

    def copyShadow(self, op2: Varnode) -> bool:
        """Are this and op2 copied from the same source?"""
        from ghidra.core.opcodes import OpCode
        if self is op2:
            return True
        vn = self
        while vn.isWritten() and vn.getDef().code() == OpCode.CPUI_COPY:
            vn = vn.getDef().getIn(0)
            if vn is op2:
                return True
        while op2.isWritten() and op2.getDef().code() == OpCode.CPUI_COPY:
            op2 = op2.getDef().getIn(0)
            if vn is op2:
                return True
        return False

    def findSubpieceShadow(self, leastByte: int, whole: Varnode, recurse: int) -> bool:
        """Try to find a SUBPIECE operation producing this from whole."""
        from ghidra.core.opcodes import OpCode
        vn = self
        while vn.isWritten() and vn.getDef().code() == OpCode.CPUI_COPY:
            vn = vn.getDef().getIn(0)
        if not vn.isWritten():
            if vn.isConstant():
                w = whole
                while w.isWritten() and w.getDef().code() == OpCode.CPUI_COPY:
                    w = w.getDef().getIn(0)
                if not w.isConstant():
                    return False
                off = w.getOffset() >> (leastByte * 8)
                off &= calc_mask(vn.getSize())
                return off == vn.getOffset()
            return False
        opc = vn.getDef().code()
        if opc == OpCode.CPUI_SUBPIECE:
            tmpvn = vn.getDef().getIn(0)
            off = vn.getDef().getIn(1).getOffset()
            if off != leastByte or tmpvn.getSize() != whole.getSize():
                return False
            if tmpvn is whole:
                return True
            while tmpvn.isWritten() and tmpvn.getDef().code() == OpCode.CPUI_COPY:
                tmpvn = tmpvn.getDef().getIn(0)
                if tmpvn is whole:
                    return True
        elif opc == OpCode.CPUI_MULTIEQUAL:
            recurse += 1
            if recurse > 1:
                return False
            w = whole
            while w.isWritten() and w.getDef().code() == OpCode.CPUI_COPY:
                w = w.getDef().getIn(0)
            if not w.isWritten():
                return False
            bigOp = w.getDef()
            if bigOp.code() != OpCode.CPUI_MULTIEQUAL:
                return False
            smallOp = vn.getDef()
            if bigOp.getParent() is not smallOp.getParent():
                return False
            for i in range(smallOp.numInput()):
                if not smallOp.getIn(i).findSubpieceShadow(leastByte, bigOp.getIn(i), recurse):
                    return False
            return True
        return False

    def findPieceShadow(self, leastByte: int, piece: Varnode) -> bool:
        """Try to find a PIECE operation that produces this from a given piece."""
        from ghidra.core.opcodes import OpCode
        vn = self
        while vn.isWritten() and vn.getDef().code() == OpCode.CPUI_COPY:
            vn = vn.getDef().getIn(0)
        if not vn.isWritten():
            return False
        opc = vn.getDef().code()
        if opc == OpCode.CPUI_PIECE:
            tmpvn = vn.getDef().getIn(1)  # Least significant part
            if leastByte >= tmpvn.getSize():
                leastByte -= tmpvn.getSize()
                tmpvn = vn.getDef().getIn(0)
            else:
                if piece.getSize() + leastByte > tmpvn.getSize():
                    return False
            if leastByte == 0 and tmpvn.getSize() == piece.getSize():
                if tmpvn is piece:
                    return True
                while tmpvn.isWritten() and tmpvn.getDef().code() == OpCode.CPUI_COPY:
                    tmpvn = tmpvn.getDef().getIn(0)
                    if tmpvn is piece:
                        return True
                return False
            return tmpvn.findPieceShadow(leastByte, piece)
        return False

    def partialCopyShadow(self, op2: Varnode, relOff: int) -> bool:
        """Is one of this or op2 a partial copy of the other?"""
        if self._size < op2._size:
            vn = self
        elif self._size > op2._size:
            vn = op2
            op2 = self
            relOff = -relOff
        else:
            return False
        if relOff < 0:
            return False
        if relOff + vn.getSize() > op2.getSize():
            return False
        bigEndian = self.getSpace().isBigEndian() if self.getSpace() else False
        leastByte = (op2.getSize() - vn.getSize()) - relOff if bigEndian else relOff
        if vn.findSubpieceShadow(leastByte, op2, 0):
            return True
        if op2.findPieceShadow(leastByte, vn):
            return True
        return False

    def getStructuredType(self):
        """Get structure/array/union that this is a piece of."""
        if self._mapentry is not None and hasattr(self._mapentry, 'getSymbol'):
            ct = self._mapentry.getSymbol().getType()
        else:
            ct = self._type
        if ct is not None and hasattr(ct, 'isPieceStructured') and ct.isPieceStructured():
            return ct
        return None

    def printInfo(self) -> str:
        """Print raw attribute info about the Varnode."""
        parts = [self.printRaw()]
        if self.isAddrTied():
            parts.append('tied')
        if self.isMapped():
            parts.append('mapped')
        if self.isPersist():
            parts.append('persistent')
        if self.isTypeLock():
            parts.append('tlock')
        if self.isNameLock():
            parts.append('nlock')
        if self.isSpacebase():
            parts.append('base')
        if self.isUnaffected():
            parts.append('unaff')
        if self.isImplied():
            parts.append('implied')
        if self.isAddrForce():
            parts.append('addrforce')
        if self.isReadOnly():
            parts.append('readonly')
        parts.append(f'consumed=0x{self._consumed:x}')
        parts.append(f'create=0x{self._create_index:x}')
        return ' '.join(parts)

    def printCover(self) -> str:
        """Print raw coverage info."""
        if self._cover is None:
            return 'No cover'
        if (self._flags & Varnode.coverdirty) != 0:
            return 'Cover is dirty'
        return str(self._cover)

    def printRawHeritage(self, depth: int = 0) -> str:
        """Print a simple SSA subtree rooted at this."""
        indent = ' ' * depth
        if self.isConstant():
            return f'{indent}{self.printRaw()}\n'
        lines = f'{indent}{self.printRaw()} '
        if self._def is not None:
            lines += str(self._def)
        else:
            lines += self.printRaw()
        if self.isInput():
            lines += ' Input'
        if self.isConstant():
            lines += ' Constant'
        if self.isAnnotation():
            lines += ' Code'
        if self._def is not None:
            lines += f'\t\t{self._def.getSeqNum()}\n'
            for i in range(self._def.numInput()):
                lines += self._def.getIn(i).printRawHeritage(depth + 5)
        else:
            lines += '\n'
        return lines

    def encode(self, encoder) -> None:
        """Encode a description of this to a stream."""
        encoder.openElement('addr')
        spc = self._loc.getSpace()
        if spc is not None:
            encoder.writeString('space', spc.getName())
        encoder.writeUnsignedInteger('offset', self._loc.getOffset())
        encoder.writeSignedInteger('size', self._size)
        encoder.writeUnsignedInteger('ref', self._create_index)
        if self._mergegroup != 0:
            encoder.writeSignedInteger('grp', self._mergegroup)
        if self.isPersist():
            encoder.writeBool('persists', True)
        if self.isAddrTied():
            encoder.writeBool('addrtied', True)
        if self.isUnaffected():
            encoder.writeBool('unaff', True)
        if self.isInput():
            encoder.writeBool('input', True)
        if self.isVolatile():
            encoder.writeBool('volatile', True)
        encoder.closeElement('addr')

    @staticmethod
    def comparePointers(a: Varnode, b: Varnode) -> bool:
        return a < b

    @staticmethod
    def printRawStatic(vn) -> str:
        if vn is None:
            return '<null>'
        return vn.printRaw()

    def __lt__(self, op2: Varnode) -> bool:
        if self._loc != op2._loc:
            return self._loc < op2._loc
        if self._size != op2._size:
            return self._size < op2._size
        f1 = self._flags & (Varnode.input | Varnode.written)
        f2 = op2._flags & (Varnode.input | Varnode.written)
        if f1 != f2:
            return ((f1 - 1) & 0xFFFFFFFF) < ((f2 - 1) & 0xFFFFFFFF)
        if f1 == Varnode.written:
            if self._def is not None and op2._def is not None:
                if self._def.getSeqNum() != op2._def.getSeqNum():
                    return self._def.getSeqNum() < op2._def.getSeqNum()
        return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Varnode):
            return NotImplemented
        if self._loc != other._loc:
            return False
        if self._size != other._size:
            return False
        f1 = self._flags & (Varnode.input | Varnode.written)
        f2 = other._flags & (Varnode.input | Varnode.written)
        if f1 != f2:
            return False
        if f1 == Varnode.written:
            if self._def is not None and other._def is not None:
                if self._def.getSeqNum() != other._def.getSeqNum():
                    return False
        return True

    def __hash__(self) -> int:
        return id(self)

    def printRaw(self) -> str:
        """Print a simple identifier for the Varnode."""
        if self.isConstant():
            return f"#{self._loc.getOffset():#x}"
        sname = self._loc.getSpace().getName() if self._loc.getSpace() else "?"
        return f"({sname}, {self._loc.getOffset():#x}, {self._size})"

    def __repr__(self) -> str:
        extra = ""
        if self.isConstant():
            extra = " const"
        if self.isInput():
            extra += " input"
        if self.isWritten():
            extra += " written"
        return f"Varnode({self.printRaw()}{extra})"


# =========================================================================
# Comparators for VarnodeBank sorted containers
# =========================================================================

def varnode_compare_loc_def(a: Varnode, b: Varnode) -> bool:
    """Compare two Varnodes by location then definition."""
    if a.getAddr() != b.getAddr():
        return a.getAddr() < b.getAddr()
    if a.getSize() != b.getSize():
        return a.getSize() < b.getSize()
    a_flags = a.getFlags() & (Varnode.input | Varnode.written)
    b_flags = b.getFlags() & (Varnode.input | Varnode.written)
    if a_flags != b_flags:
        return a_flags < b_flags
    if a.isWritten() and b.isWritten():
        return a.getDef().getSeqNum() < b.getDef().getSeqNum()
    return False


def varnode_compare_def_loc(a: Varnode, b: Varnode) -> bool:
    """Compare two Varnodes by definition then location."""
    a_flags = a.getFlags() & (Varnode.input | Varnode.written)
    b_flags = b.getFlags() & (Varnode.input | Varnode.written)
    if a_flags != b_flags:
        return a_flags < b_flags
    if a.isWritten() and b.isWritten():
        if a.getDef().getSeqNum() != b.getDef().getSeqNum():
            return a.getDef().getSeqNum() < b.getDef().getSeqNum()
    if a.getAddr() != b.getAddr():
        return a.getAddr() < b.getAddr()
    return a.getSize() < b.getSize()


# =========================================================================
# VarnodeBank
# =========================================================================

class VarnodeBank:
    """Container for Varnode objects within a function.

    Maintains two sorted sets of Varnodes:
      - loc_tree: sorted by location (address) then definition
      - def_tree: sorted by definition then location
    """

    def __init__(self) -> None:
        self._loc_tree: List[Varnode] = []  # Sorted by location
        self._def_tree: List[Varnode] = []  # Sorted by definition
        self._create_index: int = 0
        self._uniq_id: int = 0

    def clear(self) -> None:
        self._loc_tree.clear()
        self._def_tree.clear()
        self._create_index = 0

    def size(self) -> int:
        return len(self._loc_tree)

    def empty(self) -> bool:
        return len(self._loc_tree) == 0

    def create(self, s: int, m: Address, dt=None) -> Varnode:
        """Create a new Varnode and add it to the bank."""
        vn = Varnode(s, m, dt)
        vn._create_index = self._create_index
        self._create_index += 1
        self._loc_tree.append(vn)
        self._def_tree.append(vn)
        return vn

    def createDef(self, s: int, m: Address, dt, op: PcodeOp) -> Varnode:
        """Create a new Varnode with a defining PcodeOp."""
        vn = self.create(s, m, dt)
        vn.setDef(op)
        return vn

    def destroy(self, vn: Varnode) -> None:
        """Remove a Varnode from the bank."""
        try:
            self._loc_tree.remove(vn)
        except ValueError:
            pass
        try:
            self._def_tree.remove(vn)
        except ValueError:
            pass

    def clearDead(self) -> None:
        """Remove Varnodes that have no def and no descendants."""
        alive = [vn for vn in self._loc_tree
                 if vn.isWritten() or not vn.hasNoDescend()
                 or vn.isInput() or vn.isConstant()]
        self._loc_tree = alive
        alive_set = set(id(v) for v in alive)
        self._def_tree = [vn for vn in self._def_tree if id(vn) in alive_set]

    def getCreateIndex(self) -> int:
        return self._create_index

    def beginLoc(self) -> Iterator[Varnode]:
        return iter(self._loc_tree)

    def beginDef(self) -> Iterator[Varnode]:
        return iter(self._def_tree)

    def findLoc(self, addr: Address, size: int) -> List[Varnode]:
        """Find all Varnodes at the given location and size."""
        return [vn for vn in self._loc_tree
                if vn.getAddr() == addr and vn.getSize() == size]

    def findInput(self, size: int, addr: Address) -> Optional[Varnode]:
        """Find an input Varnode of given size at given address."""
        for vn in self._loc_tree:
            if vn.getAddr() == addr and vn.getSize() == size and vn.isInput():
                return vn
        return None

    def allVarnodes(self) -> Iterator[Varnode]:
        """Iterate over all Varnodes in the bank."""
        return iter(self._loc_tree)

    def createUnique(self, s: int, dt=None) -> Varnode:
        """Create a temporary Varnode in unique space."""
        from ghidra.core.address import Address as Addr
        # Use a simple unique offset scheme
        addr = Addr(None, self._uniq_id)  # Placeholder unique address
        self._uniq_id += s
        return self.create(s, addr, dt)

    def createDefUnique(self, s: int, dt, op) -> Varnode:
        """Create a temporary Varnode as output of a PcodeOp."""
        vn = self.createUnique(s, dt)
        vn.setDef(op)
        return vn

    def numVarnodes(self) -> int:
        return len(self._loc_tree)

    def makeFree(self, vn: Varnode) -> None:
        """Convert a Varnode to be free."""
        try:
            self._loc_tree.remove(vn)
        except ValueError:
            pass
        try:
            self._def_tree.remove(vn)
        except ValueError:
            pass
        vn._def = None
        vn.clearFlags(Varnode.insert | Varnode.input | Varnode.written | Varnode.indirect_creation)
        vn.setFlags(Varnode.coverdirty)
        self._loc_tree.append(vn)
        self._def_tree.append(vn)

    def replace(self, oldvn: Varnode, newvn: Varnode) -> None:
        """Replace every read of oldvn with newvn."""
        for op in list(oldvn._descend):
            i = op.getSlot(oldvn)
            newvn.addDescend(op)
            op.setInput(newvn, i)
        oldvn._descend.clear()
        oldvn.setFlags(Varnode.coverdirty)
        newvn.setFlags(Varnode.coverdirty)

    def setInput(self, vn: Varnode) -> Varnode:
        """Mark a Varnode as an input to the function."""
        vn.setInput()
        vn.setFlags(Varnode.insert)
        return vn

    def setDef(self, vn: Varnode, op) -> Varnode:
        """Change Varnode to be defined by the given PcodeOp."""
        vn.setDef(op)
        vn.setFlags(Varnode.insert)
        return vn

    def find(self, s: int, loc: Address, pc: Address = None, uniq: int = None) -> Optional[Varnode]:
        """Find a Varnode given (loc, size) and optionally the defining address."""
        for vn in self._loc_tree:
            if vn.getAddr() != loc or vn.getSize() != s:
                continue
            if pc is None:
                return vn
            op = vn.getDef()
            if op is not None and op.getAddr() == pc:
                if uniq is None or op.getTime() == uniq:
                    return vn
        return None

    def findCoveredInput(self, size: int, addr: Address) -> Optional[Varnode]:
        """Find an input Varnode completely contained within the given range."""
        end = addr.getOffset() + size - 1
        for vn in self._loc_tree:
            if not vn.isInput():
                continue
            if vn.getAddr().getSpace() is not addr.getSpace():
                continue
            if vn.getAddr().getOffset() >= addr.getOffset() and \
               (vn.getAddr().getOffset() + vn.getSize() - 1) <= end:
                return vn
        return None

    def findCoveringInput(self, size: int, addr: Address) -> Optional[Varnode]:
        """Find an input Varnode that completely covers the given range."""
        for vn in self._loc_tree:
            if not vn.isInput():
                continue
            if vn.getAddr().getSpace() is not addr.getSpace():
                continue
            if vn.getAddr().getOffset() <= addr.getOffset() and \
               (vn.getAddr().getOffset() + vn.getSize() - 1) >= (addr.getOffset() + size - 1):
                return vn
        return None

    def hasInputIntersection(self, size: int, addr: Address) -> bool:
        """Check for input Varnode that overlaps the given range."""
        for vn in self._loc_tree:
            if not vn.isInput():
                continue
            if vn.intersects(addr, size):
                return True
        return False

    def endLoc(self) -> Iterator[Varnode]:
        return iter([])

    def endDef(self) -> Iterator[Varnode]:
        return iter([])

    def beginLocSpace(self, spaceid: AddrSpace) -> List[Varnode]:
        """Get Varnodes in given address space sorted by location."""
        return [vn for vn in self._loc_tree if vn.getSpace() is spaceid]

    def endLocSpace(self, spaceid: AddrSpace) -> List[Varnode]:
        return []

    def beginLocAddr(self, addr: Address) -> List[Varnode]:
        """Get Varnodes starting at given address."""
        return [vn for vn in self._loc_tree if vn.getAddr() == addr]

    def beginLocSize(self, s: int, addr: Address) -> List[Varnode]:
        """Get Varnodes of given size at given address."""
        return [vn for vn in self._loc_tree
                if vn.getAddr() == addr and vn.getSize() == s]

    def beginLocFlags(self, s: int, addr: Address, fl: int) -> List[Varnode]:
        """Get Varnodes of given size at address with matching flags."""
        result = []
        for vn in self._loc_tree:
            if vn.getAddr() != addr or vn.getSize() != s:
                continue
            vn_fl = vn.getFlags() & (Varnode.input | Varnode.written)
            if fl == Varnode.input and vn.isInput():
                result.append(vn)
            elif fl == Varnode.written and vn.isWritten():
                result.append(vn)
            elif fl == 0 and vn_fl == 0:
                result.append(vn)
        return result

    def beginDefFlags(self, fl: int) -> List[Varnode]:
        """Get Varnodes by definition property."""
        if fl == Varnode.input:
            return [vn for vn in self._def_tree if vn.isInput()]
        elif fl == Varnode.written:
            return [vn for vn in self._def_tree if vn.isWritten()]
        else:
            return [vn for vn in self._def_tree if vn.isFree()]

    def beginDefFlagsAddr(self, fl: int, addr: Address) -> List[Varnode]:
        """Get Varnodes by definition property and address."""
        if fl == Varnode.input:
            return [vn for vn in self._def_tree
                    if vn.isInput() and vn.getAddr() == addr]
        return []

    def overlapLoc(self, startiter, bounds: list) -> int:
        """Given start, return maximal range of overlapping Varnodes.

        Returns union of Varnode flags across the range.
        bounds is filled with sub-range iterators (as lists of Varnodes).
        """
        # Simplified Python version: collect all overlapping varnodes
        if not self._loc_tree:
            return 0
        # Find the varnode at startiter position
        start_idx = 0
        if isinstance(startiter, int):
            start_idx = startiter
        vn = self._loc_tree[start_idx]
        spc = vn.getSpace()
        off = vn.getOffset()
        maxOff = off + (vn.getSize() - 1)
        flags = vn.getFlags()
        group = [vn]
        idx = start_idx + 1
        while idx < len(self._loc_tree):
            vn2 = self._loc_tree[idx]
            if vn2.getSpace() is not spc or vn2.getOffset() > maxOff:
                break
            if vn2.isFree():
                idx += 1
                continue
            endOff = vn2.getOffset() + (vn2.getSize() - 1)
            if endOff > maxOff:
                maxOff = endOff
            flags |= vn2.getFlags()
            group.append(vn2)
            idx += 1
        bounds.extend(group)
        return flags


# =========================================================================
# Free functions
# =========================================================================

def contiguous_test(vn1: Varnode, vn2: Varnode) -> bool:
    """Test if Varnodes are pieces of a whole (contiguous in storage)."""
    if vn1.getSpace() is not vn2.getSpace():
        return False
    if vn1.getOffset() + vn1.getSize() == vn2.getOffset():
        return True
    if vn2.getOffset() + vn2.getSize() == vn1.getOffset():
        return True
    return False


def findContiguousWhole(data, vn1: Varnode, vn2: Varnode) -> Optional[Varnode]:
    """Retrieve the whole Varnode given pieces.

    If vn1 and vn2 are contiguous, look for an input Varnode covering both.
    """
    if vn1.getSpace() is not vn2.getSpace():
        return None
    # Order by offset
    if vn1.getOffset() > vn2.getOffset():
        vn1, vn2 = vn2, vn1
    if vn1.getOffset() + vn1.getSize() != vn2.getOffset():
        return None
    whole_size = vn1.getSize() + vn2.getSize()
    whole_addr = vn1.getAddr()
    # Look for a covering input varnode
    return data.findCoveringInput(whole_size, whole_addr)
