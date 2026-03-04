"""
Corresponds to: op.hh / op.cc

The PcodeOp and PcodeOpBank classes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List, Dict, Iterator

from ghidra.core.address import Address, SeqNum
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.core.marshal import Encoder, Decoder


class PcodeOp:
    """Lowest level operation of the p-code language.

    Only one version of any type of operation exists, and all effects
    are completely explicit. All operations except control flow operations
    have exactly one explicit output.
    """

    # --- Primary flags (uint4 flags) ---
    startbasic       = 1
    branch           = 2
    call             = 4
    returns          = 0x8
    nocollapse       = 0x10
    dead             = 0x20
    marker           = 0x40
    booloutput       = 0x80
    boolean_flip     = 0x100
    fallthru_true    = 0x200
    indirect_source  = 0x400
    coderef          = 0x800
    startmark        = 0x1000
    mark             = 0x2000
    commutative      = 0x4000
    unary            = 0x8000
    binary           = 0x10000
    special          = 0x20000
    ternary          = 0x40000
    return_copy      = 0x80000
    nonprinting      = 0x100000
    halt             = 0x200000
    badinstruction   = 0x400000
    unimplemented    = 0x800000
    noreturn         = 0x1000000
    missing          = 0x2000000
    spacebase_ptr    = 0x4000000
    indirect_creation = 0x8000000
    calculated_bool  = 0x10000000
    has_callspec     = 0x20000000
    ptrflow          = 0x40000000
    indirect_store   = 0x80000000

    # --- Additional flags (uint4 addlflags) ---
    special_prop         = 1
    special_print        = 2
    modified             = 4
    warning              = 8
    incidental_copy      = 0x10
    is_cpool_transformed = 0x20
    stop_type_propagation = 0x40
    hold_output          = 0x80
    concat_root          = 0x100
    no_indirect_collapse = 0x200
    store_unmapped       = 0x400

    def __init__(self, num_inputs: int, sq: SeqNum) -> None:
        self._opcode = None  # TypeOp reference
        self._opcode_enum: OpCode = OpCode.CPUI_BLANK
        self._flags: int = 0
        self._addlflags: int = 0
        self._start: SeqNum = sq
        self._parent = None  # BlockBasic
        self._output: Optional[Varnode] = None
        self._inrefs: List[Optional[Varnode]] = [None] * num_inputs

    # --- Basic accessors ---

    def numInput(self) -> int:
        return len(self._inrefs)

    def getOut(self) -> Optional[Varnode]:
        return self._output

    def getIn(self, slot: int) -> Optional[Varnode]:
        return self._inrefs[slot]

    def getParent(self):
        """Get the parent basic block."""
        return self._parent

    def getAddr(self) -> Address:
        return self._start.getAddr()

    def getTime(self) -> int:
        return self._start.getTime()

    def getSeqNum(self) -> SeqNum:
        return self._start

    def getSlot(self, vn: Varnode) -> int:
        """Get the slot number of the indicated input varnode."""
        for i, ref in enumerate(self._inrefs):
            if ref is vn:
                return i
        return len(self._inrefs)

    def getEvalType(self) -> int:
        return self._flags & (PcodeOp.unary | PcodeOp.binary | PcodeOp.special | PcodeOp.ternary)

    def getHaltType(self) -> int:
        return self._flags & (PcodeOp.halt | PcodeOp.badinstruction | PcodeOp.unimplemented |
                              PcodeOp.noreturn | PcodeOp.missing)

    def code(self) -> OpCode:
        """Get the opcode id (enum) for this op."""
        return self._opcode_enum

    def getOpcode(self):
        """Get the TypeOp for this op."""
        return self._opcode

    def getOpName(self) -> str:
        if self._opcode is not None:
            return self._opcode.getName()
        from ghidra.core.opcodes import get_opname
        return get_opname(self._opcode_enum)

    # --- Flag queries ---

    def isDead(self) -> bool:
        return (self._flags & PcodeOp.dead) != 0

    def isAssignment(self) -> bool:
        return self._output is not None

    def isCall(self) -> bool:
        return (self._flags & PcodeOp.call) != 0

    def isCallWithoutSpec(self) -> bool:
        return (self._flags & (PcodeOp.call | PcodeOp.has_callspec)) == PcodeOp.call

    def isMarker(self) -> bool:
        return (self._flags & PcodeOp.marker) != 0

    def isIndirectCreation(self) -> bool:
        return (self._flags & PcodeOp.indirect_creation) != 0

    def isIndirectStore(self) -> bool:
        return (self._flags & PcodeOp.indirect_store) != 0

    def notPrinted(self) -> bool:
        return (self._flags & (PcodeOp.marker | PcodeOp.nonprinting | PcodeOp.noreturn)) != 0

    def isBoolOutput(self) -> bool:
        return (self._flags & PcodeOp.booloutput) != 0

    def isBranch(self) -> bool:
        return (self._flags & PcodeOp.branch) != 0

    def isCallOrBranch(self) -> bool:
        return (self._flags & (PcodeOp.branch | PcodeOp.call)) != 0

    def isFlowBreak(self) -> bool:
        return (self._flags & (PcodeOp.branch | PcodeOp.returns)) != 0

    def isBooleanFlip(self) -> bool:
        return (self._flags & PcodeOp.boolean_flip) != 0

    def isFallthruTrue(self) -> bool:
        return (self._flags & PcodeOp.fallthru_true) != 0

    def isCodeRef(self) -> bool:
        return (self._flags & PcodeOp.coderef) != 0

    def isInstructionStart(self) -> bool:
        return (self._flags & PcodeOp.startmark) != 0

    def isBlockStart(self) -> bool:
        return (self._flags & PcodeOp.startbasic) != 0

    def isModified(self) -> bool:
        return (self._addlflags & PcodeOp.modified) != 0

    def isMark(self) -> bool:
        return (self._flags & PcodeOp.mark) != 0

    def isCommutative(self) -> bool:
        return (self._flags & PcodeOp.commutative) != 0

    def isIndirectSource(self) -> bool:
        return (self._flags & PcodeOp.indirect_source) != 0

    def isPtrFlow(self) -> bool:
        return (self._flags & PcodeOp.ptrflow) != 0

    def isCalculatedBool(self) -> bool:
        return (self._flags & (PcodeOp.calculated_bool | PcodeOp.booloutput)) != 0

    def isReturnCopy(self) -> bool:
        return (self._flags & PcodeOp.return_copy) != 0

    def usesSpacebasePtr(self) -> bool:
        return (self._flags & PcodeOp.spacebase_ptr) != 0

    # --- Flag mutators ---

    def setFlag(self, fl: int) -> None:
        self._flags |= fl

    def clearFlag(self, fl: int) -> None:
        self._flags &= ~fl

    def flipFlag(self, fl: int) -> None:
        self._flags ^= fl

    def setAdditionalFlag(self, fl: int) -> None:
        self._addlflags |= fl

    def clearAdditionalFlag(self, fl: int) -> None:
        self._addlflags &= ~fl

    def setMark(self) -> None:
        self._flags |= PcodeOp.mark

    def clearMark(self) -> None:
        self._flags &= ~PcodeOp.mark

    def setIndirectSource(self) -> None:
        self._flags |= PcodeOp.indirect_source

    def clearIndirectSource(self) -> None:
        self._flags &= ~PcodeOp.indirect_source

    def setPtrFlow(self) -> None:
        self._flags |= PcodeOp.ptrflow

    # --- Structural mutators (Funcdata-level) ---

    def setOpcode(self, t_op) -> None:
        self._opcode = t_op
        if t_op is not None:
            self._opcode_enum = t_op.getOpcode()

    def setOpcodeEnum(self, opc: OpCode) -> None:
        self._opcode_enum = opc

    def setOutput(self, vn: Optional[Varnode]) -> None:
        self._output = vn

    def clearInput(self, slot: int) -> None:
        self._inrefs[slot] = None

    def setInput(self, vn: Varnode, slot: int) -> None:
        self._inrefs[slot] = vn

    def setNumInputs(self, num: int) -> None:
        while len(self._inrefs) < num:
            self._inrefs.append(None)
        while len(self._inrefs) > num:
            self._inrefs.pop()

    def removeInput(self, slot: int) -> None:
        del self._inrefs[slot]

    def insertInput(self, slot: int) -> None:
        self._inrefs.insert(slot, None)

    def setOrder(self, ord_: int) -> None:
        self._start.setOrder(ord_)

    def setParent(self, p) -> None:
        self._parent = p

    # --- Navigation ---

    def nextOp(self) -> Optional[PcodeOp]:
        """Return the next op in control-flow from this, or None."""
        # Simplified: requires basic block linkage
        return None

    def previousOp(self) -> Optional[PcodeOp]:
        """Return the previous op within this op's basic block, or None."""
        return None

    def compareOrder(self, bop: PcodeOp) -> int:
        """Compare the control-flow order of this and bop.
        Returns -1, 0, or 1.
        """
        if self._parent is not bop._parent:
            si = self._parent.getIndex() if self._parent else -1
            bi = bop._parent.getIndex() if bop._parent else -1
            return -1 if si < bi else (1 if si > bi else 0)
        so = self._start.getOrder()
        bo = bop._start.getOrder()
        if so < bo:
            return -1
        if so > bo:
            return 1
        return 0

    @staticmethod
    def getOpFromConst(addr: Address) -> int:
        """Retrieve the PcodeOp encoded as the address offset."""
        return addr.getOffset()

    def printRaw(self) -> str:
        """Print raw info about this op."""
        parts = []
        if self._output is not None:
            parts.append(f"{self._output.printRaw()} = ")
        parts.append(self.getOpName())
        for i, inp in enumerate(self._inrefs):
            if inp is not None:
                parts.append(f" {inp.printRaw()}")
        return "".join(parts)

    def doesSpecialPrinting(self) -> bool:
        return (self._addlflags & PcodeOp.special_print) != 0

    def doesSpecialPropagation(self) -> bool:
        return (self._addlflags & PcodeOp.special_prop) != 0

    def isIncidentalCopy(self) -> bool:
        return (self._addlflags & PcodeOp.incidental_copy) != 0

    def isCpoolTransformed(self) -> bool:
        return (self._addlflags & PcodeOp.is_cpool_transformed) != 0

    def stopsTypePropagation(self) -> bool:
        return (self._addlflags & PcodeOp.stop_type_propagation) != 0

    def setStopTypePropagation(self) -> None:
        self._addlflags |= PcodeOp.stop_type_propagation

    def clearStopTypePropagation(self) -> None:
        self._addlflags &= ~PcodeOp.stop_type_propagation

    def holdOutput(self) -> bool:
        return (self._addlflags & PcodeOp.hold_output) != 0

    def setHoldOutput(self) -> None:
        self._addlflags |= PcodeOp.hold_output

    def isPartialRoot(self) -> bool:
        return (self._addlflags & PcodeOp.concat_root) != 0

    def setPartialRoot(self) -> None:
        self._addlflags |= PcodeOp.concat_root

    def noIndirectCollapse(self) -> bool:
        return (self._addlflags & PcodeOp.no_indirect_collapse) != 0

    def setNoIndirectCollapse(self) -> None:
        self._addlflags |= PcodeOp.no_indirect_collapse

    def isStoreUnmapped(self) -> bool:
        return (self._addlflags & PcodeOp.store_unmapped) != 0

    def setStoreUnmapped(self) -> None:
        self._addlflags |= PcodeOp.store_unmapped

    def isWarning(self) -> bool:
        return (self._addlflags & PcodeOp.warning) != 0

    def isCollapsible(self) -> bool:
        if (self._flags & PcodeOp.nocollapse) != 0:
            return False
        if self._output is None:
            return False
        return True

    def isMoveable(self, point) -> bool:
        return not self.isMarker() and not self.isCall()

    def setHaltType(self, flag: int) -> None:
        self._flags = (self._flags & ~(PcodeOp.halt | PcodeOp.badinstruction | PcodeOp.unimplemented | PcodeOp.noreturn | PcodeOp.missing)) | flag

    def getRepeatSlot(self, vn, firstSlot, op) -> int:
        for i in range(firstSlot, len(self._inrefs)):
            if self._inrefs[i] is vn:
                return i
        return -1

    def getCseHash(self) -> int:
        if self._output is None:
            return 0
        h = int(self._opcode_enum) * 0x9e3779b9
        for inp in self._inrefs:
            if inp is not None and inp.isConstant():
                h ^= inp.getOffset() * 0x517cc1b7
        return h & 0xFFFFFFFF

    def isCseMatch(self, other) -> bool:
        if self._opcode_enum != other._opcode_enum:
            return False
        if len(self._inrefs) != len(other._inrefs):
            return False
        for i in range(len(self._inrefs)):
            if self._inrefs[i] is not other._inrefs[i]:
                return False
        return True

    def getBasicIter(self):
        return getattr(self, '_basiciter', None)

    def setBasicIter(self, it):
        self._basiciter = it

    def getInsertIter(self):
        return getattr(self, '_insertiter', None)

    def getNZMaskLocal(self, clipsize: int) -> int:
        return 0  # Stub

    def collapse(self, trialVn):
        return None  # Stub

    def collapseConstantSymbol(self, vn):
        pass  # Stub

    def printDebug(self) -> str:
        return self.printRaw()

    def outputTypeLocal(self):
        """Calculate the local output type."""
        if self._opcode is not None and hasattr(self._opcode, 'getOutputLocal'):
            return self._opcode.getOutputLocal(self)
        return None

    def inputTypeLocal(self, slot: int):
        """Calculate the local input type for a given slot."""
        if self._opcode is not None and hasattr(self._opcode, 'getInputLocal'):
            return self._opcode.getInputLocal(self, slot)
        return None

    def target(self):
        """Return starting op for instruction associated with this op."""
        return self  # Simplified

    def encode(self, encoder) -> None:
        """Encode a description of this op to stream."""
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement('op')
            encoder.writeSignedInteger('code', int(self._opcode_enum))
            self._start.encode(encoder)
            if self._output is not None:
                self._output.encode(encoder)
            for inp in self._inrefs:
                if inp is not None:
                    inp.encode(encoder)
            encoder.closeElement('op')

    def setAllInput(self, newInputs: list) -> None:
        """Replace all inputs with the given list."""
        self._inrefs = list(newInputs)

    def __repr__(self) -> str:
        return f"PcodeOp({self.getOpName()} @ {self._start})"


# =========================================================================
# PcodeOpBank
# =========================================================================

class PcodeOpBank:
    """Container class for PcodeOps associated with a single function.

    Maintains multiple sorted structures for quick access.
    """

    def __init__(self) -> None:
        self._optree: Dict[SeqNum, PcodeOp] = {}  # Main sequence number sort
        self._deadlist: List[PcodeOp] = []
        self._alivelist: List[PcodeOp] = []
        self._storelist: List[PcodeOp] = []
        self._loadlist: List[PcodeOp] = []
        self._returnlist: List[PcodeOp] = []
        self._useroplist: List[PcodeOp] = []
        self._uniqid: int = 0

    def clear(self) -> None:
        self._optree.clear()
        self._deadlist.clear()
        self._alivelist.clear()
        self._storelist.clear()
        self._loadlist.clear()
        self._returnlist.clear()
        self._useroplist.clear()

    def clearDead(self) -> None:
        """Remove all dead PcodeOps."""
        self._deadlist.clear()

    def setUniqId(self, val: int) -> None:
        self._uniqid = val

    def getUniqId(self) -> int:
        return self._uniqid

    def empty(self) -> bool:
        return len(self._optree) == 0

    def create(self, inputs: int, addr_or_sq) -> PcodeOp:
        """Create a PcodeOp with a given Address or SeqNum."""
        if isinstance(addr_or_sq, Address):
            sq = SeqNum(addr_or_sq, self._uniqid)
            self._uniqid += 1
        else:
            sq = addr_or_sq
        op = PcodeOp(inputs, sq)
        self._optree[sq] = op
        self._deadlist.append(op)
        op.setFlag(PcodeOp.dead)
        return op

    def destroy(self, op: PcodeOp) -> None:
        """Destroy/retire the given PcodeOp."""
        sq = op.getSeqNum()
        self._optree.pop(sq, None)
        try:
            self._deadlist.remove(op)
        except ValueError:
            pass
        try:
            self._alivelist.remove(op)
        except ValueError:
            pass
        self._removeFromCodeList(op)

    def destroyDead(self) -> None:
        """Destroy/retire all PcodeOps in the dead list."""
        for op in list(self._deadlist):
            self.destroy(op)

    def markAlive(self, op: PcodeOp) -> None:
        """Mark the given PcodeOp as alive."""
        op.clearFlag(PcodeOp.dead)
        try:
            self._deadlist.remove(op)
        except ValueError:
            pass
        self._alivelist.append(op)

    def markDead(self, op: PcodeOp) -> None:
        """Mark the given PcodeOp as dead."""
        op.setFlag(PcodeOp.dead)
        try:
            self._alivelist.remove(op)
        except ValueError:
            pass
        self._deadlist.append(op)
        self._removeFromCodeList(op)

    def _addToCodeList(self, op: PcodeOp) -> None:
        opc = op.code()
        if opc == OpCode.CPUI_STORE:
            self._storelist.append(op)
        elif opc == OpCode.CPUI_LOAD:
            self._loadlist.append(op)
        elif opc == OpCode.CPUI_RETURN:
            self._returnlist.append(op)
        elif opc == OpCode.CPUI_CALLOTHER:
            self._useroplist.append(op)

    def _removeFromCodeList(self, op: PcodeOp) -> None:
        opc = op.code()
        for lst in (self._storelist, self._loadlist, self._returnlist, self._useroplist):
            try:
                lst.remove(op)
            except ValueError:
                pass

    def findOp(self, num: SeqNum) -> Optional[PcodeOp]:
        return self._optree.get(num)

    def target(self, addr: Address) -> Optional[PcodeOp]:
        """Find the first executing PcodeOp for a target address."""
        for sq, op in self._optree.items():
            if sq.getAddr() == addr:
                return op
        return None

    def beginAll(self) -> Iterator[PcodeOp]:
        return iter(self._optree.values())

    def beginAlive(self) -> Iterator[PcodeOp]:
        return iter(self._alivelist)

    def beginDead(self) -> Iterator[PcodeOp]:
        return iter(self._deadlist)

    def getStoreList(self) -> List[PcodeOp]:
        return self._storelist

    def getReturnList(self) -> List[PcodeOp]:
        return self._returnlist

    def getLoadList(self) -> List[PcodeOp]:
        return self._loadlist

    def getUserOpList(self) -> List[PcodeOp]:
        return self._useroplist

    def getDeadList(self) -> List[PcodeOp]:
        """Get all PcodeOps in the dead list."""
        return self._deadlist

    def getAliveList(self) -> List[PcodeOp]:
        """Get all PcodeOps in the alive list."""
        return self._alivelist

    def endDead(self):
        """End sentinel for dead list iteration."""
        return None

    def endAlive(self):
        """End sentinel for alive list iteration."""
        return None

    def endAll(self):
        """End sentinel for all ops iteration."""
        return None

    def getNextDead(self, op: PcodeOp) -> Optional[PcodeOp]:
        """Get the next op after the given op in the dead list."""
        try:
            idx = self._deadlist.index(op)
            if idx + 1 < len(self._deadlist):
                return self._deadlist[idx + 1]
        except ValueError:
            pass
        return None

    def changeOpcode(self, op: PcodeOp, newopc) -> None:
        """Change the op-code for the given PcodeOp."""
        self._removeFromCodeList(op)
        op.setOpcode(newopc)
        self._addToCodeList(op)

    def insertAfterDead(self, op: PcodeOp, prev: PcodeOp) -> None:
        """Insert the given PcodeOp after a point in the dead list."""
        try:
            idx = self._deadlist.index(prev)
            self._deadlist.insert(idx + 1, op)
        except ValueError:
            self._deadlist.append(op)

    def moveSequenceDead(self, firstop: PcodeOp, lastop: PcodeOp, prev: PcodeOp) -> None:
        """Move a sequence of PcodeOps in the dead list to after prev."""
        # Collect the ops in the sequence
        try:
            first_idx = self._deadlist.index(firstop)
            last_idx = self._deadlist.index(lastop)
        except ValueError:
            return
        seq = self._deadlist[first_idx:last_idx + 1]
        for op in seq:
            self._deadlist.remove(op)
        try:
            insert_idx = self._deadlist.index(prev) + 1
        except ValueError:
            insert_idx = len(self._deadlist)
        for i, op in enumerate(seq):
            self._deadlist.insert(insert_idx + i, op)

    def markIncidentalCopy(self, firstop: PcodeOp, lastop: PcodeOp) -> None:
        """Mark any COPY ops in the given range as incidental."""
        in_range = False
        for op in self._deadlist:
            if op is firstop:
                in_range = True
            if in_range:
                if op.code() == OpCode.CPUI_COPY:
                    op.setAdditionalFlag(PcodeOp.incidental_copy)
            if op is lastop:
                break

    def fallthru(self, op: PcodeOp) -> Optional[PcodeOp]:
        """Find the PcodeOp considered a fallthru of the given PcodeOp."""
        return self.getNextDead(op)

    def beginByAddr(self, addr: Address) -> List[PcodeOp]:
        """Get all PcodeOps at the given address."""
        return [op for sq, op in self._optree.items() if sq.getAddr() == addr]

    def beginByOpcode(self, opc: OpCode) -> List[PcodeOp]:
        """Get all alive PcodeOps with the given opcode."""
        if opc == OpCode.CPUI_STORE:
            return list(self._storelist)
        elif opc == OpCode.CPUI_LOAD:
            return list(self._loadlist)
        elif opc == OpCode.CPUI_RETURN:
            return list(self._returnlist)
        elif opc == OpCode.CPUI_CALLOTHER:
            return list(self._useroplist)
        return [op for op in self._alivelist if op.code() == opc]


# =========================================================================
# PieceNode
# =========================================================================

class PieceNode:
    """A node in a tree structure of CPUI_PIECE operations.

    If a group of Varnodes are concatenated into a larger structure,
    this object explicitly gathers the PcodeOps and Varnodes.
    """

    def __init__(self, op, sl: int, off: int, leaf: bool) -> None:
        self._pieceOp = op
        self._slot: int = sl
        self._typeOffset: int = off
        self._leaf: bool = leaf

    def isLeaf(self) -> bool:
        return self._leaf

    def getTypeOffset(self) -> int:
        return self._typeOffset

    def getSlot(self) -> int:
        return self._slot

    def getOp(self):
        return self._pieceOp

    def getVarnode(self):
        return self._pieceOp.getIn(self._slot)

    @staticmethod
    def isLeafStatic(rootVn, vn, typeOffset: int) -> bool:
        """Check if vn is a leaf of the CONCAT tree rooted at rootVn."""
        if vn is rootVn:
            return False
        if vn.hasNoDescend():
            return True
        descs = list(vn.beginDescend())
        if len(descs) != 1:
            return True
        return descs[0].code() != OpCode.CPUI_PIECE

    @staticmethod
    def findRoot(vn):
        """Find the root Varnode of a PIECE tree containing vn."""
        while True:
            if vn.hasNoDescend():
                return vn
            descs = list(vn.beginDescend())
            if len(descs) != 1:
                return vn
            op = descs[0]
            if op.code() != OpCode.CPUI_PIECE:
                return vn
            vn = op.getOut()
        return vn

    @staticmethod
    def gatherPieces(stack: list, rootVn, op, baseOffset: int, rootOffset: int) -> None:
        """Gather all pieces in a CPUI_PIECE tree."""
        if op is None or op.code() != OpCode.CPUI_PIECE:
            return
        hiVn = op.getIn(0)  # Most significant
        loVn = op.getIn(1)  # Least significant
        loSize = loVn.getSize()
        # Process low part
        loOff = rootOffset
        if loVn.isWritten() and loVn.getDef().code() == OpCode.CPUI_PIECE:
            PieceNode.gatherPieces(stack, rootVn, loVn.getDef(), baseOffset, loOff)
        else:
            isLeaf = PieceNode.isLeafStatic(rootVn, loVn, loOff)
            stack.append(PieceNode(op, 1, loOff, isLeaf))
        # Process high part
        hiOff = rootOffset + loSize
        if hiVn.isWritten() and hiVn.getDef().code() == OpCode.CPUI_PIECE:
            PieceNode.gatherPieces(stack, rootVn, hiVn.getDef(), baseOffset, hiOff)
        else:
            isLeaf = PieceNode.isLeafStatic(rootVn, hiVn, hiOff)
            stack.append(PieceNode(op, 0, hiOff, isLeaf))
