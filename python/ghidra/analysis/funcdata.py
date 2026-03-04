"""
Corresponds to: funcdata.hh / funcdata.cc / funcdata_block.cc / funcdata_op.cc / funcdata_varnode.cc

Container for data structures associated with a single function.
Holds control-flow, data-flow, and prototype information.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List, Iterator

from ghidra.core.address import Address, SeqNum
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_INTERNAL
from ghidra.ir.varnode import Varnode, VarnodeBank
from ghidra.ir.op import PcodeOp, PcodeOpBank
from ghidra.ir.variable import HighVariable
from ghidra.block.block import BlockBasic, BlockGraph
from ghidra.fspec.fspec import FuncProto, FuncCallSpecs

if TYPE_CHECKING:
    from ghidra.database.database import Scope, FunctionSymbol
    from ghidra.types.datatype import Datatype


class Funcdata:
    """Container for data structures associated with a single function.

    Holds control-flow, data-flow, and prototype information, plus class
    instances to help with SSA form, structure control-flow, recover
    jump-tables, recover parameters, and merge Varnodes.
    """

    # Internal flags
    highlevel_on = 1
    blocks_generated = 2
    blocks_unreachable = 4
    processing_started = 8
    processing_complete = 0x10
    typerecovery_on = 0x20
    typerecovery_start = 0x40
    no_code = 0x80
    jumptablerecovery_on = 0x100
    jumptablerecovery_dont = 0x200
    restart_pending = 0x400
    unimplemented_present = 0x800
    baddata_present = 0x1000
    double_precis_on = 0x2000
    typerecovery_exceeded = 0x4000

    def __init__(self, nm: str, disp: str, scope: Optional[Scope],
                 addr: Address, sym: Optional[FunctionSymbol] = None,
                 sz: int = 0) -> None:
        self._flags: int = 0
        self._clean_up_index: int = 0
        self._high_level_index: int = 0
        self._cast_phase_index: int = 0
        self._minLanedSize: int = 0
        self._size: int = sz
        self._glb = None  # Architecture (set externally)
        self._functionSymbol = sym
        self._name: str = nm
        self._displayName: str = disp
        self._baseaddr: Address = addr
        self._funcp: FuncProto = FuncProto()
        self._localmap: Optional[Scope] = scope  # ScopeLocal

        self._qlst: List[FuncCallSpecs] = []
        self._qlst_map: dict = {}  # PcodeOp id -> FuncCallSpecs
        self._jumpvec = []  # List[JumpTable]
        self._override = None  # Override
        self._unionMap = None  # UnionResolveMap

        self._vbank: VarnodeBank = VarnodeBank()
        self._obank: PcodeOpBank = PcodeOpBank()
        self._bblocks: BlockGraph = BlockGraph()
        self._sblocks: BlockGraph = BlockGraph()

    # --- Basic accessors ---

    def getName(self) -> str:
        return self._name

    def getDisplayName(self) -> str:
        return self._displayName

    def getAddress(self) -> Address:
        return self._baseaddr

    def getSize(self) -> int:
        return self._size

    def getArch(self):
        return self._glb

    def setArch(self, glb) -> None:
        self._glb = glb

    def getSymbol(self):
        return self._functionSymbol

    def getVarnodeBank(self):
        return self._vbank

    def getOpBank(self):
        return self._obank

    def getOverride(self):
        if self._override is None:
            from ghidra.arch.override import Override
            self._override = Override()
        return self._override

    def getJumpTable(self, ind):
        """Get the JumpTable associated with the given BRANCHIND op."""
        for jt in self._jumpvec:
            if jt.getIndirectOp() is ind:
                return jt
        return None

    def getJumpTables(self):
        return self._jumpvec

    def installJumpTable(self, addr):
        from ghidra.analysis.jumptable import JumpTable
        jt = JumpTable(self._glb, addr)
        self._jumpvec.append(jt)
        return jt

    def getCallSpecs(self, op):
        """Look up FuncCallSpecs for a given CALL/CALLIND PcodeOp."""
        opid = id(op)
        if opid in self._qlst_map:
            return self._qlst_map[opid]
        for fc in self._qlst:
            if hasattr(fc, 'getOp') and fc.getOp() is op:
                self._qlst_map[opid] = fc
                return fc
        return None

    def addCallSpecs(self, fc):
        """Register a FuncCallSpecs for this function."""
        self._qlst.append(fc)
        if hasattr(fc, 'getOp') and fc.getOp() is not None:
            self._qlst_map[id(fc.getOp())] = fc

    def setUnionField(self, dt, op, slot, res):
        if self._unionMap is None:
            from ghidra.types.resolve import UnionResolveMap
            self._unionMap = UnionResolveMap()
        self._unionMap.setUnionField(dt, op, slot, res)

    def getUnionField(self, dt, op, slot):
        if self._unionMap is None:
            return None
        return self._unionMap.getUnionField(dt, op, slot)

    def getFirstReturnOp(self):
        from ghidra.core.opcodes import OpCode
        for i in range(self._bblocks.getSize()):
            bl = self._bblocks.getBlock(i)
            if hasattr(bl, 'getOpList'):
                for op in bl.getOpList():
                    if op.code() == OpCode.CPUI_RETURN:
                        return op
        return None

    def getFuncProto(self) -> FuncProto:
        return self._funcp

    def getLocalScope(self):
        return self._localmap

    def getScopeLocal(self):
        return self._localmap

    def getBasicBlocks(self) -> BlockGraph:
        return self._bblocks

    def getStructure(self) -> BlockGraph:
        return self._sblocks

    # --- Flag queries ---

    def isHighOn(self) -> bool:
        return (self._flags & Funcdata.highlevel_on) != 0

    def isProcStarted(self) -> bool:
        return (self._flags & Funcdata.processing_started) != 0

    def isProcComplete(self) -> bool:
        return (self._flags & Funcdata.processing_complete) != 0

    def hasUnreachableBlocks(self) -> bool:
        return (self._flags & Funcdata.blocks_unreachable) != 0

    def isTypeRecoveryOn(self) -> bool:
        return (self._flags & Funcdata.typerecovery_on) != 0

    def hasTypeRecoveryStarted(self) -> bool:
        return (self._flags & Funcdata.typerecovery_start) != 0

    def hasNoCode(self) -> bool:
        return (self._flags & Funcdata.no_code) != 0

    def setNoCode(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.no_code
        else:
            self._flags &= ~Funcdata.no_code

    def hasRestartPending(self) -> bool:
        return (self._flags & Funcdata.restart_pending) != 0

    def setRestartPending(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.restart_pending
        else:
            self._flags &= ~Funcdata.restart_pending

    def hasUnimplemented(self) -> bool:
        return (self._flags & Funcdata.unimplemented_present) != 0

    def hasBadData(self) -> bool:
        return (self._flags & Funcdata.baddata_present) != 0

    def isDoublePrecisOn(self) -> bool:
        return (self._flags & Funcdata.double_precis_on) != 0

    def setTypeRecovery(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.typerecovery_on
        else:
            self._flags &= ~Funcdata.typerecovery_on

    def hasNoStructBlocks(self) -> bool:
        return self._sblocks.getSize() == 0

    # --- Processing lifecycle ---

    def startProcessing(self) -> None:
        self._flags |= Funcdata.processing_started

    def stopProcessing(self) -> None:
        self._flags |= Funcdata.processing_complete

    def startTypeRecovery(self) -> bool:
        if (self._flags & Funcdata.typerecovery_on) == 0:
            return False
        self._flags |= Funcdata.typerecovery_start
        return True

    def startCastPhase(self) -> None:
        self._cast_phase_index = self._vbank.getCreateIndex()

    def startCleanUp(self) -> None:
        self._clean_up_index = self._vbank.getCreateIndex()

    def opHeritage(self) -> None:
        """Build SSA representation (heritage pass)."""
        if not hasattr(self, '_heritage'):
            from ghidra.analysis.heritage import Heritage
            self._heritage = Heritage(self)
        self._heritage.heritage()

    def getHeritagePass(self) -> int:
        """Get the current heritage pass number."""
        if hasattr(self, '_heritage'):
            return self._heritage.getPass()
        return 0

    def setHighLevel(self) -> None:
        """Assign HighVariable objects to each Varnode."""
        if (self._flags & Funcdata.highlevel_on) != 0:
            return
        self._flags |= Funcdata.highlevel_on
        self._high_level_index = self._vbank.getCreateIndex()

    def getActiveOutput(self):
        """Get the active output parameter recovery object, or None."""
        return getattr(self, '_activeoutput', None)

    def clearActiveOutput(self) -> None:
        """Clear the active output recovery object."""
        self._activeoutput = None

    def initActiveOutput(self) -> None:
        """Initialize active output parameter recovery."""
        from ghidra.fspec.paramactive import ParamActive
        self._activeoutput = ParamActive(False)

    def calcNZMask(self) -> None:
        """Calculate the non-zero mask property on all Varnodes."""
        from ghidra.transform.nzmask import calcNZMask as _calcNZMask
        _calcNZMask(self)

    def clearDeadVarnodes(self) -> None:
        """Remove Varnodes that are no longer referenced."""
        self._vbank.clearDead()

    def clearDeadOps(self) -> None:
        """Remove PcodeOps that have been marked as dead."""
        self._obank.clearDead()

    def seenDeadcode(self, spc) -> None:
        """Record that dead code has been seen for a given space."""
        pass  # TODO: heritage.seenDeadCode(spc)

    def spacebase(self) -> None:
        """Mark Varnode objects that hold stack-pointer values as spacebase."""
        from ghidra.ir.varnode import Varnode
        glb = self._glb
        if glb is None:
            return
        for j in range(glb.numSpaces()):
            spc = glb.getSpace(j)
            if spc is None:
                continue
            numspace = getattr(spc, 'numSpacebase', lambda: 0)()
            for i in range(numspace):
                point = spc.getSpacebase(i)
                from ghidra.core.address import Address
                addr = Address(point.space, point.offset)
                for vn in list(self._vbank.beginLoc()):
                    if vn.getAddr() == addr and vn.getSize() == point.size:
                        if vn.isFree():
                            continue
                        if not vn.isSpacebase():
                            vn._flags |= Varnode.spacebase

    def structureReset(self) -> None:
        """Reset the control-flow structuring hierarchy."""
        self._sblocks.clear()

    def opZeroMulti(self, op) -> None:
        """Handle MULTIEQUAL with 0 or 1 inputs after edge removal."""
        if op.numInput() == 0:
            self.opInsertInput(op, self.newVarnode(op.getOut().getSize(), op.getOut().getAddr()), 0)
            self.setInputVarnode(op.getIn(0))
            self.opSetOpcode(op, OpCode.CPUI_COPY)
        elif op.numInput() == 1:
            self.opSetOpcode(op, OpCode.CPUI_COPY)

    def branchRemoveInternal(self, bb, num: int) -> None:
        """Remove outgoing branch edge, patch MULTIEQUAL ops in target block."""
        if bb.sizeOut() == 2:
            self.opDestroy(bb.lastOp())
        bbout = bb.getOut(num)
        blocknum = bbout.getInIndex(bb)
        self._bblocks.removeEdge(bb, bbout)
        if hasattr(bbout, 'getOpList'):
            for op in list(bbout.getOpList()):
                if op.code() != OpCode.CPUI_MULTIEQUAL:
                    continue
                if blocknum < op.numInput():
                    self.opRemoveInput(op, blocknum)
                self.opZeroMulti(op)

    def removeUnreachableBlocks(self, issuewarning: bool, checkexistence: bool) -> bool:
        """Remove unreachable blocks from the control flow graph."""
        if checkexistence:
            found = False
            for i in range(self._bblocks.getSize()):
                blk = self._bblocks.getBlock(i)
                if blk.isEntryPoint():
                    continue
                if blk.getImmedDom() is None:
                    found = True
                    break
            if not found:
                return False
        entry = self._bblocks.getEntryBlock()
        if entry is None:
            return False
        unreachable = []
        self._bblocks.collectReachable(unreachable, entry, True)
        if not unreachable:
            return False
        for bl in unreachable:
            bl.setDead()
        for bl in unreachable:
            while bl.sizeOut() > 0:
                self.branchRemoveInternal(bl, 0)
        for bl in unreachable:
            self.blockRemoveInternal(bl, True)
        self.structureReset()
        return True

    def removeBranch(self, bb, num: int) -> None:
        """Remove a branch edge from a basic block."""
        self.branchRemoveInternal(bb, num)
        self.structureReset()

    def blockRemoveInternal(self, bb, unreachable: bool) -> None:
        """Remove a basic block, destroying all its ops."""
        self._bblocks.removeFromFlow(bb)
        if hasattr(bb, 'getOpList'):
            for op in list(bb.getOpList()):
                if op.isCall():
                    self.deleteCallSpecs(op)
                self.opDestroy(op)
        self._bblocks.removeBlock(bb)

    def spliceBlockBasic(self, bb) -> None:
        """Splice a block with a single exit into its successor."""
        if bb.sizeOut() != 1:
            return
        target = bb.getOut(0)
        if target.sizeIn() != 1:
            return
        if hasattr(bb, 'getOpList') and hasattr(target, 'getOpList'):
            last = bb.lastOp()
            if last is not None and last.code() in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
                self.opDestroy(last)
            for op in list(bb.getOpList()):
                bb.removeOp(op)
                target.insertOp(op, 0)
        self._bblocks.removeEdge(bb, target)
        while bb.sizeIn() > 0:
            src = bb.getIn(0)
            lab = bb._intothis[0].label
            bb.removeInEdge(0)
            target.addInEdge(src, lab)
        self._bblocks.removeBlock(bb)
        self.structureReset()

    def removeDoNothingBlock(self, bb) -> None:
        """Remove a block that does nothing."""
        bb.setDead()
        self.blockRemoveInternal(bb, False)
        self.structureReset()

    def deleteCallSpecs(self, op) -> None:
        """Remove call specs associated with the given op."""
        self._qlst = [cs for cs in self._qlst if cs.getOp() is not op]

    def clear(self) -> None:
        """Clear out old disassembly."""
        self._vbank.clear()
        self._obank.clear()
        self._bblocks.clear()
        self._sblocks.clear()
        self._qlst.clear()
        self._qlst_map.clear()
        self._jumpvec.clear()
        self._override = None
        self._unionMap = None
        self._flags &= Funcdata.highlevel_on  # Keep only highlevel_on

    # --- Call specification routines ---

    def numCalls(self) -> int:
        return len(self._qlst)

    def getCallSpecsByIndex(self, i: int) -> Optional[FuncCallSpecs]:
        return self._qlst[i] if 0 <= i < len(self._qlst) else None

    # --- Varnode creation routines ---

    def newVarnode(self, s: int, addr: Address, ct: Optional[Datatype] = None) -> Varnode:
        """Create a new Varnode."""
        vn = self._vbank.create(s, addr, ct)
        return vn

    def newConstant(self, s: int, val: int) -> Varnode:
        """Create a new constant Varnode."""
        cs = None
        if self._glb is not None:
            cs = self._glb.getConstantSpace()
        if cs is None and self._localmap is not None:
            # Try to get constant space from scope's architecture
            pass
        if cs is None:
            # Fallback: create a minimal ConstantSpace
            from ghidra.core.space import ConstantSpace
            cs = ConstantSpace()
        addr = Address(cs, val)
        vn = self._vbank.create(s, addr)
        return vn

    def newUnique(self, s: int, ct: Optional[Datatype] = None) -> Varnode:
        """Create a new temporary Varnode in unique space."""
        if self._glb is not None:
            uniq = self._glb.getUniqueSpace()
            base = self._glb.getUniqueBase()
        else:
            uniq = None
            base = 0x10000000
        addr = Address(uniq, base)
        vn = self._vbank.create(s, addr, ct)
        return vn

    def newVarnodeOut(self, s: int, addr: Address, op: PcodeOp) -> Varnode:
        """Create a new output Varnode."""
        vn = self._vbank.createDef(s, addr, None, op)
        op.setOutput(vn)
        return vn

    def newUniqueOut(self, s: int, op: PcodeOp) -> Varnode:
        """Create a new temporary output Varnode."""
        vn = self.newUnique(s)
        vn.setDef(op)
        op.setOutput(vn)
        return vn

    def setInputVarnode(self, vn: Varnode) -> Varnode:
        """Mark a Varnode as an input to the function."""
        vn.setInput()
        return vn

    def deleteVarnode(self, vn: Varnode) -> None:
        self._vbank.destroy(vn)

    def findVarnodeInput(self, s: int, loc: Address) -> Optional[Varnode]:
        return self._vbank.findInput(s, loc)

    def findCoveredInput(self, s: int, loc: Address) -> Optional[Varnode]:
        return self._vbank.findCoveredInput(s, loc)

    def numVarnodes(self) -> int:
        return self._vbank.size()

    def findVarnodeWritten(self, s, loc, pc, uniq=-1):
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == loc and vn.getSize() == s and vn.isWritten():
                if vn.getDef() is not None and vn.getDef().getAddr() == pc:
                    return vn
        return None

    def findCoveringInput(self, s, loc):
        return self._vbank.findCoveredInput(s, loc)

    def findHigh(self, nm):
        for vn in self._vbank.allVarnodes():
            h = vn.getHigh() if hasattr(vn, 'getHigh') else None
            if h and hasattr(h, 'getSymbol'):
                sym = h.getSymbol()
                if sym and sym.getName() == nm:
                    return h
        return None

    def beginLoc(self):
        return self._vbank.beginLoc()

    def beginDef(self):
        return self._vbank.beginDef()

    def newVarnodeIop(self, op):
        addr = op.getAddr() if hasattr(op, 'getAddr') else Address()
        return self._vbank.create(1, addr)

    def newVarnodeSpace(self, spc):
        cs = self._glb.getConstantSpace() if self._glb else None
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        return self._vbank.create(4, Address(cs, idx) if cs else Address())

    def newVarnodeCallSpecs(self, fc):
        addr = fc.getEntryAddress() if hasattr(fc, 'getEntryAddress') else Address()
        return self._vbank.create(4, addr)

    def newCodeRef(self, m):
        return self._vbank.create(1, m)

    def numHeritagePasses(self, spc):
        return self._heritage.numHeritagePasses(spc) if hasattr(self, '_heritage') else 0

    def deadRemovalAllowed(self, spc):
        return self._heritage.deadRemovalAllowed(spc) if hasattr(self, '_heritage') else True

    def deadRemovalAllowedSeen(self, spc):
        return self._heritage.deadRemovalAllowedSeen(spc) if hasattr(self, '_heritage') else False

    def isHeritaged(self, vn):
        return self._heritage.heritagePass(vn.getAddr()) >= 0 if hasattr(self, '_heritage') else False

    def setDeadCodeDelay(self, spc, delay):
        if hasattr(self, '_heritage'):
            self._heritage.setDeadCodeDelay(spc, delay)

    def getMerge(self):
        if not hasattr(self, '_covermerge'):
            from ghidra.analysis.merge import Merge
            self._covermerge = Merge(self)
        return self._covermerge

    def fillinExtrapop(self):
        return self._glb.extra_pop if self._glb and hasattr(self._glb, 'extra_pop') else 0

    def isJumptableRecoveryOn(self):
        return (self._flags & Funcdata.jumptablerecovery_on) != 0

    def setJumptableRecovery(self, val):
        if val:
            self._flags &= ~Funcdata.jumptablerecovery_dont
        else:
            self._flags |= Funcdata.jumptablerecovery_dont

    def setDoublePrecisRecovery(self, val):
        if val:
            self._flags |= Funcdata.double_precis_on
        else:
            self._flags &= ~Funcdata.double_precis_on

    def isTypeRecoveryExceeded(self):
        return (self._flags & Funcdata.typerecovery_exceeded) != 0

    def setTypeRecoveryExceeded(self):
        self._flags |= Funcdata.typerecovery_exceeded

    def getCastPhaseIndex(self):
        return self._cast_phase_index

    def getHighLevelIndex(self):
        return self._high_level_index

    def getCleanUpIndex(self):
        return self._clean_up_index

    def setLanedRegGenerated(self):
        self._minLanedSize = 1000000

    def numJumpTables(self):
        return len(self._jumpvec)

    def findJumpTable(self, op):
        for jt in self._jumpvec:
            if jt.getIndirectOp() is op:
                return jt
        return None

    def removeJumpTable(self, jt):
        try:
            self._jumpvec.remove(jt)
        except ValueError:
            pass

    def linkJumpTable(self, op):
        return self.findJumpTable(op)

    def opUnlink(self, op):
        self.opUnsetOutput(op)
        for i in range(op.numInput()):
            inv = op.getIn(i)
            if inv is not None:
                inv.eraseDescend(op)
        parent = op.getParent()
        if parent is not None:
            parent.removeOp(op)

    def opDestroyRaw(self, op):
        self._obank.destroy(op)

    def opMarkHalt(self, op, flag):
        if hasattr(op, 'setHaltType'):
            op.setHaltType(flag)

    def opMarkStartBasic(self, op):
        op.setFlag(PcodeOp.startbasic)

    def opMarkStartInstruction(self, op):
        op.setFlag(PcodeOp.startmark)

    def opMarkNonPrinting(self, op):
        op.setFlag(PcodeOp.nonprinting)

    def opMarkNoCollapse(self, op):
        op.setFlag(PcodeOp.nocollapse)

    def opMarkCalculatedBool(self, op):
        op.setFlag(PcodeOp.calculated_bool)

    def opMarkSpacebasePtr(self, op):
        op.setFlag(PcodeOp.spacebase_ptr)

    def opClearSpacebasePtr(self, op):
        op.clearFlag(PcodeOp.spacebase_ptr)

    def opMarkSpecialPrint(self, op):
        if hasattr(op, 'setAdditionalFlag'):
            op.setAdditionalFlag(PcodeOp.special_print)

    def opMarkCpoolTransformed(self, op):
        if hasattr(op, 'setAdditionalFlag'):
            op.setAdditionalFlag(PcodeOp.is_cpool_transformed)

    def target(self, addr):
        return self._obank.target(addr) if hasattr(self._obank, 'target') else None

    def findOp(self, sq):
        return self._obank.findOp(sq) if hasattr(self._obank, 'findOp') else None

    def beginOp(self, opc=None):
        if opc is not None and hasattr(self._obank, 'begin'):
            return self._obank.begin(opc)
        return self._obank.beginAll() if hasattr(self._obank, 'beginAll') else iter([])

    def beginOpAlive(self):
        return self._obank.beginAlive() if hasattr(self._obank, 'beginAlive') else iter([])

    def beginOpDead(self):
        return self._obank.beginDead() if hasattr(self._obank, 'beginDead') else iter([])

    def beginOpAll(self):
        return self._obank.beginAll() if hasattr(self._obank, 'beginAll') else iter([])

    def mapGlobals(self):
        pass

    def prepareThisPointer(self):
        pass

    def markIndirectOnly(self):
        pass

    def setBasicBlockRange(self, bb, beg, end):
        if hasattr(bb, 'setInitialRange'):
            bb.setInitialRange(beg, end)
        elif hasattr(bb, 'setRange'):
            bb.setRange(beg, end)

    def clearBlocks(self):
        self._bblocks.clear()
        self._sblocks.clear()

    def clearCallSpecs(self):
        self._qlst.clear()
        self._qlst_map.clear()

    def clearJumpTables(self):
        self._jumpvec.clear()

    def sortCallSpecs(self):
        pass

    # --- PcodeOp creation routines ---

    def newOp(self, inputs: int, addr: Address) -> PcodeOp:
        """Create a new PcodeOp at the given address."""
        return self._obank.create(inputs, addr)

    def newOpBefore(self, op: PcodeOp, opc: OpCode, out: Optional[Varnode],
                    in0: Optional[Varnode], in1: Optional[Varnode] = None) -> PcodeOp:
        """Create and insert a new PcodeOp before the given op."""
        numinputs = 1 if in1 is None else 2
        newop = self._obank.create(numinputs, op.getAddr())
        newop.setOpcodeEnum(opc)
        if out is not None:
            newop.setOutput(out)
            out.setDef(newop)
        if in0 is not None:
            newop.setInput(in0, 0)
            in0.addDescend(newop)
        if in1 is not None:
            newop.setInput(in1, 1)
            in1.addDescend(newop)
        return newop

    def opSetOpcode(self, op: PcodeOp, opc: OpCode) -> None:
        """Change the opcode of an existing PcodeOp."""
        op.setOpcodeEnum(opc)

    def opSetOutput(self, op: PcodeOp, vn: Varnode) -> None:
        """Set the output of a PcodeOp."""
        op.setOutput(vn)
        vn.setDef(op)

    def opSetInput(self, op: PcodeOp, vn: Varnode, slot: int) -> None:
        """Set an input of a PcodeOp."""
        old = op.getIn(slot)
        if old is not None:
            old.eraseDescend(op)
        op.setInput(vn, slot)
        vn.addDescend(op)

    def opSwapInput(self, op: PcodeOp, slot1: int, slot2: int) -> None:
        """Swap two inputs of a PcodeOp."""
        vn1 = op.getIn(slot1)
        vn2 = op.getIn(slot2)
        op.setInput(vn2, slot1)
        op.setInput(vn1, slot2)

    def opRemoveInput(self, op: PcodeOp, slot: int) -> None:
        """Remove an input from a PcodeOp."""
        old = op.getIn(slot)
        if old is not None:
            old.eraseDescend(op)
        op.removeInput(slot)

    def opInsertInput(self, op: PcodeOp, vn: Varnode, slot: int) -> None:
        """Insert a new input into a PcodeOp at the given slot."""
        op.insertInput(slot)
        op.setInput(vn, slot)
        vn.addDescend(op)

    def opSetAllInput(self, op: PcodeOp, inputs: List[Varnode]) -> None:
        """Set all inputs of a PcodeOp at once."""
        # Clear old
        for i in range(op.numInput()):
            old = op.getIn(i)
            if old is not None:
                old.eraseDescend(op)
        op.setNumInputs(len(inputs))
        for i, vn in enumerate(inputs):
            op.setInput(vn, i)
            vn.addDescend(op)

    def opUnsetOutput(self, op: PcodeOp) -> None:
        """Remove the output from a PcodeOp."""
        out = op.getOut()
        if out is not None:
            out._def = None
            out.clearFlags(Varnode.written)
        op.setOutput(None)

    def opDestroy(self, op: PcodeOp) -> None:
        """Destroy a PcodeOp, unlinking it from everything."""
        self.opUnsetOutput(op)
        for i in range(op.numInput()):
            inv = op.getIn(i)
            if inv is not None:
                inv.eraseDescend(op)
        parent = op.getParent()
        if parent is not None:
            parent.removeOp(op)
        self._obank.destroy(op)

    def totalReplace(self, vn, newvn) -> None:
        """Replace every read of vn with newvn."""
        for op in list(vn.getDescendants()):
            slot = op.getSlot(vn)
            self.opSetInput(op, newvn, slot)

    def totalReplaceConstant(self, vn, val: int) -> None:
        """Replace every read of vn with a constant value."""
        copyop = None
        newrep = None
        for op in list(vn.getDescendants()):
            slot = op.getSlot(vn)
            if op.isMarker():
                if copyop is None:
                    if vn.isWritten():
                        copyop = self.newOp(1, vn.getDef().getSeqNum().getAddr())
                        self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                        newrep = self.newUniqueOut(vn.getSize(), copyop)
                        self.opSetInput(copyop, self.newConstant(vn.getSize(), val), 0)
                        self.opInsertAfter(copyop, vn.getDef())
                    else:
                        bb = self._bblocks.getBlock(0)
                        copyop = self.newOp(1, bb.getStart())
                        self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                        newrep = self.newUniqueOut(vn.getSize(), copyop)
                        self.opSetInput(copyop, self.newConstant(vn.getSize(), val), 0)
                        self.opInsertBegin(copyop, bb)
                else:
                    newrep = copyop.getOut()
            else:
                newrep = self.newConstant(vn.getSize(), val)
            self.opSetInput(op, newrep, slot)

    def opFlipCondition(self, op: PcodeOp) -> None:
        """Flip output condition of given CBRANCH."""
        op.flipFlag(PcodeOp.boolean_flip)

    def opDeadAndGone(self, op: PcodeOp) -> None:
        """Mark a PcodeOp as dead (but keep it around)."""
        self._obank.markDead(op)

    def opMarkAlive(self, op: PcodeOp) -> None:
        """Mark a PcodeOp as alive."""
        self._obank.markAlive(op)

    def totalNumOps(self) -> int:
        return len(list(self._obank.beginAll()))

    # --- Block routines ---

    def getBasicBlockCount(self) -> int:
        return self._bblocks.getSize()

    def getBlock(self, i: int):
        return self._bblocks.getBlock(i)

    def nodeJoinCreateBlock(self, addr: Address) -> BlockBasic:
        """Create a new basic block and add it to the graph."""
        bb = BlockBasic()
        bb.setRange(addr, addr)
        self._bblocks.addBlock(bb)
        return bb

    def opInsertBegin(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the beginning of a basic block."""
        bl.insertOp(op, 0)
        self.opMarkAlive(op)

    def opInsertEnd(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the end of a basic block."""
        bl.addOp(op)
        self.opMarkAlive(op)

    def opInsertAfter(self, op: PcodeOp, prev: PcodeOp) -> None:
        """Insert op after a specific PcodeOp in its basic block."""
        bl = prev.getParent()
        if bl is not None:
            ops = bl.getOpList()
            try:
                idx = ops.index(prev)
                bl.insertOp(op, idx + 1)
            except ValueError:
                bl.addOp(op)
        self.opMarkAlive(op)

    def opInsertBefore(self, op: PcodeOp, follow: PcodeOp) -> None:
        """Insert op before a specific PcodeOp in its basic block."""
        bl = follow.getParent()
        if bl is not None:
            ops = bl.getOpList()
            try:
                idx = ops.index(follow)
                bl.insertOp(op, idx)
            except ValueError:
                bl.addOp(op)
        self.opMarkAlive(op)

    # --- Warning / comment ---

    def warning(self, txt: str, ad: Address) -> None:
        """Add a warning comment in the function body."""
        pass  # Would use CommentDatabase

    def warningHeader(self, txt: str) -> None:
        """Add a warning comment in the function header."""
        pass

    # --- Flow and inline ---

    def followFlow(self, baddr, eaddr) -> None:
        """Generate raw p-code and basic blocks for the function body."""
        from ghidra.analysis.flow import FlowInfo
        flow = FlowInfo(self, self._obank, self._bblocks, self._qlst)
        flow.setRange(baddr, eaddr)
        flow.setFlags(self._glb.flowoptions if self._glb else 0)
        flow.setMaximumInstructions(self._glb.max_instructions if self._glb else 100000)
        flow.generateOps()
        flow.generateBlocks()
        self._flags |= Funcdata.blocks_generated
        if flow.hasUnimplemented():
            self._flags |= Funcdata.unimplemented_present
        if flow.hasBadData():
            self._flags |= Funcdata.baddata_present

    def truncatedFlow(self, fd, flow) -> None:
        """Generate a truncated set of p-code from an existing flow."""
        pass

    def inlineFlow(self, inlinefd, flow, callop) -> int:
        """In-line the given function. Returns 0=EZ, 1=hard, -1=fail."""
        return -1

    def overrideFlow(self, addr, flowtype: int) -> None:
        """Override the flow at a specific address."""
        if self._localoverride is not None and hasattr(self._localoverride, 'insertFlowOverride'):
            self._localoverride.insertFlowOverride(addr, flowtype)

    def doLiveInject(self, payload, addr, bl, pos) -> None:
        """Inject p-code into a live basic block."""
        pass

    # --- Clone / Indirect ---

    def cloneOp(self, op, seq):
        """Clone a PcodeOp into this function."""
        newop = self._obank.create(op.numInput(), seq)
        self.opSetOpcode(newop, op.code())
        if op.getOut() is not None:
            outvn = self.newVarnodeOut(op.getOut().getSize(), op.getOut().getAddr(), newop)
        for i in range(op.numInput()):
            invn = op.getIn(i)
            if invn is not None:
                newvn = self.newVarnode(invn.getSize(), invn.getAddr())
                self.opSetInput(newop, newvn, i)
        return newop

    def newIndirectOp(self, indeffect, addr, sz: int, extraFlags: int = 0):
        """Create a new INDIRECT PcodeOp."""
        from ghidra.core.opcodes import OpCode
        indop = self.newOp(2, indeffect.getAddr())
        self.opSetOpcode(indop, OpCode.CPUI_INDIRECT)
        outvn = self.newVarnodeOut(sz, addr, indop)
        invn = self.newVarnode(sz, addr)
        self.opSetInput(indop, invn, 0)
        iopvn = self.newVarnodeIop(indeffect)
        self.opSetInput(indop, iopvn, 1)
        self.opInsertBefore(indop, indeffect)
        return indop

    def newIndirectCreation(self, indeffect, addr, sz: int, possibleout: bool):
        """Create a new indirect creation PcodeOp."""
        from ghidra.core.opcodes import OpCode
        indop = self.newOp(2, indeffect.getAddr())
        self.opSetOpcode(indop, OpCode.CPUI_INDIRECT)
        outvn = self.newVarnodeOut(sz, addr, indop)
        outvn.setFlags(Varnode.indirect_creation)
        invn = self.newConstant(sz, 0)
        invn.setFlags(Varnode.indirect_creation)
        self.opSetInput(indop, invn, 0)
        iopvn = self.newVarnodeIop(indeffect)
        self.opSetInput(indop, iopvn, 1)
        indop.setFlag(PcodeOp.indirect_creation)
        self.opInsertBefore(indop, indeffect)
        return indop

    def markIndirectCreation(self, indop, possibleOutput: bool) -> None:
        """Convert CPUI_INDIRECT into an indirect creation."""
        indop.setFlag(PcodeOp.indirect_creation)
        if indop.getOut() is not None:
            indop.getOut().setFlags(Varnode.indirect_creation)

    def opInsert(self, op, bl, pos) -> None:
        """Insert a PcodeOp into a specific position in a basic block."""
        if bl is not None:
            if pos is not None and hasattr(bl, 'insertOpBefore'):
                bl.insertOpBefore(op, pos)
            elif hasattr(bl, 'addOp'):
                bl.addOp(op)
            op.setParent(bl)
        self.opMarkAlive(op)

    def opUninsert(self, op) -> None:
        """Remove the given PcodeOp from its basic block without destroying it."""
        bl = op.getParent()
        if bl is not None and hasattr(bl, 'removeOp'):
            bl.removeOp(op)
        op.setParent(None)

    def opDeadInsertAfter(self, op, prev) -> None:
        """Insert op after prev in the dead list."""
        if hasattr(self._obank, 'insertAfterDead'):
            self._obank.insertAfterDead(op, prev)

    def opDestroyRecursive(self, op, scratch: list = None) -> None:
        """Remove a PcodeOp and recursively remove ops producing its inputs."""
        if scratch is None:
            scratch = []
        for i in range(op.numInput()):
            invn = op.getIn(i)
            if invn is not None and invn.isWritten():
                defop = invn.getDef()
                if defop is not None and defop.getOut().hasNoDescend():
                    scratch.append(defop)
        self.opDestroy(op)
        for sop in scratch:
            self.opDestroyRecursive(sop)

    # --- Varnode search / link ---

    def findLinkedVarnode(self, entry):
        """Find a Varnode matching the given Symbol mapping."""
        if entry is None:
            return None
        addr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        sz = entry.getSize() if hasattr(entry, 'getSize') else 0
        if addr is None or sz == 0:
            return None
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == addr and vn.getSize() == sz:
                return vn
        return None

    def findLinkedVarnodes(self, entry, res: list) -> None:
        """Find Varnodes that map to the given SymbolEntry."""
        if entry is None:
            return
        addr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        sz = entry.getSize() if hasattr(entry, 'getSize') else 0
        if addr is None or sz == 0:
            return
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == addr and vn.getSize() == sz:
                res.append(vn)

    def linkSymbol(self, vn):
        """Find or create Symbol associated with given Varnode."""
        return None

    def linkSymbolReference(self, vn):
        """Discover and attach Symbol to a constant reference."""
        return None

    def linkProtoPartial(self, vn) -> None:
        """Find or create Symbol and a partial mapping."""
        pass

    def buildDynamicSymbol(self, vn) -> None:
        """Build a dynamic Symbol associated with the given Varnode."""
        pass

    def combineInputVarnodes(self, vnHi, vnLo) -> None:
        """Combine two contiguous input Varnodes into one."""
        pass

    def findSpacebaseInput(self, spc):
        """Find the input Varnode for the given spacebase."""
        if spc is None or not hasattr(spc, 'numSpacebase'):
            return None
        for i in range(spc.numSpacebase()):
            base = spc.getSpacebase(i)
            vn = self._vbank.findInput(base.size, base.getAddr())
            if vn is not None:
                return vn
        return None

    def constructSpacebaseInput(self, spc):
        """Construct a new spacebase register input for the given space."""
        if spc is None or not hasattr(spc, 'numSpacebase') or spc.numSpacebase() == 0:
            return None
        base = spc.getSpacebase(0)
        vn = self.newVarnode(base.size, base.getAddr())
        return self.setInputVarnode(vn)

    def newSpacebasePtr(self, spc):
        """Construct a new spacebase register for a given address space."""
        return self.constructSpacebaseInput(spc)

    def hasInputIntersection(self, s: int, loc) -> bool:
        return self._vbank.hasInputIntersection(s, loc)

    def getAliveOps(self):
        """Get all alive PcodeOps as an iterable."""
        if hasattr(self._obank, 'getAliveList'):
            return self._obank.getAliveList()
        return []

    def getStoreGuards(self):
        return self._heritage.getStoreGuards() if self._heritage else []

    def getLoadGuards(self):
        return self._heritage.getLoadGuards() if self._heritage else []

    def getStoreGuard(self, op):
        return self._heritage.getStoreGuard(op) if self._heritage else None

    # --- Encode / decode ---

    def encode(self, encoder, uid=0, savetree: bool = True) -> None:
        """Encode a description of this function to stream."""
        pass

    def decode(self, decoder) -> int:
        """Restore the state of this function from a stream."""
        return 0

    def encodeTree(self, encoder) -> None:
        """Encode a description of the p-code tree to stream."""
        pass

    def encodeHigh(self, encoder) -> None:
        """Encode a description of all HighVariables to stream."""
        pass

    def encodeJumpTable(self, encoder) -> None:
        """Encode a description of jump-tables to stream."""
        pass

    def decodeJumpTable(self, decoder) -> None:
        """Decode jump-tables from a stream."""
        pass

    # --- Data-flow / transformation helpers ---

    def syncVarnodesWithSymbols(self, lm=None, updateDatatypes: bool = False,
                                 unmappedAliasCheck: bool = False) -> bool:
        return False

    def transferVarnodeProperties(self, vn, newVn, lsbOffset: int = 0) -> None:
        """Transfer properties from one Varnode to another."""
        if vn is not None and newVn is not None:
            newVn._type = vn._type
            if vn.isTypeLock():
                newVn.setFlags(Varnode.typelock)

    def fillinReadOnly(self, vn) -> bool:
        """Replace the given Varnode with its (constant) value in the load image."""
        return False

    def replaceVolatile(self, vn) -> bool:
        """Replace accesses of the given Varnode with volatile operations."""
        return False

    def remapVarnode(self, vn, sym, usepoint) -> None:
        pass

    def remapDynamicVarnode(self, vn, sym, usepoint, hashval) -> None:
        pass

    def newExtendedConstant(self, s: int, val, op):
        """Create extended precision constant."""
        return self.newConstant(s, val[0] if isinstance(val, list) else val)

    def adjustInputVarnodes(self, addr, sz: int) -> None:
        pass

    def findDisjointCover(self, vn):
        """Find range covering given Varnode and any intersecting Varnodes."""
        return (vn.getAddr(), vn.getSize())

    def checkForLanedRegister(self, sz: int, addr) -> None:
        pass

    def recoverJumpTable(self, op, flow=None, mode_ref=None):
        """Recover a jump-table for the given BRANCHIND op."""
        return None

    def earlyJumpTableFail(self, op):
        return None

    def testForReturnAddress(self, vn) -> bool:
        return False

    def getInternalString(self, buf, size, ptrType, readOp):
        return None

    def moveRespectingCover(self, op, lastOp) -> bool:
        return False

    def getUnionField(self, parent, op, slot):
        return self._unionMap.get((id(op), slot)) if hasattr(self, '_unionMap') else None

    def forceFacingType(self, parent, fieldNum: int, op, slot: int) -> None:
        pass

    def inheritResolution(self, parent, op, slot: int, oldOp, oldSlot: int) -> int:
        return -1

    def markReturnCopy(self, op) -> None:
        op.setFlag(PcodeOp.return_copy)

    def newCodeRef(self, addr):
        """Create a code address annotation Varnode."""
        from ghidra.core.space import IPTR_IOP
        spc = None
        if self._glb is not None:
            for s in self._glb._spaces:
                if s is not None and s.getType() == IPTR_IOP:
                    spc = s
                    break
        if spc is None:
            return self.newConstant(addr.getAddrSize(), addr.getOffset())
        return self.newVarnode(addr.getAddrSize(), Address(spc, addr.getOffset()))

    # --- Print / debug ---

    def printRaw(self) -> str:
        """Print raw p-code op descriptions."""
        lines = []
        lines.append(f"Function: {self._name} @ {self._baseaddr}")
        for i in range(self._bblocks.getSize()):
            bl = self._bblocks.getBlock(i)
            if isinstance(bl, BlockBasic):
                lines.append(f"  Block {bl.getIndex()} ({bl.getStart()} - {bl.getStop()}):")
                for op in bl.getOpList():
                    lines.append(f"    {op.printRaw()}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (f"Funcdata({self._name!r} @ {self._baseaddr}, "
                f"varnodes={self._vbank.size()}, "
                f"blocks={self._bblocks.getSize()})")
