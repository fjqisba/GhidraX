"""
Corresponds to: coreaction.hh / coreaction.cc
Core decompilation Action classes and universalAction pipeline wiring.
"""
from __future__ import annotations
from typing import Optional, TYPE_CHECKING
from ghidra.transform.action import Action, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


# --- Simple Action stubs that delegate to Funcdata methods ---

class ActionStart(Action):
    def __init__(self, g): super().__init__(0, "start", g)
    def clone(self, gl):
        return ActionStart(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.startProcessing(); return 0

class ActionStop(Action):
    def __init__(self, g): super().__init__(0, "stop", g)
    def clone(self, gl):
        return ActionStop(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.stopProcessing(); return 0

class ActionStartCleanUp(Action):
    def __init__(self, g): super().__init__(0, "startcleanup", g)
    def clone(self, gl):
        return ActionStartCleanUp(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.startCleanUp(); return 0

class ActionStartTypes(Action):
    def __init__(self, g): super().__init__(0, "starttypes", g)
    def clone(self, gl):
        return ActionStartTypes(self._basegroup) if gl.contains(self._basegroup) else None
    def reset(self, data): data.setTypeRecovery(True)
    def apply(self, data):
        if data.startTypeRecovery(): self._count += 1
        return 0

class ActionHeritage(Action):
    def __init__(self, g): super().__init__(0, "heritage", g)
    def clone(self, gl):
        return ActionHeritage(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.opHeritage(); return 0

class ActionNonzeroMask(Action):
    def __init__(self, g): super().__init__(0, "nonzeromask", g)
    def clone(self, gl):
        return ActionNonzeroMask(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.calcNZMask(); return 0

class ActionConstbase(Action):
    """Inject tracked-context register constants as COPY ops at function entry."""
    def __init__(self, g): super().__init__(0, "constbase", g)
    def clone(self, gl):
        return ActionConstbase(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        if graph.getSize() == 0:
            return 0
        bb = graph.getBlock(0)
        glb = data.getArch()
        if glb is None:
            return 0
        ctx = getattr(glb, 'context', None)
        if ctx is None:
            return 0
        trackset = ctx.getTrackedSet(data.getAddress())
        if trackset is None:
            return 0
        for tracked in trackset:
            from ghidra.core.address import Address
            addr = Address(tracked.loc.space, tracked.loc.offset)
            op = data.newOp(1, bb.getStart())
            data.newVarnodeOut(tracked.loc.size, addr, op)
            vnin = data.newConstant(tracked.loc.size, tracked.val)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, vnin, 0)
            data.opInsertBegin(op, bb)
        return 0

class ActionSpacebase(Action):
    """Mark Varnode objects that hold stack-pointer values as spacebase."""
    def __init__(self, g): super().__init__(0, "spacebase", g)
    def clone(self, gl):
        return ActionSpacebase(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.spacebase()
        return 0

class ActionUnreachable(Action):
    """Remove unreachable blocks."""
    def __init__(self, g): super().__init__(0, "unreachable", g)
    def clone(self, gl):
        return ActionUnreachable(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        if data.removeUnreachableBlocks(True, False):
            self._count += 1
        return 0

from ghidra.transform.deadcode import ActionDeadCode  # Real implementation

class ActionDoNothing(Action):
    """Remove blocks that do nothing."""
    def __init__(self, g): super().__init__(Action.rule_repeatapply, "donothing", g)
    def clone(self, gl):
        return ActionDoNothing(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            if hasattr(bb, 'isDoNothing') and bb.isDoNothing():
                if bb.sizeOut() == 1 and bb.getOut(0) is bb:
                    pass  # Infinite loop - skip
                else:
                    data.removeDoNothingBlock(bb)
                    self._count += 1
                    return 0
        return 0

class ActionRedundBranch(Action):
    """Remove redundant branches: duplicate edges between same input and output block."""
    def __init__(self, g): super().__init__(0, "redundbranch", g)
    def clone(self, gl):
        return ActionRedundBranch(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getBasicBlocks()
        i = 0
        while i < graph.getSize():
            bb = graph.getBlock(i)
            if bb.sizeOut() == 0:
                i += 1
                continue
            bl = bb.getOut(0)
            if bb.sizeOut() == 1:
                if bl.sizeIn() == 1 and not bl.isEntryPoint():
                    data.spliceBlockBasic(bb)
                    self._count += 1
                    i = 0
                    continue
                i += 1
                continue
            allsame = all(bb.getOut(j) is bl for j in range(1, bb.sizeOut()))
            if allsame:
                data.removeBranch(bb, 1)
                self._count += 1
            i += 1
        return 0

class ActionDeterminedBranch(Action):
    """Remove conditional branches if the condition is constant."""
    def __init__(self, g): super().__init__(0, "determinedbranch", g)
    def clone(self, gl):
        return ActionDeterminedBranch(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            cbranch = bb.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                continue
            if not cbranch.getIn(1).isConstant():
                continue
            val = cbranch.getIn(1).getOffset()
            num = 0 if ((val != 0) != cbranch.isBooleanFlip()) else 1
            data.removeBranch(bb, num)
            self._count += 1
        return 0

class ActionVarnodeProps(Action):
    """Transform based on Varnode properties (readonly, volatile, unconsumed)."""
    def __init__(self, g): super().__init__(0, "varnodeprops", g)
    def clone(self, gl):
        return ActionVarnodeProps(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.address import calc_mask
        from ghidra.core.opcodes import OpCode
        for vn in list(data._vbank.beginLoc()):
            if vn.isAnnotation(): continue
            sz = vn.getSize()
            if sz > 8: continue
            nzm = vn.getNZMask()
            cons = vn.getConsume()
            if (nzm & cons) == 0 and not vn.isConstant():
                if vn.isWritten():
                    defop = vn.getDef()
                    if defop.code() == OpCode.CPUI_COPY:
                        inv = defop.getIn(0)
                        if inv.isConstant() and inv.getOffset() == 0:
                            continue
                if not vn.hasNoDescend():
                    for desc in list(vn.getDescendants()):
                        slot = desc.getSlot(vn)
                        data.opSetInput(desc, data.newConstant(sz, 0), slot)
                    self._count += 1
        return 0

class ActionDirectWrite(Action):
    """Mark Varnodes built out of legal parameters with directwrite attribute."""
    def __init__(self, g, prop=True):
        super().__init__(0, "directwrite", g)
        self._propagateIndirect = prop
    def clone(self, gl):
        return ActionDirectWrite(self._basegroup, self._propagateIndirect) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        worklist = []
        for vn in list(data._vbank.beginLoc()):
            vn.clearDirectWrite()
            if vn.isInput():
                if vn.isPersist() or vn.isSpacebase():
                    vn.setDirectWrite()
                    worklist.append(vn)
            elif vn.isWritten():
                op = vn.getDef()
                if not op.isMarker():
                    if vn.isPersist():
                        vn.setDirectWrite()
                        worklist.append(vn)
                    elif op.code() not in (OpCode.CPUI_COPY, OpCode.CPUI_PIECE, OpCode.CPUI_SUBPIECE):
                        vn.setDirectWrite()
                        worklist.append(vn)
                elif not self._propagateIndirect and op.code() == OpCode.CPUI_INDIRECT:
                    outvn = op.getOut()
                    if op.getIn(0).getAddr() != outvn.getAddr():
                        vn.setDirectWrite()
                    elif outvn.isPersist():
                        vn.setDirectWrite()
            elif vn.isConstant():
                if not vn.isIndirectZero():
                    vn.setDirectWrite()
                    worklist.append(vn)
        while worklist:
            vn = worklist.pop()
            for op in vn.getDescendants():
                if not op.isAssignment():
                    continue
                dvn = op.getOut()
                if not dvn.isDirectWrite():
                    dvn.setDirectWrite()
                    if self._propagateIndirect or op.code() != OpCode.CPUI_INDIRECT or op.isIndirectStore():
                        worklist.append(dvn)
        return 0

class ActionForceGoto(Action):
    def __init__(self, g): super().__init__(0, "forcegoto", g)
    def clone(self, gl):
        return ActionForceGoto(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data): return 0  # TODO

class ActionSegmentize(Action):
    def __init__(self, g): super().__init__(0, "segmentize", g)
    def clone(self, gl):
        return ActionSegmentize(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data): return 0  # TODO

class ActionInternalStorage(Action):
    def __init__(self, g): super().__init__(0, "internalstorage", g)
    def clone(self, gl):
        return ActionInternalStorage(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data): return 0  # TODO

class ActionMultiCse(Action):
    """Eliminate redundant MULTIEQUAL ops sharing all inputs in same block."""
    def __init__(self, g): super().__init__(0, "multicse", g)
    def clone(self, gl):
        return ActionMultiCse(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            ops = list(bl.getOps()) if hasattr(bl, 'getOps') else []
            mequals = [op for op in ops if op.code() == OpCode.CPUI_MULTIEQUAL]
            for idx in range(len(mequals)):
                target = mequals[idx]
                for jdx in range(idx):
                    pair = mequals[jdx]
                    if pair.numInput() != target.numInput():
                        continue
                    match = True
                    for k in range(target.numInput()):
                        if target.getIn(k) is not pair.getIn(k):
                            match = False; break
                    if match:
                        data.totalReplace(target.getOut(), pair.getOut())
                        data.opDestroy(target)
                        self._count += 1
                        break
        return 0

class ActionShadowVar(Action):
    """Detect shadow MULTIEQUAL ops that share input[0] and are redundant."""
    def __init__(self, g): super().__init__(0, "shadowvar", g)
    def clone(self, gl):
        return ActionShadowVar(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        oplist = []
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            vnlist = []
            ops = list(bl.getOps()) if hasattr(bl, 'getOps') else []
            for op in ops:
                if op.code() != OpCode.CPUI_MULTIEQUAL:
                    continue
                vn = op.getIn(0)
                if vn.isMark():
                    oplist.append(op)
                else:
                    vn.setMark()
                    vnlist.append(vn)
            for vn in vnlist:
                vn.clearMark()
        for op in oplist:
            prev = op.previousOp() if hasattr(op, 'previousOp') else None
            while prev is not None:
                if prev.code() != OpCode.CPUI_MULTIEQUAL:
                    prev = prev.previousOp() if hasattr(prev, 'previousOp') else None
                    continue
                if prev.numInput() != op.numInput():
                    prev = prev.previousOp() if hasattr(prev, 'previousOp') else None
                    continue
                match = all(op.getIn(k) is prev.getIn(k) for k in range(op.numInput()))
                if match:
                    data.opSetOpcode(op, OpCode.CPUI_COPY)
                    data.opSetAllInput(op, [prev.getOut()])
                    self._count += 1
                    break
                prev = prev.previousOp() if hasattr(prev, 'previousOp') else None
        return 0

class ActionDeindirect(Action):
    """Resolve indirect calls to direct calls where possible."""
    def __init__(self, g): super().__init__(0, "deindirect", g)
    def clone(self, gl):
        return ActionDeindirect(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            op = fc.getOp()
            if op.code() != OpCode.CPUI_CALLIND:
                continue
            vn = op.getIn(0)
            while vn.isWritten() and vn.getDef().code() == OpCode.CPUI_COPY:
                vn = vn.getDef().getIn(0)
            if vn.isConstant():
                # Could resolve to a known function address
                pass  # TODO: query function database
        return 0

class ActionStackPtrFlow(Action):
    """Analyze stack-pointer flow and resolve unknown extra-pop values."""
    def __init__(self, g, ss=None):
        super().__init__(0, "stackptrflow", g)
        self._stackspace = ss
        self._analysis_finished = False
    def clone(self, gl):
        return ActionStackPtrFlow(self._basegroup, self._stackspace) if gl.contains(self._basegroup) else None
    def reset(self, data):
        super().reset(data)
        self._analysis_finished = False
    def apply(self, data):
        if self._analysis_finished:
            return 0
        if self._stackspace is None:
            self._analysis_finished = True
            return 0
        # Simplified: just mark analysis as finished after first pass
        # Full impl would use StackSolver to resolve extra-pop across calls
        self._analysis_finished = True
        return 0

class ActionLaneDivide(Action):
    """Divide laned registers (SIMD) into individual lane-sized variables."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "lanedivide", g)
    def clone(self, gl):
        return ActionLaneDivide(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Would iterate laned register accesses and divide into lanes
        # using LaneDescription and LaneDivide infrastructure
        if hasattr(data, 'beginLaneAccess'):
            for vdata, lanedReg in data.beginLaneAccess():
                pass  # Process each laned register
            if hasattr(data, 'clearLanedAccessMap'):
                data.clearLanedAccessMap()
        return 0

class ActionConstantPtr(Action):
    """Identify constant values that are likely pointers and mark them."""
    def __init__(self, g): super().__init__(0, "constantptr", g)
    def clone(self, gl):
        return ActionConstantPtr(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        glb = data.getArch()
        if glb is None:
            return 0
        for op in list(data._obank.beginAlive()):
            for slot in range(op.numInput()):
                vn = op.getIn(slot)
                if not vn.isConstant():
                    continue
                if vn.getSize() < 4:
                    continue
                if hasattr(vn, '_addlflags') and (vn._addlflags & 0x10) != 0:
                    continue  # ptrcheck already set
                opc = op.code()
                if opc in (OpCode.CPUI_STORE, OpCode.CPUI_LOAD):
                    if slot == 1:  # pointer operand
                        vn._addlflags |= 0x10  # Mark as ptr-checked
                elif opc == OpCode.CPUI_CALLIND and slot == 0:
                    vn._addlflags |= 0x10
        return 0

class ActionConditionalConst(Action):
    """Propagate constants down conditional branches where the condition implies a known value."""
    def __init__(self, g): super().__init__(0, "condconst", g)
    def clone(self, gl):
        return ActionConditionalConst(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            cbranch = bl.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                continue
            boolVn = cbranch.getIn(1)
            if boolVn.loneDescend() is not None:
                continue  # Only read once (by the CBRANCH itself)
            # The boolean is read elsewhere: propagate bool=0 / bool=1
            # down the false/true branches respectively
            flipEdge = cbranch.isBooleanFlip()
            falseVal = 1 if flipEdge else 0
            trueVal = 0 if flipEdge else 1
            # For each descendant of boolVn that is dominated by one branch,
            # replace boolVn with the appropriate constant
            for desc in list(boolVn.getDescendants()):
                if desc is cbranch:
                    continue
                parent = desc.getParent()
                if parent is None:
                    continue
                # Check if desc's block is dominated by false or true out
                falseOut = bl.getFalseOut()
                trueOut = bl.getTrueOut()
                if falseOut is not None and falseOut.dominates(parent):
                    slot = desc.getSlot(boolVn)
                    data.opSetInput(desc, data.newConstant(boolVn.getSize(), falseVal), slot)
                    self._count += 1
                elif trueOut is not None and trueOut.dominates(parent):
                    slot = desc.getSlot(boolVn)
                    data.opSetInput(desc, data.newConstant(boolVn.getSize(), trueVal), slot)
                    self._count += 1
        return 0

class ActionInferTypes(Action):
    """Infer and propagate data-types through the data-flow graph."""
    def __init__(self, g): super().__init__(0, "infertypes", g)
    def clone(self, gl):
        return ActionInferTypes(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data): return 0  # TODO
