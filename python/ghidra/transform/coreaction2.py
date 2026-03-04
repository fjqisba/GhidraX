"""
Corresponds to: coreaction.hh / coreaction.cc (part 2)
Remaining Action stubs + universalAction pipeline wiring.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
from ghidra.transform.action import (
    Action, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase,
)
from ghidra.transform.coreaction import *

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


# --- Prototype / parameter Actions ---

class ActionNormalizeSetup(Action):
    """Clear prototype locks for re-evaluation during normalization."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "normalizesetup", g)
    def clone(self, gl):
        return ActionNormalizeSetup(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        fp = data.getFuncProto()
        if hasattr(fp, 'clearInput'):
            fp.clearInput()
        return 0

class ActionPrototypeTypes(Action):
    """Apply prototype types: strip indirect registers from RETURN, force locked inputs."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "prototypetypes", g)
    def clone(self, gl):
        return ActionPrototypeTypes(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        # Strip indirect register from all RETURN ops
        for op in list(data._obank.beginAlive()):
            if op.code() != OpCode.CPUI_RETURN:
                continue
            if op.isDead():
                continue
            if op.numInput() > 0 and not op.getIn(0).isConstant():
                vn = data.newConstant(op.getIn(0).getSize(), 0)
                data.opSetInput(op, vn, 0)
        # Force locked inputs to exist as varnodes
        proto = data.getFuncProto()
        if proto.isInputLocked():
            graph = data.getBasicBlocks()
            if graph.getSize() > 0:
                topbl = graph.getBlock(0)
                for i in range(proto.numParams()):
                    param = proto.getParam(i)
                    if param is None:
                        continue
                    vn = data.newVarnode(param.getSize(), param.getAddress())
                    data.setInputVarnode(vn)
        return 0

class ActionDefaultParams(Action):
    """Set up default parameter information for calls without locked prototypes."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "defaultparams", g)
    def clone(self, gl):
        return ActionDefaultParams(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Set up default parameters for each call without locked input
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            if not fc.isInputLocked():
                pass  # Would set up active input gathering
        return 0

class ActionExtraPopSetup(Action):
    """Set up INDIRECT or INT_ADD ops to model stack-pointer changes across calls."""
    def __init__(self, g, ss=None):
        super().__init__(Action.rule_onceperfunc, "extrapopsetup", g)
        self._stackspace = ss
    def clone(self, gl):
        return ActionExtraPopSetup(self._basegroup, self._stackspace) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.core.address import Address
        if self._stackspace is None:
            return 0
        if not hasattr(self._stackspace, 'getSpacebase'):
            return 0
        point = self._stackspace.getSpacebase(0)
        sb_addr = Address(point.space, point.offset)
        sb_size = point.size
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            extrapop = fc.getExtraPop()
            if extrapop == 0:
                continue
            op = data.newOp(2, fc.getOp().getAddr())
            data.newVarnodeOut(sb_size, sb_addr, op)
            data.opSetInput(op, data.newVarnode(sb_size, sb_addr), 0)
            if extrapop != 0x7FFFFFFF:  # Not unknown
                fc.setEffectiveExtraPop(extrapop)
                data.opSetOpcode(op, OpCode.CPUI_INT_ADD)
                data.opSetInput(op, data.newConstant(sb_size, extrapop), 1)
                data.opInsertAfter(op, fc.getOp())
            else:
                data.opSetOpcode(op, OpCode.CPUI_INDIRECT)
                data.opSetInput(op, data.newConstant(sb_size, 0), 1)
                data.opInsertBefore(op, fc.getOp())
        return 0

class ActionFuncLink(Action):
    """Link call sites to function prototypes, setting up inputs/outputs."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "funclink", g)
    def clone(self, gl):
        return ActionFuncLink(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            self._funcLinkInput(fc, data)
            self._funcLinkOutput(fc, data)
        return 0

    @staticmethod
    def _funcLinkInput(fc, data):
        """Set up input parameters for a call based on prototype."""
        if not fc.isInputLocked():
            return
        op = fc.getOp()
        numparam = fc.numParams()
        for i in range(numparam):
            param = fc.getParam(i)
            if param is None:
                continue
            data.opInsertInput(op, data.newVarnode(param.getSize(), param.getAddress()), op.numInput())

    @staticmethod
    def _funcLinkOutput(fc, data):
        """Set up output for a call based on prototype."""
        callop = fc.getOp()
        if callop.getOut() is not None:
            data.opUnsetOutput(callop)
        if not fc.isOutputLocked():
            return
        outparam = fc.getOutput()
        if outparam is None:
            return
        from ghidra.types.datatype import TYPE_VOID
        outtype = outparam.getType()
        if outtype is not None and outtype.getMetatype() != TYPE_VOID:
            data.newVarnodeOut(outparam.getSize(), outparam.getAddress(), callop)

class ActionFuncLinkOutOnly(Action):
    """Link only output prototypes for calls (used during noproto phase)."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "funclinkoutonly", g)
    def clone(self, gl):
        return ActionFuncLinkOutOnly(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        for i in range(data.numCalls()):
            ActionFuncLink._funcLinkOutput(data.getCallSpecs(i), data)
        return 0

class ActionParamDouble(Action):
    """Split double-precision parameters into their component pieces at call sites."""
    def __init__(self, g): super().__init__(0, "paramdouble", g)
    def clone(self, gl):
        return ActionParamDouble(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            if fc.isInputActive():
                active = fc.getActiveInput()
                if active is None:
                    continue
                op = fc.getOp()
                for j in range(active.getNumTrials()):
                    trial = active.getTrial(j)
                    if trial.isChecked():
                        continue
                    if trial.isUnref():
                        continue
                    slot = trial.getSlot()
                    if slot >= op.numInput():
                        continue
                    vn = op.getIn(slot)
                    if not vn.isWritten():
                        continue
                    concatop = vn.getDef()
                    if concatop.code() != OpCode.CPUI_PIECE:
                        continue
                    # Found a PIECE feeding into a call - potential double-precision split
                    # Would call fc.checkInputSplit and active.splitTrial
        return 0

class ActionActiveParam(Action):
    """Actively recover function parameters through trial analysis."""
    def __init__(self, g): super().__init__(0, "activeparam", g)
    def clone(self, gl):
        return ActionActiveParam(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            if not fc.isInputActive():
                continue
            active = fc.getActiveInput()
            if active is None:
                continue
            active.finishPass()
            if active.getNumPasses() > active.getMaxPass():
                active.markFullyChecked()
            else:
                self._count += 1
            if active.isFullyChecked():
                # Would resolve model and build inputs from trials
                fc.clearActiveInput()
                self._count += 1
        return 0

class ActionReturnRecovery(Action):
    """Recover return values through ancestor analysis of RETURN ops."""
    def __init__(self, g): super().__init__(0, "returnrecovery", g)
    def clone(self, gl):
        return ActionReturnRecovery(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        active = data.getActiveOutput()
        if active is None:
            return 0
        from ghidra.core.opcodes import OpCode
        for op in list(data._obank.beginAlive()):
            if op.code() != OpCode.CPUI_RETURN or op.isDead():
                continue
            for i in range(active.getNumTrials()):
                trial = active.getTrial(i)
                if trial.isChecked():
                    continue
                # Simplified: mark trial as active if it has a non-constant input
                slot = trial.getSlot()
                if slot < op.numInput():
                    vn = op.getIn(slot)
                    if not vn.isConstant():
                        trial.markActive()
                self._count += 1
        active.finishPass()
        if active.getNumPasses() > active.getMaxPass():
            active.markFullyChecked()
        if active.isFullyChecked():
            data.clearActiveOutput()
            self._count += 1
        return 0

class ActionRestrictLocal(Action):
    """Restrict local variable ranges based on call effects."""
    def __init__(self, g): super().__init__(0, "restrictlocal", g)
    def clone(self, gl):
        return ActionRestrictLocal(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Mark storage for saved registers as not mapped
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None or not fc.isInputLocked():
                continue
        return 0

class ActionDynamicMapping(Action):
    """Map dynamic variables to their storage locations using DynamicHash."""
    def __init__(self, g): super().__init__(0, "dynamicmapping", g)
    def clone(self, gl):
        return ActionDynamicMapping(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        localmap = data.getLocalScope()
        if localmap is None:
            return 0
        if not hasattr(localmap, 'beginDynamic'):
            return 0
        from ghidra.analysis.dynamic import DynamicHash
        dhash = DynamicHash()
        for entry in localmap.beginDynamic():
            if hasattr(data, 'attemptDynamicMapping'):
                if data.attemptDynamicMapping(entry, dhash):
                    self._count += 1
        return 0

class ActionRestructureVarnode(Action):
    """Restructure Varnodes based on local variable recovery and symbol mapping."""
    def __init__(self, g): super().__init__(0, "restructurevarnode", g)
    def clone(self, gl):
        return ActionRestructureVarnode(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        localmap = data.getLocalScope()
        if localmap is None:
            return 0
        # Would sync varnode properties with symbols in localmap
        # and restructure based on mapped ranges
        if hasattr(localmap, 'restructureVarnode'):
            if localmap.restructureVarnode(data):
                self._count += 1
        return 0

class ActionLikelyTrash(Action):
    """Detect input varnodes that are likely trash (unused register values)."""
    def __init__(self, g): super().__init__(0, "likelytrash", g)
    def clone(self, gl):
        return ActionLikelyTrash(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        # Check function prototype's trash list
        proto = data.getFuncProto()
        if not hasattr(proto, 'trashBegin'):
            return 0
        return 0

class ActionSwitchNorm(Action):
    """Normalize switch/case statements by recovering labels."""
    def __init__(self, g): super().__init__(0, "switchnorm", g)
    def clone(self, gl):
        return ActionSwitchNorm(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Would iterate jump tables, match models, recover labels
        for i in range(len(data._jumpvec)):
            pass  # TODO: jt.matchModel, recoverLabels, foldInNormalization
        return 0

class ActionUnjustifiedParams(Action):
    """Check for input varnodes that don't match the prototype and extend them."""
    def __init__(self, g): super().__init__(0, "unjustifiedparams", g)
    def clone(self, gl):
        return ActionUnjustifiedParams(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data): return 0  # Needs unjustifiedInputParam

class ActionActiveReturn(Action):
    """Check active return value recovery for each call site."""
    def __init__(self, g): super().__init__(0, "activereturn", g)
    def clone(self, gl):
        return ActionActiveReturn(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            # Would check fc.isOutputActive() and process
        return 0

class ActionReturnSplit(Action):
    """Split RETURN blocks that are shared by multiple gotos."""
    def __init__(self, g): super().__init__(0, "returnsplit", g)
    def clone(self, gl):
        return ActionReturnSplit(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data): return 0  # Needs nodeSplit infrastructure

# --- Merge / output Actions ---

class ActionAssignHigh(Action):
    """Assign initial HighVariable objects to each Varnode."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "assignhigh", g)
    def clone(self, gl):
        return ActionAssignHigh(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.setHighLevel()
        return 0

class ActionMergeRequired(Action):
    """Merge Varnodes that are required to be in the same HighVariable (MULTIEQUAL inputs/outputs)."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergerequired", g)
    def clone(self, gl):
        return ActionMergeRequired(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        for op in list(data._obank.beginAlive()):
            if op.code() != OpCode.CPUI_MULTIEQUAL:
                continue
            outvn = op.getOut()
            if outvn is None:
                continue
            outhigh = outvn.getHigh()
            if outhigh is None:
                continue
            for i in range(op.numInput()):
                invn = op.getIn(i)
                inhigh = invn.getHigh()
                if inhigh is not None and inhigh is not outhigh:
                    outhigh.mergeInternal(inhigh)
                    self._count += 1
        return 0

class ActionMergeAdjacent(Action):
    """Merge Varnodes at the same address that don't conflict."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergeadjacent", g)
    def clone(self, gl):
        return ActionMergeAdjacent(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.analysis.merge import Merge
        merger = Merge(data)
        prev = None
        for vn in list(data._vbank.beginLoc()):
            if prev is not None and prev.getAddr() == vn.getAddr() and prev.getSize() == vn.getSize():
                ph = prev.getHigh()
                vh = vn.getHigh()
                if ph is not None and vh is not None and ph is not vh:
                    if merger.mergeTest(ph, vh):
                        ph.mergeInternal(vh)
                        self._count += 1
            prev = vn
        return 0

class ActionMergeCopy(Action):
    """Merge Varnodes connected by COPY operations."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergecopy", g)
    def clone(self, gl):
        return ActionMergeCopy(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.analysis.merge import Merge
        merger = Merge(data)
        for op in list(data._obank.beginAlive()):
            if op.code() != OpCode.CPUI_COPY:
                continue
            outvn = op.getOut()
            invn = op.getIn(0)
            if outvn is None or invn is None:
                continue
            oh = outvn.getHigh()
            ih = invn.getHigh()
            if oh is not None and ih is not None and oh is not ih:
                if outvn.getSize() == invn.getSize() and merger.mergeTest(oh, ih):
                    oh.mergeInternal(ih)
                    self._count += 1
        return 0

class ActionMergeMultiEntry(Action):
    """Merge Varnodes across multiple entry points."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergemultientry", g)
    def clone(self, gl):
        return ActionMergeMultiEntry(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data): return 0

class ActionMergeType(Action):
    """Merge Varnodes based on type compatibility."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergetype", g)
    def clone(self, gl):
        return ActionMergeType(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.analysis.merge import Merge
        merger = Merge(data)
        for vn in list(data._vbank.beginLoc()):
            if not vn.isWritten():
                continue
            vh = vn.getHigh()
            if vh is None:
                continue
            for desc in vn.getDescendants():
                outvn = desc.getOut()
                if outvn is None:
                    continue
                oh = outvn.getHigh()
                if oh is not None and oh is not vh:
                    if vn.getSize() == outvn.getSize() and merger.mergeTest(vh, oh):
                        vh.mergeInternal(oh)
                        self._count += 1
        return 0

class ActionMarkExplicit(Action):
    """Mark Varnodes that should be printed as explicit variables."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "markexplicit", g)
    def clone(self, gl):
        return ActionMarkExplicit(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.ir.varnode import Varnode
        for vn in list(data._vbank.beginLoc()):
            if vn.isFree():
                continue
            if vn.isConstant():
                continue
            descs = list(vn.getDescendants())
            if len(descs) == 0:
                vn.setExplicit()
                self._count += 1
            elif len(descs) > 1 or vn.isAddrTied() or vn.isPersist() or vn.isInput():
                vn.setExplicit()
                self._count += 1
        return 0

class ActionMarkImplied(Action):
    """Mark Varnodes that can be printed as implied (inline) expressions."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "markimplied", g)
    def clone(self, gl):
        return ActionMarkImplied(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.ir.varnode import Varnode
        for vn in list(data._vbank.beginLoc()):
            if vn.isFree() or vn.isConstant():
                continue
            if vn.isExplicit():
                continue
            vn.setImplied()
            self._count += 1
        return 0

class ActionMarkIndirectOnly(Action):
    """Mark Varnodes only used through INDIRECT as indirect-only."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "markindirectonly", g)
    def clone(self, gl):
        return ActionMarkIndirectOnly(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.ir.varnode import Varnode
        for vn in list(data._vbank.beginLoc()):
            if not vn.isWritten():
                continue
            allIndirect = True
            for desc in vn.getDescendants():
                if desc.code() != OpCode.CPUI_INDIRECT:
                    allIndirect = False
                    break
            if allIndirect and not vn.hasNoDescend():
                vn._flags |= Varnode.indirectonly
        return 0

class ActionNameVars(Action):
    """Assign names to high-level variables."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "namevars", g)
    def clone(self, gl):
        return ActionNameVars(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Would iterate HighVariables and assign names from symbols or generate names
        return 0

class ActionSetCasts(Action):
    """Insert CAST operations where type conversions are needed."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "setcasts", g)
    def clone(self, gl):
        return ActionSetCasts(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.startCastPhase()
        return 0

class ActionDominantCopy(Action):
    """Replace COPY ops where the output is dominated by its input."""
    def __init__(self, g): super().__init__(0, "dominantcopy", g)
    def clone(self, gl):
        return ActionDominantCopy(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        for op in list(data._obank.beginAlive()):
            if op.code() != OpCode.CPUI_COPY:
                continue
            outvn = op.getOut()
            invn = op.getIn(0)
            if outvn is None or invn is None:
                continue
            oh = outvn.getHigh()
            ih = invn.getHigh()
            if oh is not None and ih is not None and oh is ih:
                # Already merged - this COPY can potentially be eliminated
                pass
        return 0

class ActionDynamicSymbols(Action):
    """Map dynamic hash-based symbols to their Varnodes."""
    def __init__(self, g): super().__init__(0, "dynamicsymbols", g)
    def clone(self, gl):
        return ActionDynamicSymbols(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        localmap = data.getLocalScope()
        if localmap is None:
            return 0
        if not hasattr(localmap, 'beginDynamic'):
            return 0
        from ghidra.analysis.dynamic import DynamicHash
        dhash = DynamicHash()
        for entry in localmap.beginDynamic():
            if hasattr(data, 'attemptDynamicMappingLate'):
                if data.attemptDynamicMappingLate(entry, dhash):
                    self._count += 1
        return 0

class ActionCopyMarker(Action):
    """Mark COPY ops that should not be printed (they become assignments)."""
    def __init__(self, g): super().__init__(0, "copymarker", g)
    def clone(self, gl):
        return ActionCopyMarker(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        for op in list(data._obank.beginAlive()):
            if op.code() != OpCode.CPUI_COPY:
                continue
            outvn = op.getOut()
            invn = op.getIn(0)
            if outvn is None or invn is None:
                continue
            oh = outvn.getHigh()
            ih = invn.getHigh()
            if oh is not None and ih is not None and oh is ih:
                op.setNonPrinting()
        return 0

class ActionHideShadow(Action):
    """Hide shadow copies of input varnodes that were saved/restored."""
    def __init__(self, g): super().__init__(0, "hideshadow", g)
    def clone(self, gl):
        return ActionHideShadow(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Iterate through written varnodes and check for shadow merges
        seen = set()
        for vn in list(data._vbank.beginLoc()):
            if not vn.isWritten():
                continue
            high = vn.getHigh()
            if high is None:
                continue
            hid = id(high)
            if hid in seen:
                continue
            seen.add(hid)
            # Would call data.getMerge().hideShadows(high) if implemented
        return 0

class ActionOutputPrototype(Action):
    """Determine the output prototype from RETURN operations."""
    def __init__(self, g): super().__init__(0, "outputprototype", g)
    def clone(self, gl):
        return ActionOutputPrototype(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        proto = data.getFuncProto()
        outparam = proto.getOutput()
        if outparam is None:
            return 0
        if not outparam.isTypeLocked():
            # Collect return values from first non-dead RETURN op
            from ghidra.core.opcodes import OpCode
            for op in list(data._obank.beginAlive()):
                if op.code() != OpCode.CPUI_RETURN or op.isDead():
                    continue
                vnlist = [op.getIn(i) for i in range(1, op.numInput())]
                break
        return 0

class ActionInputPrototype(Action):
    """Finalize the input prototype based on actually used input varnodes."""
    def __init__(self, g): super().__init__(0, "inputprototype", g)
    def clone(self, gl):
        return ActionInputPrototype(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        proto = data.getFuncProto()
        if not proto.isInputLocked():
            # Collect input varnodes that are actually used
            for vn in list(data._vbank.beginLoc()):
                if not vn.isInput():
                    continue
                if vn.hasNoDescend():
                    continue
                # This input is used - would register as a trial parameter
        data.clearDeadVarnodes()
        return 0

class ActionMapGlobals(Action):
    """Map global variables to their symbol entries."""
    def __init__(self, g): super().__init__(0, "mapglobals", g)
    def clone(self, gl):
        return ActionMapGlobals(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Iterate through all persistent varnodes and map to global symbols
        for vn in list(data._vbank.beginLoc()):
            if not vn.isPersist():
                continue
            if vn.isTypeLock():
                continue
            # Would query global scope for symbol at vn's address
        return 0

class ActionMappedLocalSync(Action):
    """Synchronize mapped local variables with their symbols."""
    def __init__(self, g): super().__init__(0, "mappedlocalsync", g)
    def clone(self, gl):
        return ActionMappedLocalSync(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Would synchronize ScopeLocal with Varnode properties
        return 0

class ActionPrototypeWarnings(Action):
    """Emit warnings about prototype issues (missing returns, bad params)."""
    def __init__(self, g): super().__init__(0, "prototypewarnings", g)
    def clone(self, gl):
        return ActionPrototypeWarnings(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Check for prototype anomalies and emit warnings
        return 0

# --- Block structure Actions (stubs) ---

class ActionBlockStructure(Action):
    """Structure control-flow using standard high-level code constructs."""
    def __init__(self, g): super().__init__(0, "blockstructure", g)
    def clone(self, gl):
        return ActionBlockStructure(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        if graph.getSize() != 0:
            return 0
        graph.buildCopy(data.getBasicBlocks())
        from ghidra.block.collapse import CollapseStructure
        collapse = CollapseStructure(graph)
        collapse.collapseAll()
        self._count += collapse.getChangeCount()
        return 0

class ActionNodeJoin(Action):
    """Join split conditional blocks back together."""
    def __init__(self, g): super().__init__(0, "nodejoin", g)
    def clone(self, gl):
        return ActionNodeJoin(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        if graph.getSize() == 0:
            return 0
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            if bb.sizeOut() != 2:
                continue
            out0 = bb.getOut(0)
            out1 = bb.getOut(1)
            # Find the output with fewer inputs
            if out0.sizeIn() < out1.sizeIn():
                leastout = out0
                inslot = bb.getOutRevIndex(0)
            else:
                leastout = out1
                inslot = bb.getOutRevIndex(1)
            if leastout.sizeIn() == 1:
                continue
            # Look for another CBRANCH block feeding into leastout
            for j in range(leastout.sizeIn()):
                if j == inslot:
                    continue
                bb2 = leastout.getIn(j)
                if bb2.sizeOut() != 2:
                    continue
                # Check if bb and bb2 share the same two exit blocks
                exits_bb = {id(bb.getOut(0)), id(bb.getOut(1))}
                exits_bb2 = {id(bb2.getOut(0)), id(bb2.getOut(1))}
                if exits_bb == exits_bb2:
                    # Potential conditional join - needs deeper matching
                    pass
        return 0

class ActionConditionalExe(Action):
    """Remove redundant CBRANCHs that test the same condition as an earlier branch."""
    def __init__(self, g): super().__init__(0, "conditionalexe", g)
    def clone(self, gl):
        return ActionConditionalExe(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.transform.condexe import ConditionalExecution
        condexe = ConditionalExecution(data)
        graph = data.getBasicBlocks()
        changed = True
        while changed:
            changed = False
            for i in range(graph.getSize()):
                bb = graph.getBlock(i)
                if condexe.trial(bb):
                    condexe.execute()
                    self._count += 1
                    changed = True
                    break
        return 0

class ActionPreferComplement(Action):
    """Choose preferred complement for symmetric if/else structuring."""
    def __init__(self, g): super().__init__(0, "prefercomplement", g)
    def clone(self, gl):
        return ActionPreferComplement(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        if graph.getSize() == 0:
            return 0
        # Would walk structure tree calling preferComplement on each node
        return 0

class ActionStructureTransform(Action):
    """Give each structure element a chance to do final transforms (e.g. for-loop setup)."""
    def __init__(self, g): super().__init__(0, "structuretransform", g)
    def clone(self, gl):
        return ActionStructureTransform(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        if graph.getSize() == 0:
            return 0
        # Would walk structure tree calling finalTransform on WhileDo blocks
        return 0

class ActionNormalizeBranches(Action):
    """Normalize CBRANCH conditions for cleaner structured output."""
    def __init__(self, g): super().__init__(0, "normalizebranches", g)
    def clone(self, gl):
        return ActionNormalizeBranches(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            if bb.sizeOut() != 2:
                continue
            cbranch = bb.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                continue
            # Attempt to normalize: flip if the boolean input can be simplified
            # by removing a BOOL_NEGATE
            inv = cbranch.getIn(1)
            if inv.isWritten() and inv.getDef().code() == OpCode.CPUI_BOOL_NEGATE:
                # Flip the branch and remove the negate
                bb.negateCondition(True)
                self._count += 1
        return 0

class ActionFinalStructure(Action):
    """Finalize control-flow structure: order blocks, insert breaks/gotos."""
    def __init__(self, g): super().__init__(0, "finalstructure", g)
    def clone(self, gl):
        return ActionFinalStructure(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        # Would call graph.orderBlocks(), finalizePrinting(), scopeBreak(), markUnstructured(), markLabelBumpUp()
        return 0
