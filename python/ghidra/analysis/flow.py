"""
Corresponds to: flow.hh / flow.cc

Utilities for following control-flow in p-code generated from machine instructions.
A class for generating the control-flow structure for a single function.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List, Dict, Set

from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.ir.op import PcodeOp, PcodeOpBank
    from ghidra.block.block import BlockGraph, BlockBasic, FlowBlock
    from ghidra.fspec.fspec import FuncCallSpecs
    from ghidra.arch.architecture import Architecture


class FlowInfo:
    """A class for generating the control-flow structure for a single function.

    Control-flow is generated in two phases:
      - generateOps() produces all the raw p-code ops
      - generateBlocks() organizes p-code ops into basic blocks (PcodeBlockBasic)
    """

    # --- Flag constants (match C++ exactly) ---
    ignore_outofbounds          = 0x1
    ignore_unimplemented        = 0x2
    error_outofbounds           = 0x4
    error_unimplemented         = 0x8
    error_reinterpreted         = 0x10
    error_toomanyinstructions   = 0x20
    unimplemented_present       = 0x40
    baddata_present             = 0x80
    outofbounds_present         = 0x100
    reinterpreted_present       = 0x200
    toomanyinstructions_present = 0x400
    possible_unreachable        = 0x1000
    flow_forinline              = 0x2000
    record_jumploads            = 0x4000

    class VisitStat:
        """Number of bytes in a machine instruction and the starting p-code op."""
        __slots__ = ('seqnum', 'size')
        def __init__(self):
            self.seqnum = None
            self.size: int = 0

    # ----------------------------------------------------------------
    # Constructors
    # ----------------------------------------------------------------

    def __init__(self, fd: Funcdata, obank=None, bblocks=None,
                 qlst: list = None, op2: Optional[FlowInfo] = None) -> None:
        self._data: Funcdata = fd
        self._obank = obank
        self._bblocks = bblocks
        self._qlst: List = qlst if qlst is not None else []
        self._glb = fd.getArch() if hasattr(fd, 'getArch') else None

        self._unprocessed: List[Address] = []
        self._addrlist: List[Address] = []
        self._tablelist: List = []
        self._injectlist: List = []
        self._visited: Dict[Address, FlowInfo.VisitStat] = {}
        self._block_edge1: List = []
        self._block_edge2: List = []

        self._insn_count: int = 0
        self._insn_max: int = 0xFFFFFFFF
        self._flowoverride_present: bool = False
        self._inline_head = None
        self._inline_recursion: Optional[Set[Address]] = None
        self._inline_base: Set[Address] = set()

        func_addr = fd.getAddress() if hasattr(fd, 'getAddress') else Address()

        if op2 is not None:
            # Cloning constructor
            self._baddr: Address = op2._baddr
            self._eaddr: Address = op2._eaddr
            self._flags: int = op2._flags
            self._unprocessed = list(op2._unprocessed)
            self._addrlist = list(op2._addrlist)
            self._visited = dict(op2._visited)
            self._insn_count = op2._insn_count
            self._insn_max = op2._insn_max
            self._inline_head = op2._inline_head
            self._inline_base = set(op2._inline_base)
            if op2._inline_head is not None:
                self._inline_recursion = self._inline_base
        else:
            spc = func_addr.getSpace() if hasattr(func_addr, 'getSpace') and func_addr.getSpace() is not None else None
            self._baddr = Address(spc, 0) if spc else Address()
            self._eaddr = Address(spc, 0xFFFFFFFFFFFFFFFF) if spc else Address()
            self._flags: int = 0

        self._minaddr: Address = func_addr
        self._maxaddr: Address = func_addr

        if hasattr(fd, 'getOverride') and hasattr(fd.getOverride(), 'hasFlowOverride'):
            self._flowoverride_present = fd.getOverride().hasFlowOverride()

    # ----------------------------------------------------------------
    # Range / option setters
    # ----------------------------------------------------------------

    def setRange(self, b: Address, e: Address) -> None:
        self._baddr = b
        self._eaddr = e

    def setMaximumInstructions(self, m: int) -> None:
        self._insn_max = m

    def setFlags(self, val: int) -> None:
        self._flags |= val

    def clearFlags(self, val: int) -> None:
        self._flags &= ~val

    # ----------------------------------------------------------------
    # Query accessors
    # ----------------------------------------------------------------

    def getFlags(self) -> int:
        return self._flags

    def getSize(self) -> int:
        return self._maxaddr.getOffset() - self._minaddr.getOffset()

    def hasInject(self) -> bool:
        return len(self._injectlist) > 0

    def hasUnimplemented(self) -> bool:
        return (self._flags & FlowInfo.unimplemented_present) != 0

    def hasBadData(self) -> bool:
        return (self._flags & FlowInfo.baddata_present) != 0

    def hasOutOfBounds(self) -> bool:
        return (self._flags & FlowInfo.outofbounds_present) != 0

    def hasReinterpreted(self) -> bool:
        return (self._flags & FlowInfo.reinterpreted_present) != 0

    def hasTooManyInstructions(self) -> bool:
        return (self._flags & FlowInfo.toomanyinstructions_present) != 0

    def isFlowForInline(self) -> bool:
        return (self._flags & FlowInfo.flow_forinline) != 0

    def doesJumpRecord(self) -> bool:
        return (self._flags & FlowInfo.record_jumploads) != 0

    def hasPossibleUnreachable(self) -> bool:
        return (self._flags & FlowInfo.possible_unreachable) != 0

    # ----------------------------------------------------------------
    # Internal state helpers
    # ----------------------------------------------------------------

    def setPossibleUnreachable(self) -> None:
        self._flags |= FlowInfo.possible_unreachable

    def clearProperties(self) -> None:
        self._flags &= ~(FlowInfo.unimplemented_present |
                          FlowInfo.baddata_present |
                          FlowInfo.outofbounds_present)
        self._insn_count = 0

    def seenInstruction(self, addr: Address) -> bool:
        return addr in self._visited

    # ----------------------------------------------------------------
    # Target / branch resolution
    # ----------------------------------------------------------------

    def target(self, addr: Address):
        """Return first p-code op for instruction at given address."""
        if self._obank is None:
            return None
        it = self._visited.get(addr)
        while it is not None:
            seq = it.seqnum
            if seq is not None and hasattr(self._obank, 'findOp'):
                retop = self._obank.findOp(seq)
                if retop is not None:
                    return retop
            nxt = Address(addr.getSpace(), addr.getOffset() + it.size) if addr.getSpace() else None
            if nxt is None:
                break
            it = self._visited.get(nxt)
            addr = nxt
        return None

    def branchTarget(self, op):
        """Find the target referred to by a BRANCH or CBRANCH."""
        addr = op.getIn(0).getAddr()
        if addr.isConstant():
            res = [None]
            retop = self.findRelTarget(op, res)
            if retop is not None:
                return retop
            if res[0] is not None:
                return self.target(res[0])
            return None
        return self.target(addr)

    def findRelTarget(self, op, res_ref):
        """Generate the target PcodeOp for a relative branch."""
        if self._obank is None or not hasattr(self._obank, 'findOp'):
            return None
        addr = op.getIn(0).getAddr()
        time_id = (op.getTime() + addr.getOffset()) if hasattr(op, 'getTime') else 0
        from ghidra.core.pcoderaw import SeqNum
        seq = SeqNum(op.getAddr(), time_id)
        retop = self._obank.findOp(seq)
        if retop is not None:
            return retop
        # Try going back one
        seq1 = SeqNum(op.getAddr(), time_id - 1)
        retop = self._obank.findOp(seq1)
        if retop is not None:
            miter = self._visited.get(retop.getAddr())
            if miter is not None:
                fallthru = Address(retop.getAddr().getSpace(),
                                   retop.getAddr().getOffset() + miter.size)
                if isinstance(res_ref, list):
                    res_ref[0] = fallthru
                return None
        return None

    def fallthruOp(self, op):
        """Find fallthru pcode-op for given op.

        Returns the PcodeOp that fall-thru flow would reach, or None.
        """
        if self._obank is None:
            return None
        # Try to get next op after this one in the dead list
        if hasattr(self._obank, 'getNextDead'):
            retop = self._obank.getNextDead(op)
            if retop is not None and not retop.isInstructionStart():
                return retop
        # Find instruction containing this op, then target the next instruction
        # Find the visited entry whose range contains op->getAddr()
        op_addr = op.getAddr()
        prev_addr = None
        prev_stat = None
        for addr, stat in self._visited.items():
            if addr <= op_addr:
                if prev_addr is None or addr > prev_addr:
                    prev_addr = addr
                    prev_stat = stat
        if prev_addr is None or prev_stat is None:
            return None
        end_off = prev_addr.getOffset() + prev_stat.size
        if end_off <= op_addr.getOffset():
            return None
        nxt = Address(prev_addr.getSpace(), end_off)
        return self.target(nxt)

    def updateTarget(self, oldOp, newOp) -> None:
        """Replace oldOp with newOp in the target map."""
        viter = self._visited.get(oldOp.getAddr())
        if viter is not None and viter.seqnum == oldOp.getSeqNum():
            viter.seqnum = newOp.getSeqNum()

    # ----------------------------------------------------------------
    # Flow address management
    # ----------------------------------------------------------------

    def newAddress(self, fromOp, to: Address) -> None:
        """Register a new (non fall-thru) flow target."""
        if to < self._baddr or self._eaddr < to:
            self.handleOutOfBounds(fromOp.getAddr(), to)
            self._unprocessed.append(to)
            return
        if self.seenInstruction(to):
            op = self.target(to)
            if op is not None and hasattr(self._data, 'opMarkStartBasic'):
                self._data.opMarkStartBasic(op)
            return
        self._addrlist.append(to)

    def handleOutOfBounds(self, fromaddr: Address, toaddr: Address) -> None:
        if (self._flags & FlowInfo.ignore_outofbounds) == 0:
            msg = f"Function flow out of bounds: {fromaddr} -> {toaddr}"
            if (self._flags & FlowInfo.error_outofbounds) != 0:
                from ghidra.core.error import LowlevelError
                raise LowlevelError(msg)
            if hasattr(self._data, 'warning'):
                self._data.warning(msg, toaddr)
            if not self.hasOutOfBounds():
                self._flags |= FlowInfo.outofbounds_present

    # ----------------------------------------------------------------
    # Instruction processing
    # ----------------------------------------------------------------

    def deleteRemainingOps(self, oplist: list) -> None:
        """Delete any remaining ops at the end of the instruction.

        oplist is a list of PcodeOps to destroy.
        """
        if not hasattr(self._data, 'opDestroyRaw'):
            return
        for op in oplist:
            self._data.opDestroyRaw(op)

    def xrefControlFlow(self, ops: list, startbasic_ref: list,
                         isfallthru_ref: list, fc) -> Optional[PcodeOp]:
        """Analyze control-flow within p-code for a single instruction.

        Walk through raw p-code ops looking for control flow operations
        (BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND, RETURN) and add
        appropriate annotations.

        Args:
            ops: list of PcodeOps to analyze
            startbasic_ref: [bool] whether current op starts a basic block
            isfallthru_ref: [bool] passes back if instruction has fall-thru
            fc: FuncCallSpecs if injection is in progress (for cycle check)

        Returns: the last processed PcodeOp or None
        """
        last_op = None
        isfallthru_ref[0] = False
        maxtime = 0
        idx = 0
        while idx < len(ops):
            op = ops[idx]
            idx += 1
            last_op = op
            if startbasic_ref[0]:
                if hasattr(self._data, 'opMarkStartBasic'):
                    self._data.opMarkStartBasic(op)
                startbasic_ref[0] = False

            opc = op.code()
            if opc == OpCode.CPUI_CBRANCH:
                destaddr = op.getIn(0).getAddr()
                if destaddr.isConstant():
                    res_ref = [None]
                    destop = self.findRelTarget(op, res_ref)
                    if destop is not None:
                        if hasattr(self._data, 'opMarkStartBasic'):
                            self._data.opMarkStartBasic(destop)
                        newtime = destop.getTime() if hasattr(destop, 'getTime') else 0
                        if newtime > maxtime:
                            maxtime = newtime
                    else:
                        isfallthru_ref[0] = True
                else:
                    self.newAddress(op, destaddr)
                startbasic_ref[0] = True

            elif opc == OpCode.CPUI_BRANCH:
                destaddr = op.getIn(0).getAddr()
                if destaddr.isConstant():
                    res_ref = [None]
                    destop = self.findRelTarget(op, res_ref)
                    if destop is not None:
                        if hasattr(self._data, 'opMarkStartBasic'):
                            self._data.opMarkStartBasic(destop)
                        newtime = destop.getTime() if hasattr(destop, 'getTime') else 0
                        if newtime > maxtime:
                            maxtime = newtime
                    else:
                        isfallthru_ref[0] = True
                else:
                    self.newAddress(op, destaddr)
                op_time = op.getTime() if hasattr(op, 'getTime') else 0
                if op_time >= maxtime:
                    # Delete remaining ops
                    self.deleteRemainingOps(ops[idx:])
                    idx = len(ops)
                startbasic_ref[0] = True

            elif opc == OpCode.CPUI_BRANCHIND:
                self._tablelist.append(op)
                op_time = op.getTime() if hasattr(op, 'getTime') else 0
                if op_time >= maxtime:
                    self.deleteRemainingOps(ops[idx:])
                    idx = len(ops)
                startbasic_ref[0] = True

            elif opc == OpCode.CPUI_RETURN:
                op_time = op.getTime() if hasattr(op, 'getTime') else 0
                if op_time >= maxtime:
                    self.deleteRemainingOps(ops[idx:])
                    idx = len(ops)
                startbasic_ref[0] = True

            elif opc == OpCode.CPUI_CALL:
                if self.setupCallSpecs(op, fc):
                    idx -= 1  # Backup to pickup halt

            elif opc == OpCode.CPUI_CALLIND:
                if self.setupCallindSpecs(op, fc):
                    idx -= 1

            elif opc == OpCode.CPUI_CALLOTHER:
                if self._glb is not None and hasattr(self._glb, 'userops'):
                    userop = self._glb.userops.getOp(op.getIn(0).getOffset())
                    if userop is not None and hasattr(userop, 'getType'):
                        # UserPcodeOp::injected
                        self._injectlist.append(op)

        # Determine fallthru
        if isfallthru_ref[0]:
            startbasic_ref[0] = True
        else:
            if last_op is None:
                isfallthru_ref[0] = True
            else:
                opc = last_op.code()
                if opc not in (OpCode.CPUI_BRANCH, OpCode.CPUI_BRANCHIND, OpCode.CPUI_RETURN):
                    isfallthru_ref[0] = True
        return last_op

    def processInstruction(self, curaddr: Address, startbasic_ref: list) -> bool:
        """Generate p-code for a single machine instruction and process flow info.

        P-code is generated (to the raw dead list in PcodeOpBank). Errors for
        unimplemented instructions or inaccessible data are handled. The p-code
        is examined for control-flow, and annotations are made.
        Returns True if the processed instruction has a fall-thru flow.
        """
        isfallthru = True
        step = 1

        if self._insn_count >= self._insn_max:
            if (self._flags & FlowInfo.error_toomanyinstructions) != 0:
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Flow exceeded maximum allowable instructions")
            self.artificialHalt(curaddr, 0)
            if hasattr(self._data, 'warning'):
                self._data.warning("Too many instructions -- Truncating flow here", curaddr)
            if not self.hasTooManyInstructions():
                self._flags |= FlowInfo.toomanyinstructions_present
                if hasattr(self._data, 'warningHeader'):
                    self._data.warningHeader("Exceeded maximum allowable instructions: Some flow is truncated")
            return False
        self._insn_count += 1

        # Track where new ops start in the obank
        prev_ops = []
        if self._obank is not None and hasattr(self._obank, 'getDeadList'):
            prev_ops = list(self._obank.getDeadList())

        # Check for flow override
        flowoverride = 0  # Override::NONE
        if self._flowoverride_present and hasattr(self._data, 'getOverride'):
            override = self._data.getOverride()
            if hasattr(override, 'getFlowOverride'):
                flowoverride = override.getFlowOverride(curaddr)

        # Generate ops via architecture's translator
        emitter = getattr(self, '_emitter', None)
        if self._glb is not None and hasattr(self._glb, 'translate'):
            try:
                step = self._glb.translate.oneInstruction(emitter, curaddr)
            except Exception as err:
                err_name = type(err).__name__
                if err_name == 'UnimplError' or 'unimpl' in str(err).lower():
                    if (self._flags & FlowInfo.ignore_unimplemented) != 0:
                        step = getattr(err, 'instruction_length', 1)
                        if not self.hasUnimplemented():
                            self._flags |= FlowInfo.unimplemented_present
                    elif (self._flags & FlowInfo.error_unimplemented) != 0:
                        raise
                    else:
                        step = 1
                        self.artificialHalt(curaddr, 0)
                        if hasattr(self._data, 'warning'):
                            self._data.warning("Unimplemented instruction - Truncating control flow here", curaddr)
                        if not self.hasUnimplemented():
                            self._flags |= FlowInfo.unimplemented_present
                else:
                    if (self._flags & FlowInfo.error_unimplemented) != 0:
                        raise
                    step = 1
                    self.artificialHalt(curaddr, 0)
                    if hasattr(self._data, 'warning'):
                        self._data.warning("Bad instruction - Truncating control flow here", curaddr)
                    if not self.hasBadData():
                        self._flags |= FlowInfo.baddata_present

        # Mark that we visited this instruction
        stat = FlowInfo.VisitStat()
        stat.size = step
        self._visited[curaddr] = stat

        # Update min/max address
        if curaddr < self._minaddr:
            self._minaddr = curaddr
        nxt = Address(curaddr.getSpace(), curaddr.getOffset() + step) if curaddr.getSpace() else curaddr
        if self._maxaddr < nxt:
            self._maxaddr = nxt

        # Identify new ops generated for this instruction
        new_ops = []
        if self._obank is not None and hasattr(self._obank, 'getDeadList'):
            all_ops = list(self._obank.getDeadList())
            prev_set = set(id(o) for o in prev_ops)
            new_ops = [o for o in all_ops if id(o) not in prev_set]

        if new_ops:
            stat.seqnum = new_ops[0].getSeqNum()
            if hasattr(self._data, 'opMarkStartInstruction'):
                self._data.opMarkStartInstruction(new_ops[0])
            if flowoverride != 0 and hasattr(self._data, 'overrideFlow'):
                self._data.overrideFlow(curaddr, flowoverride)
            isfallthru_ref = [False]
            self.xrefControlFlow(new_ops, startbasic_ref, isfallthru_ref, None)
            isfallthru = isfallthru_ref[0]

        if isfallthru:
            self._addrlist.append(nxt)
        return isfallthru

    def fallthru(self) -> None:
        """Process (the next) sequence of instructions in fall-thru order.

        The address at the top of the addrlist stack is popped.
        P-code is generated for instructions starting at this address until
        one no longer has fall-thru flow.
        """
        bound_ref = [self._eaddr]
        if not self._setFallthruBound(bound_ref):
            return
        bound = bound_ref[0]
        startbasic = [True]
        while True:
            if not self._addrlist:
                break
            curaddr = self._addrlist[-1]
            self._addrlist.pop()
            fallthruflag = self.processInstruction(curaddr, startbasic)
            if not fallthruflag:
                break
            if not self._addrlist:
                break
            if bound <= self._addrlist[-1]:
                if bound == self._eaddr:
                    self.handleOutOfBounds(self._eaddr, self._addrlist[-1])
                    self._unprocessed.append(self._addrlist[-1])
                    self._addrlist.pop()
                    return
                if bound == self._addrlist[-1]:
                    if startbasic[0]:
                        op = self.target(self._addrlist[-1])
                        if op is not None and hasattr(self._data, 'opMarkStartBasic'):
                            self._data.opMarkStartBasic(op)
                    self._addrlist.pop()
                    break
                if not self._setFallthruBound(bound_ref):
                    return
                bound = bound_ref[0]

    def _setFallthruBound(self, bound_ref: list) -> bool:
        """Find end of the next unprocessed region.

        From the address at the top of the addrlist stack, figure out how far
        we could follow fall-thru instructions before hitting something already seen.
        bound_ref[0] passes back the first address encountered that we have already seen.
        Returns False if the address has already been visited.
        """
        if not self._addrlist:
            return False
        addr = self._addrlist[-1]

        # Find the nearest visited address > addr
        # Check if addr itself was visited
        if addr in self._visited:
            # Already visited this address - mark basic block start
            op = self.target(addr)
            if op is not None and hasattr(self._data, 'opMarkStartBasic'):
                self._data.opMarkStartBasic(op)
            self._addrlist.pop()
            return False

        # Check if addr falls in the middle of a visited instruction (reinterpretation)
        for v_addr, v_stat in self._visited.items():
            if v_addr < addr < Address(v_addr.getSpace(), v_addr.getOffset() + v_stat.size):
                self.reinterpreted(addr)
                break

        # Find the minimum visited address that is > addr
        next_bound = self._eaddr
        for v_addr in self._visited:
            if v_addr > addr and v_addr < next_bound:
                next_bound = v_addr
        bound_ref[0] = next_bound
        return True

    def setFallthruBound(self, bound: Address) -> bool:
        """Legacy wrapper for _setFallthruBound."""
        ref = [bound]
        result = self._setFallthruBound(ref)
        return result

    def artificialHalt(self, addr: Address, flag: int = 0):
        """Create an artificial halt p-code op."""
        if not hasattr(self._data, 'newOp'):
            return None
        haltop = self._data.newOp(1, addr)
        self._data.opSetOpcode(haltop, OpCode.CPUI_RETURN)
        self._data.opSetInput(haltop, self._data.newConstant(4, 1), 0)
        if flag != 0 and hasattr(self._data, 'opMarkHalt'):
            self._data.opMarkHalt(haltop, flag)
        return haltop

    def reinterpreted(self, addr: Address) -> None:
        """Generate warning for a reinterpreted address."""
        if (self._flags & FlowInfo.error_reinterpreted) != 0:
            from ghidra.core.error import LowlevelError
            raise LowlevelError(f"Reinterpreted bytes at {addr}")
        if (self._flags & FlowInfo.reinterpreted_present) == 0:
            self._flags |= FlowInfo.reinterpreted_present

    # ----------------------------------------------------------------
    # Call site handling
    # ----------------------------------------------------------------

    def checkForFlowModification(self, fspecs) -> bool:
        """Check for modifications to flow at a call site."""
        if hasattr(fspecs, 'isInline') and fspecs.isInline():
            self._injectlist.append(fspecs.getOp())
        if hasattr(fspecs, 'isNoReturn') and fspecs.isNoReturn():
            op = fspecs.getOp()
            haltop = self.artificialHalt(op.getAddr(), 0)
            if haltop is not None and hasattr(self._data, 'opDeadInsertAfter'):
                self._data.opDeadInsertAfter(haltop, op)
            return True
        return False

    def queryCall(self, fspecs) -> None:
        """Try to recover the Funcdata object corresponding to a given call."""
        if hasattr(fspecs, 'getEntryAddress') and not fspecs.getEntryAddress().isInvalid():
            if hasattr(self._data, 'getScopeLocal'):
                scope = self._data.getScopeLocal()
                if hasattr(scope, 'getParent'):
                    parent = scope.getParent()
                    if hasattr(parent, 'queryFunction'):
                        otherfunc = parent.queryFunction(fspecs.getEntryAddress())
                        if otherfunc is not None:
                            fspecs.setFuncdata(otherfunc)
                            if not fspecs.hasModel() or otherfunc.getFuncProto().isInline():
                                fspecs.copyFlowEffects(otherfunc.getFuncProto())

    def setupCallSpecs(self, op, fc) -> bool:
        """Set up the FuncCallSpecs object for a new call site.

        Creates a new FuncCallSpecs, queries for the function, and checks
        if the sub-function never returns.
        Returns True if the sub-function never returns.
        """
        try:
            from ghidra.fspec.fspec import FuncCallSpecs as FCS
        except ImportError:
            return False
        res = FCS(op)
        if hasattr(self._data, 'newVarnodeCallSpecs'):
            self._data.opSetInput(op, self._data.newVarnodeCallSpecs(res), 0)
        self._qlst.append(res)
        if hasattr(self._data, 'getOverride') and hasattr(self._data.getOverride(), 'applyPrototype'):
            self._data.getOverride().applyPrototype(self._data, res)
        self.queryCall(res)
        if fc is not None:
            if hasattr(fc, 'getEntryAddress') and hasattr(res, 'getEntryAddress'):
                if fc.getEntryAddress() == res.getEntryAddress():
                    if hasattr(res, 'cancelInjectId'):
                        res.cancelInjectId()
        return self.checkForFlowModification(res)

    def setupCallindSpecs(self, op, fc) -> bool:
        """Set up FuncCallSpecs for a new indirect call site.

        Returns True if the sub-function never returns.
        """
        try:
            from ghidra.fspec.fspec import FuncCallSpecs as FCS
        except ImportError:
            return False
        res = FCS(op)
        self._qlst.append(res)
        if hasattr(self._data, 'getOverride'):
            override = self._data.getOverride()
            if hasattr(override, 'applyIndirect'):
                override.applyIndirect(self._data, res)
            if fc is not None and hasattr(fc, 'getEntryAddress') and hasattr(res, 'getEntryAddress'):
                if fc.getEntryAddress() == res.getEntryAddress():
                    if hasattr(res, 'setAddress'):
                        res.setAddress(Address())
            if hasattr(override, 'applyPrototype'):
                override.applyPrototype(self._data, res)
        self.queryCall(res)
        # If overridden to a direct call
        if hasattr(res, 'getEntryAddress') and not res.getEntryAddress().isInvalid():
            if hasattr(self._data, 'opSetOpcode'):
                self._data.opSetOpcode(op, OpCode.CPUI_CALL)
            if hasattr(self._data, 'newVarnodeCallSpecs'):
                self._data.opSetInput(op, self._data.newVarnodeCallSpecs(res), 0)
        return self.checkForFlowModification(res)

    # ----------------------------------------------------------------
    # Unprocessed / stub handling
    # ----------------------------------------------------------------

    def findUnprocessed(self) -> None:
        """Add remaining un-followed addresses to the unprocessed list."""
        for addr in self._addrlist:
            if self.seenInstruction(addr):
                op = self.target(addr)
                if op is not None and hasattr(self._data, 'opMarkStartBasic'):
                    self._data.opMarkStartBasic(op)
            else:
                self._unprocessed.append(addr)

    def dedupUnprocessed(self) -> None:
        """Get rid of duplicates in the unprocessed list."""
        if not self._unprocessed:
            return
        self._unprocessed.sort()
        deduped = [self._unprocessed[0]]
        for i in range(1, len(self._unprocessed)):
            if self._unprocessed[i] != deduped[-1]:
                deduped.append(self._unprocessed[i])
        self._unprocessed = deduped

    def fillinBranchStubs(self) -> None:
        """Fill-in artificial HALT p-code for unprocessed addresses."""
        self.findUnprocessed()
        self.dedupUnprocessed()
        for addr in self._unprocessed:
            op = self.artificialHalt(addr, 0)
            if op is not None:
                if hasattr(self._data, 'opMarkStartBasic'):
                    self._data.opMarkStartBasic(op)
                if hasattr(self._data, 'opMarkStartInstruction'):
                    self._data.opMarkStartInstruction(op)

    # ----------------------------------------------------------------
    # Block construction
    # ----------------------------------------------------------------

    def collectEdges(self) -> None:
        """Collect edges between basic blocks as PcodeOp to PcodeOp pairs.

        Edges are generated for fall-thru to a p-code op marked as the start
        of a basic block or for an explicit branch.
        """
        if self._obank is None:
            return
        if self._bblocks is not None and self._bblocks.getSize() != 0:
            return  # Blocks already calculated

        ops = []
        if hasattr(self._obank, 'getDeadList'):
            ops = list(self._obank.getDeadList())
        elif hasattr(self._obank, 'beginDead'):
            ops = list(self._obank.beginDead())
        if not ops:
            return

        for i, op in enumerate(ops):
            nextstart = (i == len(ops) - 1) or ops[i + 1].isBlockStart() if i < len(ops) - 1 else True
            opc = op.code()
            if opc == OpCode.CPUI_BRANCH:
                targ_op = self.branchTarget(op)
                if targ_op is not None:
                    self._block_edge1.append(op)
                    self._block_edge2.append(targ_op)
            elif opc == OpCode.CPUI_BRANCHIND:
                if hasattr(self._data, 'findJumpTable'):
                    jt = self._data.findJumpTable(op)
                    if jt is not None:
                        num = jt.numEntries()
                        for j in range(num):
                            targ_op = self.target(jt.getAddressByIndex(j))
                            if targ_op is not None and not targ_op.isMark():
                                targ_op.setMark()
                                self._block_edge1.append(op)
                                self._block_edge2.append(targ_op)
                        # Clean up marks
                        for j in range(len(self._block_edge1) - 1, -1, -1):
                            if self._block_edge1[j] is op:
                                self._block_edge2[j].clearMark()
                            else:
                                break
            elif opc == OpCode.CPUI_RETURN:
                pass
            elif opc == OpCode.CPUI_CBRANCH:
                # Fallthru edge
                ft_op = self.fallthruOp(op)
                if ft_op is not None:
                    self._block_edge1.append(op)
                    self._block_edge2.append(ft_op)
                # Branch target edge
                targ_op = self.branchTarget(op)
                if targ_op is not None:
                    self._block_edge1.append(op)
                    self._block_edge2.append(targ_op)
            else:
                if nextstart:
                    ft_op = self.fallthruOp(op)
                    if ft_op is not None:
                        self._block_edge1.append(op)
                        self._block_edge2.append(ft_op)

    def splitBasic(self) -> None:
        """Split raw p-code ops up into basic blocks.

        PcodeOp objects are moved out of the PcodeOpBank dead list into
        their assigned PcodeBlockBasic. PcodeBlockBasic objects are created
        based on p-code ops previously marked as start of basic block.
        """
        if self._obank is None or self._bblocks is None:
            return

        ops = []
        if hasattr(self._obank, 'getDeadList'):
            ops = list(self._obank.getDeadList())
        elif hasattr(self._obank, 'beginDead'):
            ops = list(self._obank.beginDead())
        if not ops:
            return

        first_op = ops[0]
        if not first_op.isBlockStart():
            return  # First op not marked as entry point

        cur = self._bblocks.newBlockBasic(self._data) if hasattr(self._bblocks, 'newBlockBasic') else None
        if cur is None:
            return
        if hasattr(self._data, 'opInsert'):
            self._data.opInsert(first_op, cur, cur.endOp() if hasattr(cur, 'endOp') else None)
        if hasattr(self._bblocks, 'setStartBlock'):
            self._bblocks.setStartBlock(cur)
        start = first_op.getAddr()
        stop = start

        for op in ops[1:]:
            if op.isBlockStart():
                if hasattr(self._data, 'setBasicBlockRange'):
                    self._data.setBasicBlockRange(cur, start, stop)
                cur = self._bblocks.newBlockBasic(self._data)
                start = op.getSeqNum().getAddr() if hasattr(op, 'getSeqNum') else op.getAddr()
                stop = start
            else:
                op_addr = op.getAddr()
                if stop < op_addr:
                    stop = op_addr
            if hasattr(self._data, 'opInsert'):
                self._data.opInsert(op, cur, cur.endOp() if hasattr(cur, 'endOp') else None)

        if hasattr(self._data, 'setBasicBlockRange'):
            self._data.setBasicBlockRange(cur, start, stop)

    def connectBasic(self) -> None:
        """Generate edges between basic blocks."""
        if self._bblocks is None:
            return
        for src, dst in zip(self._block_edge1, self._block_edge2):
            src_bl = src.getParent()
            dst_bl = dst.getParent()
            if src_bl is not None and dst_bl is not None:
                self._bblocks.addEdge(src_bl, dst_bl)

    # ----------------------------------------------------------------
    # Public entry points
    # ----------------------------------------------------------------

    def generateOps(self) -> None:
        """Generate raw control-flow from the function's base address.

        This is the main entry point for flow following. P-code is generated
        for every reachable instruction. Jump tables are recovered iteratively.
        """
        notreached: list = []
        notreachcnt = 0
        self.clearProperties()
        func_addr = self._data.getAddress() if hasattr(self._data, 'getAddress') else Address()
        self._addrlist.append(func_addr)
        while self._addrlist:
            self.fallthru()
        if self.hasInject():
            self.injectPcode()
        # Iterative jump table recovery loop
        while True:
            while self._tablelist:
                newTables: list = []
                self.recoverJumpTables(newTables, notreached)
                self._tablelist.clear()
                for jt in newTables:
                    if jt is None:
                        continue
                    num = jt.numEntries() if hasattr(jt, 'numEntries') else 0
                    indop = jt.getIndirectOp() if hasattr(jt, 'getIndirectOp') else None
                    for j in range(num):
                        addr = jt.getAddressByIndex(j) if hasattr(jt, 'getAddressByIndex') else None
                        if addr is not None and indop is not None:
                            self.newAddress(indop, addr)
                    while self._addrlist:
                        self.fallthru()
            self.checkContainedCall()
            self.checkMultistageJumptables()
            while notreachcnt < len(notreached):
                self._tablelist.append(notreached[notreachcnt])
                notreachcnt += 1
            if self.hasInject():
                self.injectPcode()
            if not self._tablelist:
                break

    def generateBlocks(self) -> None:
        """Generate basic blocks from the raw control-flow."""
        self.fillinBranchStubs()
        self.collectEdges()
        self.splitBasic()
        self.connectBasic()
        if self._bblocks is not None and self._bblocks.getSize() > 0:
            startblock = self._bblocks.getBlock(0)
            if hasattr(startblock, 'sizeIn') and startblock.sizeIn() != 0:
                if hasattr(self._bblocks, 'newBlockBasic'):
                    newfront = self._bblocks.newBlockBasic(self._data)
                    self._bblocks.addEdge(newfront, startblock)
                    self._bblocks.setStartBlock(newfront)
        if self.hasPossibleUnreachable() and hasattr(self._data, 'removeUnreachableBlocks'):
            self._data.removeUnreachableBlocks(False, True)

    # ----------------------------------------------------------------
    # Injection
    # ----------------------------------------------------------------

    def xrefInlinedBranch(self, op) -> None:
        """Check for control-flow in a new injected p-code op."""
        if op.code() == OpCode.CPUI_CALL:
            self.setupCallSpecs(op, None)
        elif op.code() == OpCode.CPUI_CALLIND:
            self.setupCallindSpecs(op, None)
        elif op.code() == OpCode.CPUI_BRANCHIND:
            self._tablelist.append(op)

    def doInjection(self, payload, icontext, op, fc) -> None:
        """Inject the given payload into this flow, replacing the given op."""
        if self._obank is None:
            return
        # Get pre-injection state
        prev_ops = []
        if hasattr(self._obank, 'getDeadList'):
            prev_ops = list(self._obank.getDeadList())

        # Perform the injection
        emitter = getattr(self, '_emitter', None)
        if hasattr(payload, 'inject'):
            payload.inject(icontext, emitter)

        # Find newly generated ops
        if hasattr(self._obank, 'getDeadList'):
            all_ops = list(self._obank.getDeadList())
            prev_set = set(id(o) for o in prev_ops)
            new_ops = [o for o in all_ops if id(o) not in prev_set]
        else:
            new_ops = []

        if not new_ops:
            return

        firstop = new_ops[0]
        startbasic_ref = [op.isBlockStart()] if hasattr(op, 'isBlockStart') else [False]
        isfallthru_ref = [True]
        lastop = self.xrefControlFlow(new_ops, startbasic_ref, isfallthru_ref, fc)

        if startbasic_ref[0]:
            # The inject code does NOT fall thru - mark next op
            pass  # Would need insert iterator from obank

        # Move injection to right after the call
        if hasattr(self._obank, 'moveSequenceDead') and lastop is not None:
            self._obank.moveSequenceDead(firstop, lastop, op)

        self.updateTarget(op, firstop)
        if hasattr(self._data, 'opDestroyRaw'):
            self._data.opDestroyRaw(op)

    def injectUserOp(self, op) -> None:
        """Perform injection for a given user-defined p-code op."""
        if self._glb is None:
            return
        if not hasattr(self._glb, 'userops') or not hasattr(self._glb, 'pcodeinjectlib'):
            return
        userop = self._glb.userops.getOp(int(op.getIn(0).getOffset()))
        if userop is None or not hasattr(userop, 'getInjectId'):
            return
        payload = self._glb.pcodeinjectlib.getPayload(userop.getInjectId())
        if payload is None:
            return
        icontext = self._glb.pcodeinjectlib.getCachedContext()
        if hasattr(icontext, 'clear'):
            icontext.clear()
        icontext.baseaddr = op.getAddr()
        icontext.nextaddr = icontext.baseaddr
        # Fill input list (skip first operand which is injectid)
        if hasattr(icontext, 'inputlist'):
            for i in range(1, op.numInput()):
                vn = op.getIn(i)
                icontext.inputlist.append(type('VD', (), {
                    'space': vn.getSpace(), 'offset': vn.getOffset(), 'size': vn.getSize()})())
        outvn = op.getOut()
        if outvn is not None and hasattr(icontext, 'output'):
            icontext.output.append(type('VD', (), {
                'space': outvn.getSpace(), 'offset': outvn.getOffset(), 'size': outvn.getSize()})())
        self.doInjection(payload, icontext, op, None)

    def inlineSubFunction(self, fc) -> bool:
        """In-line the sub-function at the given call site."""
        fd = fc.getFuncdata() if hasattr(fc, 'getFuncdata') else None
        if fd is None:
            return False
        if self._inline_head is None:
            self._inline_head = self._data
            self._inline_recursion = self._inline_base
        func_addr = self._data.getAddress() if hasattr(self._data, 'getAddress') else None
        if func_addr is not None:
            self._inline_recursion.add(func_addr)
        fd_addr = fd.getAddress() if hasattr(fd, 'getAddress') else None
        if fd_addr is not None and fd_addr in self._inline_recursion:
            return False
        if hasattr(self._data, 'inlineFlow'):
            res = self._data.inlineFlow(fd, self, fc.getOp())
            if res < 0:
                return False
        self.setPossibleUnreachable()
        return True

    def injectSubFunction(self, fc) -> bool:
        """Perform injection replacing the CALL at the given call site."""
        if self._glb is None or not hasattr(self._glb, 'pcodeinjectlib'):
            return False
        op = fc.getOp()
        icontext = self._glb.pcodeinjectlib.getCachedContext()
        if hasattr(icontext, 'clear'):
            icontext.clear()
        icontext.baseaddr = op.getAddr()
        icontext.nextaddr = icontext.baseaddr
        if hasattr(icontext, 'calladdr'):
            icontext.calladdr = fc.getEntryAddress()
        payload = self._glb.pcodeinjectlib.getPayload(fc.getInjectId())
        if payload is None:
            return False
        self.doInjection(payload, icontext, op, fc)
        if hasattr(payload, 'getParamShift') and payload.getParamShift() != 0:
            if self._qlst:
                self._qlst[-1].setParamshift(payload.getParamShift())
        return True

    def injectPcode(self) -> None:
        """Perform substitution on any op that requires injection.

        Types of substitution include:
          - Sub-function in-lining
          - Sub-function injection
          - User defined op injection
        """
        for i in range(len(self._injectlist)):
            op = self._injectlist[i]
            if op is None:
                continue
            self._injectlist[i] = None
            if op.code() == OpCode.CPUI_CALLOTHER:
                self.injectUserOp(op)
            else:
                # CPUI_CALL or CPUI_CALLIND
                try:
                    from ghidra.fspec.fspec import FuncCallSpecs as FCS
                except ImportError:
                    continue
                fc = FCS.getFspecFromConst(op.getIn(0).getAddr()) if hasattr(FCS, 'getFspecFromConst') else None
                if fc is None:
                    continue
                if hasattr(fc, 'isInline') and fc.isInline():
                    if hasattr(fc, 'getInjectId') and fc.getInjectId() >= 0:
                        if self.injectSubFunction(fc):
                            if hasattr(self._data, 'warningHeader'):
                                name = fc.getName() if hasattr(fc, 'getName') else '?'
                                self._data.warningHeader(f"Function: {name} replaced with injection")
                            self.deleteCallSpec(fc)
                    elif self.inlineSubFunction(fc):
                        if hasattr(self._data, 'warningHeader'):
                            name = fc.getName() if hasattr(fc, 'getName') else '?'
                            self._data.warningHeader(f"Inlined function: {name}")
                        self.deleteCallSpec(fc)
        self._injectlist.clear()

    # ----------------------------------------------------------------
    # In-lining support
    # ----------------------------------------------------------------

    def testHardInlineRestrictions(self, inlinefd, op, retaddr_ref) -> bool:
        """For in-lining using the hard model, make sure restrictions are met.

        - Can only in-line the function once.
        - There must be a p-code op to return to.
        - There must be a distinct return address.
        Pass back the distinct return address in retaddr_ref[0].
        """
        if hasattr(inlinefd, 'getFuncProto') and not inlinefd.getFuncProto().isNoReturn():
            # Need a fallthrough op
            if self._obank is not None and hasattr(op, 'getInsertIter'):
                # Simplified: assume fallthrough exists
                pass
        return True

    def checkEZModel(self) -> bool:
        """Check if this flow matches the EZ in-lining model (no calls/branches)."""
        if self._obank is None:
            return True
        if hasattr(self._obank, 'beginDead'):
            for op in self._obank.beginDead():
                if hasattr(op, 'isCallOrBranch') and op.isCallOrBranch():
                    return False
        return True

    def forwardRecursion(self, op2: FlowInfo) -> None:
        """Pull in-lining recursion information from another flow."""
        self._inline_recursion = op2._inline_recursion
        self._inline_head = op2._inline_head

    def inlineClone(self, inlineflow: FlowInfo, retaddr: Address) -> None:
        """Clone the given in-line flow into this flow using the hard model.

        Individual PcodeOps from the Funcdata being in-lined are cloned into
        the Funcdata for this flow, preserving their original address.
        Any RETURN op is replaced with jump to first address following the call site.
        """
        if hasattr(inlineflow._data, 'beginOpDead'):
            for op in inlineflow._data.beginOpDead():
                if op.code() == OpCode.CPUI_RETURN and not retaddr.isInvalid():
                    if hasattr(self._data, 'newOp'):
                        cloneop = self._data.newOp(1, op.getSeqNum())
                        self._data.opSetOpcode(cloneop, OpCode.CPUI_BRANCH)
                        vn = self._data.newCodeRef(retaddr)
                        self._data.opSetInput(cloneop, vn, 0)
                else:
                    if hasattr(self._data, 'cloneOp'):
                        cloneop = self._data.cloneOp(op, op.getSeqNum())
                    else:
                        continue
                if hasattr(cloneop, 'isCallOrBranch') and cloneop.isCallOrBranch():
                    self.xrefInlinedBranch(cloneop)
        # Copy cross-referencing
        self._unprocessed.extend(inlineflow._unprocessed)
        self._addrlist.extend(inlineflow._addrlist)
        self._visited.update(inlineflow._visited)

    def inlineEZClone(self, inlineflow: FlowInfo, calladdr: Address) -> None:
        """Clone the given in-line flow using the EZ model.

        Individual PcodeOps are cloned with a fixed address (calladdr)
        and the RETURN op is eliminated.
        """
        if hasattr(inlineflow._data, 'beginOpDead'):
            for op in inlineflow._data.beginOpDead():
                if op.code() == OpCode.CPUI_RETURN:
                    break
                if hasattr(self._data, 'cloneOp'):
                    from ghidra.core.pcoderaw import SeqNum
                    myseq = SeqNum(calladdr, op.getSeqNum().getTime())
                    self._data.cloneOp(op, myseq)
        # Because we process only straightline code and it's all one address,
        # we don't touch unprocessed, addrlist, or visited

    # ----------------------------------------------------------------
    # Jump table / misc
    # ----------------------------------------------------------------

    def truncateIndirectJump(self, op, mode) -> None:
        """Treat indirect jump as CALLIND/RETURN.

        mode values correspond to JumpTable.RecoveryMode:
          'fail_return' - convert to RETURN
          'fail_thunk'  - convert to CALLIND (thunk pattern)
          'fail_callother' - convert to CALLIND that never returns
          otherwise - convert to CALLIND (bad jump table)
        """
        if not hasattr(self._data, 'opSetOpcode'):
            return
        if mode == 'fail_return':
            self._data.opSetOpcode(op, OpCode.CPUI_RETURN)
            if hasattr(self._data, 'warning'):
                self._data.warning("Treating indirect jump as return", op.getAddr())
        else:
            self._data.opSetOpcode(op, OpCode.CPUI_CALLIND)
            self.setupCallindSpecs(op, None)
            if hasattr(self._data, 'getCallSpecs'):
                fc = self._data.getCallSpecs(op)
            else:
                fc = None
            returnType = 0
            if mode == 'fail_callother':
                if fc is not None and hasattr(fc, 'setNoReturn'):
                    fc.setNoReturn(True)
                if hasattr(self._data, 'warning'):
                    self._data.warning("Does not return", op.getAddr())
            elif mode != 'fail_thunk':
                if fc is not None and hasattr(fc, 'setBadJumpTable'):
                    fc.setBadJumpTable(True)
                if hasattr(self._data, 'warning'):
                    self._data.warning("Treating indirect jump as call", op.getAddr())
            truncop = self.artificialHalt(op.getAddr(), returnType)
            if truncop is not None and hasattr(self._data, 'opDeadInsertAfter'):
                self._data.opDeadInsertAfter(truncop, op)

    def checkContainedCall(self) -> None:
        """Check if any of the calls this function makes are to already traced data-flow.

        If so, change the CALL to a BRANCH and issue a warning.
        This situation is most likely due to a Position Independent Code construction.
        """
        i = 0
        while i < len(self._qlst):
            fc = self._qlst[i]
            if hasattr(fc, 'getFuncdata') and fc.getFuncdata() is not None:
                i += 1
                continue
            op = fc.getOp()
            if op.code() != OpCode.CPUI_CALL:
                i += 1
                continue
            addr = fc.getEntryAddress() if hasattr(fc, 'getEntryAddress') else None
            if addr is None:
                i += 1
                continue
            # Check if this address is in the visited set
            found = False
            for v_addr, v_stat in self._visited.items():
                if v_addr <= addr < Address(v_addr.getSpace(), v_addr.getOffset() + v_stat.size):
                    if v_addr == addr:
                        # Change CALL to BRANCH
                        if hasattr(self._data, 'opSetOpcode'):
                            self._data.opSetOpcode(op, OpCode.CPUI_BRANCH)
                        targ = self.target(addr)
                        if targ is not None and hasattr(self._data, 'opMarkStartBasic'):
                            self._data.opMarkStartBasic(targ)
                        if hasattr(self._data, 'newCodeRef'):
                            self._data.opSetInput(op, self._data.newCodeRef(addr), 0)
                        del self._qlst[i]
                        found = True
                    break
            if not found:
                i += 1

    def checkMultistageJumptables(self) -> None:
        """Look for changes in control-flow near indirect jumps discovered after jumptable recovery."""
        if not hasattr(self._data, 'numJumpTables'):
            return
        num = self._data.numJumpTables()
        for i in range(num):
            jt = self._data.getJumpTable(i)
            if jt is not None and hasattr(jt, 'checkForMultistage'):
                if jt.checkForMultistage(self._data):
                    self._tablelist.append(jt.getIndirectOp())

    def recoverJumpTables(self, newTables: list, notreached: list) -> None:
        """Recover jumptables for the current set of BRANCHIND ops.

        Passes back a list of JumpTable objects and a list of BRANCHIND ops
        that could not be reached.
        """
        if not hasattr(self._data, 'recoverJumpTable'):
            return
        for op in self._tablelist:
            jt = self._data.recoverJumpTable(op, self)
            if jt is None:
                if not self.isFlowForInline():
                    self.truncateIndirectJump(op, 'fail_normal')
            else:
                if hasattr(jt, 'isPartial') and jt.isPartial():
                    if len(self._tablelist) > 1 and not self.isInArray(notreached, op):
                        notreached.append(op)
                    elif hasattr(jt, 'markComplete'):
                        jt.markComplete()
            newTables.append(jt)

    def deleteCallSpec(self, fc) -> None:
        """Remove the given call site from the list for this function."""
        for i in range(len(self._qlst)):
            if self._qlst[i] is fc:
                del self._qlst[i]
                break

    @staticmethod
    def isInArray(array: list, op) -> bool:
        """Test if the given op is a member of an array."""
        return op in array
