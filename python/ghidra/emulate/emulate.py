"""
Corresponds to: emulate.hh / emulate.cc

P-code emulator: executes raw p-code operations on a MemoryState.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List

from ghidra.core.opcodes import OpCode
from ghidra.core.address import Address, calc_mask
from ghidra.core.pcoderaw import VarnodeData, PcodeOpRaw
from ghidra.core.opbehavior import OpBehavior, EvaluationError
from ghidra.core.space import IPTR_CONSTANT
from ghidra.emulate.memstate import MemoryState

if TYPE_CHECKING:
    from ghidra.core.translate import Translate


class BreakCallBack:
    """A callback for breakpoints during emulation."""

    def addressCallback(self, addr: Address) -> bool:
        return True  # True = continue

    def pcodeCallback(self, op: PcodeOpRaw) -> bool:
        return True


class BreakTable:
    """A collection of breakpoints for an emulator."""

    def __init__(self) -> None:
        self._addressBreaks: dict = {}
        self._pcodeBreaks: dict = {}

    def setAddressBreak(self, addr: Address, cb: BreakCallBack) -> None:
        key = (addr.getSpace().getIndex() if addr.getSpace() else 0, addr.getOffset())
        self._addressBreaks[key] = cb

    def doPcodeBreak(self, op: PcodeOpRaw) -> bool:
        return True

    def doAddressBreak(self, addr: Address) -> bool:
        key = (addr.getSpace().getIndex() if addr.getSpace() else 0, addr.getOffset())
        cb = self._addressBreaks.get(key)
        if cb is not None:
            return cb.addressCallback(addr)
        return True


class Emulate:
    """Base P-code emulator.

    Executes raw p-code operations on a MemoryState, handling branches,
    loads, stores, and all arithmetic/logic operations.
    """

    def __init__(self, trans: Translate, memstate: MemoryState,
                 breaktable: Optional[BreakTable] = None) -> None:
        self._trans: Translate = trans
        self._memstate: MemoryState = memstate
        self._breaktable: BreakTable = breaktable if breaktable else BreakTable()
        self._behaviors: List[Optional[OpBehavior]] = OpBehavior.registerInstructions(trans)
        self._currentAddress: Address = Address()
        self._executionAddress: Address = Address()
        self._halt: bool = False

    def getMemoryState(self) -> MemoryState:
        return self._memstate

    def getCurrentAddress(self) -> Address:
        return self._currentAddress

    def setCurrentAddress(self, addr: Address) -> None:
        self._currentAddress = addr

    def isHalted(self) -> bool:
        return self._halt

    def setHalt(self, val: bool) -> None:
        self._halt = val

    def getVarnodeValue(self, vn: VarnodeData) -> int:
        """Read a value from a VarnodeData location."""
        if vn.space is not None and vn.space.getType() == IPTR_CONSTANT:
            return vn.offset & calc_mask(vn.size)
        return self._memstate.getValue(vn.space, vn.offset, vn.size)

    def setVarnodeValue(self, vn: VarnodeData, val: int) -> None:
        """Write a value to a VarnodeData location."""
        if vn.space is not None and vn.space.getType() == IPTR_CONSTANT:
            return
        self._memstate.setValue(vn.space, vn.offset, vn.size, val & calc_mask(vn.size))

    def executeOp(self, op: PcodeOpRaw) -> None:
        """Execute a single raw PcodeOp."""
        behave = op.getBehavior()
        if behave is None:
            raise EvaluationError(f"No behavior for opcode {op.getOpcode()}")

        opc = behave.getOpcode()

        if opc == OpCode.CPUI_COPY:
            val = self.getVarnodeValue(op.getInput(0))
            self.setVarnodeValue(op.getOutput(), val)

        elif opc == OpCode.CPUI_LOAD:
            spc_vn = op.getInput(0)
            off_vn = op.getInput(1)
            out_vn = op.getOutput()
            offset = self.getVarnodeValue(off_vn)
            # spc_vn encodes the target space
            spc = spc_vn.getSpaceFromConst()
            if spc is None:
                spc = off_vn.space
            val = self._memstate.getValue(spc, offset, out_vn.size)
            self.setVarnodeValue(out_vn, val)

        elif opc == OpCode.CPUI_STORE:
            spc_vn = op.getInput(0)
            off_vn = op.getInput(1)
            data_vn = op.getInput(2)
            offset = self.getVarnodeValue(off_vn)
            val = self.getVarnodeValue(data_vn)
            spc = spc_vn.getSpaceFromConst()
            if spc is None:
                spc = off_vn.space
            self._memstate.setValue(spc, offset, data_vn.size, val)

        elif opc == OpCode.CPUI_BRANCH:
            dest = op.getInput(0)
            self._executionAddress = dest.getAddr()

        elif opc == OpCode.CPUI_CBRANCH:
            cond_vn = op.getInput(1)
            cond = self.getVarnodeValue(cond_vn)
            if cond != 0:
                dest = op.getInput(0)
                self._executionAddress = dest.getAddr()

        elif opc == OpCode.CPUI_BRANCHIND:
            off_vn = op.getInput(0)
            offset = self.getVarnodeValue(off_vn)
            self._executionAddress = Address(off_vn.space, offset)

        elif opc == OpCode.CPUI_RETURN:
            self._halt = True

        elif opc == OpCode.CPUI_CALL or opc == OpCode.CPUI_CALLIND:
            pass  # Calls handled by breakpoints or skipped

        elif opc == OpCode.CPUI_CALLOTHER:
            pass  # User-defined ops

        elif behave.isSpecial():
            pass  # Other special ops

        elif behave.isUnary():
            in1 = self.getVarnodeValue(op.getInput(0))
            out_vn = op.getOutput()
            result = behave.evaluateUnary(out_vn.size, op.getInput(0).size, in1)
            self.setVarnodeValue(out_vn, result)

        else:
            # Binary operation
            in1 = self.getVarnodeValue(op.getInput(0))
            in2 = self.getVarnodeValue(op.getInput(1))
            out_vn = op.getOutput()
            result = behave.evaluateBinary(out_vn.size, op.getInput(0).size, in1, in2)
            self.setVarnodeValue(out_vn, result)

    def executeCurrentOp(self, op: PcodeOpRaw) -> None:
        """Execute the current op with breakpoint checking."""
        if not self._breaktable.doPcodeBreak(op):
            self._halt = True
            return
        self.executeOp(op)
