"""
ActionDeadCode implementation.
Corresponds to ActionDeadCode in coreaction.cc.
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING

from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, coveringmask, minimalmask, leastsigbit_set
from ghidra.transform.action import Action

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


class ActionDeadCode(Action):
    """Dead code removal via consumed-bit propagation."""

    def __init__(self, g: str) -> None:
        super().__init__(0, "deadcode", g)

    def clone(self, gl):
        return ActionDeadCode(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def _pushConsumed(val: int, vn, worklist: List):
        newval = (val | vn.getConsume()) & calc_mask(vn.getSize())
        if newval == vn.getConsume() and vn.isConsumeVacuous():
            return
        vn.setConsumeVacuous()
        if not vn.isConsumeList():
            vn.setConsumeList()
            if vn.isWritten():
                worklist.append(vn)
        vn.setConsume(newval)

    @staticmethod
    def _propagateConsumed(worklist: List):
        vn = worklist.pop()
        outc = vn.getConsume()
        vn.clearConsumeList()
        op = vn.getDef()
        opc = op.code()
        ALL = 0xFFFFFFFFFFFFFFFF

        if opc == OpCode.CPUI_INT_MULT:
            b = coveringmask(outc)
            if op.getIn(1).isConstant():
                ls = leastsigbit_set(op.getIn(1).getOffset())
                if ls >= 0:
                    a = (calc_mask(vn.getSize()) >> ls) & b
                else:
                    a = 0
            else:
                a = b
            ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
            ActionDeadCode._pushConsumed(b, op.getIn(1), worklist)
        elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB):
            a = coveringmask(outc)
            ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
            ActionDeadCode._pushConsumed(a, op.getIn(1), worklist)
        elif opc == OpCode.CPUI_SUBPIECE:
            sz = int(op.getIn(1).getOffset())
            if sz >= 8:
                a = 0
            else:
                a = outc << (sz * 8)
            b = ALL if outc != 0 else 0
            ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
            ActionDeadCode._pushConsumed(b, op.getIn(1), worklist)
        elif opc == OpCode.CPUI_PIECE:
            sz = op.getIn(1).getSize()
            a = outc >> (sz * 8)
            b = outc ^ (a << (sz * 8))
            ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
            ActionDeadCode._pushConsumed(b, op.getIn(1), worklist)
        elif opc in (OpCode.CPUI_COPY, OpCode.CPUI_INT_NEGATE):
            ActionDeadCode._pushConsumed(outc, op.getIn(0), worklist)
        elif opc in (OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR):
            ActionDeadCode._pushConsumed(outc, op.getIn(0), worklist)
            ActionDeadCode._pushConsumed(outc, op.getIn(1), worklist)
        elif opc == OpCode.CPUI_INT_AND:
            if op.getIn(1).isConstant():
                val = op.getIn(1).getOffset()
                ActionDeadCode._pushConsumed(outc & val, op.getIn(0), worklist)
                ActionDeadCode._pushConsumed(outc, op.getIn(1), worklist)
            else:
                ActionDeadCode._pushConsumed(outc, op.getIn(0), worklist)
                ActionDeadCode._pushConsumed(outc, op.getIn(1), worklist)
        elif opc == OpCode.CPUI_MULTIEQUAL:
            for i in range(op.numInput()):
                ActionDeadCode._pushConsumed(outc, op.getIn(i), worklist)
        elif opc == OpCode.CPUI_INT_ZEXT:
            ActionDeadCode._pushConsumed(outc, op.getIn(0), worklist)
        elif opc == OpCode.CPUI_INT_SEXT:
            b = calc_mask(op.getIn(0).getSize())
            a = outc & b
            if outc > b:
                a |= (b ^ (b >> 1))
            ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
        elif opc == OpCode.CPUI_INT_LEFT:
            if op.getIn(1).isConstant():
                sa = int(op.getIn(1).getOffset())
                a = outc >> sa if sa < 64 else 0
                b = ALL if outc != 0 else 0
                ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
                ActionDeadCode._pushConsumed(b, op.getIn(1), worklist)
            else:
                a = ALL if outc != 0 else 0
                ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
                ActionDeadCode._pushConsumed(a, op.getIn(1), worklist)
        elif opc == OpCode.CPUI_INT_RIGHT:
            if op.getIn(1).isConstant():
                sa = int(op.getIn(1).getOffset())
                a = (outc << sa) & calc_mask(op.getIn(0).getSize()) if sa < 64 else 0
                b = ALL if outc != 0 else 0
                ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
                ActionDeadCode._pushConsumed(b, op.getIn(1), worklist)
            else:
                a = ALL if outc != 0 else 0
                ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
                ActionDeadCode._pushConsumed(a, op.getIn(1), worklist)
        elif opc in (OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
                     OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
            if outc == 0:
                a = 0
            else:
                a = op.getIn(0).getNZMask() | op.getIn(1).getNZMask()
            ActionDeadCode._pushConsumed(a, op.getIn(0), worklist)
            ActionDeadCode._pushConsumed(a, op.getIn(1), worklist)
        elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            pass
        else:
            a = ALL if outc != 0 else 0
            for i in range(op.numInput()):
                ActionDeadCode._pushConsumed(a, op.getIn(i), worklist)

    @staticmethod
    def _neverConsumed(vn, data) -> bool:
        if vn.getSize() > 8:
            return False
        for desc in list(vn.getDescendants()):
            slot = desc.getSlot(vn)
            data.opSetInput(desc, data.newConstant(vn.getSize(), 0), slot)
        op = vn.getDef()
        if op.isCall():
            data.opUnsetOutput(op)
        else:
            data.opDestroy(op)
        return True

    def apply(self, data) -> int:
        worklist = []
        ALL = 0xFFFFFFFFFFFFFFFF

        # Clear consume flags on all varnodes
        for vn in list(data._vbank.beginLoc()):
            vn.clearConsumeList()
            vn.clearConsumeVacuous()
            vn.setConsume(0)
            if vn.isAddrForce() and not vn.isDirectWrite():
                vn.clearAddrForce()

        # Seed: mark all alive ops' inputs/outputs
        for op in list(data._obank.beginAlive()):
            if op.isCall():
                if not op.isAssignment():
                    continue
            elif not op.isAssignment():
                opc = op.code()
                if opc == OpCode.CPUI_RETURN:
                    self._pushConsumed(ALL, op.getIn(0), worklist)
                    for i in range(1, op.numInput()):
                        self._pushConsumed(ALL, op.getIn(i), worklist)
                else:
                    for i in range(op.numInput()):
                        self._pushConsumed(ALL, op.getIn(i), worklist)
                continue
            else:
                for i in range(op.numInput()):
                    vn = op.getIn(i)
                    if vn.isAutoLive():
                        self._pushConsumed(ALL, vn, worklist)
            outvn = op.getOut()
            if outvn is not None and outvn.isAutoLive():
                self._pushConsumed(ALL, outvn, worklist)

        # Propagate consumed bits
        while worklist:
            self._propagateConsumed(worklist)

        # Remove dead varnodes/ops
        for vn in list(data._vbank.beginLoc()):
            if not vn.isWritten():
                continue
            vacflag = vn.isConsumeVacuous()
            vn.clearConsumeList()
            vn.clearConsumeVacuous()
            if not vacflag:
                op = vn.getDef()
                if op.isCall():
                    data.opUnsetOutput(op)
                else:
                    data.opDestroy(op)
            elif vn.getConsume() == 0:
                self._neverConsumed(vn, data)

        data.clearDeadVarnodes()
        data.clearDeadOps()
        return 0
