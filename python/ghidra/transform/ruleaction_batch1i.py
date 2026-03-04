"""
Batch 1i: Sign/division pattern rules.
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask
from ghidra.transform.action import Rule
if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


class RuleSignForm(Rule):
    """sub(sext(V),c) s>> 31 => V s>> (N-1)."""
    def __init__(self, g): super().__init__(g, 0, "signform")
    def clone(self, gl):
        return RuleSignForm(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_SRIGHT)]
    def applyOp(self, op, data):
        sextout = op.getIn(0)
        if not sextout.isWritten(): return 0
        sextop = sextout.getDef()
        if sextop.code() != OpCode.CPUI_INT_SEXT: return 0
        a = sextop.getIn(0)
        c = int(op.getIn(1).getOffset())
        if c < a.getSize(): return 0
        if a.isFree(): return 0
        data.opSetInput(op, a, 0)
        n = 8 * a.getSize() - 1
        data.opSetInput(op, data.newConstant(4, n), 1)
        data.opSetOpcode(op, OpCode.CPUI_INT_SRIGHT)
        return 1


class RuleSignNearMult(Rule):
    """(V + (V s>> 0x1f)>>(32-n)) & (-1<<n) => (V s/ 2^n) * 2^n."""
    def __init__(self, g): super().__init__(g, 0, "signnearmult")
    def clone(self, gl):
        return RuleSignNearMult(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_AND)]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant(): return 0
        if not op.getIn(0).isWritten(): return 0
        addop = op.getIn(0).getDef()
        if addop.code() != OpCode.CPUI_INT_ADD: return 0
        unshiftop = None
        for i in range(2):
            shiftvn = addop.getIn(i)
            if not shiftvn.isWritten(): continue
            unshiftop = shiftvn.getDef()
            if unshiftop.code() == OpCode.CPUI_INT_RIGHT:
                if unshiftop.getIn(1).isConstant(): break
        else:
            return 0
        x = addop.getIn(1 - i)
        if x.isFree(): return 0
        n = int(unshiftop.getIn(1).getOffset())
        if n <= 0: return 0
        n = shiftvn.getSize() * 8 - n
        if n <= 0: return 0
        mask = calc_mask(shiftvn.getSize())
        mask = (mask << n) & mask
        if mask != op.getIn(1).getOffset(): return 0
        sgnvn = unshiftop.getIn(0)
        if not sgnvn.isWritten(): return 0
        sshiftop = sgnvn.getDef()
        if sshiftop.code() != OpCode.CPUI_INT_SRIGHT: return 0
        if not sshiftop.getIn(1).isConstant(): return 0
        if sshiftop.getIn(0) is not x: return 0
        val = int(sshiftop.getIn(1).getOffset())
        if val != 8 * x.getSize() - 1: return 0
        pw = 1 << n
        newdiv = data.newOp(2, op.getAddr())
        data.opSetOpcode(newdiv, OpCode.CPUI_INT_SDIV)
        divvn = data.newUniqueOut(x.getSize(), newdiv)
        data.opSetInput(newdiv, x, 0)
        data.opSetInput(newdiv, data.newConstant(x.getSize(), pw), 1)
        data.opInsertBefore(newdiv, op)
        data.opSetOpcode(op, OpCode.CPUI_INT_MULT)
        data.opSetInput(op, divvn, 0)
        data.opSetInput(op, data.newConstant(x.getSize(), pw), 1)
        return 1


class RuleModOpt(Rule):
    """Simplify expressions that optimize INT_REM/INT_SREM."""
    def __init__(self, g): super().__init__(g, 0, "modopt")
    def clone(self, gl):
        return RuleModOpt(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [int(OpCode.CPUI_INT_DIV), int(OpCode.CPUI_INT_SDIV)]
    def applyOp(self, op, data):
        x = op.getIn(0)
        div = op.getIn(1)
        outvn = op.getOut()
        for multop in outvn.getDescendants():
            if multop.code() != OpCode.CPUI_INT_MULT: continue
            div2 = multop.getIn(1)
            if div2 is outvn: div2 = multop.getIn(0)
            if div2.isConstant():
                if not div.isConstant(): continue
                mask = calc_mask(div2.getSize())
                if (((div2.getOffset() ^ mask) + 1) & mask) != div.getOffset():
                    continue
            else:
                if not div2.isWritten(): continue
                if div2.getDef().code() != OpCode.CPUI_INT_2COMP: continue
                if div2.getDef().getIn(0) is not div: continue
            outvn2 = multop.getOut()
            for addop in outvn2.getDescendants():
                if addop.code() != OpCode.CPUI_INT_ADD: continue
                lvn = addop.getIn(0)
                if lvn is outvn2: lvn = addop.getIn(1)
                if lvn is not x: continue
                data.opSetInput(addop, x, 0)
                if div.isConstant():
                    data.opSetInput(addop, data.newConstant(div.getSize(), div.getOffset()), 1)
                else:
                    data.opSetInput(addop, div, 1)
                ropc = OpCode.CPUI_INT_REM if op.code() == OpCode.CPUI_INT_DIV else OpCode.CPUI_INT_SREM
                data.opSetOpcode(addop, ropc)
                return 1
        return 0
