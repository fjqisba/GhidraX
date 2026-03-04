"""
Batch 1f: Reassembly + cleanup rules.
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask
from ghidra.transform.action import Rule, ActionGroupList
if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


class RuleHumptyDumpty(Rule):
    """concat(sub(V,c), sub(V,0)) => V."""
    def __init__(self, g): super().__init__(g, 0, "humptydumpty")
    def clone(self, gl):
        return RuleHumptyDumpty(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_PIECE)]
    def applyOp(self, op, data):
        vn1 = op.getIn(0)
        if not vn1.isWritten(): return 0
        sub1 = vn1.getDef()
        if sub1.code() != OpCode.CPUI_SUBPIECE: return 0
        vn2 = op.getIn(1)
        if not vn2.isWritten(): return 0
        sub2 = vn2.getDef()
        if sub2.code() != OpCode.CPUI_SUBPIECE: return 0
        root = sub1.getIn(0)
        if root is not sub2.getIn(0): return 0
        pos1 = int(sub1.getIn(1).getOffset())
        pos2 = int(sub2.getIn(1).getOffset())
        size1 = vn1.getSize(); size2 = vn2.getSize()
        if pos1 != pos2 + size2: return 0
        if pos2 == 0 and size1 + size2 == root.getSize():
            data.opRemoveInput(op, 1)
            data.opSetInput(op, root, 0)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
        else:
            data.opSetInput(op, root, 0)
            data.opSetInput(op, data.newConstant(sub2.getIn(1).getSize(), pos2), 1)
            data.opSetOpcode(op, OpCode.CPUI_SUBPIECE)
        return 1


class RuleDumptyHump(Rule):
    """sub(concat(V,W), c) => sub(W,c) or V."""
    def __init__(self, g): super().__init__(g, 0, "dumptyhump")
    def clone(self, gl):
        return RuleDumptyHump(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_SUBPIECE)]
    def applyOp(self, op, data):
        base = op.getIn(0)
        if not base.isWritten(): return 0
        pieceop = base.getDef()
        if pieceop.code() != OpCode.CPUI_PIECE: return 0
        offset = int(op.getIn(1).getOffset())
        outsize = op.getOut().getSize()
        vn1 = pieceop.getIn(0); vn2 = pieceop.getIn(1)
        if offset < vn2.getSize():
            if offset + outsize > vn2.getSize(): return 0
            vn = vn2
        else:
            vn = vn1; offset -= vn2.getSize()
        if vn.isFree() and not vn.isConstant(): return 0
        if offset == 0 and outsize == vn.getSize():
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opRemoveInput(op, 1)
            data.opSetInput(op, vn, 0)
        else:
            data.opSetInput(op, vn, 0)
            data.opSetInput(op, data.newConstant(4, offset), 1)
        return 1


class RuleHumptyOr(Rule):
    """(V & ff00) | (V & 00ff) => V."""
    def __init__(self, g): super().__init__(g, 0, "humptyor")
    def clone(self, gl):
        return RuleHumptyOr(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_OR)]
    def applyOp(self, op, data):
        vn1 = op.getIn(0)
        if not vn1.isWritten(): return 0
        vn2 = op.getIn(1)
        if not vn2.isWritten(): return 0
        and1 = vn1.getDef()
        if and1.code() != OpCode.CPUI_INT_AND: return 0
        and2 = vn2.getDef()
        if and2.code() != OpCode.CPUI_INT_AND: return 0
        a, b = and1.getIn(0), and1.getIn(1)
        c, d = and2.getIn(0), and2.getIn(1)
        if a is c: c = d
        elif a is d: pass
        elif b is c: b, a, c = a, c, d
        elif b is d: b, a = a, d
        else: return 0
        if b.isConstant() and c.isConstant():
            tot = b.getOffset() | c.getOffset()
            if tot == calc_mask(a.getSize()):
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, a, 0)
            else:
                data.opSetOpcode(op, OpCode.CPUI_INT_AND)
                data.opSetInput(op, a, 0)
                data.opSetInput(op, data.newConstant(a.getSize(), tot), 1)
        else:
            if not b.isHeritageKnown() or not c.isHeritageKnown(): return 0
            am = a.getNZMask()
            if (b.getNZMask() & am) == 0 or (c.getNZMask() & am) == 0: return 0
            nop = data.newOp(2, op.getAddr())
            data.opSetOpcode(nop, OpCode.CPUI_INT_OR)
            ov = data.newUniqueOut(a.getSize(), nop)
            data.opSetInput(nop, b, 0); data.opSetInput(nop, c, 1)
            data.opInsertBefore(nop, op)
            data.opSetInput(op, a, 0); data.opSetInput(op, ov, 1)
            data.opSetOpcode(op, OpCode.CPUI_INT_AND)
        return 1


class RuleMultNegOne(Rule):
    """V * -1 => -V (INT_2COMP)."""
    def __init__(self, g): super().__init__(g, 0, "multnegone")
    def clone(self, gl):
        return RuleMultNegOne(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_MULT)]
    def applyOp(self, op, data):
        cv = op.getIn(1)
        if not cv.isConstant(): return 0
        if cv.getOffset() != calc_mask(cv.getSize()): return 0
        data.opSetOpcode(op, OpCode.CPUI_INT_2COMP)
        data.opRemoveInput(op, 1)
        return 1


class Rule2Comp2Sub(Rule):
    """V + -W => V - W."""
    def __init__(self, g): super().__init__(g, 0, "2comp2sub")
    def clone(self, gl):
        return Rule2Comp2Sub(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_2COMP)]
    def applyOp(self, op, data):
        addop = op.getOut().loneDescend()
        if addop is None: return 0
        if addop.code() != OpCode.CPUI_INT_ADD: return 0
        if addop.getIn(0) is op.getOut():
            data.opSetInput(addop, addop.getIn(1), 0)
        data.opSetInput(addop, op.getIn(0), 1)
        data.opSetOpcode(addop, OpCode.CPUI_INT_SUB)
        data.opDestroy(op)
        return 1


class RuleSubNormal(Rule):
    """Pull SUBPIECE back through INT_RIGHT: sub(V,c) => sub(V >> c*8, 0)."""
    def __init__(self, g): super().__init__(g, 0, "subnormal")
    def clone(self, gl):
        return RuleSubNormal(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_SUBPIECE)]
    def applyOp(self, op, data):
        c = int(op.getIn(1).getOffset())
        if c == 0: return 0
        a = op.getIn(0)
        if a.isFree(): return 0
        d = c * 8
        shiftop = data.newOp(2, op.getAddr())
        data.opSetOpcode(shiftop, OpCode.CPUI_INT_RIGHT)
        newout = data.newUniqueOut(a.getSize(), shiftop)
        data.opSetInput(shiftop, a, 0)
        data.opSetInput(shiftop, data.newConstant(4, d), 1)
        data.opInsertBefore(shiftop, op)
        data.opSetInput(op, newout, 0)
        data.opSetInput(op, data.newConstant(4, 0), 1)
        return 1
