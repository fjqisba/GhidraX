"""
Batch 1g: FloatCast, ConcatCommute, FuncPtrEncoding, SubZext, SubRight, AddUnsigned, PositiveDiv.
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, signbit_negative
from ghidra.transform.action import Rule, ActionGroupList
if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


class RuleFloatCast(Rule):
    """Collapse chained float casts: float2float(float2float(V)) => float2float(V)."""
    def __init__(self, g): super().__init__(g, 0, "floatcast")
    def clone(self, gl):
        return RuleFloatCast(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [int(OpCode.CPUI_FLOAT_FLOAT2FLOAT), int(OpCode.CPUI_FLOAT_TRUNC)]
    def applyOp(self, op, data):
        vn1 = op.getIn(0)
        if not vn1.isWritten(): return 0
        castop = vn1.getDef()
        opc2 = castop.code()
        if opc2 not in (OpCode.CPUI_FLOAT_FLOAT2FLOAT, OpCode.CPUI_FLOAT_INT2FLOAT):
            return 0
        opc1 = op.code()
        vn2 = castop.getIn(0)
        insize1 = vn1.getSize()
        insize2 = vn2.getSize()
        outsize = op.getOut().getSize()
        if vn2.isFree(): return 0
        if opc2 == OpCode.CPUI_FLOAT_FLOAT2FLOAT and opc1 == OpCode.CPUI_FLOAT_FLOAT2FLOAT:
            if insize1 > outsize:
                data.opSetInput(op, vn2, 0)
                if outsize == insize2:
                    data.opSetOpcode(op, OpCode.CPUI_COPY)
                return 1
            elif insize2 < insize1:
                data.opSetInput(op, vn2, 0)
                return 1
        elif opc2 == OpCode.CPUI_FLOAT_INT2FLOAT and opc1 == OpCode.CPUI_FLOAT_FLOAT2FLOAT:
            data.opSetInput(op, vn2, 0)
            data.opSetOpcode(op, OpCode.CPUI_FLOAT_INT2FLOAT)
            return 1
        elif opc2 == OpCode.CPUI_FLOAT_FLOAT2FLOAT and opc1 == OpCode.CPUI_FLOAT_TRUNC:
            data.opSetInput(op, vn2, 0)
            return 1
        return 0


class RuleConcatCommute(Rule):
    """Commute PIECE with INT_AND/INT_OR/INT_XOR when one input is constant."""
    def __init__(self, g): super().__init__(g, 0, "concatcommute")
    def clone(self, gl):
        return RuleConcatCommute(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_PIECE)]
    def applyOp(self, op, data):
        outsz = op.getOut().getSize()
        if outsz > 8: return 0
        for i in range(2):
            vn = op.getIn(i)
            if not vn.isWritten(): continue
            logicop = vn.getDef()
            opc = logicop.code()
            if opc in (OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
                if not logicop.getIn(1).isConstant(): continue
                val = logicop.getIn(1).getOffset()
                if i == 0:
                    hi = logicop.getIn(0); lo = op.getIn(1)
                    val <<= 8 * lo.getSize()
                else:
                    hi = op.getIn(0); lo = logicop.getIn(0)
            elif opc == OpCode.CPUI_INT_AND:
                if not logicop.getIn(1).isConstant(): continue
                val = logicop.getIn(1).getOffset()
                if i == 0:
                    hi = logicop.getIn(0); lo = op.getIn(1)
                    val <<= 8 * lo.getSize()
                    val |= calc_mask(lo.getSize())
                else:
                    hi = op.getIn(0); lo = logicop.getIn(0)
                    val |= calc_mask(hi.getSize()) << (8 * lo.getSize())
            else:
                continue
            if hi.isFree() or lo.isFree(): continue
            nc = data.newOp(2, op.getAddr())
            data.opSetOpcode(nc, OpCode.CPUI_PIECE)
            nv = data.newUniqueOut(outsz, nc)
            data.opSetInput(nc, hi, 0)
            data.opSetInput(nc, lo, 1)
            data.opInsertBefore(nc, op)
            data.opSetOpcode(op, opc)
            data.opSetInput(op, nv, 0)
            data.opSetInput(op, data.newConstant(nv.getSize(), val), 1)
            return 1
        return 0


class RulePositiveDiv(Rule):
    """Convert INT_SDIV to INT_DIV when both inputs are positive."""
    def __init__(self, g): super().__init__(g, 0, "positivediv")
    def clone(self, gl):
        return RulePositiveDiv(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [int(OpCode.CPUI_INT_SDIV), int(OpCode.CPUI_INT_SREM)]
    def applyOp(self, op, data):
        sa = op.getOut().getSize()
        if sa > 8: return 0
        sa = sa * 8 - 1
        if ((op.getIn(0).getNZMask() >> sa) & 1) != 0: return 0
        if ((op.getIn(1).getNZMask() >> sa) & 1) != 0: return 0
        opc = OpCode.CPUI_INT_DIV if op.code() == OpCode.CPUI_INT_SDIV else OpCode.CPUI_INT_REM
        data.opSetOpcode(op, opc)
        return 1


class RuleFuncPtrEncoding(Rule):
    """Eliminate ARM/THUMB function pointer encoding: V & -2 => V."""
    def __init__(self, g): super().__init__(g, 0, "funcptrencoding")
    def clone(self, gl):
        return RuleFuncPtrEncoding(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_CALLIND)]
    def applyOp(self, op, data):
        vn = op.getIn(0)
        if not vn.isWritten(): return 0
        andop = vn.getDef()
        if andop.code() != OpCode.CPUI_INT_AND: return 0
        maskvn = andop.getIn(1)
        if not maskvn.isConstant(): return 0
        sz = maskvn.getSize()
        mask = maskvn.getOffset()
        if mask != (calc_mask(sz) ^ 1): return 0
        invn = andop.getIn(0)
        if invn.isFree(): return 0
        data.opSetInput(op, invn, 0)
        return 1


class RuleSubZext(Rule):
    """zext(sub(V,0)) => V & mask; zext(sub(V,c) >> d) => (V >> (c*8+d)) & mask."""
    def __init__(self, g): super().__init__(g, 0, "subzext")
    def clone(self, gl):
        return RuleSubZext(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_ZEXT)]
    def applyOp(self, op, data):
        subvn = op.getIn(0)
        if not subvn.isWritten(): return 0
        subop = subvn.getDef()
        if subop.code() == OpCode.CPUI_SUBPIECE:
            basevn = subop.getIn(0)
            if basevn.isFree(): return 0
            if basevn.getSize() != op.getOut().getSize(): return 0
            if basevn.getSize() > 8: return 0
            if subop.getIn(1).getOffset() != 0:
                if subvn.loneDescend() != op: return 0
                constvn = subop.getIn(1)
                rightVal = constvn.getOffset() * 8
                newvn = data.newUniqueOut(basevn.getSize(), data.newOp(2, op.getAddr()))
                shiftop = newvn.getDef()
                data.opSetOpcode(shiftop, OpCode.CPUI_INT_RIGHT)
                data.opSetInput(shiftop, basevn, 0)
                data.opSetInput(shiftop, data.newConstant(constvn.getSize(), rightVal), 1)
                data.opInsertBefore(shiftop, op)
                data.opSetInput(op, newvn, 0)
            else:
                data.opSetInput(op, basevn, 0)
            val = calc_mask(subvn.getSize())
            constvn = data.newConstant(basevn.getSize(), val)
            data.opSetOpcode(op, OpCode.CPUI_INT_AND)
            data.opInsertInput(op, constvn, 1)
            return 1
        return 0
