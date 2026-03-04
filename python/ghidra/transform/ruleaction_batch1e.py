"""
Batch 1e rules: Subpiece/concat/zext manipulation rules.
"""

from __future__ import annotations
from typing import Optional, List, TYPE_CHECKING

from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, leastsigbit_set
from ghidra.transform.action import Rule, ActionGroupList

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


class RuleSubExtComm(Rule):
    """Commute SUBPIECE with INT_ZEXT/INT_SEXT."""
    def __init__(self, g): super().__init__(g, 0, "subextcomm")
    def clone(self, gl):
        return RuleSubExtComm(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_SUBPIECE)]
    def applyOp(self, op, data):
        base = op.getIn(0)
        if not base.isWritten(): return 0
        extop = base.getDef()
        if extop.code() not in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT): return 0
        invn = extop.getIn(0)
        if invn.isFree(): return 0
        subcut = int(op.getIn(1).getOffset())
        if op.getOut().getSize() + subcut <= invn.getSize():
            data.opSetInput(op, invn, 0)
            if invn.getSize() == op.getOut().getSize():
                data.opRemoveInput(op, 1)
                data.opSetOpcode(op, OpCode.CPUI_COPY)
            return 1
        if subcut >= invn.getSize(): return 0
        if subcut != 0:
            newop = data.newOp(2, op.getAddr())
            data.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
            newvn = data.newUniqueOut(invn.getSize() - subcut, newop)
            data.opSetInput(newop, data.newConstant(op.getIn(1).getSize(), subcut), 1)
            data.opSetInput(newop, invn, 0)
            data.opInsertBefore(newop, op)
        else:
            newvn = invn
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, extop.code())
        data.opSetInput(op, newvn, 0)
        return 1


class RuleConcatZext(Rule):
    """concat(zext(V),W) => zext(concat(V,W))."""
    def __init__(self, g): super().__init__(g, 0, "concatzext")
    def clone(self, gl):
        return RuleConcatZext(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_PIECE)]
    def applyOp(self, op, data):
        hi = op.getIn(0)
        if not hi.isWritten(): return 0
        zextop = hi.getDef()
        if zextop.code() != OpCode.CPUI_INT_ZEXT: return 0
        hi = zextop.getIn(0)
        lo = op.getIn(1)
        if hi.isFree() or lo.isFree(): return 0
        nc = data.newOp(2, op.getAddr())
        data.opSetOpcode(nc, OpCode.CPUI_PIECE)
        nv = data.newUniqueOut(hi.getSize() + lo.getSize(), nc)
        data.opSetInput(nc, hi, 0)
        data.opSetInput(nc, lo, 1)
        data.opInsertBefore(nc, op)
        data.opRemoveInput(op, 1)
        data.opSetInput(op, nv, 0)
        data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
        return 1


class RuleZextCommute(Rule):
    """zext(V) >> W => zext(V >> W)."""
    def __init__(self, g): super().__init__(g, 0, "zextcommute")
    def clone(self, gl):
        return RuleZextCommute(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_RIGHT)]
    def applyOp(self, op, data):
        zextvn = op.getIn(0)
        if not zextvn.isWritten(): return 0
        zextop = zextvn.getDef()
        if zextop.code() != OpCode.CPUI_INT_ZEXT: return 0
        zextin = zextop.getIn(0)
        if zextin.isFree(): return 0
        savn = op.getIn(1)
        if not savn.isConstant() and savn.isFree(): return 0
        newop = data.newOp(2, op.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_INT_RIGHT)
        newout = data.newUniqueOut(zextin.getSize(), newop)
        data.opRemoveInput(op, 1)
        data.opSetInput(op, newout, 0)
        data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
        data.opSetInput(newop, zextin, 0)
        data.opSetInput(newop, savn, 1)
        data.opInsertBefore(newop, op)
        return 1


class RuleZextShiftZext(Rule):
    """zext(zext(V) << c) => zext(V) << c; zext(zext(V)) => zext(V)."""
    def __init__(self, g): super().__init__(g, 0, "zextshiftzext")
    def clone(self, gl):
        return RuleZextShiftZext(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_INT_ZEXT)]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        shiftop = invn.getDef()
        if shiftop.code() == OpCode.CPUI_INT_ZEXT:
            vn = shiftop.getIn(0)
            if vn.isFree(): return 0
            if invn.loneDescend() != op: return 0
            data.opSetInput(op, vn, 0)
            return 1
        if shiftop.code() != OpCode.CPUI_INT_LEFT: return 0
        if not shiftop.getIn(1).isConstant(): return 0
        if not shiftop.getIn(0).isWritten(): return 0
        z2 = shiftop.getIn(0).getDef()
        if z2.code() != OpCode.CPUI_INT_ZEXT: return 0
        rootvn = z2.getIn(0)
        if rootvn.isFree(): return 0
        sa = shiftop.getIn(1).getOffset()
        if sa > 8 * (z2.getOut().getSize() - rootvn.getSize()): return 0
        newop = data.newOp(1, op.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_INT_ZEXT)
        outvn = data.newUniqueOut(op.getOut().getSize(), newop)
        data.opSetInput(newop, rootvn, 0)
        data.opSetOpcode(op, OpCode.CPUI_INT_LEFT)
        data.opSetInput(op, outvn, 0)
        data.opInsertInput(op, data.newConstant(4, sa), 1)
        data.opInsertBefore(newop, op)
        return 1


class RuleShiftAnd(Rule):
    """Eliminate INT_AND when bits it zeroes are discarded by shift."""
    def __init__(self, g): super().__init__(g, 0, "shiftand")
    def clone(self, gl):
        return RuleShiftAnd(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [int(OpCode.CPUI_INT_RIGHT), int(OpCode.CPUI_INT_LEFT), int(OpCode.CPUI_INT_MULT)]
    def applyOp(self, op, data):
        cvn = op.getIn(1)
        if not cvn.isConstant(): return 0
        shiftin = op.getIn(0)
        if not shiftin.isWritten(): return 0
        andop = shiftin.getDef()
        if andop.code() != OpCode.CPUI_INT_AND: return 0
        if shiftin.loneDescend() != op: return 0
        maskvn = andop.getIn(1)
        if not maskvn.isConstant(): return 0
        mask = maskvn.getOffset()
        invn = andop.getIn(0)
        if invn.isFree(): return 0
        opc = op.code()
        if opc in (OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_LEFT):
            sa = int(cvn.getOffset())
        else:
            sa = leastsigbit_set(cvn.getOffset())
            if sa <= 0: return 0
            if (1 << sa) != cvn.getOffset(): return 0
            opc = OpCode.CPUI_INT_LEFT
        nzm = invn.getNZMask()
        fullmask = calc_mask(invn.getSize())
        if opc == OpCode.CPUI_INT_RIGHT:
            nzm >>= sa; mask >>= sa
        else:
            nzm = (nzm << sa) & fullmask; mask = (mask << sa) & fullmask
        if (mask & nzm) != nzm: return 0
        data.opSetOpcode(andop, OpCode.CPUI_COPY)
        data.opRemoveInput(andop, 1)
        return 1


class RuleConcatZero(Rule):
    """concat(V, 0) => zext(V) << c."""
    def __init__(self, g): super().__init__(g, 0, "concatzero")
    def clone(self, gl):
        return RuleConcatZero(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_PIECE)]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant(): return 0
        if op.getIn(1).getOffset() != 0: return 0
        sa = 8 * op.getIn(1).getSize()
        highvn = op.getIn(0)
        newop = data.newOp(1, op.getAddr())
        outvn = data.newUniqueOut(op.getOut().getSize(), newop)
        data.opSetOpcode(newop, OpCode.CPUI_INT_ZEXT)
        data.opSetOpcode(op, OpCode.CPUI_INT_LEFT)
        data.opSetInput(op, outvn, 0)
        data.opSetInput(op, data.newConstant(4, sa), 1)
        data.opSetInput(newop, highvn, 0)
        data.opInsertBefore(newop, op)
        return 1


class RuleConcatLeftShift(Rule):
    """concat(V, zext(W) << c) => concat(concat(V,W), 0)."""
    def __init__(self, g): super().__init__(g, 0, "concatleftshift")
    def clone(self, gl):
        return RuleConcatLeftShift(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_PIECE)]
    def applyOp(self, op, data):
        vn2 = op.getIn(1)
        if not vn2.isWritten(): return 0
        shiftop = vn2.getDef()
        if shiftop.code() != OpCode.CPUI_INT_LEFT: return 0
        if not shiftop.getIn(1).isConstant(): return 0
        sa = int(shiftop.getIn(1).getOffset())
        if (sa & 7) != 0: return 0
        tmpvn = shiftop.getIn(0)
        if not tmpvn.isWritten(): return 0
        zextop = tmpvn.getDef()
        if zextop.code() != OpCode.CPUI_INT_ZEXT: return 0
        b = zextop.getIn(0)
        if b.isFree(): return 0
        vn1 = op.getIn(0)
        if vn1.isFree(): return 0
        sa //= 8
        if sa + b.getSize() != tmpvn.getSize(): return 0
        newop = data.newOp(2, op.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_PIECE)
        newout = data.newUniqueOut(vn1.getSize() + b.getSize(), newop)
        data.opSetInput(newop, vn1, 0)
        data.opSetInput(newop, b, 1)
        data.opInsertBefore(newop, op)
        data.opSetInput(op, newout, 0)
        data.opSetInput(op, data.newConstant(op.getOut().getSize() - newout.getSize(), 0), 1)
        return 1


class RuleSubCancel(Rule):
    """Simplify SUBPIECE composed with INT_ZEXT/INT_SEXT/INT_AND."""
    def __init__(self, g): super().__init__(g, 0, "subcancel")
    def clone(self, gl):
        return RuleSubCancel(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_SUBPIECE)]
    def applyOp(self, op, data):
        base = op.getIn(0)
        if not base.isWritten(): return 0
        extop = base.getDef()
        opc = extop.code()
        if opc not in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT, OpCode.CPUI_INT_AND):
            return 0
        offset = int(op.getIn(1).getOffset())
        outsize = op.getOut().getSize()
        if opc == OpCode.CPUI_INT_AND:
            cvn = extop.getIn(1)
            if offset == 0 and cvn.isConstant() and cvn.getOffset() == calc_mask(outsize):
                thruvn = extop.getIn(0)
                if not thruvn.isFree():
                    data.opSetInput(op, thruvn, 0)
                    return 1
            return 0
        farinsize = extop.getIn(0).getSize()
        if offset == 0:
            thruvn = extop.getIn(0)
            if thruvn.isFree(): return 0
            if outsize == farinsize:
                opc = OpCode.CPUI_COPY
            elif outsize < farinsize:
                opc = OpCode.CPUI_SUBPIECE
        else:
            if opc == OpCode.CPUI_INT_ZEXT and farinsize <= offset:
                opc = OpCode.CPUI_COPY
                thruvn = data.newConstant(outsize, 0)
            else:
                return 0
        data.opSetOpcode(op, opc)
        data.opSetInput(op, thruvn, 0)
        if opc != OpCode.CPUI_SUBPIECE:
            data.opRemoveInput(op, 1)
        return 1


class RuleShiftSub(Rule):
    """sub(V << 8*k, c) => sub(V, c-k)."""
    def __init__(self, g): super().__init__(g, 0, "shiftsub")
    def clone(self, gl):
        return RuleShiftSub(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [int(OpCode.CPUI_SUBPIECE)]
    def applyOp(self, op, data):
        if not op.getIn(0).isWritten(): return 0
        shiftop = op.getIn(0).getDef()
        if shiftop.code() != OpCode.CPUI_INT_LEFT: return 0
        sa = shiftop.getIn(1)
        if not sa.isConstant(): return 0
        n = int(sa.getOffset())
        if (n & 7) != 0: return 0
        c = int(op.getIn(1).getOffset())
        vn = shiftop.getIn(0)
        if vn.isFree(): return 0
        insize = vn.getSize()
        outsize = op.getOut().getSize()
        c -= n // 8
        if c < 0 or c + outsize > insize: return 0
        data.opSetInput(op, vn, 0)
        data.opSetInput(op, data.newConstant(op.getIn(1).getSize(), c), 1)
        return 1
