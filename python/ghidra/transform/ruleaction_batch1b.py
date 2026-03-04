"""
Batch 1b rules: Comparison, branch, and structural rules.
Corresponds to additional rules from ruleaction.hh / ruleaction.cc
"""

from __future__ import annotations

from typing import Optional, List, TYPE_CHECKING

from ghidra.core.opcodes import OpCode
from ghidra.core.address import (
    calc_mask, pcode_left, pcode_right, leastsigbit_set, signbit_negative,
)
from ghidra.transform.action import Rule, ActionGroupList

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# RuleLessEqual
# =========================================================================

class RuleLessEqual(Rule):
    """Simplify 'less than or equal': V < W || V == W => V <= W."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "lessequal")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleLessEqual(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_BOOL_OR)]

    def applyOp(self, op, data) -> int:
        vnout1 = op.getIn(0)
        if not vnout1.isWritten():
            return 0
        vnout2 = op.getIn(1)
        if not vnout2.isWritten():
            return 0
        op_less = vnout1.getDef()
        opc = op_less.code()
        if opc not in (OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_SLESS):
            op_equal = op_less
            op_less = vnout2.getDef()
            opc = op_less.code()
            if opc not in (OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_SLESS):
                return 0
        else:
            op_equal = vnout2.getDef()
        equalopc = op_equal.code()
        if equalopc not in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
            return 0
        compvn1 = op_less.getIn(0)
        compvn2 = op_less.getIn(1)
        if not compvn1.isHeritageKnown():
            return 0
        if not compvn2.isHeritageKnown():
            return 0
        eq0 = op_equal.getIn(0)
        eq1 = op_equal.getIn(1)
        match = (compvn1 is eq0 and compvn2 is eq1) or (compvn1 is eq1 and compvn2 is eq0)
        if not match:
            return 0
        if equalopc == OpCode.CPUI_INT_NOTEQUAL:
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opRemoveInput(op, 1)
            data.opSetInput(op, op_equal.getOut(), 0)
        else:
            data.opSetInput(op, compvn1, 0)
            data.opSetInput(op, compvn2, 1)
            newopc = OpCode.CPUI_INT_SLESSEQUAL if opc == OpCode.CPUI_INT_SLESS else OpCode.CPUI_INT_LESSEQUAL
            data.opSetOpcode(op, newopc)
        return 1


# =========================================================================
# RuleLessNotEqual
# =========================================================================

class RuleLessNotEqual(Rule):
    """Simplify V <= W && V != W => V < W."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "lessnotequal")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleLessNotEqual(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_BOOL_AND)]

    def applyOp(self, op, data) -> int:
        vnout1 = op.getIn(0)
        if not vnout1.isWritten():
            return 0
        vnout2 = op.getIn(1)
        if not vnout2.isWritten():
            return 0
        op_less = vnout1.getDef()
        opc = op_less.code()
        if opc not in (OpCode.CPUI_INT_LESSEQUAL, OpCode.CPUI_INT_SLESSEQUAL):
            op_equal = op_less
            op_less = vnout2.getDef()
            opc = op_less.code()
            if opc not in (OpCode.CPUI_INT_LESSEQUAL, OpCode.CPUI_INT_SLESSEQUAL):
                return 0
        else:
            op_equal = vnout2.getDef()
        if op_equal.code() != OpCode.CPUI_INT_NOTEQUAL:
            return 0
        compvn1 = op_less.getIn(0)
        compvn2 = op_less.getIn(1)
        if not compvn1.isHeritageKnown():
            return 0
        if not compvn2.isHeritageKnown():
            return 0
        eq0 = op_equal.getIn(0)
        eq1 = op_equal.getIn(1)
        match = (compvn1 is eq0 and compvn2 is eq1) or (compvn1 is eq1 and compvn2 is eq0)
        if not match:
            return 0
        data.opSetInput(op, compvn1, 0)
        data.opSetInput(op, compvn2, 1)
        newopc = OpCode.CPUI_INT_SLESS if opc == OpCode.CPUI_INT_SLESSEQUAL else OpCode.CPUI_INT_LESS
        data.opSetOpcode(op, newopc)
        return 1


# =========================================================================
# RuleFloatRange
# =========================================================================

class RuleFloatRange(Rule):
    """Merge float comparisons: (V f< W) || (V f== W) => V f<= W."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "floatrange")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleFloatRange(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_BOOL_OR), int(OpCode.CPUI_BOOL_AND)]

    def applyOp(self, op, data) -> int:
        vn1 = op.getIn(0)
        if not vn1.isWritten():
            return 0
        vn2 = op.getIn(1)
        if not vn2.isWritten():
            return 0
        cmp1 = vn1.getDef()
        cmp2 = vn2.getDef()
        opccmp1 = cmp1.code()
        if opccmp1 not in (OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL):
            cmp1, cmp2 = cmp2, cmp1
            opccmp1 = cmp1.code()
        resultopc = OpCode.CPUI_COPY
        if opccmp1 == OpCode.CPUI_FLOAT_LESS:
            if cmp2.code() == OpCode.CPUI_FLOAT_EQUAL and op.code() == OpCode.CPUI_BOOL_OR:
                resultopc = OpCode.CPUI_FLOAT_LESSEQUAL
        elif opccmp1 == OpCode.CPUI_FLOAT_LESSEQUAL:
            if cmp2.code() == OpCode.CPUI_FLOAT_NOTEQUAL and op.code() == OpCode.CPUI_BOOL_AND:
                resultopc = OpCode.CPUI_FLOAT_LESS
        if resultopc == OpCode.CPUI_COPY:
            return 0
        slot1 = 0
        nvn1 = cmp1.getIn(slot1)
        if nvn1.isConstant():
            slot1 = 1
            nvn1 = cmp1.getIn(slot1)
            if nvn1.isConstant():
                return 0
        if nvn1.isFree():
            return 0
        cvn1 = cmp1.getIn(1 - slot1)
        if nvn1 is not cmp2.getIn(0):
            slot2 = 1
            if nvn1 is not cmp2.getIn(1):
                return 0
        else:
            slot2 = 0
        matchvn = cmp2.getIn(1 - slot2)
        if cvn1.isConstant():
            if not matchvn.isConstant():
                return 0
            if matchvn.getOffset() != cvn1.getOffset():
                return 0
        elif cvn1 is not matchvn:
            return 0
        elif cvn1.isFree():
            return 0
        data.opSetOpcode(op, resultopc)
        data.opSetInput(op, nvn1, slot1)
        if cvn1.isConstant():
            data.opSetInput(op, data.newConstant(cvn1.getSize(), cvn1.getOffset()), 1 - slot1)
        else:
            data.opSetInput(op, cvn1, 1 - slot1)
        return 1


# =========================================================================
# RuleAndPiece
# =========================================================================

class RuleAndPiece(Rule):
    """Convert PIECE to INT_ZEXT where appropriate: V & concat(W,X) => zext(X)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "andpiece")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleAndPiece(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        size = op.getOut().getSize()
        found_i = -1
        opc = OpCode.CPUI_PIECE
        highvn = lowvn = None
        for i in range(2):
            piecevn = op.getIn(i)
            if not piecevn.isWritten():
                continue
            pieceop = piecevn.getDef()
            if pieceop.code() != OpCode.CPUI_PIECE:
                continue
            othervn = op.getIn(1 - i)
            othermask = othervn.getNZMask()
            if othermask == calc_mask(size):
                continue
            if othermask == 0:
                continue
            highvn = pieceop.getIn(0)
            if not highvn.isHeritageKnown():
                continue
            lowvn = pieceop.getIn(1)
            if not lowvn.isHeritageKnown():
                continue
            maskhigh = highvn.getNZMask()
            if (maskhigh & (othermask >> (lowvn.getSize() * 8))) == 0:
                if maskhigh == 0 and highvn.isConstant():
                    continue
                opc = OpCode.CPUI_INT_ZEXT
                found_i = i
                break
            elif (lowvn.getNZMask() & othermask) == 0:
                if lowvn.isConstant():
                    continue
                opc = OpCode.CPUI_PIECE
                found_i = i
                break
        if found_i == -1:
            return 0
        if opc == OpCode.CPUI_INT_ZEXT:
            newop = data.newOp(1, op.getAddr())
            data.opSetOpcode(newop, opc)
            data.opSetInput(newop, lowvn, 0)
        else:
            newvn2 = data.newConstant(lowvn.getSize(), 0)
            newop = data.newOp(2, op.getAddr())
            data.opSetOpcode(newop, opc)
            data.opSetInput(newop, highvn, 0)
            data.opSetInput(newop, newvn2, 1)
        newvn = data.newUniqueOut(size, newop)
        data.opInsertBefore(newop, op)
        data.opSetInput(op, newvn, found_i)
        return 1


# =========================================================================
# RuleAndCommute
# =========================================================================

class RuleAndCommute(Rule):
    """Commute INT_AND with INT_LEFT/RIGHT: (V << W) & d => (V & (d >> W)) << W."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "andcommute")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleAndCommute(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        size = op.getOut().getSize()
        if size > 8:
            return 0
        fullmask = calc_mask(size)
        found = False
        opc = sa = None
        orvn = savn = othervn = None
        for i in range(2):
            shiftvn = op.getIn(i)
            if not shiftvn.isWritten():
                continue
            shiftop = shiftvn.getDef()
            opc = shiftop.code()
            if opc not in (OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT):
                continue
            savn = shiftop.getIn(1)
            if not savn.isConstant():
                continue
            sa = int(savn.getOffset())
            othervn = op.getIn(1 - i)
            if not othervn.isHeritageKnown():
                continue
            othermask = othervn.getNZMask()
            if opc == OpCode.CPUI_INT_RIGHT:
                if (fullmask >> sa) == othermask:
                    continue
                othermask_shifted = (othermask << sa) & fullmask
            else:
                if ((fullmask << sa) & fullmask) == othermask:
                    continue
                othermask_shifted = othermask >> sa
            if othermask_shifted == 0:
                continue
            if othermask_shifted == fullmask:
                continue
            orvn = shiftop.getIn(0)
            if opc == OpCode.CPUI_INT_LEFT and othervn.isConstant():
                if shiftvn.loneDescend() == op:
                    found = True
                    break
            if not orvn.isWritten():
                continue
            orop = orvn.getDef()
            if orop.code() == OpCode.CPUI_INT_OR:
                ormask1 = orop.getIn(0).getNZMask()
                if (ormask1 & othermask_shifted) == 0:
                    found = True
                    break
                ormask2 = orop.getIn(1).getNZMask()
                if (ormask2 & othermask_shifted) == 0:
                    found = True
                    break
                if othervn.isConstant():
                    if (ormask1 & othermask_shifted) == ormask1:
                        found = True
                        break
                    if (ormask2 & othermask_shifted) == ormask2:
                        found = True
                        break
            elif orop.code() == OpCode.CPUI_PIECE:
                ormask1 = orop.getIn(1).getNZMask()
                if (ormask1 & othermask_shifted) == 0:
                    found = True
                    break
                ormask2 = orop.getIn(0).getNZMask()
                ormask2 <<= orop.getIn(1).getSize() * 8
                if (ormask2 & othermask_shifted) == 0:
                    found = True
                    break
        if not found:
            return 0
        revOpc = OpCode.CPUI_INT_RIGHT if opc == OpCode.CPUI_INT_LEFT else OpCode.CPUI_INT_LEFT
        newop1 = data.newOp(2, op.getAddr())
        newvn1 = data.newUniqueOut(size, newop1)
        data.opSetOpcode(newop1, revOpc)
        data.opSetInput(newop1, othervn, 0)
        data.opSetInput(newop1, savn, 1)
        data.opInsertBefore(newop1, op)
        newop2 = data.newOp(2, op.getAddr())
        newvn2 = data.newUniqueOut(size, newop2)
        data.opSetOpcode(newop2, OpCode.CPUI_INT_AND)
        data.opSetInput(newop2, orvn, 0)
        data.opSetInput(newop2, newvn1, 1)
        data.opInsertBefore(newop2, op)
        data.opSetInput(op, newvn2, 0)
        data.opSetInput(op, savn, 1)
        data.opSetOpcode(op, opc)
        return 1


# =========================================================================
# RuleShiftCompare
# =========================================================================

class RuleShiftCompare(Rule):
    """Simplify shift then compare with constant: (V << c) == d => V == (d >> c)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "shiftcompare")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleShiftCompare(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL),
                int(OpCode.CPUI_INT_LESS), int(OpCode.CPUI_INT_LESSEQUAL)]

    def applyOp(self, op, data) -> int:
        shiftvn = op.getIn(0)
        constvn = op.getIn(1)
        if not constvn.isConstant():
            return 0
        if not shiftvn.isWritten():
            return 0
        shiftop = shiftvn.getDef()
        opc = shiftop.code()
        if opc == OpCode.CPUI_INT_LEFT:
            isleft = True
            savn = shiftop.getIn(1)
            if not savn.isConstant():
                return 0
            sa = int(savn.getOffset())
        elif opc == OpCode.CPUI_INT_RIGHT:
            isleft = False
            savn = shiftop.getIn(1)
            if not savn.isConstant():
                return 0
            sa = int(savn.getOffset())
            if shiftvn.loneDescend() != op:
                return 0
        elif opc == OpCode.CPUI_INT_MULT:
            isleft = True
            savn = shiftop.getIn(1)
            if not savn.isConstant():
                return 0
            val = savn.getOffset()
            sa = leastsigbit_set(val)
            if (val >> sa) != 1:
                return 0
        elif opc == OpCode.CPUI_INT_DIV:
            isleft = False
            savn = shiftop.getIn(1)
            if not savn.isConstant():
                return 0
            val = savn.getOffset()
            sa = leastsigbit_set(val)
            if (val >> sa) != 1:
                return 0
            if shiftvn.loneDescend() != op:
                return 0
        else:
            return 0
        if sa == 0:
            return 0
        mainvn = shiftop.getIn(0)
        if mainvn.isFree():
            return 0
        if mainvn.getSize() > 8:
            return 0
        constval = constvn.getOffset()
        nzmask = mainvn.getNZMask()
        mask = calc_mask(shiftvn.getSize())
        if isleft:
            newconst = constval >> sa
            if (newconst << sa) != constval:
                return 0
            tmp = (nzmask << sa) & mask
            if (tmp >> sa) != nzmask:
                if shiftvn.loneDescend() != op:
                    return 0
                sa2 = 8 * shiftvn.getSize() - sa
                tmpmask = (1 << sa2) - 1
                newmask = data.newConstant(constvn.getSize(), tmpmask)
                newop = data.newOp(2, op.getAddr())
                data.opSetOpcode(newop, OpCode.CPUI_INT_AND)
                newtmpvn = data.newUniqueOut(constvn.getSize(), newop)
                data.opSetInput(newop, mainvn, 0)
                data.opSetInput(newop, newmask, 1)
                data.opInsertBefore(newop, shiftop)
                data.opSetInput(op, newtmpvn, 0)
                data.opSetInput(op, data.newConstant(constvn.getSize(), newconst), 1)
                return 1
        else:
            if ((nzmask >> sa) << sa) != nzmask:
                return 0
            newconst = (constval << sa) & mask
            if (newconst >> sa) != constval:
                return 0
        newconstvn = data.newConstant(constvn.getSize(), newconst)
        data.opSetInput(op, mainvn, 0)
        data.opSetInput(op, newconstvn, 1)
        return 1


# =========================================================================
# RuleShiftPiece
# =========================================================================

class RuleShiftPiece(Rule):
    """Convert shift-and-add to PIECE: (zext(V) << 16) + zext(W) => concat(V,W)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "shiftpiece")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleShiftPiece(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_OR), int(OpCode.CPUI_INT_XOR),
                int(OpCode.CPUI_INT_ADD)]

    def applyOp(self, op, data) -> int:
        vn1 = op.getIn(0)
        if not vn1.isWritten():
            return 0
        vn2 = op.getIn(1)
        if not vn2.isWritten():
            return 0
        shiftop = vn1.getDef()
        zextloop = vn2.getDef()
        if shiftop.code() != OpCode.CPUI_INT_LEFT:
            if zextloop.code() != OpCode.CPUI_INT_LEFT:
                return 0
            shiftop, zextloop = zextloop, shiftop
        if not shiftop.getIn(1).isConstant():
            return 0
        hivn_src = shiftop.getIn(0)
        if not hivn_src.isWritten():
            return 0
        zexthiop = hivn_src.getDef()
        if zexthiop.code() not in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
            return 0
        hivn = zexthiop.getIn(0)
        if hivn.isConstant():
            if hivn.getSize() < 8:
                return 0
        elif hivn.isFree():
            return 0
        sa = int(shiftop.getIn(1).getOffset())
        concatsize = sa + 8 * hivn.getSize()
        if op.getOut().getSize() * 8 < concatsize:
            return 0
        if zextloop.code() != OpCode.CPUI_INT_ZEXT:
            return 0
        lovn = zextloop.getIn(0)
        if lovn.isFree():
            return 0
        if sa != 8 * lovn.getSize():
            return 0
        if concatsize == op.getOut().getSize() * 8:
            data.opSetOpcode(op, OpCode.CPUI_PIECE)
            data.opSetInput(op, hivn, 0)
            data.opSetInput(op, lovn, 1)
        else:
            newop = data.newOp(2, op.getAddr())
            data.newUniqueOut(concatsize // 8, newop)
            data.opSetOpcode(newop, OpCode.CPUI_PIECE)
            data.opSetInput(newop, hivn, 0)
            data.opSetInput(newop, lovn, 1)
            data.opInsertBefore(newop, op)
            data.opSetOpcode(op, zexthiop.code())
            data.opRemoveInput(op, 1)
            data.opSetInput(op, newop.getOut(), 0)
        return 1
