"""
Batch 1a rules: Simple arithmetic/logic/comparison rules.
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
# RuleShiftBitops
# =========================================================================

class RuleShiftBitops(Rule):
    """Shifting away all non-zero bits of one-side of a logical/arithmetic op.

    (V & 0xf000) << 4 => #0 << 4
    (V + 0xf000) << 4 =>  V << 4
    """

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "shiftbitops")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleShiftBitops(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LEFT), int(OpCode.CPUI_INT_RIGHT),
                int(OpCode.CPUI_SUBPIECE), int(OpCode.CPUI_INT_MULT)]

    def applyOp(self, op, data) -> int:
        constvn = op.getIn(1)
        if not constvn.isConstant():
            return 0
        vn = op.getIn(0)
        if not vn.isWritten():
            return 0
        if vn.getSize() > 8:
            return 0

        opc = op.code()
        if opc == OpCode.CPUI_INT_LEFT:
            sa = int(constvn.getOffset())
            leftshift = True
        elif opc == OpCode.CPUI_INT_RIGHT:
            sa = int(constvn.getOffset())
            leftshift = False
        elif opc == OpCode.CPUI_SUBPIECE:
            sa = int(constvn.getOffset()) * 8
            leftshift = False
        elif opc == OpCode.CPUI_INT_MULT:
            sa = leastsigbit_set(constvn.getOffset())
            if sa == -1:
                return 0
            leftshift = True
        else:
            return 0

        bitop = vn.getDef()
        bitopc = bitop.code()
        if bitopc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            pass
        elif bitopc in (OpCode.CPUI_INT_MULT, OpCode.CPUI_INT_ADD):
            if not leftshift:
                return 0
        else:
            return 0

        outmask = calc_mask(op.getOut().getSize())
        found = -1
        for i in range(bitop.numInput()):
            nzm = bitop.getIn(i).getNZMask()
            nzm = pcode_left(nzm, sa) if leftshift else pcode_right(nzm, sa)
            if (nzm & outmask) == 0:
                found = i
                break
        if found == -1:
            return 0

        if bitopc in (OpCode.CPUI_INT_MULT, OpCode.CPUI_INT_AND):
            data.opSetInput(op, data.newConstant(vn.getSize(), 0), 0)
        elif bitopc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR):
            othervn = bitop.getIn(1 - found)
            if not othervn.isHeritageKnown():
                return 0
            data.opSetInput(op, othervn, 0)
        return 1


# =========================================================================
# RuleIntLessEqual
# =========================================================================

class RuleIntLessEqual(Rule):
    """Convert LESSEQUAL to LESS: V <= c => V < (c+1)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "intlessequal")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleIntLessEqual(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LESSEQUAL), int(OpCode.CPUI_INT_SLESSEQUAL)]

    def applyOp(self, op, data) -> int:
        constvn = op.getIn(1)
        if not constvn.isConstant():
            return 0
        val = constvn.getOffset()
        size = constvn.getSize()
        mask = calc_mask(size)
        if op.code() == OpCode.CPUI_INT_LESSEQUAL:
            if val == mask:
                return 0
            data.opSetOpcode(op, OpCode.CPUI_INT_LESS)
        else:
            smax = mask >> 1
            if val == smax:
                return 0
            data.opSetOpcode(op, OpCode.CPUI_INT_SLESS)
        data.opSetInput(op, data.newConstant(size, (val + 1) & mask), 1)
        return 1


# =========================================================================
# RuleEquality
# =========================================================================

class RuleEquality(Rule):
    """Collapse INT_EQUAL/INT_NOTEQUAL when both inputs are identical: f(V,W)==f(V,W) => true."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "equality")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleEquality(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL)]

    def applyOp(self, op, data) -> int:
        from ghidra.core.expression import functionalEquality
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        if not functionalEquality(in0, in1):
            return 0
        val = 1 if op.code() == OpCode.CPUI_INT_EQUAL else 0
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opRemoveInput(op, 1)
        data.opSetInput(op, data.newConstant(1, val), 0)
        return 1


# =========================================================================
# RuleTrivialShift
# =========================================================================

class RuleTrivialShift(Rule):
    """Simplify trivial shifts: V << 0 => V, V >> n (n>=size*8) => 0."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "trivialshift")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleTrivialShift(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LEFT), int(OpCode.CPUI_INT_RIGHT),
                int(OpCode.CPUI_INT_SRIGHT)]

    def applyOp(self, op, data) -> int:
        constvn = op.getIn(1)
        if not constvn.isConstant():
            return 0
        val = constvn.getOffset()
        if val != 0:
            if val < 8 * op.getIn(0).getSize():
                return 0
            if op.code() == OpCode.CPUI_INT_SRIGHT:
                return 0
            replace = data.newConstant(op.getIn(0).getSize(), 0)
            data.opSetInput(op, replace, 0)
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


# =========================================================================
# RuleTestSign
# =========================================================================

class RuleTestSign(Rule):
    """Convert sign-bit test to signed comparison: (V s>> 0x1f) != 0 => V s< 0."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "testsign")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleTestSign(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SRIGHT)]

    @staticmethod
    def _findComparisons(vn):
        res = []
        for descop in vn.getDescendants():
            opc = descop.code()
            if opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
                if descop.getIn(1).isConstant():
                    res.append(descop)
        return res

    def applyOp(self, op, data) -> int:
        constVn = op.getIn(1)
        if not constVn.isConstant():
            return 0
        val = constVn.getOffset()
        inVn = op.getIn(0)
        if val != 8 * inVn.getSize() - 1:
            return 0
        if inVn.isFree():
            return 0
        outVn = op.getOut()
        compareOps = self._findComparisons(outVn)
        resultCode = 0
        for compareOp in compareOps:
            compSize = compareOp.getIn(0).getSize()
            offset = compareOp.getIn(1).getOffset()
            if offset == 0:
                sgn = 1
            elif offset == calc_mask(compSize):
                sgn = -1
            else:
                continue
            if compareOp.code() == OpCode.CPUI_INT_NOTEQUAL:
                sgn = -sgn
            zeroVn = data.newConstant(inVn.getSize(), 0)
            if sgn == 1:
                data.opSetInput(compareOp, inVn, 1)
                data.opSetInput(compareOp, zeroVn, 0)
                data.opSetOpcode(compareOp, OpCode.CPUI_INT_SLESSEQUAL)
            else:
                data.opSetInput(compareOp, inVn, 0)
                data.opSetInput(compareOp, zeroVn, 1)
                data.opSetOpcode(compareOp, OpCode.CPUI_INT_SLESS)
            resultCode = 1
        return resultCode


# =========================================================================
# RuleAndDistribute
# =========================================================================

class RuleAndDistribute(Rule):
    """Distribute INT_AND through INT_OR if result is simpler."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "anddistribute")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleAndDistribute(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        size = op.getOut().getSize()
        if size > 8:
            return 0
        fullmask = calc_mask(size)
        found = False
        othervn = None
        orop = None
        for i in range(2):
            othervn = op.getIn(1 - i)
            if not othervn.isHeritageKnown():
                continue
            orvn = op.getIn(i)
            if not orvn.isWritten():
                continue
            orop = orvn.getDef()
            if orop.code() != OpCode.CPUI_INT_OR:
                continue
            if not orop.getIn(0).isHeritageKnown():
                continue
            if not orop.getIn(1).isHeritageKnown():
                continue
            othermask = othervn.getNZMask()
            if othermask == 0:
                continue
            if othermask == fullmask:
                continue
            ormask1 = orop.getIn(0).getNZMask()
            if (ormask1 & othermask) == 0:
                found = True
                break
            ormask2 = orop.getIn(1).getNZMask()
            if (ormask2 & othermask) == 0:
                found = True
                break
            if othervn.isConstant():
                if (ormask1 & othermask) == ormask1:
                    found = True
                    break
                if (ormask2 & othermask) == ormask2:
                    found = True
                    break
        if not found:
            return 0

        newop1 = data.newOp(2, op.getAddr())
        newvn1 = data.newUniqueOut(size, newop1)
        data.opSetOpcode(newop1, OpCode.CPUI_INT_AND)
        data.opSetInput(newop1, orop.getIn(0), 0)
        data.opSetInput(newop1, othervn, 1)
        data.opInsertBefore(newop1, op)

        newop2 = data.newOp(2, op.getAddr())
        newvn2 = data.newUniqueOut(size, newop2)
        data.opSetOpcode(newop2, OpCode.CPUI_INT_AND)
        data.opSetInput(newop2, orop.getIn(1), 0)
        data.opSetInput(newop2, othervn, 1)
        data.opInsertBefore(newop2, op)

        data.opSetInput(op, newvn1, 0)
        data.opSetInput(op, newvn2, 1)
        data.opSetOpcode(op, OpCode.CPUI_INT_OR)
        return 1


# =========================================================================
# RuleSlessToLess
# =========================================================================

class RuleSlessToLess(Rule):
    """Convert INT_SLESS to INT_LESS when comparing positive values."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "slesstoless")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleSlessToLess(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SLESS), int(OpCode.CPUI_INT_SLESSEQUAL)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        sz = vn.getSize()
        if signbit_negative(vn.getNZMask(), sz):
            return 0
        if signbit_negative(op.getIn(1).getNZMask(), sz):
            return 0
        if op.code() == OpCode.CPUI_INT_SLESS:
            data.opSetOpcode(op, OpCode.CPUI_INT_LESS)
        else:
            data.opSetOpcode(op, OpCode.CPUI_INT_LESSEQUAL)
        return 1


# =========================================================================
# RuleZextSless
# =========================================================================

class RuleZextSless(Rule):
    """Transform INT_ZEXT and INT_SLESS: zext(V) s< c => V < c."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "zextsless")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleZextSless(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SLESS), int(OpCode.CPUI_INT_SLESSEQUAL)]

    def applyOp(self, op, data) -> int:
        vn1 = op.getIn(0)
        vn2 = op.getIn(1)
        zextslot = 0
        otherslot = 1
        if vn2.isWritten() and vn2.getDef().code() == OpCode.CPUI_INT_ZEXT:
            vn1 = vn2
            vn2 = op.getIn(0)
            zextslot = 1
            otherslot = 0
        elif not (vn1.isWritten() and vn1.getDef().code() == OpCode.CPUI_INT_ZEXT):
            return 0
        if not vn2.isConstant():
            return 0
        zext = vn1.getDef()
        if not zext.getIn(0).isHeritageKnown():
            return 0
        smallsize = zext.getIn(0).getSize()
        val = vn2.getOffset()
        if (val >> (8 * smallsize - 1)) != 0:
            return 0
        newvn = data.newConstant(smallsize, val)
        data.opSetInput(op, zext.getIn(0), zextslot)
        data.opSetInput(op, newvn, otherslot)
        newopc = OpCode.CPUI_INT_LESS if op.code() == OpCode.CPUI_INT_SLESS else OpCode.CPUI_INT_LESSEQUAL
        data.opSetOpcode(op, newopc)
        return 1


# =========================================================================
# RuleBitUndistribute
# =========================================================================

class RuleBitUndistribute(Rule):
    """Undo distributed operations: zext(V) & zext(W) => zext(V & W)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "bitundistribute")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleBitUndistribute(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND), int(OpCode.CPUI_INT_OR),
                int(OpCode.CPUI_INT_XOR)]

    def applyOp(self, op, data) -> int:
        vn1 = op.getIn(0)
        vn2 = op.getIn(1)
        if not vn1.isWritten():
            return 0
        if not vn2.isWritten():
            return 0
        opc = vn1.getDef().code()
        if vn2.getDef().code() != opc:
            return 0

        if opc in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
            in1 = vn1.getDef().getIn(0)
            if in1.isFree():
                return 0
            in2 = vn2.getDef().getIn(0)
            if in2.isFree():
                return 0
            if in1.getSize() != in2.getSize():
                return 0
            data.opRemoveInput(op, 1)
        elif opc in (OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT):
            shin1 = vn1.getDef().getIn(1)
            shin2 = vn2.getDef().getIn(1)
            if shin1.isConstant() and shin2.isConstant():
                if shin1.getOffset() != shin2.getOffset():
                    return 0
                vnextra = data.newConstant(shin1.getSize(), shin1.getOffset())
            elif shin1 is shin2:
                if shin1.isFree():
                    return 0
                vnextra = shin1
            else:
                return 0
            in1 = vn1.getDef().getIn(0)
            if in1.isFree():
                return 0
            in2 = vn2.getDef().getIn(0)
            if in2.isFree():
                return 0
            data.opSetInput(op, vnextra, 1)
        else:
            return 0

        newext = data.newOp(2, op.getAddr())
        smalllogic = data.newUniqueOut(in1.getSize(), newext)
        data.opSetInput(newext, in1, 0)
        data.opSetInput(newext, in2, 1)
        data.opSetOpcode(newext, op.code())
        data.opSetOpcode(op, opc)
        data.opSetInput(op, smalllogic, 0)
        data.opInsertBefore(newext, op)
        return 1


# =========================================================================
# RuleNegateNegate
# =========================================================================

class RuleNegateNegate(Rule):
    """Eliminate double INT_NEGATE: ~(~V) => V."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "negatenegate")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleNegateNegate(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_NEGATE)]

    def applyOp(self, op, data) -> int:
        vn1 = op.getIn(0)
        if not vn1.isWritten():
            return 0
        neg2 = vn1.getDef()
        if neg2.code() != OpCode.CPUI_INT_NEGATE:
            return 0
        vn2 = neg2.getIn(0)
        if vn2.isFree():
            return 0
        data.opSetInput(op, vn2, 0)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1
