"""
Batch 1d rules: Comparison/branch rules.
RuleLess2Zero, RuleLessEqual2Zero, RuleSLess2Zero, RuleEqual2Zero,
RuleEqual2Constant, RuleCondNegate, RuleBoolNegate.
"""

from __future__ import annotations

from typing import Optional, List, TYPE_CHECKING

from ghidra.core.opcodes import OpCode, get_booleanflip
from ghidra.core.address import calc_mask
from ghidra.transform.action import Rule, ActionGroupList

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# RuleLess2Zero
# =========================================================================

class RuleLess2Zero(Rule):
    """Simplify INT_LESS applied to extremal constants.

    0 < V => 0 != V;  V < 0 => false;  ffff < V => false;  V < ffff => V != ffff.
    """

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "less2zero")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleLess2Zero(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LESS)]

    def applyOp(self, op, data) -> int:
        lvn = op.getIn(0)
        rvn = op.getIn(1)
        if lvn.isConstant():
            if lvn.getOffset() == 0:
                data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL)
                return 1
            elif lvn.getOffset() == calc_mask(lvn.getSize()):
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, data.newConstant(1, 0), 0)
                return 1
        elif rvn.isConstant():
            if rvn.getOffset() == 0:
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, data.newConstant(1, 0), 0)
                return 1
            elif rvn.getOffset() == calc_mask(rvn.getSize()):
                data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL)
                return 1
        return 0


# =========================================================================
# RuleLessEqual2Zero
# =========================================================================

class RuleLessEqual2Zero(Rule):
    """Simplify INT_LESSEQUAL applied to extremal constants.

    0 <= V => true;  V <= 0 => V == 0;  ffff <= V => ffff == V;  V <= ffff => true.
    """

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "lessequal2zero")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleLessEqual2Zero(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LESSEQUAL)]

    def applyOp(self, op, data) -> int:
        lvn = op.getIn(0)
        rvn = op.getIn(1)
        if lvn.isConstant():
            if lvn.getOffset() == 0:
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, data.newConstant(1, 1), 0)
                return 1
            elif lvn.getOffset() == calc_mask(lvn.getSize()):
                data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL)
                return 1
        elif rvn.isConstant():
            if rvn.getOffset() == 0:
                data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL)
                return 1
            elif rvn.getOffset() == calc_mask(rvn.getSize()):
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, data.newConstant(1, 1), 0)
                return 1
        return 0


# =========================================================================
# RuleSLess2Zero
# =========================================================================

class RuleSLess2Zero(Rule):
    """Simplify INT_SLESS applied to 0 or -1.

    Handles SUBPIECE, NEGATE, AND with sign-bit mask, PIECE, and high-bit extraction forms.
    """

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "sless2zero")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleSLess2Zero(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SLESS)]

    @staticmethod
    def _getHiBit(feedOp):
        """Get the piece containing the sign-bit, or None."""
        opc = feedOp.code()
        if opc not in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            return None
        vn1 = feedOp.getIn(0)
        vn2 = feedOp.getIn(1)
        mask = calc_mask(vn1.getSize())
        mask = mask ^ (mask >> 1)  # Only high-bit set
        nzm1 = vn1.getNZMask()
        if nzm1 != mask and (nzm1 & mask) != 0:
            return None
        nzm2 = vn2.getNZMask()
        if nzm2 != mask and (nzm2 & mask) != 0:
            return None
        if nzm1 == mask:
            return vn1
        if nzm2 == mask:
            return vn2
        return None

    def applyOp(self, op, data) -> int:
        lvn = op.getIn(0)
        rvn = op.getIn(1)

        if lvn.isConstant():
            if not rvn.isWritten():
                return 0
            if lvn.getOffset() == calc_mask(lvn.getSize()):
                feedOp = rvn.getDef()
                feedOpCode = feedOp.code()
                hibit = self._getHiBit(feedOp)
                if hibit is not None:
                    if hibit.isConstant():
                        data.opSetInput(op, data.newConstant(hibit.getSize(), hibit.getOffset()), 1)
                    else:
                        data.opSetInput(op, hibit, 1)
                    data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL)
                    data.opSetInput(op, data.newConstant(hibit.getSize(), 0), 0)
                    return 1
                elif feedOpCode == OpCode.CPUI_SUBPIECE:
                    avn = feedOp.getIn(0)
                    if avn.isFree() or avn.getSize() > 8:
                        return 0
                    if rvn.getSize() + int(feedOp.getIn(1).getOffset()) == avn.getSize():
                        data.opSetInput(op, avn, 1)
                        data.opSetInput(op, data.newConstant(avn.getSize(), calc_mask(avn.getSize())), 0)
                        return 1
                elif feedOpCode == OpCode.CPUI_INT_NEGATE:
                    avn = feedOp.getIn(0)
                    if avn.isFree():
                        return 0
                    data.opSetInput(op, avn, 0)
                    data.opSetInput(op, data.newConstant(avn.getSize(), 0), 1)
                    return 1
                elif feedOpCode == OpCode.CPUI_INT_AND:
                    avn = feedOp.getIn(0)
                    if avn.isFree() or rvn.loneDescend() is None:
                        return 0
                    maskVn = feedOp.getIn(1)
                    if maskVn.isConstant():
                        mask = maskVn.getOffset()
                        mask >>= (8 * avn.getSize() - 1)
                        if (mask & 1) != 0:
                            data.opSetInput(op, avn, 1)
                            return 1
                elif feedOpCode == OpCode.CPUI_PIECE:
                    avn = feedOp.getIn(0)
                    if avn.isFree():
                        return 0
                    data.opSetInput(op, avn, 1)
                    data.opSetInput(op, data.newConstant(avn.getSize(), calc_mask(avn.getSize())), 0)
                    return 1
                elif feedOpCode == OpCode.CPUI_INT_LEFT:
                    coeff = feedOp.getIn(1)
                    if not coeff.isConstant() or coeff.getOffset() != lvn.getSize() * 8 - 1:
                        return 0
                    avn = feedOp.getIn(0)
                    if not avn.isWritten() or not avn.getDef().isBoolOutput():
                        return 0
                    data.opSetOpcode(op, OpCode.CPUI_BOOL_NEGATE)
                    data.opRemoveInput(op, 1)
                    data.opSetInput(op, avn, 0)
                    return 1
        elif rvn.isConstant():
            if not lvn.isWritten():
                return 0
            if rvn.getOffset() == 0:
                feedOp = lvn.getDef()
                feedOpCode = feedOp.code()
                hibit = self._getHiBit(feedOp)
                if hibit is not None:
                    if hibit.isConstant():
                        data.opSetInput(op, data.newConstant(hibit.getSize(), hibit.getOffset()), 0)
                    else:
                        data.opSetInput(op, hibit, 0)
                    data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL)
                    return 1
                elif feedOpCode == OpCode.CPUI_SUBPIECE:
                    avn = feedOp.getIn(0)
                    if avn.isFree() or avn.getSize() > 8:
                        return 0
                    if lvn.getSize() + int(feedOp.getIn(1).getOffset()) == avn.getSize():
                        data.opSetInput(op, avn, 0)
                        data.opSetInput(op, data.newConstant(avn.getSize(), 0), 1)
                        return 1
                elif feedOpCode == OpCode.CPUI_INT_NEGATE:
                    avn = feedOp.getIn(0)
                    if avn.isFree():
                        return 0
                    data.opSetInput(op, avn, 1)
                    data.opSetInput(op, data.newConstant(avn.getSize(), calc_mask(avn.getSize())), 0)
                    return 1
                elif feedOpCode == OpCode.CPUI_INT_AND:
                    avn = feedOp.getIn(0)
                    if avn.isFree() or lvn.loneDescend() is None:
                        return 0
                    maskVn = feedOp.getIn(1)
                    if maskVn.isConstant():
                        mask = maskVn.getOffset()
                        mask >>= (8 * avn.getSize() - 1)
                        if (mask & 1) != 0:
                            data.opSetInput(op, avn, 0)
                            return 1
                elif feedOpCode == OpCode.CPUI_PIECE:
                    avn = feedOp.getIn(0)
                    if avn.isFree():
                        return 0
                    data.opSetInput(op, avn, 0)
                    data.opSetInput(op, data.newConstant(avn.getSize(), 0), 1)
                    return 1
        return 0


# =========================================================================
# RuleEqual2Zero
# =========================================================================

class RuleEqual2Zero(Rule):
    """Simplify INT_EQUAL applied to 0: 0 == V + W*-1 => V == W  or  0 == V + c => V == -c."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "equal2zero")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleEqual2Zero(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        if vn.isConstant() and vn.getOffset() == 0:
            addvn = op.getIn(1)
        else:
            addvn = vn
            vn = op.getIn(1)
            if not vn.isConstant() or vn.getOffset() != 0:
                return 0
        for desc in addvn.getDescendants():
            if not desc.isBoolOutput():
                return 0
        addop = addvn.getDef()
        if addop is None:
            return 0
        if addop.code() != OpCode.CPUI_INT_ADD:
            return 0
        vn = addop.getIn(0)
        vn2 = addop.getIn(1)
        if vn2.isConstant():
            mask = calc_mask(vn2.getSize())
            negval = ((-vn2.getOffset()) & mask)
            unnegvn = data.newConstant(vn2.getSize(), negval)
            posvn = vn
        else:
            negvn = None
            if vn.isWritten() and vn.getDef().code() == OpCode.CPUI_INT_MULT:
                negvn = vn
                posvn = vn2
            elif vn2.isWritten() and vn2.getDef().code() == OpCode.CPUI_INT_MULT:
                negvn = vn2
                posvn = vn
            else:
                return 0
            if not negvn.getDef().getIn(1).isConstant():
                return 0
            unnegvn = negvn.getDef().getIn(0)
            multiplier = negvn.getDef().getIn(1).getOffset()
            if multiplier != calc_mask(unnegvn.getSize()):
                return 0
        if not posvn.isHeritageKnown():
            return 0
        if not unnegvn.isHeritageKnown():
            return 0
        data.opSetInput(op, posvn, 0)
        data.opSetInput(op, unnegvn, 1)
        return 1


# =========================================================================
# RuleEqual2Constant
# =========================================================================

class RuleEqual2Constant(Rule):
    """Simplify INT_EQUAL applied to arithmetic: V * -1 == c => V == -c; V + c == d => V == (d-c)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "equal2constant")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleEqual2Constant(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL)]

    def applyOp(self, op, data) -> int:
        cvn = op.getIn(1)
        if not cvn.isConstant():
            return 0
        lhs = op.getIn(0)
        if not lhs.isWritten():
            return 0
        leftop = lhs.getDef()
        opc = leftop.code()
        mask = calc_mask(cvn.getSize())
        if opc == OpCode.CPUI_INT_ADD:
            otherconst = leftop.getIn(1)
            if not otherconst.isConstant():
                return 0
            newconst = (cvn.getOffset() - otherconst.getOffset()) & mask
        elif opc == OpCode.CPUI_INT_MULT:
            otherconst = leftop.getIn(1)
            if not otherconst.isConstant():
                return 0
            if otherconst.getOffset() != calc_mask(otherconst.getSize()):
                return 0
            newconst = (-cvn.getOffset()) & mask
        elif opc == OpCode.CPUI_INT_NEGATE:
            newconst = (~cvn.getOffset()) & calc_mask(lhs.getSize())
        else:
            return 0
        a = leftop.getIn(0)
        if a.isFree():
            return 0
        for desc in lhs.getDescendants():
            if desc is op:
                continue
            if desc.code() not in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
                return 0
            if not desc.getIn(1).isConstant():
                return 0
        data.opSetInput(op, a, 0)
        data.opSetInput(op, data.newConstant(a.getSize(), newconst), 1)
        return 1


# =========================================================================
# RuleCondNegate
# =========================================================================

class RuleCondNegate(Rule):
    """Flip conditions to match structuring cues by inserting BOOL_NEGATE."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "condnegate")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleCondNegate(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_CBRANCH)]

    def applyOp(self, op, data) -> int:
        if not op.isBooleanFlip():
            return 0
        vn = op.getIn(1)
        newop = data.newOp(1, op.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_BOOL_NEGATE)
        outvn = data.newUniqueOut(1, newop)
        data.opSetInput(newop, vn, 0)
        data.opSetInput(op, outvn, 1)
        data.opInsertBefore(newop, op)
        data.opFlipCondition(op)
        return 1


# =========================================================================
# RuleBoolNegate
# =========================================================================

class RuleBoolNegate(Rule):
    """Apply identities involving BOOL_NEGATE: !!V => V; !(V==W) => V!=W; etc."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "boolnegate")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleBoolNegate(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_BOOL_NEGATE)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        if not vn.isWritten():
            return 0
        flip_op = vn.getDef()
        for desc in vn.getDescendants():
            if desc.code() != OpCode.CPUI_BOOL_NEGATE:
                return 0
        opc, flipyes = get_booleanflip(flip_op.code())
        if opc == OpCode.CPUI_MAX:
            return 0
        data.opSetOpcode(flip_op, opc)
        if flipyes:
            data.opSwapInput(flip_op, 0, 1)
        for desc in list(vn.getDescendants()):
            data.opSetOpcode(desc, OpCode.CPUI_COPY)
        return 1
