"""
Batch 1c rules: RuleXorSwap, RuleLzcountShiftBool, RuleOrCompare, RulePopcountBoolXor.
Corresponds to additional rules from ruleaction.hh / ruleaction.cc
"""

from __future__ import annotations

from typing import Optional, List, TYPE_CHECKING

from ghidra.core.opcodes import OpCode
from ghidra.core.address import (
    calc_mask, leastsigbit_set, mostsigbit_set, popcount,
)
from ghidra.transform.action import Rule, ActionGroupList

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# RuleXorSwap
# =========================================================================

class RuleXorSwap(Rule):
    """Simplify XOR swap pattern: (V ^ W) ^ V => W."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "xorswap")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleXorSwap(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_XOR)]

    def applyOp(self, op, data) -> int:
        for i in range(2):
            vn = op.getIn(i)
            if not vn.isWritten():
                continue
            op2 = vn.getDef()
            if op2.code() != OpCode.CPUI_INT_XOR:
                continue
            othervn = op.getIn(1 - i)
            vn0 = op2.getIn(0)
            vn1 = op2.getIn(1)
            if othervn is vn0 and not vn1.isFree():
                data.opRemoveInput(op, 1)
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opSetInput(op, vn1, 0)
                return 1
            elif othervn is vn1 and not vn0.isFree():
                data.opRemoveInput(op, 1)
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opSetInput(op, vn0, 0)
                return 1
        return 0


# =========================================================================
# RuleLzcountShiftBool
# =========================================================================

class RuleLzcountShiftBool(Rule):
    """Simplify lzcount equality checks: lzcount(X) >> c => X == 0 if X is 2^c bits wide."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "lzcountshiftbool")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleLzcountShiftBool(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_LZCOUNT)]

    def applyOp(self, op, data) -> int:
        outVn = op.getOut()
        max_return = 8 * op.getIn(0).getSize()
        if popcount(max_return) != 1:
            return 0
        for baseOp in list(outVn.getDescendants()):
            bopc = baseOp.code()
            if bopc != OpCode.CPUI_INT_RIGHT and bopc != OpCode.CPUI_INT_SRIGHT:
                continue
            vn1 = baseOp.getIn(1)
            if not vn1.isConstant():
                continue
            shift = vn1.getOffset()
            if (max_return >> shift) == 1:
                newOp = data.newOp(2, baseOp.getAddr())
                data.opSetOpcode(newOp, OpCode.CPUI_INT_EQUAL)
                b = data.newConstant(op.getIn(0).getSize(), 0)
                data.opSetInput(newOp, op.getIn(0), 0)
                data.opSetInput(newOp, b, 1)
                eqResVn = data.newUniqueOut(1, newOp)
                data.opInsertBefore(newOp, baseOp)
                data.opRemoveInput(baseOp, 1)
                if baseOp.getOut().getSize() == 1:
                    data.opSetOpcode(baseOp, OpCode.CPUI_COPY)
                else:
                    data.opSetOpcode(baseOp, OpCode.CPUI_INT_ZEXT)
                data.opSetInput(baseOp, eqResVn, 0)
                return 1
        return 0


# =========================================================================
# RuleOrCompare
# =========================================================================

class RuleOrCompare(Rule):
    """Simplify INT_OR in comparisons with 0.

    (V | W) == 0  =>  (V == 0) && (W == 0)
    (V | W) != 0  =>  (V != 0) || (W != 0)
    """

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "orcompare")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleOrCompare(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_OR)]

    def applyOp(self, op, data) -> int:
        outvn = op.getOut()
        hasCompares = False
        for compOp in outvn.getDescendants():
            opc = compOp.code()
            if opc != OpCode.CPUI_INT_EQUAL and opc != OpCode.CPUI_INT_NOTEQUAL:
                return 0
            if not compOp.getIn(1).constantMatch(0):
                return 0
            hasCompares = True
        if not hasCompares:
            return 0

        V = op.getIn(0)
        W = op.getIn(1)
        if V.isFree():
            return 0
        if W.isFree():
            return 0

        descList = list(outvn.getDescendants())
        for equalOp in descList:
            opc = equalOp.code()
            zero_V = data.newConstant(V.getSize(), 0)
            zero_W = data.newConstant(W.getSize(), 0)
            eq_V = data.newOp(2, equalOp.getAddr())
            data.opSetOpcode(eq_V, opc)
            data.opSetInput(eq_V, V, 0)
            data.opSetInput(eq_V, zero_V, 1)
            eq_W = data.newOp(2, equalOp.getAddr())
            data.opSetOpcode(eq_W, opc)
            data.opSetInput(eq_W, W, 0)
            data.opSetInput(eq_W, zero_W, 1)
            eq_V_out = data.newUniqueOut(1, eq_V)
            eq_W_out = data.newUniqueOut(1, eq_W)
            data.opInsertBefore(eq_V, equalOp)
            data.opInsertBefore(eq_W, equalOp)
            combineOpc = OpCode.CPUI_BOOL_AND if opc == OpCode.CPUI_INT_EQUAL else OpCode.CPUI_BOOL_OR
            data.opSetOpcode(equalOp, combineOpc)
            data.opSetInput(equalOp, eq_V_out, 0)
            data.opSetInput(equalOp, eq_W_out, 1)
        return 1


# =========================================================================
# RulePopcountBoolXor
# =========================================================================

class RulePopcountBoolXor(Rule):
    """Simplify popcount used for boolean XOR: popcount(b1 << p1 | b2 << p2) & 1 => b1 ^ b2."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "popcountboolxor")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RulePopcountBoolXor(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_POPCOUNT)]

    @staticmethod
    def _getBooleanResult(vn, bitPos):
        """Extract boolean Varnode producing bit at given position.

        Returns (Varnode, constRes) where Varnode is the boolean result or None,
        and constRes is 0 or 1 for constant, -1 if no boolean found.
        """
        mask = 1 << bitPos
        while True:
            if vn.isConstant():
                return None, (vn.getOffset() >> bitPos) & 1
            if not vn.isWritten():
                return None, -1
            if bitPos == 0 and vn.getSize() == 1 and vn.getNZMask() == mask:
                return vn, -1
            defop = vn.getDef()
            opc = defop.code()
            if opc == OpCode.CPUI_INT_AND:
                if not defop.getIn(1).isConstant():
                    return None, -1
                vn = defop.getIn(0)
            elif opc in (OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR):
                vn0 = defop.getIn(0)
                vn1 = defop.getIn(1)
                if (vn0.getNZMask() & mask) != 0:
                    if (vn1.getNZMask() & mask) != 0:
                        return None, -1
                    vn = vn0
                elif (vn1.getNZMask() & mask) != 0:
                    vn = vn1
                else:
                    return None, -1
            elif opc in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
                vn = defop.getIn(0)
                if bitPos >= vn.getSize() * 8:
                    return None, -1
            elif opc == OpCode.CPUI_SUBPIECE:
                sa = int(defop.getIn(1).getOffset()) * 8
                bitPos += sa
                mask <<= sa
                vn = defop.getIn(0)
            elif opc == OpCode.CPUI_PIECE:
                vn0 = defop.getIn(0)
                vn1 = defop.getIn(1)
                sa = vn1.getSize() * 8
                if bitPos >= sa:
                    vn = vn0
                    bitPos -= sa
                    mask >>= sa
                else:
                    vn = vn1
            elif opc == OpCode.CPUI_INT_LEFT:
                vn1 = defop.getIn(1)
                if not vn1.isConstant():
                    return None, -1
                sa = int(vn1.getOffset())
                if sa > bitPos:
                    return None, -1
                bitPos -= sa
                mask >>= sa
                vn = defop.getIn(0)
            elif opc in (OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT):
                vn1 = defop.getIn(1)
                if not vn1.isConstant():
                    return None, -1
                sa = int(vn1.getOffset())
                vn = defop.getIn(0)
                bitPos += sa
                if bitPos >= vn.getSize() * 8:
                    return None, -1
                mask <<= sa
            else:
                return None, -1

    def applyOp(self, op, data) -> int:
        outVn = op.getOut()
        for baseOp in outVn.getDescendants():
            if baseOp.code() != OpCode.CPUI_INT_AND:
                continue
            tmpVn = baseOp.getIn(1)
            if not tmpVn.isConstant():
                continue
            if tmpVn.getOffset() != 1:
                continue
            if tmpVn.getSize() != 1:
                continue
            inVn = op.getIn(0)
            if not inVn.isWritten():
                return 0
            count = popcount(inVn.getNZMask())
            if count == 1:
                leastPos = leastsigbit_set(inVn.getNZMask())
                b1, constRes = self._getBooleanResult(inVn, leastPos)
                if b1 is None:
                    continue
                data.opSetOpcode(baseOp, OpCode.CPUI_COPY)
                data.opRemoveInput(baseOp, 1)
                data.opSetInput(baseOp, b1, 0)
                return 1
            if count == 2:
                pos0 = leastsigbit_set(inVn.getNZMask())
                pos1 = mostsigbit_set(inVn.getNZMask())
                b1, constRes0 = self._getBooleanResult(inVn, pos0)
                if b1 is None and constRes0 != 1:
                    continue
                b2, constRes1 = self._getBooleanResult(inVn, pos1)
                if b2 is None and constRes1 != 1:
                    continue
                if b1 is None and b2 is None:
                    continue
                if b1 is None:
                    b1 = data.newConstant(1, 1)
                if b2 is None:
                    b2 = data.newConstant(1, 1)
                data.opSetOpcode(baseOp, OpCode.CPUI_INT_XOR)
                data.opSetInput(baseOp, b1, 0)
                data.opSetInput(baseOp, b2, 1)
                return 1
        return 0
