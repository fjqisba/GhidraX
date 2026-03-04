"""
Batch 1h: Rules unlocked by BooleanMatch infrastructure.
RuleBooleanUndistribute, RuleBooleanDedup.
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING
from ghidra.core.opcodes import OpCode
from ghidra.core.expression import BooleanMatch
from ghidra.transform.action import Rule, ActionGroupList
if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


class RuleBooleanUndistribute(Rule):
    """Undo distributed BOOL_AND through INT_NOTEQUAL.

    A && B != A && C  =>  A && (B != C)
    """
    def __init__(self, g): super().__init__(g, 0, "booleanundistribute")
    def clone(self, gl):
        return RuleBooleanUndistribute(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL)]

    @staticmethod
    def _isMatch(leftVn, rightVn, rightFlip):
        val = BooleanMatch.evaluate(leftVn, rightVn, 1)
        if val == BooleanMatch.same:
            return True, rightFlip
        if val == BooleanMatch.complementary:
            return True, not rightFlip
        return False, rightFlip

    def applyOp(self, op, data):
        vn0 = op.getIn(0)
        if not vn0.isWritten(): return 0
        vn1 = op.getIn(1)
        if not vn1.isWritten(): return 0
        op0 = vn0.getDef(); opc0 = op0.code()
        if opc0 not in (OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR): return 0
        op1 = vn1.getDef(); opc1 = op1.code()
        if opc1 not in (OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR): return 0
        ins = [op0.getIn(0), op0.getIn(1), op1.getIn(0), op1.getIn(1)]
        if any(v.isFree() for v in ins): return 0
        isflipped = [False, False, False, False]
        centralEqual = (op.code() == OpCode.CPUI_INT_EQUAL)
        if opc0 == OpCode.CPUI_BOOL_OR:
            isflipped[0] = not isflipped[0]
            isflipped[1] = not isflipped[1]
            centralEqual = not centralEqual
        if opc1 == OpCode.CPUI_BOOL_OR:
            isflipped[2] = not isflipped[2]
            isflipped[3] = not isflipped[3]
            centralEqual = not centralEqual
        leftSlot = rightSlot = -1
        for li, ri in [(0,2),(0,3),(1,2),(1,3)]:
            matched, isflipped[ri] = self._isMatch(ins[li], ins[ri], isflipped[ri])
            if matched:
                leftSlot = li; rightSlot = ri; break
        if leftSlot == -1: return 0
        if isflipped[leftSlot] != isflipped[rightSlot]: return 0
        if centralEqual:
            combineOpc = OpCode.CPUI_BOOL_OR
            isflipped[leftSlot] = not isflipped[leftSlot]
        else:
            combineOpc = OpCode.CPUI_BOOL_AND
        finalA = ins[leftSlot]
        if isflipped[leftSlot]:
            # Need to negate finalA - simplified: create BOOL_NEGATE
            negOp = data.newOp(1, op.getAddr())
            data.opSetOpcode(negOp, OpCode.CPUI_BOOL_NEGATE)
            finalA = data.newUniqueOut(1, negOp)
            data.opSetInput(negOp, ins[leftSlot], 0)
            data.opInsertBefore(negOp, op)
        if isflipped[1 - leftSlot]:
            centralEqual = not centralEqual
        if isflipped[5 - rightSlot]:
            centralEqual = not centralEqual
        finalB = ins[1 - leftSlot]
        finalC = ins[5 - rightSlot]
        eqOp = data.newOp(2, op.getAddr())
        eqOpc = OpCode.CPUI_INT_EQUAL if centralEqual else OpCode.CPUI_INT_NOTEQUAL
        data.opSetOpcode(eqOp, eqOpc)
        tmp1 = data.newUniqueOut(1, eqOp)
        data.opSetInput(eqOp, finalB, 0)
        data.opSetInput(eqOp, finalC, 1)
        data.opInsertBefore(eqOp, op)
        data.opSetOpcode(op, combineOpc)
        data.opSetInput(op, tmp1, 1)
        data.opSetInput(op, finalA, 0)
        return 1


class RuleBooleanDedup(Rule):
    """Remove duplicate clauses in boolean expressions.

    (A && B) || (A && C) => A && (B || C)
    """
    def __init__(self, g): super().__init__(g, 0, "booleandedup")
    def clone(self, gl):
        return RuleBooleanDedup(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [int(OpCode.CPUI_BOOL_AND), int(OpCode.CPUI_BOOL_OR)]

    @staticmethod
    def _isMatch(leftVn, rightVn):
        val = BooleanMatch.evaluate(leftVn, rightVn, 1)
        if val == BooleanMatch.same:
            return True, False
        if val == BooleanMatch.complementary:
            return True, True
        return False, False

    def applyOp(self, op, data):
        vn0 = op.getIn(0)
        if not vn0.isWritten(): return 0
        vn1 = op.getIn(1)
        if not vn1.isWritten(): return 0
        op0 = vn0.getDef(); opc0 = op0.code()
        if opc0 not in (OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR): return 0
        op1 = vn1.getDef(); opc1 = op1.code()
        if opc1 not in (OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR): return 0
        ins = [op0.getIn(0), op0.getIn(1), op1.getIn(0), op1.getIn(1)]
        if any(v.isFree() for v in ins): return 0

        leftA = rightA = leftO = rightO = None
        isflipped = False
        found = False
        for li, ri in [(0,2),(0,3),(1,2),(1,3)]:
            matched, isflipped = self._isMatch(ins[li], ins[ri])
            if matched:
                leftA = ins[li]; rightA = ins[ri]
                leftO = ins[1 - li]; rightO = ins[5 - ri]
                found = True; break
        if not found: return 0

        centralOpc = op.code()
        if isflipped:
            if centralOpc == OpCode.CPUI_BOOL_AND and opc0 == OpCode.CPUI_BOOL_AND and opc1 == OpCode.CPUI_BOOL_AND:
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, data.newConstant(1, 0), 0)
                return 1
            if centralOpc == OpCode.CPUI_BOOL_OR and opc0 == OpCode.CPUI_BOOL_OR and opc1 == OpCode.CPUI_BOOL_OR:
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, data.newConstant(1, 1), 0)
                return 1
            if centralOpc == OpCode.CPUI_BOOL_OR and opc0 != opc1:
                finalA = leftA if opc0 == OpCode.CPUI_BOOL_OR else rightA
                finalOpc = OpCode.CPUI_BOOL_OR
                bcOpc = OpCode.CPUI_BOOL_OR
            else:
                return 0
        else:
            if centralOpc == opc0 and centralOpc == opc1:
                finalA = leftA; finalOpc = centralOpc; bcOpc = centralOpc
            elif opc0 == opc1 and centralOpc != opc0:
                finalA = leftA; finalOpc = opc0; bcOpc = centralOpc
            else:
                return 0
        bcOp = data.newOp(2, op.getAddr())
        tmp = data.newUniqueOut(1, bcOp)
        data.opSetOpcode(bcOp, bcOpc)
        data.opSetInput(bcOp, leftO, 0)
        data.opSetInput(bcOp, rightO, 1)
        data.opInsertBefore(bcOp, op)
        data.opSetOpcode(op, finalOpc)
        data.opSetInput(op, finalA, 0)
        data.opSetInput(op, tmp, 1)
        return 1
