"""
Corresponds to: expression.hh / expression.cc
functionalEquality, BooleanMatch, and related utilities.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
from ghidra.core.opcodes import OpCode, get_booleanflip
from ghidra.core.address import signbit_negative
if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode


class BooleanMatch:
    same = 1
    complementary = 2
    uncorrelated = 3

    @staticmethod
    def _varnodeSame(a, b):
        if a is b: return True
        if a.isConstant() and b.isConstant():
            return a.getOffset() == b.getOffset()
        return False

    @staticmethod
    def _sameOpComplement(op1, op2):
        opc = op1.code()
        if opc not in (OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_LESS):
            return False
        cs = 1 if op1.getIn(1).isConstant() else 0
        if not op1.getIn(cs).isConstant(): return False
        if not op2.getIn(1-cs).isConstant(): return False
        if not BooleanMatch._varnodeSame(op1.getIn(1-cs), op2.getIn(cs)):
            return False
        v1 = op1.getIn(cs).getOffset()
        v2 = op2.getIn(1-cs).getOffset()
        if cs != 0: v1, v2 = v2, v1
        if v1 + 1 != v2: return False
        if v2 == 0 and opc == OpCode.CPUI_INT_LESS: return False
        if opc == OpCode.CPUI_INT_SLESS:
            sz = op1.getIn(cs).getSize()
            if signbit_negative(v2, sz) and not signbit_negative(v1, sz):
                return False
        return True

    @staticmethod
    def evaluate(vn1, vn2, depth):
        if vn1 is vn2: return BooleanMatch.same
        if vn1.isWritten():
            op1 = vn1.getDef(); opc1 = op1.code()
            if opc1 == OpCode.CPUI_BOOL_NEGATE:
                r = BooleanMatch.evaluate(op1.getIn(0), vn2, depth)
                return {BooleanMatch.same: BooleanMatch.complementary,
                        BooleanMatch.complementary: BooleanMatch.same}.get(r, r)
        else:
            op1 = None; opc1 = OpCode.CPUI_MAX
        if vn2.isWritten():
            op2 = vn2.getDef(); opc2 = op2.code()
            if opc2 == OpCode.CPUI_BOOL_NEGATE:
                r = BooleanMatch.evaluate(vn1, op2.getIn(0), depth)
                return {BooleanMatch.same: BooleanMatch.complementary,
                        BooleanMatch.complementary: BooleanMatch.same}.get(r, r)
        else:
            return BooleanMatch.uncorrelated
        if op1 is None: return BooleanMatch.uncorrelated
        if not op1.isBoolOutput() or not op2.isBoolOutput():
            return BooleanMatch.uncorrelated
        bools = {OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_XOR}
        if depth != 0 and opc1 in bools and opc2 in bools:
            ok = (opc1 == opc2 or {opc1,opc2} == {OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR})
            if ok:
                p1 = BooleanMatch.evaluate(op1.getIn(0), op2.getIn(0), depth-1)
                if p1 == BooleanMatch.uncorrelated:
                    p1 = BooleanMatch.evaluate(op1.getIn(0), op2.getIn(1), depth-1)
                    if p1 == BooleanMatch.uncorrelated: return BooleanMatch.uncorrelated
                    p2 = BooleanMatch.evaluate(op1.getIn(1), op2.getIn(0), depth-1)
                else:
                    p2 = BooleanMatch.evaluate(op1.getIn(1), op2.getIn(1), depth-1)
                if p2 == BooleanMatch.uncorrelated: return BooleanMatch.uncorrelated
                if opc1 == opc2:
                    if p1 == BooleanMatch.same and p2 == BooleanMatch.same:
                        return BooleanMatch.same
                    if opc1 == OpCode.CPUI_BOOL_XOR:
                        if p1 == BooleanMatch.complementary and p2 == BooleanMatch.complementary:
                            return BooleanMatch.same
                        return BooleanMatch.complementary
                else:
                    if p1 == BooleanMatch.complementary and p2 == BooleanMatch.complementary:
                        return BooleanMatch.complementary
        else:
            if opc1 == opc2:
                ok = all(BooleanMatch._varnodeSame(op1.getIn(i), op2.getIn(i))
                         for i in range(op1.numInput()))
                if ok: return BooleanMatch.same
                if BooleanMatch._sameOpComplement(op1, op2):
                    return BooleanMatch.complementary
                return BooleanMatch.uncorrelated
            comp, reorder = get_booleanflip(opc2)
            if opc1 != comp: return BooleanMatch.uncorrelated
            s2 = 1 if reorder else 0
            if not BooleanMatch._varnodeSame(op1.getIn(0), op2.getIn(s2)):
                return BooleanMatch.uncorrelated
            if not BooleanMatch._varnodeSame(op1.getIn(1), op2.getIn(1-s2)):
                return BooleanMatch.uncorrelated
            return BooleanMatch.complementary
        return BooleanMatch.uncorrelated


def _feq0(vn1, vn2):
    if vn1 is vn2: return 0
    if vn1.getSize() != vn2.getSize(): return -1
    if vn1.isConstant():
        return 0 if (vn2.isConstant() and vn1.getOffset() == vn2.getOffset()) else -1
    if vn1.isFree() or vn2.isFree(): return -1
    return 1


def functionalEquality(vn1, vn2) -> bool:
    """Determine if two Varnodes hold the same value."""
    t = _feq0(vn1, vn2)
    if t != 1: return t == 0
    if not vn1.isWritten() or not vn2.isWritten(): return False
    op1 = vn1.getDef(); op2 = vn2.getDef()
    if op1.code() != op2.code(): return False
    n = op1.numInput()
    if n != op2.numInput(): return False
    if op1.isMarker() or op2.isCall(): return False
    if op1.code() == OpCode.CPUI_LOAD:
        if op1.getAddr() != op2.getAddr(): return False
    if n >= 3: n = 2
    for i in range(n):
        if _feq0(op1.getIn(i), op2.getIn(i)) != 0:
            if n == 2 and hasattr(op1, 'isCommutative') and op1.isCommutative():
                if _feq0(op1.getIn(0), op2.getIn(1)) == 0 and _feq0(op1.getIn(1), op2.getIn(0)) == 0:
                    return True
            return False
    return True
