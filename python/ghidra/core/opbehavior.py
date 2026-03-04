"""
Corresponds to: opbehavior.hh / opbehavior.cc

Classes for describing the behavior of individual p-code operations.
Each OpBehavior subclass implements evaluateUnary/evaluateBinary for
one specific opcode.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List

from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, signbit_negative, popcount, count_leading_zeros
from ghidra.core.types import to_signed, to_unsigned

if TYPE_CHECKING:
    from ghidra.core.translate import Translate


class EvaluationError(LowlevelError):
    """Exception thrown when emulation evaluation of an operator fails."""
    pass


# =========================================================================
# OpBehavior base
# =========================================================================

class OpBehavior:
    """Base class encapsulating the action/behavior of specific pcode opcodes."""

    def __init__(self, opc: OpCode, isun: bool, isspec: bool = False) -> None:
        self._opcode: OpCode = opc
        self._isunary: bool = isun
        self._isspecial: bool = isspec

    def getOpcode(self) -> OpCode:
        return self._opcode

    def isSpecial(self) -> bool:
        return self._isspecial

    def isUnary(self) -> bool:
        return self._isunary

    def evaluateUnary(self, sizeout: int, sizein: int, in1: int) -> int:
        raise EvaluationError(f"Unary evaluation not defined for {self._opcode.name}")

    def evaluateBinary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        raise EvaluationError(f"Binary evaluation not defined for {self._opcode.name}")

    def evaluateTernary(self, sizeout: int, sizein: int, in1: int, in2: int, in3: int) -> int:
        raise EvaluationError(f"Ternary evaluation not defined for {self._opcode.name}")

    def recoverInputBinary(self, slot: int, sizeout: int, out: int, sizein: int, inp: int) -> int:
        raise EvaluationError(f"Cannot recover input for {self._opcode.name}")

    def recoverInputUnary(self, sizeout: int, out: int, sizein: int) -> int:
        raise EvaluationError(f"Cannot recover input for {self._opcode.name}")

    @staticmethod
    def registerInstructions(trans: Optional[Translate] = None) -> List[OpBehavior]:
        """Build all pcode behaviors, returning a list indexed by OpCode value."""
        inst: List[Optional[OpBehavior]] = [None] * OpCode.CPUI_MAX
        inst[OpCode.CPUI_COPY] = OpBehaviorCopy()
        inst[OpCode.CPUI_LOAD] = OpBehavior(OpCode.CPUI_LOAD, False, True)
        inst[OpCode.CPUI_STORE] = OpBehavior(OpCode.CPUI_STORE, False, True)
        inst[OpCode.CPUI_BRANCH] = OpBehavior(OpCode.CPUI_BRANCH, False, True)
        inst[OpCode.CPUI_CBRANCH] = OpBehavior(OpCode.CPUI_CBRANCH, False, True)
        inst[OpCode.CPUI_BRANCHIND] = OpBehavior(OpCode.CPUI_BRANCHIND, False, True)
        inst[OpCode.CPUI_CALL] = OpBehavior(OpCode.CPUI_CALL, False, True)
        inst[OpCode.CPUI_CALLIND] = OpBehavior(OpCode.CPUI_CALLIND, False, True)
        inst[OpCode.CPUI_CALLOTHER] = OpBehavior(OpCode.CPUI_CALLOTHER, False, True)
        inst[OpCode.CPUI_RETURN] = OpBehavior(OpCode.CPUI_RETURN, False, True)
        inst[OpCode.CPUI_INT_EQUAL] = OpBehaviorEqual()
        inst[OpCode.CPUI_INT_NOTEQUAL] = OpBehaviorNotEqual()
        inst[OpCode.CPUI_INT_SLESS] = OpBehaviorIntSless()
        inst[OpCode.CPUI_INT_SLESSEQUAL] = OpBehaviorIntSlessEqual()
        inst[OpCode.CPUI_INT_LESS] = OpBehaviorIntLess()
        inst[OpCode.CPUI_INT_LESSEQUAL] = OpBehaviorIntLessEqual()
        inst[OpCode.CPUI_INT_ZEXT] = OpBehaviorIntZext()
        inst[OpCode.CPUI_INT_SEXT] = OpBehaviorIntSext()
        inst[OpCode.CPUI_INT_ADD] = OpBehaviorIntAdd()
        inst[OpCode.CPUI_INT_SUB] = OpBehaviorIntSub()
        inst[OpCode.CPUI_INT_CARRY] = OpBehaviorIntCarry()
        inst[OpCode.CPUI_INT_SCARRY] = OpBehaviorIntScarry()
        inst[OpCode.CPUI_INT_SBORROW] = OpBehaviorIntSborrow()
        inst[OpCode.CPUI_INT_2COMP] = OpBehaviorInt2Comp()
        inst[OpCode.CPUI_INT_NEGATE] = OpBehaviorIntNegate()
        inst[OpCode.CPUI_INT_XOR] = OpBehaviorIntXor()
        inst[OpCode.CPUI_INT_AND] = OpBehaviorIntAnd()
        inst[OpCode.CPUI_INT_OR] = OpBehaviorIntOr()
        inst[OpCode.CPUI_INT_LEFT] = OpBehaviorIntLeft()
        inst[OpCode.CPUI_INT_RIGHT] = OpBehaviorIntRight()
        inst[OpCode.CPUI_INT_SRIGHT] = OpBehaviorIntSright()
        inst[OpCode.CPUI_INT_MULT] = OpBehaviorIntMult()
        inst[OpCode.CPUI_INT_DIV] = OpBehaviorIntDiv()
        inst[OpCode.CPUI_INT_SDIV] = OpBehaviorIntSdiv()
        inst[OpCode.CPUI_INT_REM] = OpBehaviorIntRem()
        inst[OpCode.CPUI_INT_SREM] = OpBehaviorIntSrem()
        inst[OpCode.CPUI_BOOL_NEGATE] = OpBehaviorBoolNegate()
        inst[OpCode.CPUI_BOOL_XOR] = OpBehaviorBoolXor()
        inst[OpCode.CPUI_BOOL_AND] = OpBehaviorBoolAnd()
        inst[OpCode.CPUI_BOOL_OR] = OpBehaviorBoolOr()
        inst[OpCode.CPUI_FLOAT_EQUAL] = OpBehaviorFloatEqual(trans)
        inst[OpCode.CPUI_FLOAT_NOTEQUAL] = OpBehaviorFloatNotEqual(trans)
        inst[OpCode.CPUI_FLOAT_LESS] = OpBehaviorFloatLess(trans)
        inst[OpCode.CPUI_FLOAT_LESSEQUAL] = OpBehaviorFloatLessEqual(trans)
        inst[OpCode.CPUI_FLOAT_NAN] = OpBehaviorFloatNan(trans)
        inst[OpCode.CPUI_FLOAT_ADD] = OpBehaviorFloatAdd(trans)
        inst[OpCode.CPUI_FLOAT_DIV] = OpBehaviorFloatDiv(trans)
        inst[OpCode.CPUI_FLOAT_MULT] = OpBehaviorFloatMult(trans)
        inst[OpCode.CPUI_FLOAT_SUB] = OpBehaviorFloatSub(trans)
        inst[OpCode.CPUI_FLOAT_NEG] = OpBehaviorFloatNeg(trans)
        inst[OpCode.CPUI_FLOAT_ABS] = OpBehaviorFloatAbs(trans)
        inst[OpCode.CPUI_FLOAT_SQRT] = OpBehaviorFloatSqrt(trans)
        inst[OpCode.CPUI_FLOAT_INT2FLOAT] = OpBehaviorFloatInt2Float(trans)
        inst[OpCode.CPUI_FLOAT_FLOAT2FLOAT] = OpBehaviorFloatFloat2Float(trans)
        inst[OpCode.CPUI_FLOAT_TRUNC] = OpBehaviorFloatTrunc(trans)
        inst[OpCode.CPUI_FLOAT_CEIL] = OpBehaviorFloatCeil(trans)
        inst[OpCode.CPUI_FLOAT_FLOOR] = OpBehaviorFloatFloor(trans)
        inst[OpCode.CPUI_FLOAT_ROUND] = OpBehaviorFloatRound(trans)
        inst[OpCode.CPUI_MULTIEQUAL] = OpBehavior(OpCode.CPUI_MULTIEQUAL, False, True)
        inst[OpCode.CPUI_INDIRECT] = OpBehavior(OpCode.CPUI_INDIRECT, False, True)
        inst[OpCode.CPUI_PIECE] = OpBehaviorPiece()
        inst[OpCode.CPUI_SUBPIECE] = OpBehaviorSubpiece()
        inst[OpCode.CPUI_CAST] = OpBehavior(OpCode.CPUI_CAST, True, True)
        inst[OpCode.CPUI_PTRADD] = OpBehaviorPtradd()
        inst[OpCode.CPUI_PTRSUB] = OpBehaviorPtrsub()
        inst[OpCode.CPUI_SEGMENTOP] = OpBehavior(OpCode.CPUI_SEGMENTOP, False, True)
        inst[OpCode.CPUI_CPOOLREF] = OpBehavior(OpCode.CPUI_CPOOLREF, False, True)
        inst[OpCode.CPUI_NEW] = OpBehavior(OpCode.CPUI_NEW, False, True)
        inst[OpCode.CPUI_INSERT] = OpBehavior(OpCode.CPUI_INSERT, False, True)
        inst[OpCode.CPUI_EXTRACT] = OpBehavior(OpCode.CPUI_EXTRACT, False, True)
        inst[OpCode.CPUI_POPCOUNT] = OpBehaviorPopcount()
        inst[OpCode.CPUI_LZCOUNT] = OpBehaviorLzcount()
        return inst


# =========================================================================
# Concrete OpBehavior subclasses (integer operations)
# =========================================================================

class OpBehaviorCopy(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_COPY, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return in1 & calc_mask(sizeout)

    def recoverInputUnary(self, sizeout, out, sizein):
        return out & calc_mask(sizein)


class OpBehaviorEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_EQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if (in1 & calc_mask(sizein)) == (in2 & calc_mask(sizein)) else 0


class OpBehaviorNotEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_NOTEQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if (in1 & calc_mask(sizein)) != (in2 & calc_mask(sizein)) else 0


class OpBehaviorIntSless(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SLESS, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if to_signed(in1, sizein) < to_signed(in2, sizein) else 0


class OpBehaviorIntSlessEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SLESSEQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if to_signed(in1, sizein) <= to_signed(in2, sizein) else 0


class OpBehaviorIntLess(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_LESS, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizein)
        return 1 if (in1 & mask) < (in2 & mask) else 0


class OpBehaviorIntLessEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_LESSEQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizein)
        return 1 if (in1 & mask) <= (in2 & mask) else 0


class OpBehaviorIntZext(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_ZEXT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return in1 & calc_mask(sizein)

    def recoverInputUnary(self, sizeout, out, sizein):
        return out & calc_mask(sizein)


class OpBehaviorIntSext(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SEXT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        mask_in = calc_mask(sizein)
        in1 &= mask_in
        if signbit_negative(in1, sizein):
            mask_out = calc_mask(sizeout)
            in1 |= (mask_out ^ mask_in)
        return in1 & calc_mask(sizeout)

    def recoverInputUnary(self, sizeout, out, sizein):
        return out & calc_mask(sizein)


class OpBehaviorIntAdd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_ADD, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 + in2) & calc_mask(sizeout)

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        return (out - inp) & calc_mask(sizeout)


class OpBehaviorIntSub(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SUB, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 - in2) & calc_mask(sizeout)

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        if slot == 0:
            return (out + inp) & calc_mask(sizeout)
        return (inp - out) & calc_mask(sizeout)


class OpBehaviorIntCarry(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_CARRY, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizein)
        res = (in1 & mask) + (in2 & mask)
        return 1 if res > mask else 0


class OpBehaviorIntScarry(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SCARRY, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        s1 = to_signed(in1, sizein)
        s2 = to_signed(in2, sizein)
        res = s1 + s2
        bits = sizein * 8
        smin = -(1 << (bits - 1))
        smax = (1 << (bits - 1)) - 1
        return 1 if (res < smin or res > smax) else 0


class OpBehaviorIntSborrow(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SBORROW, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        s1 = to_signed(in1, sizein)
        s2 = to_signed(in2, sizein)
        res = s1 - s2
        bits = sizein * 8
        smin = -(1 << (bits - 1))
        smax = (1 << (bits - 1)) - 1
        return 1 if (res < smin or res > smax) else 0


class OpBehaviorInt2Comp(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_2COMP, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        mask = calc_mask(sizeout)
        return ((~in1) + 1) & mask

    def recoverInputUnary(self, sizeout, out, sizein):
        mask = calc_mask(sizein)
        return ((~out) + 1) & mask


class OpBehaviorIntNegate(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_NEGATE, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return (~in1) & calc_mask(sizeout)

    def recoverInputUnary(self, sizeout, out, sizein):
        return (~out) & calc_mask(sizein)


class OpBehaviorIntXor(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_XOR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 ^ in2) & calc_mask(sizeout)


class OpBehaviorIntAnd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_AND, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 & in2) & calc_mask(sizeout)


class OpBehaviorIntOr(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_OR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 | in2) & calc_mask(sizeout)


class OpBehaviorIntLeft(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_LEFT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizeout)
        sa = int(in2)
        if sa >= sizeout * 8:
            return 0
        return (in1 << sa) & mask

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        if slot != 0:
            raise EvaluationError("Cannot recover shift amount")
        sa = int(inp)
        if sa >= sizeout * 8:
            return 0
        return (out >> sa) & calc_mask(sizeout)


class OpBehaviorIntRight(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_RIGHT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizein)
        sa = int(in2)
        if sa >= sizein * 8:
            return 0
        return ((in1 & mask) >> sa) & calc_mask(sizeout)

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        if slot != 0:
            raise EvaluationError("Cannot recover shift amount")
        sa = int(inp)
        if sa >= sizeout * 8:
            return 0
        return (out << sa) & calc_mask(sizeout)


class OpBehaviorIntSright(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SRIGHT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        sa = int(in2)
        bits = sizein * 8
        mask = calc_mask(sizein)
        in1 &= mask
        if sa >= bits:
            return mask if signbit_negative(in1, sizein) else 0
        sval = to_signed(in1, sizein)
        return (sval >> sa) & calc_mask(sizeout)

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        if slot != 0:
            raise EvaluationError("Cannot recover shift amount")
        sa = int(inp)
        if sa >= sizeout * 8:
            return 0
        return (out << sa) & calc_mask(sizeout)


class OpBehaviorIntMult(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_MULT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 * in2) & calc_mask(sizeout)


class OpBehaviorIntDiv(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_DIV, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizein)
        in2 &= mask
        if in2 == 0:
            raise EvaluationError("Division by zero")
        return ((in1 & mask) // (in2)) & calc_mask(sizeout)


class OpBehaviorIntSdiv(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SDIV, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        s2 = to_signed(in2, sizein)
        if s2 == 0:
            raise EvaluationError("Division by zero")
        s1 = to_signed(in1, sizein)
        # Python integer division truncates towards negative infinity; C++ truncates towards zero
        import math
        result = int(math.trunc(s1 / s2))
        return to_unsigned(result, sizeout)


class OpBehaviorIntRem(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_REM, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizein)
        in2 &= mask
        if in2 == 0:
            raise EvaluationError("Remainder by zero")
        return ((in1 & mask) % in2) & calc_mask(sizeout)


class OpBehaviorIntSrem(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SREM, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        s2 = to_signed(in2, sizein)
        if s2 == 0:
            raise EvaluationError("Remainder by zero")
        s1 = to_signed(in1, sizein)
        import math
        result = s1 - int(math.trunc(s1 / s2)) * s2
        return to_unsigned(result, sizeout)


# =========================================================================
# Boolean operations
# =========================================================================

class OpBehaviorBoolNegate(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_NEGATE, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return 1 if (in1 & 1) == 0 else 0


class OpBehaviorBoolXor(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_XOR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 ^ in2) & 1


class OpBehaviorBoolAnd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_AND, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 & in2) & 1


class OpBehaviorBoolOr(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_OR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 | in2) & 1


# =========================================================================
# Floating-point operations (delegate to FloatFormat)
# =========================================================================

class _FloatOpBase(OpBehavior):
    """Helper base for float operations that need a Translate reference."""

    def __init__(self, opc: OpCode, isun: bool, trans: Optional[Translate]) -> None:
        super().__init__(opc, isun)
        self._translate: Optional[Translate] = trans

    def _getFormat(self, size: int):
        if self._translate is None:
            from ghidra.core.float_format import FloatFormat
            return FloatFormat(size)
        return self._translate.getFloatFormat(size)


class OpBehaviorFloatEqual(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_EQUAL, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opEqual(in1, in2)


class OpBehaviorFloatNotEqual(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_NOTEQUAL, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opNotEqual(in1, in2)


class OpBehaviorFloatLess(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_LESS, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opLess(in1, in2)


class OpBehaviorFloatLessEqual(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_LESSEQUAL, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opLessEqual(in1, in2)


class OpBehaviorFloatNan(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_NAN, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opNan(in1)


class OpBehaviorFloatAdd(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_ADD, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opAdd(in1, in2)


class OpBehaviorFloatDiv(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_DIV, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opDiv(in1, in2)


class OpBehaviorFloatMult(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_MULT, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opMult(in1, in2)


class OpBehaviorFloatSub(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_SUB, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        fmt = self._getFormat(sizein)
        return fmt.opSub(in1, in2)


class OpBehaviorFloatNeg(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_NEG, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opNeg(in1)


class OpBehaviorFloatAbs(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_ABS, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opAbs(in1)


class OpBehaviorFloatSqrt(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_SQRT, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opSqrt(in1)


class OpBehaviorFloatInt2Float(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_INT2FLOAT, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizeout)
        return fmt.opInt2Float(in1, sizein)


class OpBehaviorFloatFloat2Float(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_FLOAT2FLOAT, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt_in = self._getFormat(sizein)
        fmt_out = self._getFormat(sizeout)
        return fmt_in.opFloat2Float(in1, fmt_out)


class OpBehaviorFloatTrunc(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_TRUNC, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opTrunc(in1, sizeout)


class OpBehaviorFloatCeil(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_CEIL, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opCeil(in1)


class OpBehaviorFloatFloor(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_FLOOR, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opFloor(in1)


class OpBehaviorFloatRound(_FloatOpBase):
    def __init__(self, trans=None):
        super().__init__(OpCode.CPUI_FLOAT_ROUND, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        return fmt.opRound(in1)


# =========================================================================
# Composite / special operations
# =========================================================================

class OpBehaviorPiece(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_PIECE, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        # in1 = most significant, in2 = least significant
        # sizein is the size of in2 (each input is sizein bytes)
        return ((in1 << (sizein * 8)) | in2) & calc_mask(sizeout)


class OpBehaviorSubpiece(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_SUBPIECE, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        # in2 is the byte offset to truncate from
        val = in1 >> (int(in2) * 8)
        return val & calc_mask(sizeout)


class OpBehaviorPtradd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_PTRADD, False)

    def evaluateTernary(self, sizeout, sizein, in1, in2, in3):
        return (in1 + in2 * in3) & calc_mask(sizeout)


class OpBehaviorPtrsub(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_PTRSUB, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 + in2) & calc_mask(sizeout)


class OpBehaviorPopcount(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_POPCOUNT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return popcount(in1 & calc_mask(sizein))


class OpBehaviorLzcount(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_LZCOUNT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        mask = calc_mask(sizein)
        in1 &= mask
        if in1 == 0:
            return sizein * 8
        # Count leading zeros in sizein*8 bit value
        bits = sizein * 8
        count = 0
        for i in range(bits - 1, -1, -1):
            if (in1 >> i) & 1:
                break
            count += 1
        return count
