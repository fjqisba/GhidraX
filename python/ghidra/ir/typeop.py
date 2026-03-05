"""
Corresponds to: typeop.hh / typeop.cc

Data-type and behavior information associated with specific p-code op-codes.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List
from ghidra.core.opcodes import OpCode
from ghidra.core.opbehavior import OpBehavior
from ghidra.types.datatype import (
    Datatype, TypeFactory, MetaType,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR,
)

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.core.translate import Translate


class TypeOp:
    """Associate data-type and behavior information with a specific p-code op-code."""

    inherits_sign = 1
    inherits_sign_zero = 2
    shift_op = 4
    arithmetic_op = 8
    logical_op = 0x10
    floatingpoint_op = 0x20

    def __init__(self, tlst: TypeFactory, opc: OpCode, name: str) -> None:
        self.tlst = tlst
        self.opcode = opc
        self.opflags: int = 0
        self.addlflags: int = 0
        self.name = name
        self.behave: Optional[OpBehavior] = None

    def getName(self) -> str:
        return self.name

    def getOpcode(self) -> OpCode:
        return self.opcode

    def getFlags(self) -> int:
        return self.opflags

    def getBehavior(self) -> Optional[OpBehavior]:
        return self.behave

    def isCommutative(self) -> bool:
        from ghidra.ir.op import PcodeOp as PcOp
        return (self.opflags & PcOp.commutative) != 0

    def inheritsSign(self) -> bool:
        return (self.addlflags & TypeOp.inherits_sign) != 0

    def isShiftOp(self) -> bool:
        return (self.addlflags & TypeOp.shift_op) != 0

    def isArithmeticOp(self) -> bool:
        return (self.addlflags & TypeOp.arithmetic_op) != 0

    def isLogicalOp(self) -> bool:
        return (self.addlflags & TypeOp.logical_op) != 0

    def isFloatingPointOp(self) -> bool:
        return (self.addlflags & TypeOp.floatingpoint_op) != 0

    def inheritsSignFirstParamOnly(self) -> bool:
        return (self.addlflags & TypeOp.inherits_sign_zero) != 0

    def evaluateUnary(self, sizeout: int, sizein: int, in1: int) -> int:
        """Emulate the unary op-code on an input value."""
        if self.behave is not None:
            return self.behave.evaluateUnary(sizeout, sizein, in1)
        return 0

    def evaluateBinary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        """Emulate the binary op-code on input values."""
        if self.behave is not None:
            return self.behave.evaluateBinary(sizeout, sizein, in1, in2)
        return 0

    def evaluateTernary(self, sizeout: int, sizein: int, in1: int, in2: int, in3: int) -> int:
        """Emulate the ternary op-code on input values."""
        if self.behave is not None and hasattr(self.behave, 'evaluateTernary'):
            return self.behave.evaluateTernary(sizeout, sizein, in1, in2, in3)
        return 0

    def recoverInputBinary(self, slot: int, sizeout: int, out: int, sizein: int, inp: int) -> int:
        """Reverse the binary op-code, recovering a constant input value."""
        if self.behave is not None and hasattr(self.behave, 'recoverInputBinary'):
            return self.behave.recoverInputBinary(slot, sizeout, out, sizein, inp)
        return 0

    def recoverInputUnary(self, sizeout: int, out: int, sizein: int) -> int:
        """Reverse the unary op-code, recovering a constant input value."""
        if self.behave is not None and hasattr(self.behave, 'recoverInputUnary'):
            return self.behave.recoverInputUnary(sizeout, out, sizein)
        return 0

    def getOutputToken(self, op, castStrategy=None) -> Optional[Datatype]:
        """Find the data-type of the output that would be assigned by a compiler."""
        return self.getOutputLocal(op)

    def getInputCast(self, op, slot: int, castStrategy=None) -> Optional[Datatype]:
        """Find the data-type of the input to a specific PcodeOp."""
        return None  # No cast needed by default

    def propagateType(self, alttype, op, invn, outvn, inslot: int, outslot: int):
        """Propagate an incoming data-type across a specific PcodeOp."""
        return None  # No propagation by default

    def stopsTypePropagation(self) -> bool:
        """Check if this op stops type propagation."""
        return False

    @staticmethod
    def floatSignManipulation(op) -> OpCode:
        """Return the floating-point op associated with sign bit manipulation."""
        return OpCode.CPUI_MAX

    @staticmethod
    def propagateToPointer(t, dt, sz: int, wordsz: int):
        """Propagate data-type to a pointer."""
        return None

    @staticmethod
    def propagateFromPointer(t, dt, sz: int):
        """Propagate data-type from a pointer."""
        return None

    @staticmethod
    def selectJavaOperators(inst: list, val: bool) -> None:
        """Toggle Java specific aspects of the op-code information."""
        pass

    def getOutputLocal(self, op) -> Optional[Datatype]:
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), TYPE_UNKNOWN)

    def getInputLocal(self, op, slot: int) -> Optional[Datatype]:
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), TYPE_UNKNOWN)

    def getOperatorName(self, op) -> str:
        return self.name

    def push(self, lng, op, readOp=None) -> None:
        """Push this op's expression onto the PrintLanguage RPN stack.

        Dispatches to the correct opXxx handler on the PrintLanguage (PrintC) instance.
        This is the bridge between recurse() and per-opcode emission.
        """
        handler = self._getHandler(lng)
        if handler is not None:
            handler(op)
        else:
            # Fallback: use opFunc-style emission
            if hasattr(lng, 'opFunc'):
                lng.opFunc(op)
            else:
                lng.pushVnExplicit(op.getOut() if op.getOut() is not None else op.getIn(0), op)

    def _getHandler(self, lng):
        """Look up the PrintC handler for this opcode."""
        _HANDLER_MAP = {
            OpCode.CPUI_COPY: 'opCopy',
            OpCode.CPUI_LOAD: 'opLoad',
            OpCode.CPUI_STORE: 'opStore',
            OpCode.CPUI_BRANCH: 'opBranch',
            OpCode.CPUI_CBRANCH: 'opCbranch',
            OpCode.CPUI_BRANCHIND: 'opBranchind',
            OpCode.CPUI_CALL: 'opCall',
            OpCode.CPUI_CALLIND: 'opCallind',
            OpCode.CPUI_CALLOTHER: 'opCallother',
            OpCode.CPUI_RETURN: 'opReturn',
            OpCode.CPUI_INT_EQUAL: 'opIntEqual',
            OpCode.CPUI_INT_NOTEQUAL: 'opIntNotEqual',
            OpCode.CPUI_INT_SLESS: 'opIntSless',
            OpCode.CPUI_INT_SLESSEQUAL: 'opIntSlessEqual',
            OpCode.CPUI_INT_LESS: 'opIntLess',
            OpCode.CPUI_INT_LESSEQUAL: 'opIntLessEqual',
            OpCode.CPUI_INT_ZEXT: 'opIntZext',
            OpCode.CPUI_INT_SEXT: 'opIntSext',
            OpCode.CPUI_INT_ADD: 'opIntAdd',
            OpCode.CPUI_INT_SUB: 'opIntSub',
            OpCode.CPUI_INT_CARRY: 'opIntCarry',
            OpCode.CPUI_INT_SCARRY: 'opIntScarry',
            OpCode.CPUI_INT_SBORROW: 'opIntSborrow',
            OpCode.CPUI_INT_2COMP: 'opInt2Comp',
            OpCode.CPUI_INT_NEGATE: 'opIntNegate',
            OpCode.CPUI_INT_XOR: 'opIntXor',
            OpCode.CPUI_INT_AND: 'opIntAnd',
            OpCode.CPUI_INT_OR: 'opIntOr',
            OpCode.CPUI_INT_LEFT: 'opIntLeft',
            OpCode.CPUI_INT_RIGHT: 'opIntRight',
            OpCode.CPUI_INT_SRIGHT: 'opIntSright',
            OpCode.CPUI_INT_MULT: 'opIntMult',
            OpCode.CPUI_INT_DIV: 'opIntDiv',
            OpCode.CPUI_INT_SDIV: 'opIntSdiv',
            OpCode.CPUI_INT_REM: 'opIntRem',
            OpCode.CPUI_INT_SREM: 'opIntSrem',
            OpCode.CPUI_BOOL_NEGATE: 'opBoolNegate',
            OpCode.CPUI_BOOL_XOR: 'opBoolXor',
            OpCode.CPUI_BOOL_AND: 'opBoolAnd',
            OpCode.CPUI_BOOL_OR: 'opBoolOr',
            OpCode.CPUI_FLOAT_EQUAL: 'opFloatEqual',
            OpCode.CPUI_FLOAT_NOTEQUAL: 'opFloatNotEqual',
            OpCode.CPUI_FLOAT_LESS: 'opFloatLess',
            OpCode.CPUI_FLOAT_LESSEQUAL: 'opFloatLessEqual',
            OpCode.CPUI_FLOAT_NAN: 'opFloatNan',
            OpCode.CPUI_FLOAT_ADD: 'opFloatAdd',
            OpCode.CPUI_FLOAT_DIV: 'opFloatDiv',
            OpCode.CPUI_FLOAT_MULT: 'opFloatMult',
            OpCode.CPUI_FLOAT_SUB: 'opFloatSub',
            OpCode.CPUI_FLOAT_NEG: 'opFloatNeg',
            OpCode.CPUI_FLOAT_ABS: 'opFloatAbs',
            OpCode.CPUI_FLOAT_SQRT: 'opFloatSqrt',
            OpCode.CPUI_FLOAT_INT2FLOAT: 'opFloatInt2Float',
            OpCode.CPUI_FLOAT_FLOAT2FLOAT: 'opFloatFloat2Float',
            OpCode.CPUI_FLOAT_TRUNC: 'opFloatTrunc',
            OpCode.CPUI_FLOAT_CEIL: 'opFloatCeil',
            OpCode.CPUI_FLOAT_FLOOR: 'opFloatFloor',
            OpCode.CPUI_FLOAT_ROUND: 'opFloatRound',
            OpCode.CPUI_MULTIEQUAL: 'opMultiequal',
            OpCode.CPUI_INDIRECT: 'opIndirect',
            OpCode.CPUI_PIECE: 'opPiece',
            OpCode.CPUI_SUBPIECE: 'opSubpiece',
            OpCode.CPUI_CAST: 'opCast',
            OpCode.CPUI_PTRADD: 'opPtradd',
            OpCode.CPUI_PTRSUB: 'opPtrsub',
            OpCode.CPUI_SEGMENTOP: 'opSegmentOp',
            OpCode.CPUI_CPOOLREF: 'opCpoolRefOp',
            OpCode.CPUI_NEW: 'opNewOp',
            OpCode.CPUI_INSERT: 'opInsertOp',
            OpCode.CPUI_EXTRACT: 'opExtractOp',
            OpCode.CPUI_POPCOUNT: 'opPopcountOp',
            OpCode.CPUI_LZCOUNT: 'opLzcountOp',
        }
        name = _HANDLER_MAP.get(self.opcode)
        if name is not None:
            return getattr(lng, name, None)
        return None

    def printRaw(self, op) -> str:
        parts = []
        outvn = op.getOut()
        if outvn is not None:
            parts.append(f"{outvn.printRaw()} = ")
        parts.append(self.name)
        for i in range(op.numInput()):
            invn = op.getIn(i)
            if invn is not None:
                parts.append(f" {invn.printRaw()}")
        return "".join(parts)


class TypeOpBinary(TypeOp):
    """A generic binary operator: two inputs and one output."""

    def __init__(self, tlst, opc, name, metaout, metain):
        super().__init__(tlst, opc, name)
        self.metaout: MetaType = metaout
        self.metain: MetaType = metain

    def getOutputLocal(self, op):
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), self.metaout)

    def getInputLocal(self, op, slot):
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), self.metain)


class TypeOpUnary(TypeOp):
    """A generic unary operator: one input and one output."""

    def __init__(self, tlst, opc, name, metaout, metain):
        super().__init__(tlst, opc, name)
        self.metaout: MetaType = metaout
        self.metain: MetaType = metain

    def getOutputLocal(self, op):
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), self.metaout)

    def getInputLocal(self, op, slot):
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), self.metain)


class TypeOpFunc(TypeOp):
    """A generic functional operator."""

    def __init__(self, tlst, opc, name, metaout, metain):
        super().__init__(tlst, opc, name)
        self.metaout: MetaType = metaout
        self.metain: MetaType = metain

    def getOutputLocal(self, op):
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), self.metaout)

    def getInputLocal(self, op, slot):
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), self.metain)


# =========================================================================
# Concrete TypeOp subclasses for opcodes with special type behavior
# =========================================================================

class TypeOpCopy(TypeOp):
    """CPUI_COPY — propagates type directly through."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_COPY, "COPY")
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None: return None
        outvn = op.getOut()
        invn = op.getIn(0)
        if outvn is None or invn is None: return None
        return castStrategy.castStandard(outvn.getHighTypeDefFacing() if hasattr(outvn,'getHighTypeDefFacing') else outvn.getType(),
                                          invn.getHighTypeReadFacing(op) if hasattr(invn,'getHighTypeReadFacing') else invn.getType(),
                                          False, True)
    def getOutputToken(self, op, castStrategy=None):
        invn = op.getIn(0)
        return invn.getHighTypeReadFacing(op) if invn is not None and hasattr(invn,'getHighTypeReadFacing') else None
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype  # COPY propagates type directly

class TypeOpLoad(TypeOp):
    """CPUI_LOAD — dereference pointer to produce value."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_LOAD, "LOAD")
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if outslot == -1 and inslot == 1:  # from pointer input to output
            if hasattr(alttype, 'getPtrTo'):
                return alttype.getPtrTo()
        return None

class TypeOpStore(TypeOp):
    """CPUI_STORE — store value through pointer."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_STORE, "STORE")
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBranch(TypeOp):
    """CPUI_BRANCH."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BRANCH, "BRANCH")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCbranch(TypeOp):
    """CPUI_CBRANCH."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CBRANCH, "CBRANCH")
    def getInputLocal(self, op, slot):
        if slot == 1:
            return self.tlst.getBase(1, TYPE_BOOL)
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpBranchind(TypeOp):
    """CPUI_BRANCHIND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BRANCHIND, "BRANCHIND")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCall(TypeOp):
    """CPUI_CALL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALL, "CALL")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCallind(TypeOp):
    """CPUI_CALLIND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALLIND, "CALLIND")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCallother(TypeOp):
    """CPUI_CALLOTHER."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALLOTHER, "CALLOTHER")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpReturn(TypeOp):
    """CPUI_RETURN."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_RETURN, "RETURN")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpIntEqual(TypeOpBinary):
    """CPUI_INT_EQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_EQUAL, "==", TYPE_BOOL, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntNotEqual(TypeOpBinary):
    """CPUI_INT_NOTEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_NOTEQUAL, "!=", TYPE_BOOL, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSless(TypeOpBinary):
    """CPUI_INT_SLESS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SLESS, "s<", TYPE_BOOL, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSlessEqual(TypeOpBinary):
    """CPUI_INT_SLESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SLESSEQUAL, "s<=", TYPE_BOOL, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntLess(TypeOpBinary):
    """CPUI_INT_LESS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LESS, "<", TYPE_BOOL, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntLessEqual(TypeOpBinary):
    """CPUI_INT_LESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LESSEQUAL, "<=", TYPE_BOOL, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntZext(TypeOpUnary):
    """CPUI_INT_ZEXT — zero extension."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_ZEXT, "ZEXT", TYPE_UINT, TYPE_UINT)
    def getOutputToken(self, op, castStrategy=None):
        return self.tlst.getBase(op.getOut().getSize(), TYPE_UINT) if op.getOut() else None
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntSext(TypeOpUnary):
    """CPUI_INT_SEXT — sign extension."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SEXT, "SEXT", TYPE_INT, TYPE_INT)
    def getOutputToken(self, op, castStrategy=None):
        return self.tlst.getBase(op.getOut().getSize(), TYPE_INT) if op.getOut() else None
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntAdd(TypeOpBinary):
    """CPUI_INT_ADD — addition, pointer arithmetic."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_ADD, "+", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if hasattr(alttype, 'getMetatype') and alttype.getMetatype() == TYPE_PTR:
            return alttype
        return None

class TypeOpIntSub(TypeOpBinary):
    """CPUI_INT_SUB — subtraction."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SUB, "-", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if hasattr(alttype, 'getMetatype') and alttype.getMetatype() == TYPE_PTR:
            if inslot == 0 and outslot == -1:
                return alttype
        return None

class TypeOpIntCarry(TypeOpBinary):
    """CPUI_INT_CARRY."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_CARRY, "CARRY", TYPE_BOOL, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntScarry(TypeOpBinary):
    """CPUI_INT_SCARRY."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SCARRY, "SCARRY", TYPE_BOOL, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSborrow(TypeOpBinary):
    """CPUI_INT_SBORROW."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SBORROW, "SBORROW", TYPE_BOOL, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpInt2Comp(TypeOpUnary):
    """CPUI_INT_2COMP — two's complement negate."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_2COMP, "-", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpIntNegate(TypeOpUnary):
    """CPUI_INT_NEGATE — bitwise negate."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_NEGATE, "~", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpIntXor(TypeOpBinary):
    """CPUI_INT_XOR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_XOR, "^", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if outslot == -1 else None

class TypeOpIntAnd(TypeOpBinary):
    """CPUI_INT_AND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_AND, "&", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if outslot == -1 else None

class TypeOpIntOr(TypeOpBinary):
    """CPUI_INT_OR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_OR, "|", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if outslot == -1 else None

class TypeOpIntLeft(TypeOpBinary):
    """CPUI_INT_LEFT — left shift."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LEFT, "<<", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntRight(TypeOpBinary):
    """CPUI_INT_RIGHT — logical right shift."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_RIGHT, ">>", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntSright(TypeOpBinary):
    """CPUI_INT_SRIGHT — arithmetic right shift."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SRIGHT, "s>>", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntMult(TypeOpBinary):
    """CPUI_INT_MULT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_MULT, "*", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntDiv(TypeOpBinary):
    """CPUI_INT_DIV — unsigned division."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_DIV, "/", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSdiv(TypeOpBinary):
    """CPUI_INT_SDIV — signed division."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SDIV, "s/", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntRem(TypeOpBinary):
    """CPUI_INT_REM — unsigned remainder."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_REM, "%", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSrem(TypeOpBinary):
    """CPUI_INT_SREM — signed remainder."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SREM, "s%", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolNegate(TypeOpUnary):
    """CPUI_BOOL_NEGATE."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_NEGATE, "!", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolXor(TypeOpBinary):
    """CPUI_BOOL_XOR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_XOR, "^^", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolAnd(TypeOpBinary):
    """CPUI_BOOL_AND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_AND, "&&", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolOr(TypeOpBinary):
    """CPUI_BOOL_OR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_OR, "||", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatEqual(TypeOpBinary):
    """CPUI_FLOAT_EQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_EQUAL, "f==", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatNotEqual(TypeOpBinary):
    """CPUI_FLOAT_NOTEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_NOTEQUAL, "f!=", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatLess(TypeOpBinary):
    """CPUI_FLOAT_LESS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_LESS, "f<", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatLessEqual(TypeOpBinary):
    """CPUI_FLOAT_LESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_LESSEQUAL, "f<=", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatNan(TypeOpUnary):
    """CPUI_FLOAT_NAN."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_NAN, "NAN", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatAdd(TypeOpBinary):
    """CPUI_FLOAT_ADD."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_ADD, "f+", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if outslot == -1 else None

class TypeOpFloatDiv(TypeOpBinary):
    """CPUI_FLOAT_DIV."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_DIV, "f/", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatMult(TypeOpBinary):
    """CPUI_FLOAT_MULT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_MULT, "f*", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatSub(TypeOpBinary):
    """CPUI_FLOAT_SUB."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_SUB, "f-", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatNeg(TypeOpUnary):
    """CPUI_FLOAT_NEG."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_NEG, "f-", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpFloatAbs(TypeOpUnary):
    """CPUI_FLOAT_ABS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_ABS, "ABS", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpFloatSqrt(TypeOpUnary):
    """CPUI_FLOAT_SQRT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_SQRT, "SQRT", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatInt2Float(TypeOpUnary):
    """CPUI_FLOAT_INT2FLOAT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_INT2FLOAT, "INT2FLOAT", TYPE_FLOAT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatFloat2Float(TypeOpUnary):
    """CPUI_FLOAT_FLOAT2FLOAT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_FLOAT2FLOAT, "FLOAT2FLOAT", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatTrunc(TypeOpUnary):
    """CPUI_FLOAT_TRUNC."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_TRUNC, "TRUNC", TYPE_INT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatCeil(TypeOpUnary):
    """CPUI_FLOAT_CEIL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_CEIL, "CEIL", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatFloor(TypeOpUnary):
    """CPUI_FLOAT_FLOOR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_FLOOR, "FLOOR", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatRound(TypeOpUnary):
    """CPUI_FLOAT_ROUND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_ROUND, "ROUND", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpPiece(TypeOpFunc):
    """CPUI_PIECE — concatenation of two values."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_PIECE, "PIECE", TYPE_UNKNOWN, TYPE_UNKNOWN)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpSubpiece(TypeOpFunc):
    """CPUI_SUBPIECE — extraction of sub-value."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_SUBPIECE, "SUBPIECE", TYPE_UNKNOWN, TYPE_UNKNOWN)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpCast(TypeOp):
    """CPUI_CAST — explicit type cast."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CAST, "CAST")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpPtradd(TypeOp):
    """CPUI_PTRADD — pointer + index*size."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_PTRADD, "PTRADD")
    def getInputLocal(self, op, slot):
        if slot == 0:
            invn = op.getIn(0)
            if invn is not None:
                return self.tlst.getBase(invn.getSize(), TYPE_PTR)
        return self.tlst.getTypeVoid()
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0:
            return alttype
        return None

class TypeOpPtrsub(TypeOpBinary):
    """CPUI_PTRSUB — pointer + constant offset."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_PTRSUB, "PTRSUB", TYPE_UNKNOWN, TYPE_UNKNOWN)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0:
            return alttype
        return None

class TypeOpMultiequal(TypeOp):
    """CPUI_MULTIEQUAL — SSA phi-node."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_MULTIEQUAL, "MULTIEQUAL")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype

class TypeOpIndirect(TypeOp):
    """CPUI_INDIRECT — indirect effect."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INDIRECT, "INDIRECT")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0:
            return alttype
        return None

class TypeOpSegmentOp(TypeOp):
    """CPUI_SEGMENTOP."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_SEGMENTOP, "SEGMENTOP")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCpoolRef(TypeOp):
    """CPUI_CPOOLREF."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CPOOLREF, "CPOOLREF")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpNew(TypeOp):
    """CPUI_NEW."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_NEW, "NEW")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpInsert(TypeOpFunc):
    """CPUI_INSERT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INSERT, "INSERT", TYPE_UNKNOWN, TYPE_UNKNOWN)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpExtract(TypeOpFunc):
    """CPUI_EXTRACT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_EXTRACT, "EXTRACT", TYPE_UNKNOWN, TYPE_UNKNOWN)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpPopcount(TypeOpUnary):
    """CPUI_POPCOUNT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_POPCOUNT, "POPCOUNT", TYPE_UINT, TYPE_UNKNOWN)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpLzcount(TypeOpUnary):
    """CPUI_LZCOUNT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_LZCOUNT, "LZCOUNT", TYPE_UINT, TYPE_UNKNOWN)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None


def registerTypeOps(tlst: TypeFactory, trans=None) -> List[Optional[TypeOp]]:
    """Build all TypeOp objects indexed by OpCode value.

    Corresponds to TypeOp::registerInstructions in typeop.cc.
    """
    from ghidra.ir.op import PcodeOp as PcOp

    inst: List[Optional[TypeOp]] = [None] * int(OpCode.CPUI_MAX)
    behaviors = OpBehavior.registerInstructions(trans)

    def _b(opc, nm, mo, mi, fl=0, al=0):
        t = TypeOpBinary(tlst, opc, nm, mo, mi)
        t.opflags = fl; t.addlflags = al
        if opc < len(behaviors) and behaviors[opc]:
            t.behave = behaviors[opc]
        inst[int(opc)] = t

    def _u(opc, nm, mo, mi, fl=0, al=0):
        t = TypeOpUnary(tlst, opc, nm, mo, mi)
        t.opflags = fl; t.addlflags = al
        if opc < len(behaviors) and behaviors[opc]:
            t.behave = behaviors[opc]
        inst[int(opc)] = t

    def _s(opc, nm, fl=0):
        t = TypeOp(tlst, opc, nm)
        t.opflags = fl | PcOp.special
        if opc < len(behaviors) and behaviors[opc]:
            t.behave = behaviors[opc]
        inst[int(opc)] = t

    U = TYPE_UNKNOWN; I = TYPE_INT; UI = TYPE_UINT; B = TYPE_BOOL; F = TYPE_FLOAT
    bi = PcOp.binary; un = PcOp.unary; bo = PcOp.booloutput; cm = PcOp.commutative
    br = PcOp.branch; ca = PcOp.call; cr = PcOp.coderef; rt = PcOp.returns
    hc = PcOp.has_callspec; mk = PcOp.marker

    _u(OpCode.CPUI_COPY, "COPY", U, U, un)
    _s(OpCode.CPUI_LOAD, "LOAD")
    _s(OpCode.CPUI_STORE, "STORE")
    _s(OpCode.CPUI_BRANCH, "BRANCH", br | cr)
    _s(OpCode.CPUI_CBRANCH, "CBRANCH", br | cr)
    _s(OpCode.CPUI_BRANCHIND, "BRANCHIND", br)
    _s(OpCode.CPUI_CALL, "CALL", ca | cr | hc)
    _s(OpCode.CPUI_CALLIND, "CALLIND", ca | hc)
    _s(OpCode.CPUI_CALLOTHER, "CALLOTHER")
    _s(OpCode.CPUI_RETURN, "RETURN", br | rt)

    _b(OpCode.CPUI_INT_EQUAL, "==", B, I, bi | bo | cm)
    _b(OpCode.CPUI_INT_NOTEQUAL, "!=", B, I, bi | bo | cm)
    _b(OpCode.CPUI_INT_SLESS, "s<", B, I, bi | bo)
    _b(OpCode.CPUI_INT_SLESSEQUAL, "s<=", B, I, bi | bo)
    _b(OpCode.CPUI_INT_LESS, "<", B, UI, bi | bo)
    _b(OpCode.CPUI_INT_LESSEQUAL, "<=", B, UI, bi | bo)

    _u(OpCode.CPUI_INT_ZEXT, "ZEXT", UI, UI, un)
    _u(OpCode.CPUI_INT_SEXT, "SEXT", I, I, un)

    _b(OpCode.CPUI_INT_ADD, "+", I, I, bi | cm, TypeOp.arithmetic_op | TypeOp.inherits_sign)
    _b(OpCode.CPUI_INT_SUB, "-", I, I, bi, TypeOp.arithmetic_op | TypeOp.inherits_sign)
    _b(OpCode.CPUI_INT_CARRY, "CARRY", B, UI, bi | bo)
    _b(OpCode.CPUI_INT_SCARRY, "SCARRY", B, I, bi | bo)
    _b(OpCode.CPUI_INT_SBORROW, "SBORROW", B, I, bi | bo)

    _u(OpCode.CPUI_INT_2COMP, "-", I, I, un)
    _u(OpCode.CPUI_INT_NEGATE, "~", UI, UI, un, TypeOp.logical_op)

    _b(OpCode.CPUI_INT_XOR, "^", UI, UI, bi | cm, TypeOp.logical_op | TypeOp.inherits_sign)
    _b(OpCode.CPUI_INT_AND, "&", UI, UI, bi | cm, TypeOp.logical_op | TypeOp.inherits_sign)
    _b(OpCode.CPUI_INT_OR, "|", UI, UI, bi | cm, TypeOp.logical_op | TypeOp.inherits_sign)
    _b(OpCode.CPUI_INT_LEFT, "<<", I, I, bi, TypeOp.shift_op | TypeOp.inherits_sign_zero)
    _b(OpCode.CPUI_INT_RIGHT, ">>", UI, UI, bi, TypeOp.shift_op)
    _b(OpCode.CPUI_INT_SRIGHT, "s>>", I, I, bi, TypeOp.shift_op)
    _b(OpCode.CPUI_INT_MULT, "*", I, I, bi | cm, TypeOp.arithmetic_op | TypeOp.inherits_sign)
    _b(OpCode.CPUI_INT_DIV, "/", UI, UI, bi, TypeOp.arithmetic_op)
    _b(OpCode.CPUI_INT_SDIV, "s/", I, I, bi, TypeOp.arithmetic_op)
    _b(OpCode.CPUI_INT_REM, "%", UI, UI, bi, TypeOp.arithmetic_op)
    _b(OpCode.CPUI_INT_SREM, "s%", I, I, bi, TypeOp.arithmetic_op)

    _u(OpCode.CPUI_BOOL_NEGATE, "!", B, B, un | bo)
    _b(OpCode.CPUI_BOOL_XOR, "^^", B, B, bi | bo | cm)
    _b(OpCode.CPUI_BOOL_AND, "&&", B, B, bi | bo | cm)
    _b(OpCode.CPUI_BOOL_OR, "||", B, B, bi | bo | cm)

    _b(OpCode.CPUI_FLOAT_EQUAL, "f==", B, F, bi | bo | cm, TypeOp.floatingpoint_op)
    _b(OpCode.CPUI_FLOAT_NOTEQUAL, "f!=", B, F, bi | bo | cm, TypeOp.floatingpoint_op)
    _b(OpCode.CPUI_FLOAT_LESS, "f<", B, F, bi | bo, TypeOp.floatingpoint_op)
    _b(OpCode.CPUI_FLOAT_LESSEQUAL, "f<=", B, F, bi | bo, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_NAN, "NAN", B, F, un | bo, TypeOp.floatingpoint_op)
    _b(OpCode.CPUI_FLOAT_ADD, "f+", F, F, bi | cm, TypeOp.floatingpoint_op)
    _b(OpCode.CPUI_FLOAT_DIV, "f/", F, F, bi, TypeOp.floatingpoint_op)
    _b(OpCode.CPUI_FLOAT_MULT, "f*", F, F, bi | cm, TypeOp.floatingpoint_op)
    _b(OpCode.CPUI_FLOAT_SUB, "f-", F, F, bi, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_NEG, "f-", F, F, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_ABS, "ABS", F, F, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_SQRT, "SQRT", F, F, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_INT2FLOAT, "INT2FLOAT", F, I, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_FLOAT2FLOAT, "FLOAT2FLOAT", F, F, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_TRUNC, "TRUNC", I, F, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_CEIL, "CEIL", F, F, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_FLOOR, "FLOOR", F, F, un, TypeOp.floatingpoint_op)
    _u(OpCode.CPUI_FLOAT_ROUND, "ROUND", F, F, un, TypeOp.floatingpoint_op)

    _s(OpCode.CPUI_MULTIEQUAL, "MULTIEQUAL", mk)
    _s(OpCode.CPUI_INDIRECT, "INDIRECT", mk)
    _b(OpCode.CPUI_PIECE, "PIECE", U, U, bi)
    _b(OpCode.CPUI_SUBPIECE, "SUBPIECE", U, U, bi)
    _s(OpCode.CPUI_CAST, "CAST", un)
    _b(OpCode.CPUI_PTRADD, "PTRADD", U, U, PcOp.ternary)
    _b(OpCode.CPUI_PTRSUB, "PTRSUB", U, U, bi)
    _s(OpCode.CPUI_SEGMENTOP, "SEGMENTOP")
    _s(OpCode.CPUI_CPOOLREF, "CPOOLREF")
    _s(OpCode.CPUI_NEW, "NEW")
    _s(OpCode.CPUI_INSERT, "INSERT")
    _s(OpCode.CPUI_EXTRACT, "EXTRACT")
    _u(OpCode.CPUI_POPCOUNT, "POPCOUNT", UI, U, un)
    _u(OpCode.CPUI_LZCOUNT, "LZCOUNT", UI, U, un)

    return inst
