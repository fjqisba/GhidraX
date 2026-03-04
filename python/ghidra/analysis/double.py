"""
Corresponds to: double.hh / double.cc

SplitVarnode and related classes for handling double-precision operations.
When the decompiler encounters operations on values that span two registers
(e.g. 64-bit values in 32-bit architectures), this module helps combine
them into single logical operations.
"""

from __future__ import annotations
from typing import Optional, List
from ghidra.core.opcodes import OpCode


class SplitVarnode:
    """A logical value split across two Varnodes (hi and lo parts).

    Represents a double-precision value that is stored in two registers
    or memory locations. The 'whole' field, if set, points to a single
    Varnode that represents the combined value.
    """

    def __init__(self) -> None:
        self.lo = None       # Varnode: low part
        self.hi = None       # Varnode: high part
        self.whole = None    # Varnode: combined (if exists)
        self.defpoint = None # PcodeOp defining the pair
        self.defblock = None # BlockBasic where pair is defined
        self.wholesize: int = 0

    def initAll(self, lo, hi) -> None:
        self.lo = lo
        self.hi = hi
        if lo is not None and hi is not None:
            self.wholesize = lo.getSize() + hi.getSize()

    def initPartial(self, sz: int, vn) -> None:
        """Initialize from a single Varnode that represents whole value."""
        self.whole = vn
        self.wholesize = sz

    def getLo(self):
        return self.lo

    def getHi(self):
        return self.hi

    def getWhole(self):
        return self.whole

    def getSize(self) -> int:
        return self.wholesize

    def isConstant(self) -> bool:
        if self.whole is not None:
            return self.whole.isConstant() if hasattr(self.whole, 'isConstant') else False
        if self.lo is not None and self.hi is not None:
            lo_const = self.lo.isConstant() if hasattr(self.lo, 'isConstant') else False
            hi_const = self.hi.isConstant() if hasattr(self.hi, 'isConstant') else False
            return lo_const and hi_const
        return False

    def getConstValue(self) -> int:
        if self.whole is not None:
            return self.whole.getOffset()
        if self.lo is not None and self.hi is not None:
            loval = self.lo.getOffset()
            hival = self.hi.getOffset()
            return (hival << (self.lo.getSize() * 8)) | loval
        return 0

    def hasBothPieces(self) -> bool:
        return self.lo is not None and self.hi is not None

    def isWholeFilled(self) -> bool:
        return self.whole is not None

    def getDefPoint(self):
        return self.defpoint

    def getDefBlock(self):
        return self.defblock

    def getValue(self) -> int:
        return self.getConstValue()

    def initPartialConst(self, sz: int, val: int) -> None:
        """Initialize as a constant."""
        self.lo = None
        self.hi = None
        self.whole = None
        self.wholesize = sz
        self._val = val

    def inHandHi(self, h) -> bool:
        """Try to initialize given just the most significant piece split from whole."""
        self.hi = h
        if h is not None and h.isWritten():
            defop = h.getDef()
            if defop.code() == OpCode.CPUI_SUBPIECE:
                w = defop.getIn(0)
                off = defop.getIn(1).getOffset() if defop.numInput() > 1 else 0
                if off == h.getSize():  # hi is upper half
                    self.whole = w
                    self.wholesize = w.getSize()
                    return True
        return False

    def inHandLo(self, l) -> bool:
        """Try to initialize given just the least significant piece split from whole."""
        self.lo = l
        if l is not None and l.isWritten():
            defop = l.getDef()
            if defop.code() == OpCode.CPUI_SUBPIECE:
                w = defop.getIn(0)
                off = defop.getIn(1).getOffset() if defop.numInput() > 1 else 0
                if off == 0:  # lo is lower half
                    self.whole = w
                    self.wholesize = w.getSize()
                    return True
        return False

    def inHandLoNoHi(self, l) -> bool:
        """Try to initialize given just the least significant piece (other may be zero)."""
        return self.inHandLo(l)

    def inHandHiOut(self, h) -> bool:
        """Try to initialize given just the most significant piece concatenated into whole."""
        return self.inHandHi(h)

    def inHandLoOut(self, l) -> bool:
        """Try to initialize given just the least significant piece concatenated into whole."""
        return self.inHandLo(l)

    def isWholeFeasible(self, existop) -> bool:
        """Does a whole Varnode already exist or can it be created?"""
        return self.whole is not None

    def isWholePhiFeasible(self, bl) -> bool:
        return self.whole is not None

    def findCreateWhole(self, data) -> None:
        """Create a whole Varnode for this, if it doesn't already exist."""
        if self.whole is not None:
            return
        if self.lo is not None and self.hi is not None:
            addr = self.lo.getAddr()
            self.whole = data.newVarnode(self.wholesize, addr)

    def findCreateOutputWhole(self, data) -> None:
        """Create a whole Varnode that will be a PcodeOp output."""
        self.findCreateWhole(data)

    def createJoinedWhole(self, data) -> None:
        """Create a whole Varnode from pieces, respecting piece storage."""
        self.findCreateWhole(data)

    def buildLoFromWhole(self, data) -> None:
        """Rebuild the least significant piece as a SUBPIECE of the whole."""
        pass

    def buildHiFromWhole(self, data) -> None:
        """Rebuild the most significant piece as a SUBPIECE of the whole."""
        pass

    def findEarliestSplitPoint(self):
        return self.defpoint

    def findOutExist(self):
        return self.defpoint

    def exceedsConstPrecision(self) -> bool:
        return self.wholesize > 8

    @staticmethod
    def adjacentOffsets(vn1, vn2, size1: int) -> bool:
        """Check if two Varnodes are at adjacent offsets."""
        if vn1.getSpace() is not vn2.getSpace():
            return False
        return vn1.getOffset() + size1 == vn2.getOffset()

    @staticmethod
    def wholeList(w, splitvec: list) -> None:
        """Find all SplitVarnodes formed from a given whole."""
        pass

    @staticmethod
    def findCopies(inv, splitvec: list) -> None:
        """Find copies of a SplitVarnode."""
        pass

    @staticmethod
    def getTrueFalse(boolop, flip: bool):
        """Get the true and false output blocks of a CBRANCH."""
        return (None, None)

    @staticmethod
    def otherwiseEmpty(branchop) -> bool:
        return False

    @staticmethod
    def verifyMultNegOne(op) -> bool:
        return False

    @staticmethod
    def prepareBinaryOp(out, in1, in2):
        return None

    @staticmethod
    def createBinaryOp(data, out, in1, in2, existop, opc) -> None:
        pass

    @staticmethod
    def prepareShiftOp(out, inv):
        return None

    @staticmethod
    def createShiftOp(data, out, inv, sa, existop, opc) -> None:
        pass

    @staticmethod
    def replaceBoolOp(data, boolop, in1, in2, opc) -> None:
        pass

    @staticmethod
    def prepareBoolOp(in1, in2, testop) -> bool:
        return False

    @staticmethod
    def createBoolOp(data, cbranch, in1, in2, opc) -> None:
        pass

    @staticmethod
    def preparePhiOp(out, inlist):
        return None

    @staticmethod
    def createPhiOp(data, out, inlist, existop) -> None:
        pass

    @staticmethod
    def prepareIndirectOp(inv, affector) -> bool:
        return False

    @staticmethod
    def replaceIndirectOp(data, out, inv, affector) -> None:
        pass

    @staticmethod
    def replaceCopyForce(data, addr, inv, copylo, copyhi) -> None:
        pass

    @staticmethod
    def testContiguousPointers(most, least):
        return (False, None, None, None)

    @staticmethod
    def isAddrTiedContiguous(lo, hi):
        return (False, None)

    @staticmethod
    def applyRuleIn(inv, data) -> int:
        return 0


class AddForm:
    """Verify and collect the components of a double-precision add."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.in2 = SplitVarnode()
        self.out = SplitVarnode()
        self.lo1 = None
        self.lo2 = None
        self.hi1 = None
        self.hi2 = None
        self.reshi = None
        self.reslo = None
        self.carry = None
        self.zext = None

    def verify(self, hi, lo, data) -> bool:
        """Verify the double-precision add form."""
        return False

    def apply(self, data) -> bool:
        return False


class SubForm:
    """Verify and collect the components of a double-precision subtract."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.in2 = SplitVarnode()
        self.out = SplitVarnode()

    def verify(self, hi, lo, data) -> bool:
        return False

    def apply(self, data) -> bool:
        return False


class LogicalForm:
    """Verify double-precision logical operations (AND, OR, XOR)."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.in2 = SplitVarnode()
        self.out = SplitVarnode()
        self.opc: int = 0

    def verify(self, hi, lo, data) -> bool:
        return False

    def apply(self, data) -> bool:
        return False


class Equal1Form:
    """Verify double-precision equality comparison."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.in2 = SplitVarnode()

    def verify(self, hi, lo, data) -> bool:
        return False

    def apply(self, data) -> bool:
        return False


class LessConstForm:
    """Verify double-precision less-than with a constant."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.val: int = 0

    def verify(self, hi, lo, data) -> bool:
        return False

    def apply(self, data) -> bool:
        return False


class ShiftForm:
    """Verify double-precision shift operations."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.sa: int = 0
        self.opc: int = 0

    def verify(self, hi, lo, data) -> bool:
        return False

    def apply(self, data) -> bool:
        return False


class MultForm:
    """Verify double-precision multiply."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.in2 = SplitVarnode()
        self.out = SplitVarnode()

    def verify(self, hi, lo, data) -> bool:
        return False

    def applyRule(self, i, hop, workishi: bool, data) -> bool:
        return False

    def apply(self, data) -> bool:
        return False


class Equal2Form:
    """Verify double-precision equality comparison (form 2)."""
    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.param2 = SplitVarnode()

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        return False


class Equal3Form:
    """Verify double-precision equality comparison (form 3: AND + compare)."""
    def __init__(self) -> None:
        self.in1 = SplitVarnode()

    def verify(self, h, l, aop) -> bool:
        return False

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        return False


class LessThreeWay:
    """Verify double-precision less-than using three-way comparison."""
    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.in2 = SplitVarnode()

    def applyRule(self, i, loop, workishi: bool, data) -> bool:
        return False


class PhiForm:
    """Verify double-precision phi (MULTIEQUAL) operation."""
    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.outvn = SplitVarnode()

    def verify(self, h, l, hphi) -> bool:
        return False

    def applyRule(self, i, hphi, workishi: bool, data) -> bool:
        return False


class IndirectForm:
    """Verify double-precision INDIRECT operation."""
    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.outvn = SplitVarnode()

    def verify(self, h, l, ihi) -> bool:
        return False

    def applyRule(self, i, ind, workishi: bool, data) -> bool:
        return False


class CopyForceForm:
    """Collapse two COPYs into contiguous address forced Varnodes."""
    def __init__(self) -> None:
        self.in1 = SplitVarnode()

    def verify(self, h, l, w, cpy) -> bool:
        return False

    def applyRule(self, i, cpy, workishi: bool, data) -> bool:
        return False


# =========================================================================
# Rule subclasses for double precision
# =========================================================================

class RuleDoubleIn:
    """Simplify a double precision operation, pushing down one level, starting from marked input."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doublein'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleIn(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        return 0

    def reset(self, data) -> None:
        pass


class RuleDoubleOut:
    """Simplify a double precision operation, pulling back one level, starting from PIECE."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doubleout'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleOut(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_PIECE)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleDoubleLoad:
    """Collapse contiguous loads into a single wider load."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doubleload'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleLoad(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_PIECE)]

    def applyOp(self, op, data) -> int:
        return 0

    @staticmethod
    def noWriteConflict(op1, op2, spc, indirects=None):
        return None


class RuleDoubleStore:
    """Collapse contiguous stores into a single wider store."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doublestore'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleStore(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_STORE)]

    def applyOp(self, op, data) -> int:
        return 0

    @staticmethod
    def testIndirectUse(op1, op2, indirects) -> bool:
        return False

    @staticmethod
    def reassignIndirects(data, newStore, indirects) -> None:
        pass
