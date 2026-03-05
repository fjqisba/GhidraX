"""
Corresponds to: rangeutil.hh / rangeutil.cc

CircleRange class for manipulating integer value ranges.
Represents a circular range [left, right) over integers mod 2^n.
Used by jump-table recovery, guard analysis, and value set analysis.
"""

from __future__ import annotations
from typing import Optional, Tuple
from ghidra.core.address import calc_mask
from ghidra.core.opcodes import OpCode


class CircleRange:
    """A circular integer range [left, right) mod 2^n with optional step.

    The range wraps around: if left > right, the range covers
    [left, 2^n) union [0, right). An empty range has isempty=True.
    A full range has left == right and step == 1.
    """

    def __init__(self, left: int = 0, right: int = 0,
                 size: int = 0, step: int = 1) -> None:
        if size == 0:
            self._left: int = 0
            self._right: int = 0
            self._mask: int = 0
            self._isempty: bool = True
            self._step: int = 1
        else:
            self._mask = calc_mask(size)
            self._step = step
            self._left = left & self._mask
            self._right = right & self._mask
            self._isempty = False
            self._normalize()

    @classmethod
    def fromSingle(cls, val: int, size: int) -> CircleRange:
        """Construct a range containing a single value."""
        r = cls.__new__(cls)
        r._mask = calc_mask(size)
        r._step = 1
        r._left = val & r._mask
        r._right = (val + 1) & r._mask
        r._isempty = False
        return r

    @classmethod
    def fromBool(cls, val: bool) -> CircleRange:
        """Construct a boolean range (0 or 1)."""
        r = cls.__new__(cls)
        r._mask = 0xFF
        r._step = 1
        r._isempty = False
        if val:
            r._left = 1
            r._right = 2
        else:
            r._left = 0
            r._right = 1
        return r

    @classmethod
    def empty(cls) -> CircleRange:
        """Construct an empty range."""
        r = cls.__new__(cls)
        r._left = 0
        r._right = 0
        r._mask = 0
        r._isempty = True
        r._step = 1
        return r

    @classmethod
    def full(cls, size: int) -> CircleRange:
        """Construct a full range covering all values for the given byte size."""
        r = cls.__new__(cls)
        r._mask = calc_mask(size)
        r._step = 1
        r._left = 0
        r._right = 0
        r._isempty = False
        return r

    def _normalize(self) -> None:
        """Normalize the representation of full sets."""
        if self._isempty:
            return
        if self._step != 1 and self._left == self._right:
            pass

    def setRange(self, left: int, right: int, size: int, step: int = 1) -> None:
        self._mask = calc_mask(size)
        self._step = step
        self._left = left & self._mask
        self._right = right & self._mask
        self._isempty = False

    def setFull(self, size: int) -> None:
        self._mask = calc_mask(size)
        self._step = 1
        self._left = 0
        self._right = 0
        self._isempty = False

    def isEmpty(self) -> bool:
        return self._isempty

    def isFull(self) -> bool:
        return not self._isempty and self._step == 1 and self._left == self._right

    def isSingle(self) -> bool:
        return not self._isempty and self._right == ((self._left + self._step) & self._mask)

    def getMin(self) -> int:
        return self._left

    def getMax(self) -> int:
        return (self._right - self._step) & self._mask

    def getEnd(self) -> int:
        return self._right

    def getMask(self) -> int:
        return self._mask

    def getStep(self) -> int:
        return self._step

    def getSize(self) -> int:
        """Get the number of elements in this range."""
        if self._isempty:
            return 0
        if self._left == self._right:
            return (self._mask + 1) // self._step
        if self._right > self._left:
            return (self._right - self._left) // self._step
        return ((self._mask + 1) - self._left + self._right) // self._step

    def getMaxInfo(self) -> int:
        """Get maximum information content of range in bits."""
        sz = self.getSize()
        if sz == 0:
            return 0
        bits = 0
        while sz > 1:
            sz >>= 1
            bits += 1
        return bits

    def __eq__(self, other) -> bool:
        if not isinstance(other, CircleRange):
            return NotImplemented
        if self._isempty and other._isempty:
            return True
        if self._isempty != other._isempty:
            return False
        return (self._left == other._left and self._right == other._right and
                self._mask == other._mask and self._step == other._step)

    def getNext(self, val: int) -> Tuple[int, bool]:
        """Advance val by step. Returns (new_val, still_in_range)."""
        val = (val + self._step) & self._mask
        return val, val != self._right

    def contains(self, val_or_range) -> bool:
        """Check if a value or range is contained in this range."""
        if self._isempty:
            return False
        if isinstance(val_or_range, CircleRange):
            op2 = val_or_range
            if op2._isempty:
                return True
            if self.isFull():
                return True
            if self._left < self._right:
                if op2._left < op2._right:
                    return op2._left >= self._left and op2._right <= self._right
                return False
            else:
                if op2._left < op2._right:
                    return op2._left >= self._left or op2._right <= self._right
                return op2._left >= self._left and op2._right <= self._right
        else:
            val = val_or_range & self._mask
            if self._left == self._right:
                return True
            if self._left < self._right:
                return self._left <= val < self._right
            return val >= self._left or val < self._right

    def intersect(self, op2: CircleRange) -> int:
        """Intersect this with another range. Returns 0 on success, 1 if result is 2 pieces, 2 if empty."""
        if self._isempty or op2._isempty:
            self._isempty = True
            return 2
        if op2.isFull():
            return 0
        if self.isFull():
            self._left = op2._left
            self._right = op2._right
            self._mask = op2._mask
            self._step = op2._step
            self._isempty = op2._isempty
            return 0
        # Simple intersection for non-wrapping ranges
        if self._left < self._right and op2._left < op2._right:
            newleft = max(self._left, op2._left)
            newright = min(self._right, op2._right)
            if newleft >= newright:
                self._isempty = True
                return 2
            self._left = newleft
            self._right = newright
            return 0
        # For wrapping ranges, use a conservative approach
        if self.contains(op2):
            self._left = op2._left
            self._right = op2._right
            return 0
        if op2.contains(self):
            return 0
        # Approximate: keep self unchanged
        return 1

    def circleUnion(self, op2: CircleRange) -> int:
        """Union two ranges. Returns 0 on success, 1 if result is approximate."""
        if self._isempty:
            self._left = op2._left
            self._right = op2._right
            self._mask = op2._mask
            self._step = op2._step
            self._isempty = op2._isempty
            return 0
        if op2._isempty:
            return 0
        if self.isFull() or op2.isFull():
            self._left = 0
            self._right = 0
            return 0
        # Simple union for adjacent/overlapping non-wrapping ranges
        if self._left < self._right and op2._left < op2._right:
            if op2._left <= self._right and self._left <= op2._right:
                self._left = min(self._left, op2._left)
                self._right = max(self._right, op2._right)
                return 0
        # Make full range as conservative union
        self._left = 0
        self._right = 0
        return 1

    def invert(self) -> int:
        """Convert to complementary range. Returns 0 on success."""
        if self._isempty:
            self._left = 0
            self._right = 0
            self._isempty = False
            return 0
        if self.isFull():
            self._isempty = True
            return 0
        self._left, self._right = self._right, self._left
        return 0

    def setStride(self, newStep: int, rem: int) -> None:
        """Set a new step on this range."""
        self._step = newStep
        if not self._isempty:
            self._left = (self._left & ~(newStep - 1)) | (rem & (newStep - 1))
            self._left &= self._mask

    def setNZMask(self, nzmask: int, size: int) -> bool:
        """Set the range based on a non-zero mask."""
        self._mask = calc_mask(size)
        self._step = 1
        self._isempty = False
        if nzmask == 0:
            self._left = 0
            self._right = 1
            return True
        self._left = 0
        self._right = (nzmask + 1) & self._mask
        if self._right == 0:
            self._right = 0  # Full range
        return True

    def pullBackUnary(self, opc: int, inSize: int, outSize: int) -> bool:
        """Pull-back this range through a unary operator."""
        if opc == OpCode.CPUI_INT_ZEXT:
            if inSize < outSize:
                inMask = calc_mask(inSize)
                if self._right <= inMask + 1:
                    self._mask = inMask
                    return True
            return False
        elif opc == OpCode.CPUI_INT_SEXT:
            return True
        elif opc == OpCode.CPUI_INT_2COMP:
            if self._isempty:
                return True
            newleft = (-self.getMax()) & self._mask
            newright = ((-self._left) + 1) & self._mask
            self._left = newleft
            self._right = newright
            return True
        elif opc == OpCode.CPUI_INT_NEGATE:
            newleft = (~self.getMax()) & self._mask
            newright = ((~self._left) + 1) & self._mask
            self._left = newleft
            self._right = newright
            return True
        elif opc == OpCode.CPUI_COPY:
            return True
        return False

    def pullBackBinary(self, opc: int, val: int, slot: int,
                       inSize: int, outSize: int) -> bool:
        """Pull-back this range through a binary operator with one constant input."""
        if opc == OpCode.CPUI_INT_ADD:
            shift = (-val) & self._mask
            self._left = (self._left + shift) & self._mask
            self._right = (self._right + shift) & self._mask
            return True
        elif opc == OpCode.CPUI_INT_SUB:
            if slot == 1:
                self._left = (self._left + val) & self._mask
                self._right = (self._right + val) & self._mask
            else:
                newleft = (val - self.getMax()) & self._mask
                newright = ((val - self._left) + 1) & self._mask
                self._left = newleft
                self._right = newright
            return True
        elif opc == OpCode.CPUI_INT_AND:
            if slot == 1:
                return self.setNZMask(val, inSize)
            return False
        elif opc == OpCode.CPUI_INT_LEFT:
            if slot == 1 and val < inSize * 8:
                self._left = (self._left >> val) & self._mask
                self._right = ((self._right - 1) >> val) + 1
                self._right &= self._mask
                return True
            return False
        elif opc == OpCode.CPUI_INT_RIGHT:
            if slot == 1 and val < inSize * 8:
                self._left = (self._left << val) & self._mask
                self._right = (self._right << val) & self._mask
                return True
            return False
        return False

    def translate2Op(self) -> Tuple[int, int, int]:
        """Translate range to a comparison op. Returns (opcode, constant, slot)."""
        if self._isempty:
            return (OpCode.CPUI_MAX, 0, 0)
        if self.isFull():
            return (OpCode.CPUI_MAX, 0, 0)
        if self._left == 0:
            return (OpCode.CPUI_INT_LESS, self._right, 1)
        if self._right == 0:
            return (OpCode.CPUI_INT_LESSEQUAL, self.getMax(), 1)
        return (OpCode.CPUI_MAX, 0, 0)

    def complement(self) -> None:
        """Set this to the complement of itself."""
        if self._isempty:
            self._left = 0
            self._right = 0
            self._isempty = False
            return
        if self.isFull():
            self._isempty = True
            return
        self._left, self._right = self._right, self._left

    def convertToBoolean(self) -> bool:
        """Convert this to boolean. Returns True if successful."""
        if self._isempty:
            return False
        if self.isSingle():
            val = self._left
            if val == 0 or val == 1:
                self._mask = 0xFF
                self._step = 1
                return True
        return False

    def minimalContainer(self, op2: CircleRange, maxStep: int) -> bool:
        """Construct minimal range that contains both this and another range."""
        if self._isempty:
            self._left = op2._left
            self._right = op2._right
            self._mask = op2._mask
            self._step = op2._step
            self._isempty = op2._isempty
            return True
        if op2._isempty:
            return True
        # Conservative: just take the union
        self.circleUnion(op2)
        return True

    def widen(self, op2: CircleRange, leftIsStable: bool) -> None:
        """Widen the unstable bound to match containing range."""
        if self._isempty:
            self._left = op2._left
            self._right = op2._right
            self._mask = op2._mask
            self._step = op2._step
            self._isempty = op2._isempty
            return
        if op2._isempty:
            return
        if leftIsStable:
            self._right = op2._right
        else:
            self._left = op2._left

    def pushForwardUnary(self, opc: int, in1: CircleRange, inSize: int, outSize: int) -> bool:
        """Push-forward through given unary operator."""
        if opc == OpCode.CPUI_COPY:
            self._left = in1._left
            self._right = in1._right
            self._mask = in1._mask
            self._step = in1._step
            self._isempty = in1._isempty
            return True
        elif opc == OpCode.CPUI_INT_ZEXT:
            self._mask = calc_mask(outSize)
            self._step = in1._step
            self._left = in1._left
            self._right = in1._right
            self._isempty = in1._isempty
            return True
        elif opc == OpCode.CPUI_INT_SEXT:
            self._mask = calc_mask(outSize)
            self._step = in1._step
            self._left = in1._left
            self._right = in1._right
            self._isempty = in1._isempty
            return True
        elif opc == OpCode.CPUI_INT_2COMP:
            if in1._isempty:
                self._isempty = True
                return True
            self._mask = in1._mask
            self._step = in1._step
            self._left = (-in1.getMax()) & self._mask
            self._right = ((-in1._left) + 1) & self._mask
            self._isempty = False
            return True
        elif opc == OpCode.CPUI_INT_NEGATE:
            if in1._isempty:
                self._isempty = True
                return True
            self._mask = in1._mask
            self._step = in1._step
            self._left = (~in1.getMax()) & self._mask
            self._right = ((~in1._left) + 1) & self._mask
            self._isempty = False
            return True
        elif opc == OpCode.CPUI_BOOL_NEGATE:
            if in1._isempty:
                self._isempty = True
                return True
            self._mask = 0xFF
            self._step = 1
            if in1.isSingle():
                val = 0 if in1._left != 0 else 1
                self._left = val
                self._right = (val + 1) & self._mask
            else:
                self._left = 0
                self._right = 2
            self._isempty = False
            return True
        return False

    def pushForwardBinary(self, opc: int, in1: CircleRange, in2: CircleRange,
                          inSize: int, outSize: int, maxStep: int) -> bool:
        """Push-forward through given binary operator."""
        if in1._isempty or in2._isempty:
            self._isempty = True
            return True
        if opc == OpCode.CPUI_INT_ADD:
            self._mask = calc_mask(outSize)
            self._step = max(in1._step, in2._step)
            if in1.isSingle() and in2.isSingle():
                val = (in1._left + in2._left) & self._mask
                self._left = val
                self._right = (val + self._step) & self._mask
            else:
                self._left = (in1._left + in2._left) & self._mask
                self._right = (in1._right + in2._right - 1) & self._mask
            self._isempty = False
            return True
        elif opc == OpCode.CPUI_INT_SUB:
            self._mask = calc_mask(outSize)
            self._step = max(in1._step, in2._step)
            if in1.isSingle() and in2.isSingle():
                val = (in1._left - in2._left) & self._mask
                self._left = val
                self._right = (val + self._step) & self._mask
            else:
                self.setFull(outSize)
            self._isempty = False
            return True
        elif opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            if in1.isSingle() and in2.isSingle():
                self._mask = calc_mask(outSize)
                self._step = 1
                if opc == OpCode.CPUI_INT_AND:
                    val = in1._left & in2._left
                elif opc == OpCode.CPUI_INT_OR:
                    val = in1._left | in2._left
                else:
                    val = in1._left ^ in2._left
                val &= self._mask
                self._left = val
                self._right = (val + 1) & self._mask
                self._isempty = False
                return True
            self.setFull(outSize)
            return True
        return False

    def pushForwardTrinary(self, opc: int, in1: CircleRange, in2: CircleRange,
                           in3: CircleRange, inSize: int, outSize: int, maxStep: int) -> bool:
        """Push-forward through given ternary operator."""
        return False

    def printRaw(self) -> str:
        if self._isempty:
            return "(empty)"
        if self.isFull():
            return "(full)"
        return f"[0x{self._left:x},0x{self._right:x})"

    def __repr__(self) -> str:
        return f"CircleRange({self.printRaw()})"


# =========================================================================
# ValueSet and related classes
# =========================================================================

class ValueSet:
    """A range of values attached to a Varnode within a data-flow subsystem."""
    MAX_STEP = 32

    class Equation:
        """An external constraint that can be applied to a ValueSet."""
        def __init__(self, slot: int = 0, typeCode: int = 0, rng: CircleRange = None):
            self.slot = slot
            self.typeCode = typeCode
            self.range = rng if rng is not None else CircleRange()

    def __init__(self) -> None:
        self.typeCode: int = 0
        self.numParams: int = 0
        self.count: int = 0
        self.opCode = OpCode.CPUI_COPY
        self.leftIsStable: bool = True
        self.rightIsStable: bool = True
        self.vn = None
        self.range: CircleRange = CircleRange()
        self.equations: list = []
        self.partHead = None
        self.next = None

    def getCount(self) -> int:
        return self.count

    def getTypeCode(self) -> int:
        return self.typeCode

    def getVarnode(self):
        return self.vn

    def getRange(self) -> CircleRange:
        return self.range

    def isLeftStable(self) -> bool:
        return self.leftIsStable

    def isRightStable(self) -> bool:
        return self.rightIsStable

    def getLandMark(self):
        """Get any landmark range."""
        for eq in self.equations:
            if eq.slot == self.numParams:
                return eq.range
        return None

    def setVarnode(self, v, tCode: int) -> None:
        self.vn = v
        self.typeCode = tCode
        if v is not None:
            self.range.setFull(v.getSize())
            v.setValueSet(self)

    def setFull(self) -> None:
        if self.vn is not None:
            self.range.setFull(self.vn.getSize())
        self.typeCode = 0

    def addEquation(self, slot: int, typeCode: int, constraint: CircleRange) -> None:
        self.equations.append(ValueSet.Equation(slot, typeCode, constraint))

    def addLandmark(self, typeCode: int, constraint: CircleRange) -> None:
        self.addEquation(self.numParams, typeCode, constraint)

    def printRaw(self) -> str:
        return f"ValueSet({self.range.printRaw()}, type={self.typeCode})"


class ValueSetRead:
    """A special form of ValueSet associated with the read point of a Varnode."""

    def __init__(self) -> None:
        self.typeCode: int = 0
        self.slot: int = 0
        self.op = None
        self.range: CircleRange = CircleRange()
        self.equationConstraint: CircleRange = CircleRange()
        self.equationTypeCode: int = 0
        self.leftIsStable: bool = True
        self.rightIsStable: bool = True

    def getTypeCode(self) -> int:
        return self.typeCode

    def getRange(self) -> CircleRange:
        return self.range

    def isLeftStable(self) -> bool:
        return self.leftIsStable

    def isRightStable(self) -> bool:
        return self.rightIsStable

    def setPcodeOp(self, o, slt: int) -> None:
        self.op = o
        self.slot = slt

    def addEquation(self, slt: int, typeCode: int, constraint: CircleRange) -> None:
        self.equationTypeCode = typeCode
        self.equationConstraint = constraint

    def compute(self) -> None:
        """Compute this value set from the underlying Varnode's ValueSet."""
        if self.op is None:
            return
        invn = self.op.getIn(self.slot) if self.slot < self.op.numInput() else None
        if invn is not None and invn.getValueSet() is not None:
            vs = invn.getValueSet()
            self.range = CircleRange(vs.range._left, vs.range._right,
                                     invn.getSize(), vs.range._step)
            self.typeCode = vs.typeCode
            self.leftIsStable = vs.leftIsStable
            self.rightIsStable = vs.rightIsStable

    def printRaw(self) -> str:
        return f"ValueSetRead({self.range.printRaw()})"


class Partition:
    """A range of nodes (within the weak topological ordering) that are iterated together."""

    def __init__(self) -> None:
        self.startNode = None
        self.stopNode = None
        self.isDirty: bool = False

    def getStartNode(self):
        return self.startNode

    def getStopNode(self):
        return self.stopNode

    def setStartNode(self, node) -> None:
        self.startNode = node

    def setStopNode(self, node) -> None:
        self.stopNode = node

    def markDirty(self) -> None:
        self.isDirty = True

    def clear(self) -> None:
        self.startNode = None
        self.stopNode = None
        self.isDirty = False


class Widener:
    """Class holding a particular widening strategy for the ValueSetSolver iteration."""

    def determineIterationReset(self, valueSet: ValueSet) -> int:
        return 0

    def checkFreeze(self, valueSet: ValueSet) -> bool:
        return False

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        return False


class WidenerFull(Widener):
    """Class for doing normal widening."""

    def __init__(self, wide: int = 2, full: int = 5) -> None:
        self._widenIteration: int = wide
        self._fullIteration: int = full

    def determineIterationReset(self, valueSet: ValueSet) -> int:
        return 0

    def checkFreeze(self, valueSet: ValueSet) -> bool:
        return valueSet.count > self._fullIteration

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        if valueSet.count < self._widenIteration:
            return False
        landmark = valueSet.getLandMark()
        if landmark is not None:
            rng.widen(newRange, valueSet.leftIsStable)
            return True
        if valueSet.vn is not None:
            rng.setFull(valueSet.vn.getSize())
        return True


class WidenerNone(Widener):
    """Class for freezing value sets at a specific iteration."""

    def __init__(self, freeze: int = 3) -> None:
        self._freezeIteration: int = freeze

    def determineIterationReset(self, valueSet: ValueSet) -> int:
        return 0

    def checkFreeze(self, valueSet: ValueSet) -> bool:
        return valueSet.count >= self._freezeIteration

    def doWidening(self, valueSet: ValueSet, rng: CircleRange, newRange: CircleRange) -> bool:
        return False


class ValueSetSolver:
    """Class that determines a ValueSet for each Varnode in a data-flow system."""

    def __init__(self) -> None:
        self._valueNodes: list = []
        self._readNodes: dict = {}
        self._orderPartition = Partition()
        self._rootNodes: list = []
        self._depthFirstIndex: int = 0
        self._numIterations: int = 0
        self._maxIterations: int = 0

    def getNumIterations(self) -> int:
        return self._numIterations

    def establishValueSets(self, sinks: list, reads: list, stackReg=None,
                           indirectAsCopy: bool = False) -> None:
        """Build the system of ValueSets from the given sinks."""
        for vn in sinks:
            if vn is None:
                continue
            vs = ValueSet()
            vs.setVarnode(vn, 0)
            self._valueNodes.append(vs)
        for op in reads:
            if op is None:
                continue
            seq = op.getSeqNum()
            vsr = ValueSetRead()
            vsr.setPcodeOp(op, 1)
            self._readNodes[seq] = vsr

    def solve(self, maxIter: int, widener: Widener) -> None:
        """Iterate the ValueSet system until it stabilizes."""
        self._maxIterations = maxIter
        self._numIterations = 0
        # Simple fixed-point iteration
        changed = True
        while changed and self._numIterations < self._maxIterations:
            changed = False
            self._numIterations += 1
            for vs in self._valueNodes:
                vs.count += 1
                if widener.checkFreeze(vs):
                    continue
                # Would compute new range from op inputs here
        # Compute read nodes
        for seq, vsr in self._readNodes.items():
            vsr.compute()

    def getValueSetRead(self, seq):
        """Get ValueSetRead by SeqNum."""
        return self._readNodes.get(seq, ValueSetRead())

    def beginValueSets(self):
        return iter(self._valueNodes)

    def endValueSets(self):
        return None

    def beginValueSetReads(self):
        return iter(self._readNodes.items())

    def endValueSetReads(self):
        return None
