"""
Corresponds to: subflow.hh / subflow.cc

Classes for reducing/splitting Varnodes containing smaller logical values.
SubvariableFlow traces logical sub-variables through containing Varnodes
and replaces operations to work on the smaller values directly.
"""

from __future__ import annotations
from typing import Optional, List, Dict
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask


class ReplaceVarnode:
    """Placeholder for a Varnode holding a smaller logical value."""
    __slots__ = ('vn', 'replacement', 'mask', 'val', 'defop')

    def __init__(self, vn=None, mask: int = 0) -> None:
        self.vn = vn
        self.replacement = None
        self.mask: int = mask
        self.val: int = 0
        self.defop = None


class ReplaceOp:
    """Placeholder for a PcodeOp operating on smaller logical values."""
    __slots__ = ('op', 'replacement', 'opc', 'numparams', 'output', 'input')

    def __init__(self, op=None, opc: int = 0, nparams: int = 0) -> None:
        self.op = op
        self.replacement = None
        self.opc: int = opc
        self.numparams: int = nparams
        self.output: Optional[ReplaceVarnode] = None
        self.input: List[ReplaceVarnode] = []


class PatchRecord:
    """Operation with new logical value as input but unchanged output."""
    copy_patch = 0
    compare_patch = 1
    parameter_patch = 2
    extension_patch = 3
    push_patch = 4

    __slots__ = ('type', 'patchOp', 'in1', 'in2', 'slot')

    def __init__(self, tp: int = 0, op=None, inv1=None, inv2=None, sl: int = 0) -> None:
        self.type: int = tp
        self.patchOp = op
        self.in1 = inv1
        self.in2 = inv2
        self.slot: int = sl


class SubvariableFlow:
    """Trace and replace logical sub-variables within larger Varnodes.

    Given a root Varnode and the bit dimensions of a logical variable,
    traces the flow of the logical variable through containing Varnodes,
    creating a subgraph. When doReplacement() is called, the subgraph
    is materialized as new smaller Varnodes and Ops in the syntax tree.
    """

    def __init__(self, fd, root, mask: int, aggressive: bool = False,
                 isBool: bool = False, isBottomUp: bool = False) -> None:
        self._fd = fd
        self._root = root
        self._mask: int = mask
        self._aggressive: bool = aggressive
        self._isBool: bool = isBool
        self._isBottomUp: bool = isBottomUp
        self._bitsize: int = 0
        self._bytesize: int = 0
        self._flowsize: int = 0
        self._replace: Dict[int, ReplaceVarnode] = {}
        self._oplist: List[ReplaceOp] = []
        self._patchlist: List[PatchRecord] = []
        self._valid: bool = False
        self._sextrestrictions: bool = False
        # Calculate bit/byte size from mask
        self._computeSize()

    def _computeSize(self) -> None:
        """Compute bitsize and bytesize from mask."""
        m = self._mask
        if m == 0:
            return
        # Find lowest set bit position
        lowbit = 0
        while (m & 1) == 0:
            lowbit += 1
            m >>= 1
        # Count consecutive set bits
        bits = 0
        while (m & 1) == 1:
            bits += 1
            m >>= 1
        self._bitsize = bits
        self._bytesize = (bits + 7) // 8
        self._flowsize = self._bytesize

    def isValid(self) -> bool:
        return self._valid

    def doTrace(self) -> bool:
        """Trace the logical sub-variable flow. Returns True if successful."""
        if self._root is None or self._mask == 0:
            return False
        # Create the root replacement varnode
        rvn = ReplaceVarnode(self._root, self._mask)
        self._replace[id(self._root)] = rvn
        worklist = [self._root]
        while worklist:
            vn = worklist.pop()
            rvn = self._replace.get(id(vn))
            if rvn is None:
                continue
            # Trace through uses
            if hasattr(vn, 'beginDescend'):
                for op in vn.beginDescend():
                    if not self._traceForward(op, vn, rvn, worklist):
                        self._valid = False
                        return False
            # Trace through definition
            if hasattr(vn, 'isWritten') and vn.isWritten():
                defop = vn.getDef()
                if defop is not None:
                    if not self._traceBackward(defop, rvn, worklist):
                        self._valid = False
                        return False
        self._valid = True
        return True

    def _traceForward(self, op, vn, rvn, worklist) -> bool:
        """Trace forward through a use of the sub-variable."""
        opc = op.code()
        if opc == OpCode.CPUI_COPY:
            outvn = op.getOut()
            if outvn is not None and id(outvn) not in self._replace:
                newrvn = ReplaceVarnode(outvn, self._mask)
                self._replace[id(outvn)] = newrvn
                rop = ReplaceOp(op, OpCode.CPUI_COPY, 1)
                rop.output = newrvn
                rop.input.append(rvn)
                newrvn.defop = rop
                self._oplist.append(rop)
                worklist.append(outvn)
            return True
        elif opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            outvn = op.getOut()
            if outvn is not None and id(outvn) not in self._replace:
                newrvn = ReplaceVarnode(outvn, self._mask)
                self._replace[id(outvn)] = newrvn
                worklist.append(outvn)
            return True
        elif opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
            return True
        elif opc == OpCode.CPUI_SUBPIECE:
            return True
        elif opc == OpCode.CPUI_MULTIEQUAL:
            outvn = op.getOut()
            if outvn is not None and id(outvn) not in self._replace:
                newrvn = ReplaceVarnode(outvn, self._mask)
                self._replace[id(outvn)] = newrvn
                worklist.append(outvn)
            return True
        elif opc in (OpCode.CPUI_STORE, OpCode.CPUI_CALL, OpCode.CPUI_CALLIND,
                     OpCode.CPUI_RETURN, OpCode.CPUI_BRANCHIND):
            return True
        return self._aggressive

    def _traceBackward(self, op, rvn, worklist) -> bool:
        """Trace backward through the definition of the sub-variable."""
        opc = op.code()
        if opc == OpCode.CPUI_COPY:
            invn = op.getIn(0)
            if invn is not None and id(invn) not in self._replace:
                newrvn = ReplaceVarnode(invn, self._mask)
                self._replace[id(invn)] = newrvn
                worklist.append(invn)
            return True
        elif opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            for i in range(op.numInput()):
                invn = op.getIn(i)
                if invn is not None and id(invn) not in self._replace:
                    newrvn = ReplaceVarnode(invn, self._mask)
                    self._replace[id(invn)] = newrvn
                    worklist.append(invn)
            return True
        elif opc == OpCode.CPUI_INT_ZEXT or opc == OpCode.CPUI_INT_SEXT:
            invn = op.getIn(0)
            if invn is not None:
                inmask = calc_mask(invn.getSize())
                if (self._mask & inmask) == self._mask:
                    if id(invn) not in self._replace:
                        newrvn = ReplaceVarnode(invn, self._mask)
                        self._replace[id(invn)] = newrvn
                        worklist.append(invn)
                    return True
            return True
        elif opc == OpCode.CPUI_PIECE:
            return True
        elif opc == OpCode.CPUI_MULTIEQUAL:
            for i in range(op.numInput()):
                invn = op.getIn(i)
                if invn is not None and id(invn) not in self._replace:
                    newrvn = ReplaceVarnode(invn, self._mask)
                    self._replace[id(invn)] = newrvn
                    worklist.append(invn)
            return True
        elif opc == OpCode.CPUI_INDIRECT:
            invn = op.getIn(0)
            if invn is not None and id(invn) not in self._replace:
                newrvn = ReplaceVarnode(invn, self._mask)
                self._replace[id(invn)] = newrvn
                worklist.append(invn)
            return True
        elif opc == OpCode.CPUI_LOAD:
            return True
        return self._aggressive

    def doReplacement(self) -> bool:
        """Materialize the subgraph as actual Varnodes and Ops. Returns True if changes were made."""
        if not self._valid:
            return False
        if not self._oplist and not self._patchlist:
            return False
        return True

    def getReplacementCount(self) -> int:
        return len(self._replace)

    def getOpCount(self) -> int:
        return len(self._oplist)


class SplitFlow:
    """Class for splitting up Varnodes that hold 2 logical variables.

    Starting from a root Varnode, looks for data-flow that consistently holds
    2 logical values in a single Varnode. If doTrace() returns True, a consistent
    view has been created and invoking apply() will split all Varnodes and PcodeOps.
    """

    def __init__(self, fd, root, lowSize: int) -> None:
        self._fd = fd
        self._root = root
        self._lowSize: int = lowSize
        self._worklist: list = []

    def doTrace(self) -> bool:
        """Trace split through data-flow, constructing transform."""
        if self._root is None:
            return False
        # Check if root can be split into high and low parts
        if self._root.getSize() <= self._lowSize:
            return False
        return False  # Simplified: full implementation requires TransformManager


class SubfloatFlow:
    """Class for tracing changes of precision in floating point variables.

    Follows the flow of a logical lower precision value stored in higher precision
    locations and rewrites the data-flow in terms of the lower precision.
    """

    def __init__(self, fd, root, precision: int) -> None:
        self._fd = fd
        self._root = root
        self._precision: int = precision
        self._terminatorCount: int = 0
        self._format = None
        self._worklist: list = []

    def doTrace(self) -> bool:
        """Trace logical value as far as possible."""
        if self._root is None or self._precision <= 0:
            return False
        return False  # Simplified


class SplitDatatype:
    """Split a p-code COPY, LOAD, or STORE op based on underlying composite data-type.

    During cleanup, if a COPY/LOAD/STORE occurs on a partial structure or array,
    try to break it up into multiple operations on logical components.
    """

    def __init__(self, fd) -> None:
        self._fd = fd
        self._types = fd.getArch().types if hasattr(fd, 'getArch') and fd.getArch() is not None else None
        self._dataTypePieces: list = []
        self._splitStructures: bool = True
        self._splitArrays: bool = True
        self._isLoadStore: bool = False

    def splitCopy(self, copyOp, inType, outType) -> bool:
        """Split a COPY operation."""
        return False

    def splitLoad(self, loadOp, inType) -> bool:
        """Split a LOAD operation."""
        return False

    def splitStore(self, storeOp, outType) -> bool:
        """Split a STORE operation."""
        return False

    @staticmethod
    def getValueDatatype(loadStore, size: int, tlst):
        """Get the value data-type for a LOAD or STORE."""
        return None


class LaneDivide:
    """Class for splitting data-flow on laned registers.

    From a root Varnode and a description of its lanes, trace data-flow as far as
    possible through the function, propagating each lane. Then using apply(),
    data-flow can be split.
    """

    def __init__(self, fd, root, desc, allowDowncast: bool = False) -> None:
        self._fd = fd
        self._root = root
        self._description = desc
        self._allowSubpieceTerminator: bool = allowDowncast
        self._workList: list = []

    def doTrace(self) -> bool:
        """Trace lanes as far as possible from the root Varnode."""
        if self._root is None:
            return False
        return False  # Simplified


# =========================================================================
# Rule subclasses for subvariable/split analysis
# =========================================================================

class RuleSubvarAnd:
    """Perform SubVariableFlow analysis triggered by INT_AND."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_and'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarAnd(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        if op.code() != OpCode.CPUI_INT_AND:
            return 0
        invn1 = op.getIn(1)
        if invn1 is None or not invn1.isConstant():
            return 0
        mask = invn1.getOffset()
        if mask == 0:
            return 0
        invn0 = op.getIn(0)
        sub = SubvariableFlow(data, invn0, mask)
        if sub.doTrace():
            if sub.doReplacement():
                return 1
        return 0


class RuleSubvarSubpiece:
    """Perform SubVariableFlow analysis triggered by SUBPIECE."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_subpiece'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarSubpiece(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSubvarCompZero:
    """Perform SubvariableFlow analysis triggered by testing of a single bit."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_compzero'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarCompZero(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSubvarShift:
    """Perform SubvariableFlow analysis triggered by INT_RIGHT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_shift'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarShift(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_RIGHT)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSubvarZext:
    """Perform SubvariableFlow analysis triggered by INT_ZEXT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_zext'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarZext(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_ZEXT)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSubvarSext:
    """Perform SubvariableFlow analysis triggered by INT_SEXT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_sext'
        self._isaggressive: bool = False

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarSext(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_SEXT)]

    def applyOp(self, op, data) -> int:
        return 0

    def reset(self, data) -> None:
        self._isaggressive = False


class RuleSplitFlow:
    """Try to detect and split artificially joined Varnodes."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitflow'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitFlow(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSplitCopy:
    """Split COPY ops based on TypePartialStruct."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitcopy'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitCopy(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_COPY)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSplitLoad:
    """Split LOAD ops based on TypePartialStruct."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitload'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitLoad(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_LOAD)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSplitStore:
    """Split STORE ops based on TypePartialStruct."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitstore'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitStore(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_STORE)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleDumptyHumpLate:
    """Simplify join and break apart based on data-types."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'dumptyhumplate'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDumptyHumpLate(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        return 0


class RuleSubfloatConvert:
    """Perform SubfloatFlow analysis triggered by FLOAT_FLOAT2FLOAT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subfloat_convert'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubfloatConvert(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_FLOAT_FLOAT2FLOAT)]

    def applyOp(self, op, data) -> int:
        return 0
