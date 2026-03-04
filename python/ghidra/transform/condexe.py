"""
ConditionalExecution: Simplify control-flow with shared conditional expressions.
Corresponds to condexe.hh / condexe.cc.

Handles patterns where two CBRANCHs branch on the same (or complementary) condition,
eliminating the redundant evaluation.
"""
from __future__ import annotations
from typing import Optional, TYPE_CHECKING
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.block.block import BlockBasic
    from ghidra.ir.op import PcodeOp
    from ghidra.analysis.funcdata import Funcdata


class ConditionalExecution:
    """Identify and remove redundant conditional branches."""

    def __init__(self, fd: Funcdata) -> None:
        self._fd = fd
        self._cbranch: Optional[PcodeOp] = None
        self._initblock: Optional[BlockBasic] = None
        self._iblock: Optional[BlockBasic] = None
        self._prea_inslot: int = 0
        self._init2a_true: bool = False
        self._iblock2posta_true: bool = False

    def _testIBlock(self) -> bool:
        """Test basic requirements: 2 in, 2 out, ends with CBRANCH."""
        if self._iblock.sizeIn() != 2:
            return False
        if self._iblock.sizeOut() != 2:
            return False
        self._cbranch = self._iblock.lastOp()
        if self._cbranch is None:
            return False
        if self._cbranch.code() != OpCode.CPUI_CBRANCH:
            return False
        return True

    def _findInitPre(self) -> bool:
        """Find the initblock that originally evaluates the boolean."""
        for slot in range(2):
            self._prea_inslot = slot
            tmp = self._iblock.getIn(slot)
            last = self._iblock
            while tmp.sizeOut() == 1 and tmp.sizeIn() == 1:
                last = tmp
                tmp = tmp.getIn(0)
            if tmp.sizeOut() != 2:
                continue
            self._initblock = tmp
            # Check other path also comes from initblock
            other = self._iblock.getIn(1 - slot)
            while other.sizeOut() == 1 and other.sizeIn() == 1:
                other = other.getIn(0)
            if other is not self._initblock:
                continue
            if self._initblock is self._iblock:
                continue
            self._init2a_true = (self._initblock.getTrueOut() is last)
            return True
        return False

    def _verifySameCondition(self) -> bool:
        """Verify initblock and iblock branch on same/complementary condition."""
        init_cbranch = self._initblock.lastOp()
        if init_cbranch is None:
            return False
        if init_cbranch.code() != OpCode.CPUI_CBRANCH:
            return False
        # Check if the boolean inputs are the same Varnode
        ibool = self._cbranch.getIn(1)
        initbool = init_cbranch.getIn(1)
        if ibool is initbool:
            return True
        # Check if one is written by the same defining op
        if ibool.isWritten() and initbool.isWritten():
            if ibool.getDef() is initbool.getDef():
                return True
        # Check through COPY chains
        while ibool.isWritten() and ibool.getDef().code() == OpCode.CPUI_COPY:
            ibool = ibool.getDef().getIn(0)
        while initbool.isWritten() and initbool.getDef().code() == OpCode.CPUI_COPY:
            initbool = initbool.getDef().getIn(0)
        if ibool is initbool:
            return True
        return False

    def _testRemovability(self) -> bool:
        """Test if iblock can be safely removed."""
        if not hasattr(self._iblock, 'getOpList'):
            return False
        for op in self._iblock.getOpList():
            if op is self._cbranch:
                continue
            opc = op.code()
            if opc == OpCode.CPUI_MULTIEQUAL:
                continue
            if opc == OpCode.CPUI_COPY:
                continue
            return False  # Non-trivial op blocks removal
        return True

    def trial(self, ib) -> bool:
        """Test for a modifiable configuration around the given block."""
        self._iblock = ib
        if not self._testIBlock():
            return False
        if not self._findInitPre():
            return False
        if not self._verifySameCondition():
            return False
        if not self._testRemovability():
            return False
        return True

    def execute(self) -> None:
        """Eliminate the unnecessary path join at iblock."""
        # The core transform: remove the redundant CBRANCH in iblock
        # and redirect flow based on the initblock's condition
        self._fd.removeBranch(self._iblock, 1 if self._init2a_true else 0)
