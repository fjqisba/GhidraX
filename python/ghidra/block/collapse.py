"""
CollapseStructure: Control-flow structuring algorithm.
Corresponds to CollapseStructure in blockaction.cc.

Repeatedly matches sub-graphs to structured code patterns
(if/else, while, do-while, switch, sequence) and collapses them.
"""
from __future__ import annotations
from typing import List, Optional
from ghidra.block.block import (
    FlowBlock, BlockBasic, BlockGraph, BlockCopy, BlockGoto,
    BlockCondition, BlockIf, BlockWhileDo, BlockDoWhile,
    BlockInfLoop, BlockSwitch, BlockList,
)


class CollapseStructure:
    """Build structured code from a control-flow graph."""

    def __init__(self, graph: BlockGraph) -> None:
        self._graph = graph
        self._changecount = 0

    def getChangeCount(self) -> int:
        return self._changecount

    # --- Rule: BlockGoto ---
    def _ruleBlockGoto(self, bl: FlowBlock) -> bool:
        """Single out-edge marked as goto → wrap in BlockGoto."""
        if bl.sizeOut() != 1:
            return False
        if not self._isGotoOut(bl, 0):
            return False
        target = bl.getOut(0)
        self._graph.newBlockGoto(bl, target)
        return True

    # --- Rule: BlockCat (sequence) ---
    def _ruleBlockCat(self, bl: FlowBlock) -> bool:
        """Two blocks in sequence (bl→next, next has single in) → BlockList."""
        if bl.sizeOut() != 1:
            return False
        if self._isGotoOut(bl, 0):
            return False
        nextbl = bl.getOut(0)
        if nextbl.sizeIn() != 1:
            return False
        if nextbl is bl:
            return False
        self._graph.newBlockList([bl, nextbl])
        return True

    # --- Rule: ProperIf (if/then with exit) ---
    def _ruleBlockProperIf(self, bl: FlowBlock) -> bool:
        """CBRANCH with one arm going to a block that merges back."""
        if bl.sizeOut() != 2:
            return False
        if self._isGotoOut(bl, 0) or self._isGotoOut(bl, 1):
            return False
        out0 = bl.getOut(0)
        out1 = bl.getOut(1)
        # Check: one arm is a simple block that exits to the other arm
        if out0.sizeOut() == 1 and out0.getOut(0) is out1 and out0.sizeIn() == 1:
            self._graph.newBlockIf(bl, out0, None)
            return True
        if out1.sizeOut() == 1 and out1.getOut(0) is out0 and out1.sizeIn() == 1:
            # Need to swap edges so "true" branch is the body
            bl.swapEdges()
            self._graph.newBlockIf(bl, out1, None)
            return True
        return False

    # --- Rule: IfElse ---
    def _ruleBlockIfElse(self, bl: FlowBlock) -> bool:
        """CBRANCH with both arms merging to same exit."""
        if bl.sizeOut() != 2:
            return False
        if self._isGotoOut(bl, 0) or self._isGotoOut(bl, 1):
            return False
        out0 = bl.getOut(0)
        out1 = bl.getOut(1)
        if out0.sizeIn() != 1 or out1.sizeIn() != 1:
            return False
        if out0.sizeOut() != 1 or out1.sizeOut() != 1:
            return False
        if out0.getOut(0) is not out1.getOut(0):
            return False
        if self._isGotoOut(out0, 0) or self._isGotoOut(out1, 0):
            return False
        self._graph.newBlockIf(bl, out1, out0)
        return True

    # --- Rule: WhileDo ---
    def _ruleBlockWhileDo(self, bl: FlowBlock) -> bool:
        """CBRANCH where one arm loops back to bl."""
        if bl.sizeOut() != 2:
            return False
        out0 = bl.getOut(0)
        out1 = bl.getOut(1)
        if out0 is bl and out1 is not bl:
            if not self._isGotoOut(bl, 0):
                self._graph.newBlockWhileDo(bl)
                return True
        if out1 is bl and out0 is not bl:
            if not self._isGotoOut(bl, 1):
                bl.swapEdges()
                self._graph.newBlockWhileDo(bl)
                return True
        return False

    # --- Rule: DoWhile ---
    def _ruleBlockDoWhile(self, bl: FlowBlock) -> bool:
        """Block with single in, CBRANCH where one out loops back to in."""
        if bl.sizeOut() != 2 or bl.sizeIn() != 1:
            return False
        out0 = bl.getOut(0)
        out1 = bl.getOut(1)
        inbl = bl.getIn(0)
        if out0 is inbl and not self._isGotoOut(bl, 0):
            return False  # TODO: need more complex check
        if out1 is inbl and not self._isGotoOut(bl, 1):
            return False
        return False

    # --- Rule: InfLoop ---
    def _ruleBlockInfLoop(self, bl: FlowBlock) -> bool:
        """Single out-edge back to itself → infinite loop."""
        if bl.sizeOut() != 1:
            return False
        if bl.getOut(0) is not bl:
            return False
        self._graph.newBlockInfLoop(bl)
        return True

    # --- Rule: IfNoExit ---
    def _ruleBlockIfNoExit(self, bl: FlowBlock) -> bool:
        """CBRANCH where one arm has no exit."""
        if bl.sizeOut() != 2:
            return False
        out0 = bl.getOut(0)
        out1 = bl.getOut(1)
        if out0.sizeOut() == 0 and out0.sizeIn() == 1 and not self._isGotoOut(bl, 0):
            self._graph.newBlockIf(bl, out0, None)
            return True
        if out1.sizeOut() == 0 and out1.sizeIn() == 1 and not self._isGotoOut(bl, 1):
            bl.swapEdges()
            self._graph.newBlockIf(bl, out1, None)
            return True
        return False

    # --- Helper ---
    @staticmethod
    def _isGotoOut(bl: FlowBlock, i: int) -> bool:
        return (bl._outofthis[i].label & FlowBlock.f_goto_edge) != 0 if i < len(bl._outofthis) else False

    # --- Main collapse loop ---
    def _collapseInternal(self) -> int:
        isolated = 0
        changed = True
        while changed:
            changed = False
            i = 0
            isolated = 0
            while i < self._graph.getSize():
                bl = self._graph.getBlock(i)
                if bl.sizeIn() == 0 and bl.sizeOut() == 0:
                    isolated += 1
                    i += 1
                    continue
                if self._ruleBlockGoto(bl):
                    changed = True; continue
                if self._ruleBlockCat(bl):
                    changed = True; continue
                if self._ruleBlockProperIf(bl):
                    changed = True; continue
                if self._ruleBlockIfElse(bl):
                    changed = True; continue
                if self._ruleBlockWhileDo(bl):
                    changed = True; continue
                if self._ruleBlockInfLoop(bl):
                    changed = True; continue
                i += 1
            # Try IfNoExit as fallback
            for j in range(self._graph.getSize()):
                bl = self._graph.getBlock(j)
                if self._ruleBlockIfNoExit(bl):
                    changed = True
                    break
        return isolated

    def collapseAll(self) -> None:
        """Run the full structuring algorithm."""
        isolated = self._collapseInternal()
        attempts = 0
        while isolated < self._graph.getSize() and attempts < 100:
            # If stuck, mark an edge as goto and try again
            found = False
            for i in range(self._graph.getSize()):
                bl = self._graph.getBlock(i)
                if bl.sizeOut() > 0 and bl.sizeIn() > 0:
                    bl.setOutEdgeFlag(0, FlowBlock.f_goto_edge)
                    found = True
                    self._changecount += 1
                    break
            if not found:
                break
            isolated = self._collapseInternal()
            attempts += 1
