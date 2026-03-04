"""
Corresponds to: block.hh / block.cc

Classes related to basic blocks and control-flow structuring.
Core classes: BlockEdge, FlowBlock, BlockBasic, BlockGraph, and structured block types.
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List, Dict

from ghidra.core.address import Address

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode


# =========================================================================
# BlockEdge
# =========================================================================

class BlockEdge:
    """A control-flow edge between blocks."""

    __slots__ = ('label', 'point', 'reverse_index')

    def __init__(self, pt: Optional[FlowBlock] = None, lab: int = 0, rev: int = 0) -> None:
        self.label: int = lab
        self.point: Optional[FlowBlock] = pt
        self.reverse_index: int = rev


# =========================================================================
# FlowBlock
# =========================================================================

class FlowBlock:
    """Description of a control-flow block containing PcodeOps.

    Base class for basic blocks (BlockBasic) and hierarchical structured code.
    """

    class BlockType(IntEnum):
        t_plain = 0
        t_basic = 1
        t_graph = 2
        t_copy = 3
        t_goto = 4
        t_multigoto = 5
        t_ls = 6
        t_condition = 7
        t_if = 8
        t_whiledo = 9
        t_dowhile = 10
        t_switch = 11
        t_infloop = 12

    # block_flags
    f_goto_goto = 1
    f_break_goto = 2
    f_continue_goto = 4
    f_switch_out = 0x10
    f_unstructured_targ = 0x20
    f_mark = 0x80
    f_mark2 = 0x100
    f_entry_point = 0x200
    f_interior_gotoout = 0x400
    f_interior_gotoin = 0x800
    f_label_bumpup = 0x1000
    f_donothing_loop = 0x2000
    f_dead = 0x4000
    f_whiledo_overflow = 0x8000
    f_flip_path = 0x10000
    f_joined_block = 0x20000
    f_duplicate_block = 0x40000

    # edge_flags
    f_goto_edge = 1
    f_loop_edge = 2
    f_defaultswitch_edge = 4
    f_irreducible = 8
    f_tree_edge = 0x10
    f_forward_edge = 0x20
    f_cross_edge = 0x40
    f_back_edge = 0x80
    f_loop_exit_edge = 0x100

    def __init__(self) -> None:
        self._flags: int = 0
        self._parent: Optional[FlowBlock] = None
        self._immed_dom: Optional[FlowBlock] = None
        self._copymap: Optional[FlowBlock] = None
        self._index: int = -1
        self._visitcount: int = 0
        self._numdesc: int = 0
        self._intothis: List[BlockEdge] = []
        self._outofthis: List[BlockEdge] = []

    # --- Basic accessors ---

    def getIndex(self) -> int:
        return self._index

    def setIndex(self, i: int) -> None:
        self._index = i

    def getParent(self) -> Optional[FlowBlock]:
        return self._parent

    def setParent(self, p: Optional[FlowBlock]) -> None:
        self._parent = p

    def getImmedDom(self) -> Optional[FlowBlock]:
        return self._immed_dom

    def setImmedDom(self, d: Optional[FlowBlock]) -> None:
        self._immed_dom = d

    def getCopyMap(self) -> Optional[FlowBlock]:
        return self._copymap

    def setCopyMap(self, c: Optional[FlowBlock]) -> None:
        self._copymap = c

    def getFlags(self) -> int:
        return self._flags

    def setFlag(self, fl: int) -> None:
        self._flags |= fl

    def clearFlag(self, fl: int) -> None:
        self._flags &= ~fl

    # --- Edge accessors ---

    def sizeOut(self) -> int:
        return len(self._outofthis)

    def sizeIn(self) -> int:
        return len(self._intothis)

    def getOut(self, i: int) -> Optional[FlowBlock]:
        return self._outofthis[i].point

    def getIn(self, i: int) -> Optional[FlowBlock]:
        return self._intothis[i].point

    def getOutRevIndex(self, i: int) -> int:
        return self._outofthis[i].reverse_index

    def getInRevIndex(self, i: int) -> int:
        return self._intothis[i].reverse_index

    def getFalseOut(self) -> Optional[FlowBlock]:
        return self._outofthis[0].point if self._outofthis else None

    def getTrueOut(self) -> Optional[FlowBlock]:
        return self._outofthis[1].point if len(self._outofthis) > 1 else None

    def addInEdge(self, b: FlowBlock, lab: int = 0) -> None:
        rev_in = len(self._intothis)
        rev_out = len(b._outofthis)
        self._intothis.append(BlockEdge(b, lab, rev_out))
        b._outofthis.append(BlockEdge(self, lab, rev_in))

    def removeInEdge(self, slot: int) -> None:
        edge = self._intothis[slot]
        src = edge.point
        out_slot = edge.reverse_index
        # Remove from source's outofthis
        if src and 0 <= out_slot < len(src._outofthis):
            del src._outofthis[out_slot]
            # Fix reverse indices
            for i in range(out_slot, len(src._outofthis)):
                target = src._outofthis[i].point
                if target:
                    rev = src._outofthis[i].reverse_index
                    if 0 <= rev < len(target._intothis):
                        target._intothis[rev].reverse_index = i
        del self._intothis[slot]
        # Fix reverse indices for remaining in-edges
        for i in range(slot, len(self._intothis)):
            src2 = self._intothis[i].point
            if src2:
                rev2 = self._intothis[i].reverse_index
                if 0 <= rev2 < len(src2._outofthis):
                    src2._outofthis[rev2].reverse_index = i

    def swapEdges(self) -> None:
        """Swap the first and second out edges."""
        if len(self._outofthis) >= 2:
            self._outofthis[0], self._outofthis[1] = self._outofthis[1], self._outofthis[0]
            # Fix reverse indices
            for i in range(2):
                target = self._outofthis[i].point
                if target:
                    rev = self._outofthis[i].reverse_index
                    if 0 <= rev < len(target._intothis):
                        target._intothis[rev].reverse_index = i

    def setOutEdgeFlag(self, i: int, lab: int) -> None:
        self._outofthis[i].label |= lab

    def clearOutEdgeFlag(self, i: int, lab: int) -> None:
        self._outofthis[i].label &= ~lab

    # --- Flag queries ---

    def isMark(self) -> bool:
        return (self._flags & FlowBlock.f_mark) != 0

    def setMark(self) -> None:
        self._flags |= FlowBlock.f_mark

    def clearMark(self) -> None:
        self._flags &= ~FlowBlock.f_mark

    def isDead(self) -> bool:
        return (self._flags & FlowBlock.f_dead) != 0

    def setDead(self) -> None:
        self._flags |= FlowBlock.f_dead

    def isEntryPoint(self) -> bool:
        return (self._flags & FlowBlock.f_entry_point) != 0

    def setEntryPoint(self) -> None:
        self._flags |= FlowBlock.f_entry_point

    def isJoined(self) -> bool:
        return (self._flags & FlowBlock.f_joined_block) != 0

    def isDuplicated(self) -> bool:
        return (self._flags & FlowBlock.f_duplicate_block) != 0

    def isLoopIn(self, i: int) -> bool:
        return (self._intothis[i].label & FlowBlock.f_loop_edge) != 0

    def isLoopOut(self, i: int) -> bool:
        return (self._outofthis[i].label & FlowBlock.f_loop_edge) != 0

    def hasLoopIn(self) -> bool:
        return any(e.label & FlowBlock.f_loop_edge for e in self._intothis)

    def hasLoopOut(self) -> bool:
        return any(e.label & FlowBlock.f_loop_edge for e in self._outofthis)

    def setLoopExit(self, i: int) -> None:
        self.setOutEdgeFlag(i, FlowBlock.f_loop_exit_edge)

    def setBackEdge(self, i: int) -> None:
        self.setOutEdgeFlag(i, FlowBlock.f_back_edge)

    def getFlipPath(self) -> bool:
        return (self._flags & FlowBlock.f_flip_path) != 0

    def isSwitchOut(self) -> bool:
        return (self._flags & FlowBlock.f_switch_out) != 0

    def isDonothingLoop(self) -> bool:
        return (self._flags & FlowBlock.f_donothing_loop) != 0

    def setDonothingLoop(self) -> None:
        self._flags |= FlowBlock.f_donothing_loop

    def getInIndex(self, bl: FlowBlock) -> int:
        """Get the index of the in-edge coming from block bl."""
        for i, e in enumerate(self._intothis):
            if e.point is bl:
                return i
        return -1

    def getOutIndex(self, bl: FlowBlock) -> int:
        """Get the index of the out-edge going to block bl."""
        for i, e in enumerate(self._outofthis):
            if e.point is bl:
                return i
        return -1

    def setVisitCount(self, i: int) -> None:
        self._visitcount = i

    def getVisitCount(self) -> int:
        return self._visitcount

    def dominates(self, subBlock: FlowBlock) -> bool:
        """Does this block dominate the given block?"""
        cur = subBlock
        while cur is not None:
            if cur is self:
                return True
            cur = cur._immed_dom
        return False

    # --- Virtual methods ---

    def getStart(self) -> Address:
        return Address()

    def getStop(self) -> Address:
        return Address()

    def getType(self) -> int:
        return FlowBlock.BlockType.t_plain

    def subBlock(self, i: int) -> Optional[FlowBlock]:
        return None

    def firstOp(self) -> Optional[PcodeOp]:
        return None

    def lastOp(self) -> Optional[PcodeOp]:
        return None

    def negateCondition(self, toporbottom: bool) -> bool:
        return False

    def isJumpTarget(self) -> bool:
        return (self._flags & (FlowBlock.f_interior_gotoin | FlowBlock.f_entry_point)) != 0 or self.sizeIn() > 1

    def isUnstructuredTarget(self) -> bool:
        return (self._flags & FlowBlock.f_unstructured_targ) != 0

    def isLabelBumpUp(self) -> bool:
        return (self._flags & FlowBlock.f_label_bumpup) != 0

    def getFrontLeaf(self):
        """Get the front leaf (entry) block of this subtree."""
        bl = self
        while True:
            sub = bl.subBlock(0)
            if sub is None:
                return bl
            bl = sub

    def hasSpecialLabel(self) -> bool:
        return False

    def nextInFlow(self):
        """Get the next block in flow order (sibling in parent)."""
        parent = self._parent
        if parent is None:
            return None
        idx = self._index
        if hasattr(parent, 'getSize'):
            if idx + 1 < parent.getSize():
                return parent.getBlock(idx + 1)
        return None

    def emit(self, lng) -> None:
        """Emit this block using the given PrintLanguage."""
        lng._emitBlockDispatch(self)

    def getEntryAddr(self) -> Address:
        return self.getStart()

    def __repr__(self) -> str:
        return f"FlowBlock(index={self._index}, in={self.sizeIn()}, out={self.sizeOut()})"


# =========================================================================
# BlockBasic
# =========================================================================

class BlockBasic(FlowBlock):
    """A basic block of PcodeOp objects.

    A maximal sequence of PcodeOps where control flow enters only at the
    beginning and exits only at the end.
    """

    def __init__(self) -> None:
        super().__init__()
        self._op: List[PcodeOp] = []
        self._rangeStart: Address = Address()
        self._rangeEnd: Address = Address()
        self._funcdata = None  # Funcdata owning this block

    def getType(self) -> int:
        return FlowBlock.BlockType.t_basic

    def getStart(self) -> Address:
        return self._rangeStart

    def getStop(self) -> Address:
        return self._rangeEnd

    def setRange(self, start: Address, end: Address) -> None:
        self._rangeStart = start
        self._rangeEnd = end

    def getOpList(self) -> List[PcodeOp]:
        return self._op

    def addOp(self, op: PcodeOp) -> None:
        self._op.append(op)
        op.setParent(self)

    def insertOp(self, op: PcodeOp, pos: int = -1) -> None:
        if pos < 0:
            self._op.append(op)
        else:
            self._op.insert(pos, op)
        op.setParent(self)

    def removeOp(self, op: PcodeOp) -> None:
        try:
            self._op.remove(op)
        except ValueError:
            pass

    def getOps(self):
        """Return iterator over ops in this block."""
        return iter(self._op)

    def isDoNothing(self) -> bool:
        """Check if block contains only marker ops (MULTIEQUAL/COPY) and possibly a branch."""
        from ghidra.core.opcodes import OpCode
        for op in self._op:
            opc = op.code()
            if opc == OpCode.CPUI_MULTIEQUAL:
                continue
            if opc == OpCode.CPUI_BRANCH:
                continue
            if opc == OpCode.CPUI_CBRANCH:
                continue
            if opc == OpCode.CPUI_COPY:
                continue
            return False
        return True

    def unblockedMulti(self, outslot: int) -> bool:
        """Check if MULTIEQUAL ops won't block removal through outslot."""
        return True  # Simplified - always allow removal

    def isEmpty(self) -> bool:
        return len(self._op) == 0

    def numOps(self) -> int:
        return len(self._op)

    def firstOp(self) -> Optional[PcodeOp]:
        return self._op[0] if self._op else None

    def lastOp(self) -> Optional[PcodeOp]:
        return self._op[-1] if self._op else None

    def negateCondition(self, toporbottom: bool) -> bool:
        last = self.lastOp()
        if last is None:
            return False
        from ghidra.core.opcodes import OpCode
        if last.code() == OpCode.CPUI_CBRANCH:
            last.flipFlag(PcodeOp.boolean_flip)
            self.swapEdges()
            return True
        return False

    def beginOp(self):
        return iter(self._op)

    def endOp(self):
        return None

    def getFuncdata(self):
        return self._funcdata

    def setFuncdata(self, fd) -> None:
        self._funcdata = fd

    def getEntryAddr(self) -> Address:
        return self._rangeStart

    def emit(self, lng) -> None:
        lng.emitBlockBasic(self)

    def __repr__(self) -> str:
        return f"BlockBasic(index={self._index}, ops={len(self._op)})"


# =========================================================================
# BlockGraph
# =========================================================================

class BlockGraph(FlowBlock):
    """A control-flow graph of FlowBlock objects.

    Contains a list of FlowBlock components that together form the
    body of a function or structured code region.
    """

    def __init__(self) -> None:
        super().__init__()
        self._list: List[FlowBlock] = []

    def getType(self) -> int:
        return FlowBlock.BlockType.t_graph

    def getSize(self) -> int:
        return len(self._list)

    def getBlock(self, i: int) -> FlowBlock:
        return self._list[i]

    def addBlock(self, bl: FlowBlock) -> None:
        bl.setIndex(len(self._list))
        bl.setParent(self)
        self._list.append(bl)

    def removeBlock(self, bl: FlowBlock) -> None:
        try:
            self._list.remove(bl)
        except ValueError:
            pass
        # Re-index
        for i, b in enumerate(self._list):
            b.setIndex(i)

    def removeEdge(self, begin: FlowBlock, end: FlowBlock) -> None:
        """Remove one edge between begin and end."""
        slot = end.getInIndex(begin)
        if slot >= 0:
            end.removeInEdge(slot)

    def removeFromFlow(self, bl: FlowBlock) -> None:
        """Remove a block from the flow, disconnecting all edges."""
        while bl.sizeIn() > 0:
            src = bl.getIn(0)
            self.removeEdge(src, bl)
        while bl.sizeOut() > 0:
            tgt = bl.getOut(0)
            self.removeEdge(bl, tgt)

    def collectReachable(self, result: list, start: FlowBlock, un: bool) -> None:
        """Collect unreachable (un=True) or reachable (un=False) blocks from start."""
        visited = set()
        stack = [start]
        while stack:
            cur = stack.pop()
            if id(cur) in visited:
                continue
            visited.add(id(cur))
            for i in range(cur.sizeOut()):
                stack.append(cur.getOut(i))
        if un:
            for bl in self._list:
                if id(bl) not in visited:
                    result.append(bl)
        else:
            for bl in self._list:
                if id(bl) in visited:
                    result.append(bl)

    def clearVisitCount(self) -> None:
        for bl in self._list:
            bl.setVisitCount(0)

    def buildCopy(self, orig: BlockGraph) -> None:
        """Build a copy of another BlockGraph using BlockCopy nodes."""
        for i in range(orig.getSize()):
            bl = orig.getBlock(i)
            cp = BlockCopy(bl)
            self.addBlock(cp)
        # Copy edges
        for i in range(orig.getSize()):
            src = orig.getBlock(i)
            for j in range(src.sizeOut()):
                tgt = src.getOut(j)
                lab = src._outofthis[j].label
                self._list[tgt.getIndex()].addInEdge(self._list[src.getIndex()], lab)
        # Copy entry point
        entry = orig.getEntryBlock()
        if entry is not None:
            self._list[entry.getIndex()].setEntryPoint()

    def _collapseNodes(self, newbl: FlowBlock, nodes: list) -> None:
        """Replace nodes with newbl, transferring external edges."""
        node_set = set(id(n) for n in nodes)
        # Collect external in-edges
        for n in nodes:
            for i in range(n.sizeIn()):
                src = n.getIn(i)
                if id(src) not in node_set:
                    newbl.addInEdge(src, n._intothis[i].label)
        # Collect external out-edges
        for n in nodes:
            for i in range(n.sizeOut()):
                tgt = n.getOut(i)
                if id(tgt) not in node_set:
                    tgt.addInEdge(newbl, n._outofthis[i].label)
        # Remove internal edges and nodes
        for n in nodes:
            n._intothis.clear()
            n._outofthis.clear()
        for n in nodes:
            try:
                self._list.remove(n)
            except ValueError:
                pass
        self.addBlock(newbl)
        # Re-index
        for i, b in enumerate(self._list):
            b.setIndex(i)

    def newBlockGoto(self, bl: FlowBlock, target: FlowBlock) -> None:
        newbl = BlockGoto(bl)
        self._collapseNodes(newbl, [bl])

    def newBlockList(self, nodes: list) -> None:
        newbl = BlockList()
        newbl._blockList = list(nodes)
        self._collapseNodes(newbl, nodes)

    def newBlockIf(self, cond: FlowBlock, trueBl: FlowBlock, falseBl: Optional[FlowBlock]) -> None:
        newbl = BlockIf()
        newbl._condBlock = cond
        newbl._trueBlock = trueBl
        newbl._falseBlock = falseBl
        nodes = [cond, trueBl]
        if falseBl is not None:
            nodes.append(falseBl)
        self._collapseNodes(newbl, nodes)

    def newBlockWhileDo(self, bl: FlowBlock) -> None:
        newbl = BlockWhileDo()
        newbl._condBlock = bl
        self._collapseNodes(newbl, [bl])

    def newBlockInfLoop(self, bl: FlowBlock) -> None:
        newbl = BlockInfLoop()
        newbl._bodyBlock = bl
        self._collapseNodes(newbl, [bl])

    def newBlockSwitch(self, cases: list, hasExit: bool) -> None:
        newbl = BlockSwitch()
        newbl._caseBlocks = list(cases)
        self._collapseNodes(newbl, cases)

    def clear(self) -> None:
        self._list.clear()

    def subBlock(self, i: int) -> Optional[FlowBlock]:
        if 0 <= i < len(self._list):
            return self._list[i]
        return None

    def getEntryBlock(self) -> Optional[FlowBlock]:
        """Get the entry point block."""
        for bl in self._list:
            if bl.isEntryPoint():
                return bl
        return self._list[0] if self._list else None

    def setStartBlock(self, bl: FlowBlock) -> None:
        """Mark a block as the entry point."""
        bl.setFlag(FlowBlock.f_entry_point)

    def __iter__(self):
        return iter(self._list)

    def __len__(self) -> int:
        return len(self._list)

    def __repr__(self) -> str:
        return f"BlockGraph(blocks={len(self._list)})"


# =========================================================================
# Structured block types (stubs for control-flow structuring)
# =========================================================================

class BlockCopy(FlowBlock):
    """A copy of a FlowBlock (for structured output)."""

    def __init__(self, bl: Optional[FlowBlock] = None) -> None:
        super().__init__()
        self._ref: Optional[FlowBlock] = bl
        if bl:
            bl.setCopyMap(self)

    def getType(self) -> int:
        return FlowBlock.BlockType.t_copy

    def getRef(self) -> Optional[FlowBlock]:
        return self._ref

    def subBlock(self, i: int):
        return self._ref if i == 0 else None

    def emit(self, lng) -> None:
        lng.emitBlockCopy(self)


class BlockGoto(FlowBlock):
    """Block ending with an explicit goto."""

    def __init__(self, bl: Optional[FlowBlock] = None) -> None:
        super().__init__()
        self._gotoTarget: Optional[FlowBlock] = None
        self._gotoType: int = FlowBlock.f_goto_goto
        self._body: Optional[FlowBlock] = bl

    def getType(self) -> int:
        return FlowBlock.BlockType.t_goto

    def getBlock(self, i: int):
        return self._body if i == 0 else None

    def getSize(self) -> int:
        return 1 if self._body is not None else 0

    def getGotoTarget(self):
        return self._gotoTarget

    def getGotoType(self) -> int:
        return self._gotoType

    def gotoPrints(self) -> bool:
        """Check if the goto actually needs to be printed."""
        return self._gotoTarget is not None

    def emit(self, lng) -> None:
        lng.emitBlockGoto(self)


class BlockCondition(FlowBlock):
    """A condition block combining two conditions with && or ||."""

    def __init__(self) -> None:
        super().__init__()
        self._opc: int = 0  # OpCode for combining (BOOL_AND or BOOL_OR)
        self._block0: Optional[FlowBlock] = None
        self._block1: Optional[FlowBlock] = None

    def getType(self) -> int:
        return FlowBlock.BlockType.t_condition

    def getOpcode(self) -> int:
        return self._opc

    def getBlock(self, i: int):
        if i == 0:
            return self._block0
        if i == 1:
            return self._block1
        return None

    def getSize(self) -> int:
        return 2

    def emit(self, lng) -> None:
        lng.emitBlockCondition(self)


class BlockIf(FlowBlock):
    """An if/then or if/then/else block."""

    def __init__(self) -> None:
        super().__init__()
        self._condBlock: Optional[FlowBlock] = None
        self._trueBlock: Optional[FlowBlock] = None
        self._falseBlock: Optional[FlowBlock] = None
        self._gotoTarget: Optional[FlowBlock] = None
        self._gotoType: int = 0

    def getType(self) -> int:
        return FlowBlock.BlockType.t_if

    def getBlock(self, i: int):
        if i == 0:
            return self._condBlock
        if i == 1:
            return self._trueBlock
        if i == 2:
            return self._falseBlock
        return None

    def getSize(self) -> int:
        if self._falseBlock is not None:
            return 3
        return 2 if self._trueBlock is not None else 1

    def getGotoTarget(self):
        return self._gotoTarget

    def getGotoType(self) -> int:
        return self._gotoType

    def emit(self, lng) -> None:
        lng.emitBlockIf(self)


class BlockWhileDo(FlowBlock):
    """A while-do loop block."""

    def __init__(self) -> None:
        super().__init__()
        self._condBlock: Optional[FlowBlock] = None
        self._bodyBlock: Optional[FlowBlock] = None
        self._initializeOp = None
        self._iterateOp = None

    def getType(self) -> int:
        return FlowBlock.BlockType.t_whiledo

    def getBlock(self, i: int):
        if i == 0:
            return self._condBlock
        if i == 1:
            return self._bodyBlock
        return None

    def getSize(self) -> int:
        return 2

    def hasOverflowSyntax(self) -> bool:
        return (self._flags & FlowBlock.f_whiledo_overflow) != 0

    def getInitializeOp(self):
        return self._initializeOp

    def getIterateOp(self):
        return self._iterateOp

    def emit(self, lng) -> None:
        lng.emitBlockWhileDo(self)


class BlockDoWhile(FlowBlock):
    """A do-while loop block."""

    def __init__(self) -> None:
        super().__init__()
        self._bodyBlock: Optional[FlowBlock] = None

    def getType(self) -> int:
        return FlowBlock.BlockType.t_dowhile

    def getBlock(self, i: int):
        return self._bodyBlock if i == 0 else None

    def getSize(self) -> int:
        return 1

    def emit(self, lng) -> None:
        lng.emitBlockDoWhile(self)


class BlockInfLoop(FlowBlock):
    """An infinite loop block."""

    def __init__(self) -> None:
        super().__init__()
        self._bodyBlock: Optional[FlowBlock] = None

    def getType(self) -> int:
        return FlowBlock.BlockType.t_infloop

    def getBlock(self, i: int):
        return self._bodyBlock if i == 0 else None

    def getSize(self) -> int:
        return 1

    def emit(self, lng) -> None:
        lng.emitBlockInfLoop(self)


class BlockSwitch(FlowBlock):
    """A switch/case block."""

    def __init__(self) -> None:
        super().__init__()
        self._caseBlocks: List[FlowBlock] = []
        self._caseValues: List[int] = []
        self._defaultCase: int = -1
        self._caseIsExit: List[bool] = []
        self._gotoTypes: List[int] = []
        self._switchType = None  # Datatype

    def getType(self) -> int:
        return FlowBlock.BlockType.t_switch

    def numCases(self) -> int:
        return len(self._caseBlocks)

    def getNumCaseBlocks(self) -> int:
        return len(self._caseBlocks)

    def getCaseBlock(self, i: int):
        return self._caseBlocks[i] if 0 <= i < len(self._caseBlocks) else None

    def getSwitchBlock(self):
        return self._caseBlocks[0] if self._caseBlocks else None

    def getSwitchType(self):
        return self._switchType

    def isDefaultCase(self, i: int) -> bool:
        return i == self._defaultCase

    def isExit(self, i: int) -> bool:
        return self._caseIsExit[i] if i < len(self._caseIsExit) else False

    def getGotoType(self, i: int) -> int:
        return self._gotoTypes[i] if i < len(self._gotoTypes) else 0

    def getNumLabels(self, casenum: int) -> int:
        return 1

    def getLabel(self, casenum: int, j: int) -> int:
        return self._caseValues[casenum] if casenum < len(self._caseValues) else casenum

    def getBlock(self, i: int):
        return self._caseBlocks[i] if 0 <= i < len(self._caseBlocks) else None

    def getSize(self) -> int:
        return len(self._caseBlocks)

    def emit(self, lng) -> None:
        lng.emitBlockSwitch(self)


class BlockList(FlowBlock):
    """A sequence of blocks executed in order."""

    def __init__(self) -> None:
        super().__init__()
        self._blockList: List[FlowBlock] = []

    def getType(self) -> int:
        return FlowBlock.BlockType.t_ls

    def getSize(self) -> int:
        return len(self._blockList)

    def getBlock(self, i: int) -> FlowBlock:
        return self._blockList[i]

    def emit(self, lng) -> None:
        lng.emitBlockLs(self)
