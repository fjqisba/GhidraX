"""
Corresponds to: block.hh / block.cc

Classes related to basic blocks and control-flow structuring.
Core classes: BlockEdge, FlowBlock, BlockBasic, BlockGraph, and structured block types.
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List

from ghidra.core.address import Address, RangeList

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode

# ---- Marshaling attribute / element IDs (mirrors C++ globals) ----
ATTRIB_ALTINDEX = 75
ATTRIB_DEPTH = 76
ATTRIB_END = 77
ATTRIB_INDEX = 78
ATTRIB_OPCODE = 79
ATTRIB_REV = 80
ATTRIB_TYPE = 81

ELEM_BHEAD = 102
ELEM_BLOCK = 103
ELEM_BLOCKEDGE = 104
ELEM_EDGE = 105
ELEM_TARGET = 106

# =========================================================================
# BlockEdge
# =========================================================================

class BlockEdge:
    """A control-flow edge between blocks (FlowBlock).

    The edge is owned by the source block and can have edge_flags labels.
    The *point* indicates the FlowBlock at the other end from the source block.
    """

    __slots__ = ('label', 'point', 'reverse_index')

    def __init__(self, pt: Optional['FlowBlock'] = None, lab: int = 0, rev: int = 0) -> None:
        self.label: int = lab
        self.point: Optional['FlowBlock'] = pt
        self.reverse_index: int = rev

    # --- encode / decode ---
    def encode(self, encoder) -> None:
        encoder.openElement(ELEM_EDGE)
        encoder.writeSignedInteger(ATTRIB_END, self.point.getIndex())
        encoder.writeSignedInteger(ATTRIB_REV, self.reverse_index)
        encoder.closeElement(ELEM_EDGE)

    def decode(self, decoder, resolver: 'BlockMap') -> None:
        elemId = decoder.openElement(ELEM_EDGE)
        self.label = 0
        endIndex = decoder.readSignedInteger(ATTRIB_END)
        self.point = resolver.findLevelBlock(endIndex)
        if self.point is None:
            raise RuntimeError("Bad serialized edge in block graph")
        self.reverse_index = decoder.readSignedInteger(ATTRIB_REV)
        decoder.closeElement(elemId)


# =========================================================================
# FlowBlock
# =========================================================================

class FlowBlock:
    """Description of a control-flow block containing PcodeOps.

    Base class for basic blocks (BlockBasic) and hierarchical structured code.
    """

    # block_type enum
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
        self._index: int = 0
        self._visitcount: int = 0
        self._numdesc: int = 0
        self._parent: Optional[FlowBlock] = None
        self._immed_dom: Optional[FlowBlock] = None
        self._copymap: Optional[FlowBlock] = None
        self._intothis: List[BlockEdge] = []
        self._outofthis: List[BlockEdge] = []

    # ---- Basic property accessors (inline in C++) ----
    def getIndex(self) -> int: return self._index
    def getParent(self) -> Optional[FlowBlock]: return self._parent
    def getImmedDom(self) -> Optional[FlowBlock]: return self._immed_dom
    def getCopyMap(self) -> Optional[FlowBlock]: return self._copymap
    def getFlags(self) -> int: return self._flags
    def setFlag(self, fl: int) -> None: self._flags |= fl
    def clearFlag(self, fl: int) -> None: self._flags &= ~fl
    def sizeOut(self) -> int: return len(self._outofthis)
    def sizeIn(self) -> int: return len(self._intothis)
    def getOut(self, i: int) -> Optional[FlowBlock]: return self._outofthis[i].point
    def getIn(self, i: int) -> Optional[FlowBlock]: return self._intothis[i].point
    def getOutRevIndex(self, i: int) -> int: return self._outofthis[i].reverse_index
    def getInRevIndex(self, i: int) -> int: return self._intothis[i].reverse_index
    def getFalseOut(self) -> FlowBlock: return self._outofthis[0].point
    def getTrueOut(self) -> FlowBlock: return self._outofthis[1].point
    def setVisitCount(self, i: int) -> None: self._visitcount = i
    def getVisitCount(self) -> int: return self._visitcount

    # ---- Flag query inlines (C++) ----
    def isMark(self) -> bool: return (self._flags & FlowBlock.f_mark) != 0
    def setMark(self) -> None: self._flags |= FlowBlock.f_mark
    def clearMark(self) -> None: self._flags &= ~FlowBlock.f_mark
    def setDonothingLoop(self) -> None: self._flags |= FlowBlock.f_donothing_loop
    def setDead(self) -> None: self._flags |= FlowBlock.f_dead
    def hasSpecialLabel(self) -> bool: return (self._flags & (FlowBlock.f_joined_block | FlowBlock.f_duplicate_block)) != 0
    def isJoined(self) -> bool: return (self._flags & FlowBlock.f_joined_block) != 0
    def isDuplicated(self) -> bool: return (self._flags & FlowBlock.f_duplicate_block) != 0
    def setLoopExit(self, i: int) -> None: self.setOutEdgeFlag(i, FlowBlock.f_loop_exit_edge)
    def clearLoopExit(self, i: int) -> None: self.clearOutEdgeFlag(i, FlowBlock.f_loop_exit_edge)
    def setBackEdge(self, i: int) -> None: self.setOutEdgeFlag(i, FlowBlock.f_back_edge)
    def getFlipPath(self) -> bool: return (self._flags & FlowBlock.f_flip_path) != 0
    def isLoopIn(self, i: int) -> bool: return (self._intothis[i].label & FlowBlock.f_loop_edge) != 0
    def isLoopOut(self, i: int) -> bool: return (self._outofthis[i].label & FlowBlock.f_loop_edge) != 0
    def isDefaultBranch(self, i: int) -> bool: return (self._outofthis[i].label & FlowBlock.f_defaultswitch_edge) != 0
    def isLabelBumpUp(self) -> bool: return (self._flags & FlowBlock.f_label_bumpup) != 0
    def isUnstructuredTarget(self) -> bool: return (self._flags & FlowBlock.f_unstructured_targ) != 0
    def isInteriorGotoTarget(self) -> bool: return (self._flags & FlowBlock.f_interior_gotoin) != 0
    def hasInteriorGoto(self) -> bool: return (self._flags & FlowBlock.f_interior_gotoout) != 0
    def isEntryPoint(self) -> bool: return (self._flags & FlowBlock.f_entry_point) != 0
    def isSwitchOut(self) -> bool: return (self._flags & FlowBlock.f_switch_out) != 0
    def isDonothingLoop(self) -> bool: return (self._flags & FlowBlock.f_donothing_loop) != 0
    def isDead(self) -> bool: return (self._flags & FlowBlock.f_dead) != 0
    def isTreeEdgeIn(self, i: int) -> bool: return (self._intothis[i].label & FlowBlock.f_tree_edge) != 0
    def isBackEdgeIn(self, i: int) -> bool: return (self._intothis[i].label & FlowBlock.f_back_edge) != 0
    def isBackEdgeOut(self, i: int) -> bool: return (self._outofthis[i].label & FlowBlock.f_back_edge) != 0
    def isIrreducibleOut(self, i: int) -> bool: return (self._outofthis[i].label & FlowBlock.f_irreducible) != 0
    def isIrreducibleIn(self, i: int) -> bool: return (self._intothis[i].label & FlowBlock.f_irreducible) != 0
    def isDecisionOut(self, i: int) -> bool: return (self._outofthis[i].label & (FlowBlock.f_irreducible | FlowBlock.f_back_edge | FlowBlock.f_goto_edge)) == 0
    def isDecisionIn(self, i: int) -> bool: return (self._intothis[i].label & (FlowBlock.f_irreducible | FlowBlock.f_back_edge | FlowBlock.f_goto_edge)) == 0
    def isLoopDAGOut(self, i: int) -> bool: return (self._outofthis[i].label & (FlowBlock.f_irreducible | FlowBlock.f_back_edge | FlowBlock.f_loop_exit_edge | FlowBlock.f_goto_edge)) == 0
    def isLoopDAGIn(self, i: int) -> bool: return (self._intothis[i].label & (FlowBlock.f_irreducible | FlowBlock.f_back_edge | FlowBlock.f_loop_exit_edge | FlowBlock.f_goto_edge)) == 0
    def isGotoIn(self, i: int) -> bool: return (self._intothis[i].label & (FlowBlock.f_irreducible | FlowBlock.f_goto_edge)) != 0
    def isGotoOut(self, i: int) -> bool: return (self._outofthis[i].label & (FlowBlock.f_irreducible | FlowBlock.f_goto_edge)) != 0

    # ---- Edge manipulation (C++ private/friend) ----
    def addInEdge(self, b: FlowBlock, lab: int = 0) -> None:
        ourrev = len(b._outofthis)
        brev = len(self._intothis)
        self._intothis.append(BlockEdge(b, lab, ourrev))
        b._outofthis.append(BlockEdge(self, lab, brev))

    def decodeNextInEdge(self, decoder, resolver: 'BlockMap') -> None:
        inedge = BlockEdge()
        self._intothis.append(inedge)
        inedge.decode(decoder, resolver)
        while len(inedge.point._outofthis) <= inedge.reverse_index:
            inedge.point._outofthis.append(BlockEdge())
        outedge = inedge.point._outofthis[inedge.reverse_index]
        outedge.label = 0
        outedge.point = self
        outedge.reverse_index = len(self._intothis) - 1

    def halfDeleteInEdge(self, slot: int) -> None:
        while slot < len(self._intothis) - 1:
            edge = self._intothis[slot]
            self._intothis[slot] = self._intothis[slot + 1]
            edge = self._intothis[slot]
            edger = edge.point._outofthis[edge.reverse_index]
            edger.reverse_index -= 1
            slot += 1
        self._intothis.pop()

    def halfDeleteOutEdge(self, slot: int) -> None:
        while slot < len(self._outofthis) - 1:
            self._outofthis[slot] = self._outofthis[slot + 1]
            edge = self._outofthis[slot]
            edger = edge.point._intothis[edge.reverse_index]
            edger.reverse_index -= 1
            slot += 1
        self._outofthis.pop()

    def removeInEdge(self, slot: int) -> None:
        b = self._intothis[slot].point
        rev = self._intothis[slot].reverse_index
        self.halfDeleteInEdge(slot)
        b.halfDeleteOutEdge(rev)

    def removeOutEdge(self, slot: int) -> None:
        b = self._outofthis[slot].point
        rev = self._outofthis[slot].reverse_index
        self.halfDeleteOutEdge(slot)
        b.halfDeleteInEdge(rev)

    def replaceInEdge(self, num: int, b: FlowBlock) -> None:
        oldb = self._intothis[num].point
        oldb.halfDeleteOutEdge(self._intothis[num].reverse_index)
        self._intothis[num].point = b
        self._intothis[num].reverse_index = len(b._outofthis)
        b._outofthis.append(BlockEdge(self, self._intothis[num].label, num))

    def replaceOutEdge(self, num: int, b: FlowBlock) -> None:
        oldb = self._outofthis[num].point
        oldb.halfDeleteInEdge(self._outofthis[num].reverse_index)
        self._outofthis[num].point = b
        self._outofthis[num].reverse_index = len(b._intothis)
        b._intothis.append(BlockEdge(self, self._outofthis[num].label, num))

    def replaceEdgesThru(self, in_: int, out: int) -> None:
        inb = self._intothis[in_].point
        inblock_outslot = self._intothis[in_].reverse_index
        outb = self._outofthis[out].point
        outblock_inslot = self._outofthis[out].reverse_index
        inb._outofthis[inblock_outslot].point = outb
        inb._outofthis[inblock_outslot].reverse_index = outblock_inslot
        outb._intothis[outblock_inslot].point = inb
        outb._intothis[outblock_inslot].reverse_index = inblock_outslot
        self.halfDeleteInEdge(in_)
        self.halfDeleteOutEdge(out)

    def swapEdges(self) -> None:
        tmp = self._outofthis[0]
        self._outofthis[0] = self._outofthis[1]
        self._outofthis[1] = tmp
        bl = self._outofthis[0].point
        bl._intothis[self._outofthis[0].reverse_index].reverse_index = 0
        bl = self._outofthis[1].point
        bl._intothis[self._outofthis[1].reverse_index].reverse_index = 1
        self._flags ^= FlowBlock.f_flip_path

    def setOutEdgeFlag(self, i: int, lab: int) -> None:
        bbout = self._outofthis[i].point
        self._outofthis[i].label |= lab
        bbout._intothis[self._outofthis[i].reverse_index].label |= lab

    def clearOutEdgeFlag(self, i: int, lab: int) -> None:
        bbout = self._outofthis[i].point
        self._outofthis[i].label &= ~lab
        bbout._intothis[self._outofthis[i].reverse_index].label &= ~lab

    def eliminateInDups(self, bl: FlowBlock) -> None:
        indval = -1
        i = 0
        while i < len(self._intothis):
            if self._intothis[i].point is bl:
                if indval == -1:
                    indval = i
                    i += 1
                else:
                    self._intothis[indval].label |= self._intothis[i].label
                    rev = self._intothis[i].reverse_index
                    self.halfDeleteInEdge(i)
                    bl.halfDeleteOutEdge(rev)
            else:
                i += 1

    def eliminateOutDups(self, bl: FlowBlock) -> None:
        indval = -1
        i = 0
        while i < len(self._outofthis):
            if self._outofthis[i].point is bl:
                if indval == -1:
                    indval = i
                    i += 1
                else:
                    self._outofthis[indval].label |= self._outofthis[i].label
                    rev = self._outofthis[i].reverse_index
                    self.halfDeleteOutEdge(i)
                    bl.halfDeleteInEdge(rev)
            else:
                i += 1

    @staticmethod
    def _findDups(ref: List[BlockEdge], duplist: List[FlowBlock]) -> None:
        for edge in ref:
            if (edge.point._flags & FlowBlock.f_mark2) != 0:
                continue
            if (edge.point._flags & FlowBlock.f_mark) != 0:
                duplist.append(edge.point)
                edge.point._flags |= FlowBlock.f_mark2
            else:
                edge.point._flags |= FlowBlock.f_mark
        for edge in ref:
            edge.point._flags &= ~(FlowBlock.f_mark | FlowBlock.f_mark2)

    def dedup(self) -> None:
        duplist: List[FlowBlock] = []
        FlowBlock._findDups(self._intothis, duplist)
        for bl in duplist:
            self.eliminateInDups(bl)
        duplist.clear()
        FlowBlock._findDups(self._outofthis, duplist)
        for bl in duplist:
            self.eliminateOutDups(bl)

    @staticmethod
    def replaceEdgeMap(vec: List[BlockEdge]) -> None:
        for edge in vec:
            edge.point = edge.point.getCopyMap()

    def replaceUsingMap(self) -> None:
        FlowBlock.replaceEdgeMap(self._intothis)
        FlowBlock.replaceEdgeMap(self._outofthis)
        if self._immed_dom is not None:
            self._immed_dom = self._immed_dom.getCopyMap()

    # ---- Virtual methods ----
    def getStart(self) -> Address: return Address()
    def getStop(self) -> Address: return Address()
    def getType(self) -> int: return FlowBlock.t_plain
    def subBlock(self, i: int) -> Optional[FlowBlock]: return None
    def markUnstructured(self) -> None: pass
    def scopeBreak(self, curexit: int, curloopexit: int) -> None: pass
    def printRaw(self, s) -> None: pass
    def printRawImpliedGoto(self, s, nextBlock) -> None: pass
    def getExitLeaf(self) -> Optional[FlowBlock]: return None
    def firstOp(self) -> Optional['PcodeOp']: return None
    def lastOp(self) -> Optional['PcodeOp']: return None
    def isComplex(self) -> bool: return True
    def finalTransform(self, data) -> None: pass
    def finalizePrinting(self, data) -> None: pass
    def encodeBody(self, encoder) -> None: pass
    def decodeBody(self, decoder) -> None: pass

    def markLabelBumpUp(self, bump: bool) -> None:
        if bump:
            self._flags |= FlowBlock.f_label_bumpup

    def negateCondition(self, toporbottom: bool) -> bool:
        if not toporbottom:
            return False
        self.swapEdges()
        return False

    def preferComplement(self, data) -> bool:
        return False

    def getSplitPoint(self) -> Optional[FlowBlock]:
        return None

    def flipInPlaceTest(self, fliplist: list) -> int:
        return 2

    def flipInPlaceExecute(self) -> None:
        pass

    def nextFlowAfter(self, bl) -> Optional[FlowBlock]:
        return None

    def emit(self, lng) -> None:
        pass

    # ---- Non-virtual methods ----
    def printHeader(self, s) -> None:
        s.write(str(self._index))
        start = self.getStart()
        stop = self.getStop()
        if start.isValid() and stop.isValid():
            s.write(f' {start}-{stop}')

    def printTree(self, s, level: int) -> None:
        s.write('  ' * level)
        self.printHeader(s)
        s.write('\n')

    def printShortHeader(self, s) -> None:
        s.write(f'Block_{self._index}')
        start = self.getStart()
        if start.isValid():
            s.write(f':{start}')

    def setGotoBranch(self, i: int) -> None:
        if 0 <= i < len(self._outofthis):
            self.setOutEdgeFlag(i, FlowBlock.f_goto_edge)
        else:
            raise RuntimeError("Could not find block edge to mark unstructured")
        self._flags |= FlowBlock.f_interior_gotoout
        self._outofthis[i].point._flags |= FlowBlock.f_interior_gotoin

    def setDefaultSwitch(self, pos: int) -> None:
        for i in range(len(self._outofthis)):
            if self.isDefaultBranch(i):
                self.clearOutEdgeFlag(i, FlowBlock.f_defaultswitch_edge)
        self.setOutEdgeFlag(pos, FlowBlock.f_defaultswitch_edge)

    def isJumpTarget(self) -> bool:
        for i in range(len(self._intothis)):
            if self._intothis[i].point._index != self._index - 1:
                return True
        return False

    def getFrontLeaf(self) -> Optional[FlowBlock]:
        bl = self
        while bl.getType() != FlowBlock.t_copy:
            sub = bl.subBlock(0)
            if sub is None:
                return sub
            bl = sub
        return bl

    def calcDepth(self, leaf) -> int:
        depth = 0
        while leaf is not self:
            if leaf is None:
                return -1
            leaf = leaf.getParent()
            depth += 1
        return depth

    def dominates(self, subBlock) -> bool:
        while subBlock is not None and self._index <= subBlock._index:
            if subBlock is self:
                return True
            subBlock = subBlock.getImmedDom()
        return False

    def restrictedByConditional(self, cond) -> bool:
        if self.sizeIn() == 1:
            return True
        if self.getImmedDom() is not cond:
            return False
        seenCond = False
        for i in range(self.sizeIn()):
            inBlock = self.getIn(i)
            if inBlock is cond:
                if seenCond:
                    return False
                seenCond = True
                continue
            while inBlock is not self:
                if inBlock is cond:
                    return False
                inBlock = inBlock.getImmedDom()
        return True

    def hasLoopIn(self) -> bool:
        for i in range(len(self._intothis)):
            if (self._intothis[i].label & FlowBlock.f_loop_edge) != 0:
                return True
        return False

    def hasLoopOut(self) -> bool:
        for i in range(len(self._outofthis)):
            if (self._outofthis[i].label & FlowBlock.f_loop_edge) != 0:
                return True
        return False

    def getInIndex(self, bl) -> int:
        for i in range(len(self._intothis)):
            if self._intothis[i].point is bl:
                return i
        return -1

    def getOutIndex(self, bl) -> int:
        for i in range(len(self._outofthis)):
            if self._outofthis[i].point is bl:
                return i
        return -1

    def getJumptable(self):
        if not self.isSwitchOut():
            return None
        indop = self.lastOp()
        if indop is not None:
            return indop.getParent().getFuncdata().findJumpTable(indop)
        return None

    def nextInFlow(self):
        if self.sizeOut() == 1:
            return self.getOut(0)
        if self.sizeOut() == 2:
            op = self.lastOp()
            if op is None:
                return None
            from ghidra.core.opcodes import OpCode
            if op.code() != OpCode.CPUI_CBRANCH:
                return None
            return self.getOut(1) if op.isFallthruTrue() else self.getOut(0)
        return None

    # ---- encode / decode ----
    def encodeHeader(self, encoder) -> None:
        encoder.writeSignedInteger(ATTRIB_ALTINDEX, self._index)

    def decodeHeader(self, decoder) -> None:
        self._index = decoder.readSignedInteger(ATTRIB_ALTINDEX)

    def encodeEdges(self, encoder) -> None:
        for edge in self._intothis:
            edge.encode(encoder)

    def decodeEdges(self, decoder, resolver: 'BlockMap') -> None:
        while True:
            subId = decoder.peekElement()
            if subId != ELEM_EDGE:
                break
            self.decodeNextInEdge(decoder, resolver)

    def encode(self, encoder) -> None:
        encoder.openElement(ELEM_BLOCK)
        self.encodeHeader(encoder)
        self.encodeBody(encoder)
        self.encodeEdges(encoder)
        encoder.closeElement(ELEM_BLOCK)

    def decode(self, decoder, resolver: 'BlockMap') -> None:
        elemId = decoder.openElement(ELEM_BLOCK)
        self.decodeHeader(decoder)
        self.decodeBody(decoder)
        self.decodeEdges(decoder, resolver)
        decoder.closeElement(elemId)

    # ---- Static methods ----
    @staticmethod
    def nameToType(nm: str) -> int:
        if nm == "graph": return FlowBlock.t_graph
        if nm == "copy": return FlowBlock.t_copy
        return FlowBlock.t_plain

    @staticmethod
    def typeToName(bt: int) -> str:
        _MAP = {
            FlowBlock.t_plain: "plain", FlowBlock.t_basic: "basic",
            FlowBlock.t_graph: "graph", FlowBlock.t_copy: "copy",
            FlowBlock.t_goto: "goto", FlowBlock.t_multigoto: "multigoto",
            FlowBlock.t_ls: "list", FlowBlock.t_condition: "condition",
            FlowBlock.t_if: "properif", FlowBlock.t_whiledo: "whiledo",
            FlowBlock.t_dowhile: "dowhile", FlowBlock.t_switch: "switch",
            FlowBlock.t_infloop: "infloop",
        }
        return _MAP.get(bt, "")

    @staticmethod
    def compareBlockIndex(bl1: FlowBlock, bl2: FlowBlock) -> bool:
        return bl1.getIndex() < bl2.getIndex()

    @staticmethod
    def compareFinalOrder(bl1: FlowBlock, bl2: FlowBlock) -> bool:
        from ghidra.core.opcodes import OpCode
        if bl1.getIndex() == 0: return True
        if bl2.getIndex() == 0: return False
        op1 = bl1.lastOp()
        op2 = bl2.lastOp()
        if op1 is not None:
            if op2 is not None:
                if op1.code() == OpCode.CPUI_RETURN and op2.code() != OpCode.CPUI_RETURN:
                    return False
                if op1.code() != OpCode.CPUI_RETURN and op2.code() == OpCode.CPUI_RETURN:
                    return True
            if op1.code() == OpCode.CPUI_RETURN:
                return False
        elif op2 is not None:
            if op2.code() == OpCode.CPUI_RETURN:
                return True
        return bl1.getIndex() < bl2.getIndex()

    @staticmethod
    def findCommonBlock(bl1, bl2=None):
        if bl2 is not None:
            return FlowBlock._findCommonBlock2(bl1, bl2)
        return FlowBlock._findCommonBlockSet(bl1)

    @staticmethod
    def _findCommonBlock2(bl1: FlowBlock, bl2: FlowBlock) -> Optional[FlowBlock]:
        common = None
        b1, b2 = bl1, bl2
        while True:
            if b2 is None:
                while b1 is not None:
                    if b1.isMark():
                        common = b1
                        break
                    b1 = b1.getImmedDom()
                break
            if b1 is None:
                while b2 is not None:
                    if b2.isMark():
                        common = b2
                        break
                    b2 = b2.getImmedDom()
                break
            if b1.isMark():
                common = b1
                break
            b1.setMark()
            if b2.isMark():
                common = b2
                break
            b2.setMark()
            b1 = b1.getImmedDom()
            b2 = b2.getImmedDom()
        b1t, b2t = bl1, bl2
        while b1t is not None:
            if not b1t.isMark(): break
            b1t.clearMark()
            b1t = b1t.getImmedDom()
        while b2t is not None:
            if not b2t.isMark(): break
            b2t.clearMark()
            b2t = b2t.getImmedDom()
        return common

    @staticmethod
    def _findCommonBlockSet(blockSet: list) -> Optional[FlowBlock]:
        markedSet: List[FlowBlock] = []
        res = blockSet[0]
        bestIndex = res.getIndex()
        bl = res
        while bl is not None:
            bl.setMark()
            markedSet.append(bl)
            bl = bl.getImmedDom()
        for i in range(1, len(blockSet)):
            if bestIndex == 0:
                break
            bl = blockSet[i]
            while not bl.isMark():
                bl.setMark()
                markedSet.append(bl)
                bl = bl.getImmedDom()
            if bl.getIndex() < bestIndex:
                res = bl
                bestIndex = res.getIndex()
        for b in markedSet:
            b.clearMark()
        return res

    @staticmethod
    def findCondition(bl1, edge1: int, bl2, edge2: int) -> tuple:
        """Returns (condBlock, slot1) or (None, -1)."""
        cond = bl1.getIn(edge1)
        while cond.sizeOut() != 2:
            if cond.sizeOut() != 1:
                return (None, -1)
            bl1 = cond
            edge1 = 0
            cond = bl1.getIn(0)
        while cond is not bl2.getIn(edge2):
            bl2 = bl2.getIn(edge2)
            if bl2.sizeOut() != 1:
                return (None, -1)
            edge2 = 0
        slot1 = bl1.getInRevIndex(edge1)
        return (cond, slot1)

    def __repr__(self) -> str:
        return f"FlowBlock(index={self._index}, in={self.sizeIn()}, out={self.sizeOut()})"


# =========================================================================
# BlockGraph  (must be defined before BlockBasic so factory methods work)
# =========================================================================

class BlockGraph(FlowBlock):
    """A control-flow block built out of sub-components.

    Core class for building a hierarchy of control-flow blocks.
    All structured elements (BlockList, BlockIf, etc.) derive from this.
    """

    def __init__(self) -> None:
        super().__init__()
        self._list: List[FlowBlock] = []

    def getList(self): return self._list
    def getSize(self) -> int: return len(self._list)
    def getBlock(self, i: int): return self._list[i]
    def getType(self) -> int: return FlowBlock.t_graph
    def subBlock(self, i: int): return self._list[i] if 0 <= i < len(self._list) else None

    def addBlock(self, bl: FlowBlock) -> None:
        m = bl._index
        if not self._list:
            self._index = m
        elif m < self._index:
            self._index = m
        bl._parent = self
        self._list.append(bl)

    def forceOutputNum(self, i: int) -> None:
        while self.sizeOut() < i:
            self.addInEdge(self, FlowBlock.f_loop_edge | FlowBlock.f_back_edge)

    def selfIdentify(self) -> None:
        if not self._list: return
        for mybl in self._list:
            i = 0
            while i < len(mybl._intothis):
                o = mybl._intothis[i].point
                if o._parent is self:
                    i += 1
                else:
                    for j in range(len(o._outofthis)):
                        if o._outofthis[j].point is mybl:
                            o.replaceOutEdge(j, self)
            i = 0
            while i < len(mybl._outofthis):
                o = mybl._outofthis[i].point
                if o._parent is self:
                    i += 1
                else:
                    for j in range(len(o._intothis)):
                        if o._intothis[j].point is mybl:
                            o.replaceInEdge(j, self)
                    if mybl.isSwitchOut():
                        self.setFlag(FlowBlock.f_switch_out)
        self.dedup()

    def identifyInternal(self, ident: 'BlockGraph', nodes: list) -> None:
        for nd in nodes:
            nd.setMark()
            ident.addBlock(nd)
            ident._flags |= (nd._flags & (FlowBlock.f_interior_gotoout | FlowBlock.f_interior_gotoin))
        self._list = [bl for bl in self._list if not bl.isMark()]
        for nd in nodes:
            nd.clearMark()
        ident.selfIdentify()

    def clearEdgeFlags(self, fl: int) -> None:
        fl = ~fl
        for bl in self._list:
            for e in bl._intothis: e.label &= fl
            for e in bl._outofthis: e.label &= fl

    @staticmethod
    def createVirtualRoot(rootlist):
        newroot = FlowBlock()
        for bl in rootlist:
            bl.addInEdge(newroot, 0)
        return newroot

    def forceFalseEdge(self, out0) -> None:
        if self.sizeOut() != 2:
            raise RuntimeError("Can only preserve binary condition")
        if out0._parent is self: out0 = self
        if self._outofthis[0].point is not out0: self.swapEdges()
        if self._outofthis[0].point is not out0:
            raise RuntimeError("Unable to preserve condition")

    def swapBlocks(self, i: int, j: int) -> None:
        self._list[i], self._list[j] = self._list[j], self._list[i]

    @staticmethod
    def markCopyBlock(bl, fl: int) -> None:
        leaf = bl.getFrontLeaf()
        if leaf is not None: leaf._flags |= fl

    def clear(self) -> None: self._list.clear()

    def markUnstructured(self) -> None:
        for bl in self._list: bl.markUnstructured()

    def markLabelBumpUp(self, bump: bool) -> None:
        FlowBlock.markLabelBumpUp(self, bump)
        if not self._list: return
        self._list[0].markLabelBumpUp(bump)
        for bl in self._list[1:]: bl.markLabelBumpUp(False)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        for i in range(len(self._list)):
            ind = curexit if i + 1 >= len(self._list) else self._list[i + 1].getIndex()
            self._list[i].scopeBreak(ind, curloopexit)

    def printTree(self, s, level: int) -> None:
        FlowBlock.printTree(self, s, level)
        for bl in self._list: bl.printTree(s, level + 1)

    def printRaw(self, s) -> None:
        self.printHeader(s); s.write('\n')
        if not self._list: return
        lastBl = self._list[0]; lastBl.printRaw(s)
        for curBl in self._list[1:]:
            lastBl.printRawImpliedGoto(s, curBl); curBl.printRaw(s); lastBl = curBl

    def printRawImpliedGoto(self, s, nextBlock) -> None:
        if self._list: self._list[-1].printRawImpliedGoto(s, nextBlock)

    def emit(self, lng) -> None: lng.emitBlockGraph(self)

    def firstOp(self):
        return self.getBlock(0).firstOp() if self._list else None

    def nextFlowAfter(self, bl):
        for i, item in enumerate(self._list):
            if item is bl:
                if i + 1 < len(self._list):
                    nb = self._list[i + 1]
                    return nb.getFrontLeaf() if nb else None
                return self._parent.nextFlowAfter(self) if self._parent else None
        return None

    def finalTransform(self, data) -> None:
        for bl in self._list: bl.finalTransform(data)

    def finalizePrinting(self, data) -> None:
        for bl in self._list: bl.finalizePrinting(data)

    def encodeBody(self, encoder) -> None:
        FlowBlock.encodeBody(self, encoder)
        for bl in self._list:
            encoder.openElement(ELEM_BHEAD)
            encoder.writeSignedInteger(ATTRIB_ALTINDEX, bl.getIndex())
            bt = bl.getType()
            if bt == FlowBlock.t_if:
                sz = bl.getSize(); nm = "ifgoto" if sz == 1 else ("properif" if sz == 2 else "ifelse")
            else:
                nm = FlowBlock.typeToName(bt)
            encoder.writeString(ATTRIB_OPCODE, nm)
            encoder.closeElement(ELEM_BHEAD)
        for bl in self._list: bl.encode(encoder)

    def decodeBody(self, decoder) -> None:
        tmplist = []; newresolver = BlockMap()
        while True:
            if decoder.peekElement() != ELEM_BHEAD: break
            subId = decoder.openElement()
            idx = decoder.readSignedInteger(ATTRIB_ALTINDEX)
            bl = newresolver.createBlock(decoder.readString(ATTRIB_OPCODE))
            bl._index = idx; tmplist.append(bl)
            decoder.closeElement(subId)
        newresolver.sortList()
        for bl in tmplist:
            bl.decode(decoder, newresolver); self.addBlock(bl)

    # ---- Graph manipulation ----
    def addEdge(self, begin, end): end.addInEdge(begin, 0)
    def addLoopEdge(self, begin, outindex: int): begin.setOutEdgeFlag(outindex, FlowBlock.f_loop_edge)

    def removeEdge(self, begin, end):
        for i in range(len(end._intothis)):
            if end._intothis[i].point is begin: end.removeInEdge(i); return

    def switchEdge(self, in_, outbefore, outafter):
        for i in range(len(in_._outofthis)):
            if in_._outofthis[i].point is outbefore: in_.replaceOutEdge(i, outafter)

    def moveOutEdge(self, blold, slot: int, blnew):
        outbl = blold.getOut(slot); i = blold.getOutRevIndex(slot)
        outbl.replaceInEdge(i, blnew)

    def removeBlock(self, bl):
        while bl.sizeIn() > 0: self.removeEdge(bl.getIn(0), bl)
        while bl.sizeOut() > 0: self.removeEdge(bl, bl.getOut(0))
        self._list = [b for b in self._list if b is not bl]

    def removeFromFlow(self, bl):
        while bl.sizeOut() > 0:
            bbout = bl.getOut(bl.sizeOut() - 1); bl.removeOutEdge(bl.sizeOut() - 1)
            while bl.sizeIn() > 0:
                bl.getIn(0).replaceOutEdge(bl._intothis[0].reverse_index, bbout)

    def removeFromFlowSplit(self, bl, flipflow: bool):
        bl.replaceEdgesThru(0, 1) if flipflow else bl.replaceEdgesThru(1, 1)
        bl.replaceEdgesThru(0, 0)

    def spliceBlock(self, bl):
        outbl = bl.getOut(0) if bl.sizeOut() == 1 else None
        if outbl and outbl.sizeIn() != 1: outbl = None
        if outbl is None: raise RuntimeError("Can only splice block with 1 out to block with 1 in")
        fl1 = bl._flags & (FlowBlock.f_unstructured_targ | FlowBlock.f_entry_point)
        fl2 = outbl._flags & FlowBlock.f_switch_out
        bl.removeOutEdge(0)
        for _ in range(outbl.sizeOut()): self.moveOutEdge(outbl, 0, bl)
        self.removeBlock(outbl); bl._flags = fl1 | fl2

    def setStartBlock(self, bl):
        if self._list and (self._list[0]._flags & FlowBlock.f_entry_point):
            if bl is self._list[0]: return
            self._list[0]._flags &= ~FlowBlock.f_entry_point
        idx = next((i for i, b in enumerate(self._list) if b is bl), 0)
        for j in range(idx, 0, -1): self._list[j] = self._list[j - 1]
        self._list[0] = bl; bl._flags |= FlowBlock.f_entry_point

    def getStartBlock(self):
        if not self._list or not (self._list[0]._flags & FlowBlock.f_entry_point):
            raise RuntimeError("No start block registered")
        return self._list[0]

    # ---- Factory methods ----
    def newBlock(self):
        ret = FlowBlock(); self.addBlock(ret); return ret

    def newBlockBasic(self, fd):
        ret = BlockBasic(fd); self.addBlock(ret); return ret

    def newBlockCopy(self, bl):
        ret = BlockCopy(bl)
        ret._intothis = list(bl._intothis); ret._outofthis = list(bl._outofthis)
        ret._immed_dom = bl._immed_dom; ret._index = bl._index; ret._numdesc = bl._numdesc
        ret._flags |= bl._flags
        if len(ret._outofthis) > 2: ret._flags |= FlowBlock.f_switch_out
        self.addBlock(ret); return ret

    def newBlockGoto(self, bl):
        ret = BlockGoto(bl.getOut(0))
        self.identifyInternal(ret, [bl]); self.addBlock(ret)
        ret.forceOutputNum(1); self.removeEdge(ret, ret.getOut(0)); return ret

    def newBlockMultiGoto(self, bl, outedge: int):
        targetbl = bl.getOut(outedge)
        isdefaultedge = bl.isDefaultBranch(outedge)
        if bl.getType() == FlowBlock.t_multigoto:
            ret = bl; ret.addGotoEdge(targetbl)
            self.removeEdge(ret, targetbl)
            if isdefaultedge: ret.setDefaultGoto()
        else:
            ret = BlockMultiGoto(bl)
            origSizeOut = bl.sizeOut()
            self.identifyInternal(ret, [bl]); self.addBlock(ret)
            ret.addGotoEdge(targetbl)
            if targetbl is not bl:
                if ret.sizeOut() != origSizeOut:
                    ret.forceOutputNum(ret.sizeOut() + 1)
                self.removeEdge(ret, targetbl)
            if isdefaultedge: ret.setDefaultGoto()
        return ret

    def newBlockList(self, nodes):
        out0 = nodes[-1].getOut(0) if nodes[-1].sizeOut() == 2 else None
        outforce = nodes[-1].sizeOut()
        ret = BlockList(); self.identifyInternal(ret, nodes); self.addBlock(ret)
        ret.forceOutputNum(outforce)
        if ret.sizeOut() == 2: ret.forceFalseEdge(out0)
        return ret

    def newBlockCondition(self, b1, b2):
        from ghidra.core.opcodes import OpCode
        out0 = b2.getOut(0)
        opc = OpCode.CPUI_INT_OR if b1.getFalseOut() is b2 else OpCode.CPUI_INT_AND
        ret = BlockCondition(opc); self.identifyInternal(ret, [b1, b2]); self.addBlock(ret)
        ret.forceOutputNum(2); ret.forceFalseEdge(out0); return ret

    def newBlockIfGoto(self, cond):
        out0 = cond.getOut(0); ret = BlockIf(); ret.setGotoTarget(cond.getOut(1))
        self.identifyInternal(ret, [cond]); self.addBlock(ret)
        ret.forceOutputNum(2); ret.forceFalseEdge(out0)
        self.removeEdge(ret, ret.getTrueOut()); return ret

    def newBlockIf(self, cond, tc):
        ret = BlockIf(); self.identifyInternal(ret, [cond, tc]); self.addBlock(ret)
        ret.forceOutputNum(1); return ret

    def newBlockIfElse(self, cond, tc, fc):
        ret = BlockIf(); self.identifyInternal(ret, [cond, tc, fc]); self.addBlock(ret)
        ret.forceOutputNum(1); return ret

    def newBlockWhileDo(self, cond, cl):
        ret = BlockWhileDo(); self.identifyInternal(ret, [cond, cl]); self.addBlock(ret)
        ret.forceOutputNum(1); return ret

    def newBlockDoWhile(self, condcl):
        ret = BlockDoWhile(); self.identifyInternal(ret, [condcl]); self.addBlock(ret)
        ret.forceOutputNum(1); return ret

    def newBlockInfLoop(self, body):
        ret = BlockInfLoop(); self.identifyInternal(ret, [body]); self.addBlock(ret)
        return ret

    def newBlockSwitch(self, cs, hasExit: bool):
        rootbl = cs[0]; ret = BlockSwitch(rootbl)
        leafbl = rootbl.getExitLeaf()
        if leafbl is None or leafbl.getType() != FlowBlock.t_copy:
            raise RuntimeError("Could not get switch leaf")
        ret.grabCaseBasic(leafbl.subBlock(0), cs)
        self.identifyInternal(ret, cs); self.addBlock(ret)
        if hasExit: ret.forceOutputNum(1)
        ret.clearFlag(FlowBlock.f_switch_out); return ret

    def decodeGraph(self, decoder) -> None:
        resolver = BlockMap()
        FlowBlock.decode(self, decoder, resolver)

    def orderBlocks(self):
        if len(self._list) != 1:
            self._list.sort(key=lambda b: (0 if b.getIndex() == 0 else 1, b.getIndex()))

    def buildCopy(self, graph):
        startsize = len(self._list)
        for bl in graph._list:
            cb = self.newBlockCopy(bl); bl._copymap = cb
        for bl in self._list[startsize:]: bl.replaceUsingMap()

    def clearVisitCount(self):
        for bl in self._list: bl._visitcount = 0

    def calcForwardDominator(self, rootlist):
        if not self._list: return
        nn = len(self._list) - 1; po = [None] * len(self._list)
        for i, bl in enumerate(self._list): bl._immed_dom = None; po[nn - i] = bl
        vr = BlockGraph.createVirtualRoot(rootlist) if len(rootlist) > 1 else None
        if vr: po.append(vr)
        b = po[-1]
        if b.sizeIn() != 0:
            if len(rootlist) != 1 or rootlist[0] is not b:
                raise RuntimeError("Problems finding root node of graph")
            vr = BlockGraph.createVirtualRoot(rootlist); po.append(vr); b = vr
        b._immed_dom = b
        for i in range(b.sizeOut()): b.getOut(i)._immed_dom = b
        changed = True
        while changed:
            changed = False
            for i in range(len(po) - 2, -1, -1):
                b = po[i]
                if b._immed_dom is po[-1]: continue
                ni = None; j = 0
                while j < b.sizeIn():
                    ni = b.getIn(j)
                    if ni._immed_dom is not None: break
                    j += 1
                j += 1
                while j < b.sizeIn():
                    rho = b.getIn(j)
                    if rho._immed_dom is not None:
                        f1 = nn - rho._index; f2 = nn - ni._index
                        while f1 != f2:
                            while f1 < f2: f1 = nn - po[f1]._immed_dom._index
                            while f2 < f1: f2 = nn - po[f2]._immed_dom._index
                        ni = po[f1]
                    j += 1
                if b._immed_dom is not ni: b._immed_dom = ni; changed = True
        if vr is not None:
            for i in range(len(self._list)):
                if po[i]._immed_dom is vr: po[i]._immed_dom = None
            while vr.sizeOut() > 0: vr.removeOutEdge(vr.sizeOut() - 1)
        else:
            po[-1]._immed_dom = None

    def buildDomTree(self):
        child = [[] for _ in range(len(self._list) + 1)]
        for bl in self._list:
            if bl._immed_dom is not None: child[bl._immed_dom._index].append(bl)
            else: child[len(self._list)].append(bl)
        return child

    def buildDomDepth(self):
        depth = [0] * (len(self._list) + 1); mx = 0
        for i, bl in enumerate(self._list):
            d = bl._immed_dom
            depth[i] = depth[d.getIndex()] + 1 if d else 1
            if mx < depth[i]: mx = depth[i]
        depth[len(self._list)] = 0; return (depth, mx)

    def buildDomSubTree(self, res, root):
        ri = root.getIndex(); res.append(root)
        for i in range(ri + 1, len(self._list)):
            bl = self._list[i]; d = bl.getImmedDom()
            if d is None or d.getIndex() > ri: break
            res.append(bl)

    def calcLoop(self):
        if not self._list: return
        path = [self._list[0]]; state = [0]
        self._list[0].setFlag(FlowBlock.f_mark | FlowBlock.f_mark2)
        while path:
            bl = path[-1]; i = state[-1]
            if i >= bl.sizeOut():
                bl.clearFlag(FlowBlock.f_mark2); path.pop(); state.pop()
            else:
                state[-1] += 1
                if bl.isLoopOut(i): continue
                nb = bl.getOut(i)
                if (nb._flags & FlowBlock.f_mark2): self.addLoopEdge(bl, i)
                elif not (nb._flags & FlowBlock.f_mark):
                    nb.setFlag(FlowBlock.f_mark | FlowBlock.f_mark2); path.append(nb); state.append(0)
        for bl in self._list: bl.clearFlag(FlowBlock.f_mark | FlowBlock.f_mark2)

    def collectReachable(self, res, bl, un: bool):
        bl.setMark(); res.append(bl); total = 0
        while total < len(res):
            blk = res[total]; total += 1
            for j in range(blk.sizeOut()):
                b2 = blk.getOut(j)
                if not b2.isMark(): b2.setMark(); res.append(b2)
        if un:
            res.clear()
            for b in self._list:
                if b.isMark(): b.clearMark()
                else: res.append(b)
        else:
            for b in res: b.clearMark()

    def findSpanningTree(self, preorder, rootlist):
        if not self._list: return
        rpo = [None] * len(self._list); st = []; ist = []
        for bl in self._list:
            bl._index = -1; bl._visitcount = -1; bl._copymap = bl
            if bl.sizeIn() == 0: rootlist.append(bl)
        if len(rootlist) > 1: rootlist[0], rootlist[-1] = rootlist[-1], rootlist[0]
        elif not rootlist: rootlist.append(self._list[0])
        orp = len(rootlist) - 1
        for rep in range(2):
            extra = False; rpc = len(self._list); ri = 0; self.clearEdgeFlags(0xFFFFFFFF)
            while len(preorder) < len(self._list):
                sb = None
                while ri < len(rootlist):
                    sb = rootlist[ri]; ri += 1
                    if sb._visitcount == -1: break
                    for ii in range(ri, len(rootlist)): rootlist[ii-1] = rootlist[ii]
                    rootlist.pop(); ri -= 1; sb = None
                if sb is None:
                    extra = True
                    for bl in self._list:
                        if bl._visitcount == -1: sb = bl; break
                    rootlist.append(sb); ri += 1
                st.append(sb); ist.append(0); sb._visitcount = len(preorder)
                preorder.append(sb); sb._numdesc = 1
                while st:
                    cb = st[-1]
                    if cb.sizeOut() <= ist[-1]:
                        st.pop(); ist.pop(); rpc -= 1; cb._index = rpc; rpo[rpc] = cb
                        if st: st[-1]._numdesc += cb._numdesc
                    else:
                        en = ist[-1]; ist[-1] += 1
                        if cb.isIrreducibleOut(en): continue
                        ch = cb.getOut(en)
                        if ch._visitcount == -1:
                            cb.setOutEdgeFlag(en, FlowBlock.f_tree_edge)
                            st.append(ch); ist.append(0); ch._visitcount = len(preorder)
                            preorder.append(ch); ch._numdesc = 1
                        elif ch._index == -1: cb.setOutEdgeFlag(en, FlowBlock.f_back_edge | FlowBlock.f_loop_edge)
                        elif cb._visitcount < ch._visitcount: cb.setOutEdgeFlag(en, FlowBlock.f_forward_edge)
                        else: cb.setOutEdgeFlag(en, FlowBlock.f_cross_edge)
            if not extra: break
            if rep == 1: raise RuntimeError("Could not generate spanning tree")
            rootlist[-1], rootlist[orp] = rootlist[orp], rootlist[-1]
            for bl in self._list: bl._index = -1; bl._visitcount = -1; bl._copymap = bl
            preorder.clear(); st.clear(); ist.clear()
        if len(rootlist) > 1: rootlist[0], rootlist[-1] = rootlist[-1], rootlist[0]
        self._list = rpo

    def findIrreducible(self, preorder, irc):
        ru = []; nr = False; xi = len(preorder) - 1
        while xi >= 0:
            x = preorder[xi]; xi -= 1
            for i in range(x.sizeIn()):
                if not x.isBackEdgeIn(i): continue
                y = x.getIn(i)
                if y is x: continue
                ru.append(y._copymap); y._copymap.setMark()
            q = 0
            while q < len(ru):
                t = ru[q]; q += 1
                for i in range(t.sizeIn()):
                    if t.isIrreducibleIn(i): continue
                    y = t.getIn(i); yp = y._copymap
                    if x._visitcount > yp._visitcount or x._visitcount + x._numdesc <= yp._visitcount:
                        irc[0] += 1; eo = t.getInRevIndex(i)
                        y.setOutEdgeFlag(eo, FlowBlock.f_irreducible)
                        if t.isTreeEdgeIn(i): nr = True
                        else: y.clearOutEdgeFlag(eo, FlowBlock.f_cross_edge | FlowBlock.f_forward_edge)
                    elif not yp.isMark() and yp is not x: ru.append(yp); yp.setMark()
            for s in ru: s.clearMark(); s._copymap = x
            ru.clear()
        return nr

    def structureLoops(self, rootlist):
        preorder = []; irc = [0]
        while True:
            self.findSpanningTree(preorder, rootlist)
            if not self.findIrreducible(preorder, irc): break
            self.clearEdgeFlags(FlowBlock.f_tree_edge | FlowBlock.f_forward_edge | FlowBlock.f_cross_edge | FlowBlock.f_back_edge | FlowBlock.f_loop_edge)
            preorder.clear(); rootlist.clear()
        if irc[0] > 0: self.calcLoop()

    def isConsistent(self) -> bool:
        for bl1 in self._list:
            for j in range(bl1.sizeIn()):
                bl2 = bl1.getIn(j)
                c1 = sum(1 for k in range(bl1.sizeIn()) if bl1.getIn(k) is bl2)
                c2 = sum(1 for k in range(bl2.sizeOut()) if bl2.getOut(k) is bl1)
                if c1 != c2: return False
            for j in range(bl1.sizeOut()):
                bl2 = bl1.getOut(j)
                c1 = sum(1 for k in range(bl1.sizeOut()) if bl1.getOut(k) is bl2)
                c2 = sum(1 for k in range(bl2.sizeIn()) if bl2.getIn(k) is bl1)
                if c1 != c2: return False
        return True

    def __iter__(self): return iter(self._list)
    def __len__(self) -> int: return len(self._list)
    def __repr__(self): return f"BlockGraph(blocks={len(self._list)})"


# =========================================================================
# BlockBasic
# =========================================================================

class BlockBasic(FlowBlock):
    """A basic block for p-code operations."""

    def __init__(self, fd=None) -> None:
        super().__init__()
        self._op: list = []
        self._data = fd
        self._cover = RangeList()

    def getFuncdata(self): return self._data
    def contains(self, addr) -> bool: return self._cover.inRange(addr, 1)
    def getType(self) -> int: return FlowBlock.t_basic
    def subBlock(self, i: int): return None
    def getExitLeaf(self): return self
    def addOp(self, op) -> None:
        """Append a PcodeOp to this basic block."""
        self._op.append(op)

    def removeOp(self, op) -> None:
        """Remove a PcodeOp from this basic block."""
        try:
            self._op.remove(op)
        except ValueError:
            pass

    def insertOp(self, op, pos: int = 0) -> None:
        """Insert a PcodeOp at a specific position."""
        self._op.insert(pos, op)

    def getOpList(self):
        """Return the list of PcodeOps."""
        return self._op

    def beginOp(self): return iter(self._op)
    def endOp(self): return None
    def emptyOp(self) -> bool: return len(self._op) == 0
    def emit(self, lng) -> None: lng.emitBlockBasic(self)

    def getEntryAddr(self) -> Address:
        if self._cover.numRanges() == 1:
            r = self._cover.getFirstRange()
        else:
            if not self._op: return Address()
            addr = self._op[0].getAddr()
            r = self._cover.getRange(addr.getSpace(), addr.getOffset())
            if r is None: return self._op[0].getAddr()
        return r.getFirstAddr()

    def getStart(self) -> Address:
        r = self._cover.getFirstRange()
        return r.getFirstAddr() if r else Address()

    def getStop(self) -> Address:
        r = self._cover.getLastRange()
        return r.getLastAddr() if r else Address()

    def firstOp(self): return self._op[0] if self._op else None
    def lastOp(self): return self._op[-1] if self._op else None

    def negateCondition(self, toporbottom: bool) -> bool:
        from ghidra.ir.op import PcodeOp as PcodeOpCls
        self._op[-1].flipFlag(PcodeOpCls.boolean_flip)
        self._op[-1].flipFlag(PcodeOpCls.fallthru_true)
        FlowBlock.negateCondition(self, True); return True

    def getSplitPoint(self):
        return self if self.sizeOut() == 2 else None

    def flipInPlaceTest(self, fliplist: list) -> int:
        from ghidra.core.opcodes import OpCode
        if not self._op: return 2
        lastop = self._op[-1]
        if lastop.code() != OpCode.CPUI_CBRANCH: return 2
        return self._data.opFlipInPlaceTest(lastop, fliplist)

    def flipInPlaceExecute(self) -> None:
        from ghidra.ir.op import PcodeOp as PcodeOpCls
        lastop = self._op[-1]
        lastop.flipFlag(PcodeOpCls.fallthru_true)
        FlowBlock.negateCondition(self, True)

    def isComplex(self) -> bool:
        st = 1 if self.sizeOut() >= 2 else 0
        for inst in self._op:
            if inst.isMarker(): continue
            vn = inst.getOut()
            if inst.isCall(): st += 1
            elif vn is None:
                if inst.isFlowBreak(): continue
                st += 1
            else: st += 1
            if st > 2: return True
        return False

    def unblockedMulti(self, outslot: int) -> bool:
        from ghidra.core.opcodes import OpCode
        blout = self.getOut(outslot); rl = []
        for i in range(self.sizeIn()):
            bl = self.getIn(i)
            for j in range(bl.sizeOut()):
                if bl.getOut(j) is blout: rl.append(bl)
        if not rl: return True
        for mop in blout._op:
            if mop.code() != OpCode.CPUI_MULTIEQUAL: continue
            for bl in rl:
                vr = mop.getIn(blout.getInIndex(bl))
                vm = mop.getIn(blout.getInIndex(self))
                if vm.isWritten():
                    om = vm.getDef()
                    if om.code() == OpCode.CPUI_MULTIEQUAL and om.getParent() is self:
                        vm = om.getIn(self.getInIndex(bl))
                if vm is not vr: return False
        return True

    def hasOnlyMarkers(self) -> bool:
        for bop in self._op:
            if bop.isMarker() or bop.isBranch(): continue
            return False
        return True

    def isDoNothing(self) -> bool:
        from ghidra.core.opcodes import OpCode
        if self.sizeOut() != 1 or self.sizeIn() == 0: return False
        for i in range(self.sizeIn()):
            sw = self.getIn(i)
            if sw.isSwitchOut() and sw.sizeOut() > 1 and self.getOut(0).sizeIn() > 1: return False
        lo = self.lastOp()
        if lo is not None and lo.code() == OpCode.CPUI_BRANCHIND: return False
        return self.hasOnlyMarkers()

    def setInitialRange(self, beg, end):
        self._cover.clear(); self._cover.insertRange(beg.getSpace(), beg.getOffset(), end.getOffset())

    def setOrder(self) -> None:
        if not self._op: return
        step = (0xFFFFFFFFFFFFFFFF // len(self._op)) - 1
        count = 0
        for inst in self._op:
            count += step; inst.setOrder(count)

    def copyRange(self, bb): self._cover = bb._cover
    def mergeRange(self, bb): self._cover.merge(bb._cover)

    def insert(self, pos, inst):
        inst.setParent(self); self._op.insert(pos, inst)
        from ghidra.core.opcodes import OpCode
        if inst.isBranch() and inst.code() == OpCode.CPUI_BRANCHIND:
            self.setFlag(FlowBlock.f_switch_out)

    def removeOp(self, inst): inst.setParent(None); self._op.remove(inst)

    def noInterveningStatement(self) -> bool:
        from ghidra.core.opcodes import OpCode
        for bop in self._op:
            if bop.isMarker() or bop.isBranch(): continue
            if bop.getEvalType() == 'special':
                if bop.isCall(): return False
                opc = bop.code()
                if opc == OpCode.CPUI_STORE or opc == OpCode.CPUI_NEW: return False
            else:
                opc = bop.code()
                if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_SUBPIECE: continue
            outvn = bop.getOut()
            if outvn is None: continue
            if outvn.isAddrTied(): return False
            for desc in outvn.getDescend():
                if desc.getParent() is not self: return False
        return True

    def findMultiequal(self, varArray: list):
        from ghidra.core.opcodes import OpCode
        vn = varArray[0]
        for op in vn.getDescend():
            if op.code() == OpCode.CPUI_MULTIEQUAL and op.getParent() is self:
                for i in range(op.numInput()):
                    if op.getIn(i) is not varArray[i]: return None
                return op
        return None

    def earliestUse(self, vn):
        res = None
        for op in vn.getDescend():
            if op.getParent() is not self: continue
            if res is None or op.getSeqNum().getOrder() < res.getSeqNum().getOrder():
                res = op
        return res

    def liftVerifyUnroll(self, varArray: list, slot: int) -> bool:
        vn = varArray[0]
        if not vn.isWritten(): return False
        op = vn.getDef(); opc = op.code()
        cvn = None
        if op.numInput() == 2:
            cvn = op.getIn(1 - slot)
            if not cvn.isConstant(): return False
        varArray[0] = op.getIn(slot)
        for i in range(1, len(varArray)):
            vn = varArray[i]
            if not vn.isWritten(): return False
            op = vn.getDef()
            if op.code() != opc: return False
            if cvn is not None:
                cvn2 = op.getIn(1 - slot)
                if not cvn2.isConstant(): return False
                if cvn.getSize() != cvn2.getSize(): return False
                if cvn.getOffset() != cvn2.getOffset(): return False
            varArray[i] = op.getIn(slot)
        return True

    def encodeBody(self, encoder): self._cover.encode(encoder)
    def decodeBody(self, decoder): self._cover.decode(decoder)

    def printHeader(self, s):
        s.write("Basic Block "); FlowBlock.printHeader(self, s)

    def printRaw(self, s):
        self.printHeader(s); s.write('\n')
        for inst in self._op:
            s.write(f"{inst.getSeqNum()}:\t"); inst.printRaw(s); s.write('\n')

    def printRawImpliedGoto(self, s, nextBlock) -> None:
        if self.sizeOut() != 1: return
        outBlock = self.getOut(0)
        if nextBlock.getType() != FlowBlock.t_basic:
            nextBlock = nextBlock.getFrontLeaf()
            if nextBlock is None: return
            nextBlock = nextBlock.subBlock(0)
        if self.getOut(0) is nextBlock: return
        if self._op and self._op[-1].isBranch(): return
        self.getStop().printRaw(s)
        s.write(':   \t[ goto ')
        outBlock.printShortHeader(s)
        s.write(' ]\n')

    def __repr__(self): return f"BlockBasic(index={self._index}, ops={len(self._op)})"


# =========================================================================
# BlockCopy  (inherits FlowBlock, mirrors a BlockBasic)
# =========================================================================

class BlockCopy(FlowBlock):
    """Mirror of a BlockBasic used during control-flow structuring."""

    def __init__(self, bl: Optional[FlowBlock] = None) -> None:
        super().__init__()
        self._copy: Optional[FlowBlock] = bl

    def subBlock(self, i: int): return self._copy
    def getType(self) -> int: return FlowBlock.t_copy
    def getExitLeaf(self): return self
    def firstOp(self): return self._copy.firstOp() if self._copy else None
    def lastOp(self): return self._copy.lastOp() if self._copy else None
    def isComplex(self) -> bool: return self._copy.isComplex() if self._copy else True
    def getSplitPoint(self): return self._copy.getSplitPoint() if self._copy else None
    def emit(self, lng) -> None: lng.emitBlockCopy(self)

    def negateCondition(self, toporbottom: bool) -> bool:
        res = self._copy.negateCondition(True) if self._copy else False
        FlowBlock.negateCondition(self, toporbottom); return res

    def printHeader(self, s) -> None:
        s.write("Basic(copy) block "); FlowBlock.printHeader(self, s)

    def printTree(self, s, level: int) -> None:
        if self._copy: self._copy.printTree(s, level)

    def encodeHeader(self, encoder) -> None:
        FlowBlock.encodeHeader(self, encoder)
        encoder.writeSignedInteger(ATTRIB_ALTINDEX, self._copy.getIndex() if self._copy else 0)

    def printRaw(self, s) -> None:
        s.write(f"BlockCopy(copy of {self._copy.getIndex() if self._copy else '?'})")

    def printRawImpliedGoto(self, s) -> None:
        s.write("implied goto")


# =========================================================================
# BlockGoto  (inherits BlockGraph)
# =========================================================================

class BlockGoto(BlockGraph):
    """A block that terminates with an unstructured goto branch."""

    def __init__(self, target: Optional[FlowBlock] = None) -> None:
        super().__init__()
        self._gototarget: Optional[FlowBlock] = target
        self._gototype: int = FlowBlock.f_goto_goto

    def getGotoTarget(self): return self._gototarget
    def getGotoType(self) -> int: return self._gototype
    def getType(self) -> int: return FlowBlock.t_goto
    def getExitLeaf(self): return self.getBlock(0).getExitLeaf() if self.getSize() > 0 else None
    def lastOp(self): return self.getBlock(0).lastOp() if self.getSize() > 0 else None
    def emit(self, lng) -> None: lng.emitBlockGoto(self)

    def gotoPrints(self) -> bool:
        if self.getParent() is not None:
            nextbl = self.getParent().nextFlowAfter(self)
            gotobl = self._gototarget.getFrontLeaf() if self._gototarget else None
            return gotobl is not nextbl
        return False

    def markUnstructured(self) -> None:
        BlockGraph.markUnstructured(self)
        if self._gototype == FlowBlock.f_goto_goto and self.gotoPrints():
            BlockGraph.markCopyBlock(self._gototarget, FlowBlock.f_unstructured_targ)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0:
            self.getBlock(0).scopeBreak(self._gototarget.getIndex(), curloopexit)
        if curloopexit == self._gototarget.getIndex():
            self._gototype = FlowBlock.f_break_goto

    def printHeader(self, s) -> None:
        s.write("Plain goto block "); FlowBlock.printHeader(self, s)

    def nextFlowAfter(self, bl):
        return self._gototarget.getFrontLeaf() if self._gototarget else None

    def encodeBody(self, encoder) -> None:
        BlockGraph.encodeBody(self, encoder)
        if self._gototarget is not None:
            encoder.openElement(ELEM_TARGET)
            leaf = self._gototarget.getFrontLeaf()
            depth = self._gototarget.calcDepth(leaf)
            encoder.writeSignedInteger(ATTRIB_INDEX, leaf.getIndex())
            encoder.writeSignedInteger(ATTRIB_DEPTH, depth)
            encoder.writeUnsignedInteger(ATTRIB_TYPE, self._gototype)
            encoder.closeElement(ELEM_TARGET)

    def printRaw(self, s) -> None:
        s.write(f"BlockGoto(target={self._gototarget.getIndex() if self._gototarget else '?'})")


# =========================================================================
# BlockMultiGoto  (inherits BlockGraph)
# =========================================================================

class BlockMultiGoto(BlockGraph):
    """A block with multiple unstructured goto edges."""

    def __init__(self, bl: Optional[FlowBlock] = None) -> None:
        super().__init__()
        self._gotoedges: List[FlowBlock] = []
        self._defaultswitch: bool = False

    def setDefaultGoto(self) -> None: self._defaultswitch = True
    def hasDefaultGoto(self) -> bool: return self._defaultswitch
    def addGotoEdge(self, bl: FlowBlock) -> None: self._gotoedges.append(bl)
    def numGotos(self) -> int: return len(self._gotoedges)
    def getGoto(self, i: int): return self._gotoedges[i]
    def getType(self) -> int: return FlowBlock.t_multigoto
    def getExitLeaf(self): return self.getBlock(0).getExitLeaf() if self.getSize() > 0 else None
    def lastOp(self): return self.getBlock(0).lastOp() if self.getSize() > 0 else None
    def emit(self, lng) -> None:
        if self.getSize() > 0: self.getBlock(0).emit(lng)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0: self.getBlock(0).scopeBreak(-1, curloopexit)

    def printHeader(self, s) -> None:
        s.write("Multi goto block "); FlowBlock.printHeader(self, s)

    def addEdge(self, bl) -> None:
        self._gotoedges.append(bl)

    def nextFlowAfter(self, bl): return None

    def printRaw(self, s) -> None:
        s.write(f"BlockMultiGoto({len(self._gotoedges)} gotos)")

    def encodeBody(self, encoder) -> None:
        BlockGraph.encodeBody(self, encoder)
        for gt in self._gotoedges:
            leaf = gt.getFrontLeaf()
            depth = gt.calcDepth(leaf)
            encoder.openElement(ELEM_TARGET)
            encoder.writeSignedInteger(ATTRIB_INDEX, leaf.getIndex())
            encoder.writeSignedInteger(ATTRIB_DEPTH, depth)
            encoder.closeElement(ELEM_TARGET)


# =========================================================================
# BlockList  (inherits BlockGraph)
# =========================================================================

class BlockList(BlockGraph):
    """A series of blocks that execute in sequence."""

    def getType(self) -> int: return FlowBlock.t_ls
    def emit(self, lng) -> None: lng.emitBlockLs(self)

    def getExitLeaf(self):
        return self.getBlock(self.getSize() - 1).getExitLeaf() if self.getSize() > 0 else None

    def lastOp(self):
        return self.getBlock(self.getSize() - 1).lastOp() if self.getSize() > 0 else None

    def negateCondition(self, toporbottom: bool) -> bool:
        bl = self.getBlock(self.getSize() - 1)
        res = bl.negateCondition(False)
        FlowBlock.negateCondition(self, toporbottom); return res

    def getSplitPoint(self):
        return self.getBlock(self.getSize() - 1).getSplitPoint() if self.getSize() > 0 else None

    def printHeader(self, s) -> None:
        s.write("List block "); FlowBlock.printHeader(self, s)


# =========================================================================
# BlockCondition  (inherits BlockGraph)
# =========================================================================

class BlockCondition(BlockGraph):
    """Two conditional blocks combined with BOOL_AND or BOOL_OR."""

    def __init__(self, opc: int = 0) -> None:
        super().__init__()
        self._opc: int = opc

    def getOpcode(self) -> int: return self._opc
    def getType(self) -> int: return FlowBlock.t_condition
    def getSplitPoint(self): return self
    def emit(self, lng) -> None: lng.emitBlockCondition(self)

    def flipInPlaceTest(self, fliplist: list) -> int:
        s1 = self.getBlock(0).getSplitPoint() if self.getSize() > 0 else None
        if s1 is None: return 2
        s2 = self.getBlock(1).getSplitPoint() if self.getSize() > 1 else None
        if s2 is None: return 2
        r1 = s1.flipInPlaceTest(fliplist)
        if r1 == 2: return 2
        r2 = s2.flipInPlaceTest(fliplist)
        return 2 if r2 == 2 else r1

    def flipInPlaceExecute(self) -> None:
        from ghidra.core.opcodes import OpCode
        self._opc = OpCode.CPUI_BOOL_OR if self._opc == OpCode.CPUI_BOOL_AND else OpCode.CPUI_BOOL_AND
        self.getBlock(0).getSplitPoint().flipInPlaceExecute()
        self.getBlock(1).getSplitPoint().flipInPlaceExecute()

    def lastOp(self):
        return self.getBlock(1).lastOp() if self.getSize() > 1 else None

    def negateCondition(self, toporbottom: bool) -> bool:
        from ghidra.core.opcodes import OpCode
        r1 = self.getBlock(0).negateCondition(False)
        r2 = self.getBlock(1).negateCondition(False)
        self._opc = OpCode.CPUI_BOOL_OR if self._opc == OpCode.CPUI_BOOL_AND else OpCode.CPUI_BOOL_AND
        FlowBlock.negateCondition(self, toporbottom); return r1 or r2

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0: self.getBlock(0).scopeBreak(-1, curloopexit)
        if self.getSize() > 1: self.getBlock(1).scopeBreak(-1, curloopexit)

    def printHeader(self, s) -> None:
        from ghidra.core.opcodes import OpCode
        s.write(f"Condition block({'&&' if self._opc == OpCode.CPUI_BOOL_AND else '||'}) ")
        FlowBlock.printHeader(self, s)

    def isComplex(self) -> bool:
        return True

    def nextFlowAfter(self, bl): return None

    def encodeHeader(self, encoder) -> None:
        BlockGraph.encodeHeader(self, encoder)
        from ghidra.core.opcodes import OpCode
        nm = OpCode.get_opname(self._opc) if hasattr(OpCode, 'get_opname') else str(self._opc)
        encoder.writeString(ATTRIB_OPCODE, nm)


# =========================================================================
# BlockIf  (inherits BlockGraph)
# =========================================================================

class BlockIf(BlockGraph):
    """A basic 'if' block (if/then, if/then/else, or if-goto)."""

    def __init__(self) -> None:
        super().__init__()
        self._gototype: int = FlowBlock.f_goto_goto
        self._gototarget: Optional[FlowBlock] = None

    def setGotoTarget(self, bl) -> None: self._gototarget = bl
    def getGotoTarget(self): return self._gototarget
    def getGotoType(self) -> int: return self._gototype
    def getType(self) -> int: return FlowBlock.t_if
    def emit(self, lng) -> None: lng.emitBlockIf(self)

    def markUnstructured(self) -> None:
        BlockGraph.markUnstructured(self)
        if self._gototarget is not None and self._gototype == FlowBlock.f_goto_goto:
            BlockGraph.markCopyBlock(self._gototarget, FlowBlock.f_unstructured_targ)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0: self.getBlock(0).scopeBreak(-1, curloopexit)
        for i in range(1, self.getSize()):
            self.getBlock(i).scopeBreak(curexit, curloopexit)
        if self._gototarget is not None and self._gototarget.getIndex() == curloopexit:
            self._gototype = FlowBlock.f_break_goto

    def printHeader(self, s) -> None:
        s.write("If block "); FlowBlock.printHeader(self, s)

    def preferComplement(self, data) -> bool:
        if self.getSize() != 3: return False
        split = self.getBlock(0).getSplitPoint()
        if split is None: return False
        fliplist = []
        if split.flipInPlaceTest(fliplist) != 0: return False
        split.flipInPlaceExecute()
        data.opFlipInPlaceExecute(fliplist)
        self.swapBlocks(1, 2); return True

    def getExitLeaf(self):
        return self.getBlock(0).getExitLeaf() if self.getSize() == 1 else None

    def lastOp(self):
        return self.getBlock(0).lastOp() if self.getSize() == 1 else None

    def nextFlowAfter(self, bl):
        if self.getBlock(0) is bl: return None
        if self.getParent() is None: return None
        return self.getParent().nextFlowAfter(self)

    def encodeBody(self, encoder) -> None:
        BlockGraph.encodeBody(self, encoder)
        if self.getSize() == 1 and self._gototarget is not None:
            leaf = self._gototarget.getFrontLeaf()
            depth = self._gototarget.calcDepth(leaf)
            encoder.openElement(ELEM_TARGET)
            encoder.writeSignedInteger(ATTRIB_INDEX, leaf.getIndex())
            encoder.writeSignedInteger(ATTRIB_DEPTH, depth)
            encoder.writeUnsignedInteger(ATTRIB_TYPE, self._gototype)
            encoder.closeElement(ELEM_TARGET)


# =========================================================================
# BlockWhileDo  (inherits BlockGraph)
# =========================================================================

class BlockWhileDo(BlockGraph):
    """A loop structure where the condition is checked at the top."""

    def __init__(self) -> None:
        super().__init__()
        self._initializeOp = None
        self._iterateOp = None
        self._loopDef = None

    def getInitializeOp(self): return self._initializeOp
    def getIterateOp(self): return self._iterateOp
    def hasOverflowSyntax(self) -> bool: return (self.getFlags() & FlowBlock.f_whiledo_overflow) != 0
    def setOverflowSyntax(self) -> None: self.setFlag(FlowBlock.f_whiledo_overflow)
    def getType(self) -> int: return FlowBlock.t_whiledo
    def emit(self, lng) -> None: lng.emitBlockWhileDo(self)

    def findLoopVariable(self, cbranch, head, tail, lastOp) -> None:
        from ghidra.core.opcodes import OpCode
        vn = cbranch.getIn(1)
        if not vn.isWritten(): return
        op = vn.getDef()
        slot = tail.getOutRevIndex(0)
        if op.isCall() or op.isMarker(): return
        path = [None] * 4; pathslot = [0] * 4
        count = 0; path[0] = op; pathslot[0] = 0
        while count >= 0:
            curOp = path[count]; ind = pathslot[count]; pathslot[count] += 1
            if ind >= curOp.numInput(): count -= 1; continue
            nextVn = curOp.getIn(ind)
            if not nextVn.isWritten(): continue
            defOp = nextVn.getDef()
            if defOp.code() == OpCode.CPUI_MULTIEQUAL:
                if defOp.getParent() is not head: continue
                itvn = defOp.getIn(slot)
                if not itvn.isWritten(): continue
                possibleIterate = itvn.getDef()
                if possibleIterate.getParent() is tail:
                    if possibleIterate.isMarker(): continue
                    if not possibleIterate.isMoveable(lastOp): continue
                    self._loopDef = defOp; self._iterateOp = possibleIterate; return
            else:
                if count == 3: continue
                if defOp.isCall() or defOp.isMarker(): continue
                count += 1; path[count] = defOp; pathslot[count] = 0

    def findInitializer(self, head, slot):
        if head.sizeIn() != 2: return None
        slot = 1 - slot
        initVn = self._loopDef.getIn(slot)
        if not initVn.isWritten(): return None
        res = initVn.getDef()
        if res.isMarker(): return None
        initialBlock = res.getParent()
        if initialBlock is not head.getIn(slot): return None
        lastOp = initialBlock.lastOp()
        if lastOp is None: return None
        if initialBlock.sizeOut() != 1: return None
        if lastOp.isBranch():
            lastOp = lastOp.previousOp()
            if lastOp is None: return None
        self._initializeOp = res
        return lastOp

    def testTerminal(self, data, slot):
        from ghidra.core.opcodes import OpCode
        vn = self._loopDef.getIn(slot)
        if not vn.isWritten(): return None
        finalOp = vn.getDef()
        parentBlock = self._loopDef.getParent().getIn(slot)
        resOp = finalOp
        if finalOp.code() == OpCode.CPUI_COPY and finalOp.notPrinted():
            vn = finalOp.getIn(0)
            if not vn.isWritten(): return None
            resOp = vn.getDef()
            if resOp.getParent() is not parentBlock: return None
        if not vn.isExplicit(): return None
        if resOp.notPrinted(): return None
        lastOp = finalOp.getParent().lastOp()
        if lastOp.isBranch(): lastOp = lastOp.previousOp()
        if not data.moveRespectingCover(finalOp, lastOp): return None
        return resOp

    def testIterateForm(self) -> bool:
        targetVn = self._loopDef.getOut()
        high = targetVn.getHigh()
        path = [(self._iterateOp, 0)]
        while path:
            op, sl = path[-1]
            if op.numInput() <= sl: path.pop(); continue
            path[-1] = (op, sl + 1)
            vn = op.getIn(sl)
            if vn.isAnnotation(): continue
            if vn.getHigh() is high: return True
            if vn.isExplicit(): continue
            if not vn.isWritten(): continue
            path.append((vn.getDef(), 0))
        return False

    def markLabelBumpUp(self, bump: bool) -> None:
        BlockGraph.markLabelBumpUp(self, True)
        if not bump: self.clearFlag(FlowBlock.f_label_bumpup)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0: self.getBlock(0).scopeBreak(-1, curexit)
        if self.getSize() > 1: self.getBlock(1).scopeBreak(self.getBlock(0).getIndex(), curexit)

    def printHeader(self, s) -> None:
        s.write("Whiledo block ")
        if self.hasOverflowSyntax(): s.write("(overflow) ")
        FlowBlock.printHeader(self, s)

    def nextFlowAfter(self, bl):
        if self.getSize() > 0 and self.getBlock(0) is bl: return None
        nb = self.getBlock(0) if self.getSize() > 0 else None
        return nb.getFrontLeaf() if nb else None

    def finalTransform(self, data) -> None:
        from ghidra.core.opcodes import OpCode
        BlockGraph.finalTransform(self, data)
        if not hasattr(data.getArch(), 'analyze_for_loops') or not data.getArch().analyze_for_loops:
            return
        if self.hasOverflowSyntax(): return
        copyBl = self.getFrontLeaf()
        if copyBl is None: return
        head = copyBl.subBlock(0)
        if head is None or head.getType() != FlowBlock.t_basic: return
        lastOp = self.getBlock(1).lastOp()
        if lastOp is None: return
        tail = lastOp.getParent()
        if tail.sizeOut() != 1 or tail.getOut(0) is not head: return
        cbranch = self.getBlock(0).lastOp()
        if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH: return
        if lastOp.isBranch():
            lastOp = lastOp.previousOp()
            if lastOp is None: return
        self.findLoopVariable(cbranch, head, tail, lastOp)
        if self._iterateOp is None: return
        if self._iterateOp is not lastOp:
            data.opUninsert(self._iterateOp); data.opInsertAfter(self._iterateOp, lastOp)
        lastOp = self.findInitializer(head, tail.getOutRevIndex(0))
        if lastOp is None: return
        if not self._initializeOp.isMoveable(lastOp):
            self._initializeOp = None; return
        if self._initializeOp is not lastOp:
            data.opUninsert(self._initializeOp); data.opInsertAfter(self._initializeOp, lastOp)

    def finalizePrinting(self, data) -> None:
        BlockGraph.finalizePrinting(self, data)
        if self._iterateOp is None: return
        slot = self._iterateOp.getParent().getOutRevIndex(0)
        self._iterateOp = self.testTerminal(data, slot)
        if self._iterateOp is None: return
        if not self.testIterateForm():
            self._iterateOp = None; return
        if self._initializeOp is None:
            self.findInitializer(self._loopDef.getParent(), slot)
        if self._initializeOp is not None:
            self._initializeOp = self.testTerminal(data, 1 - slot)
        data.opMarkNonPrinting(self._iterateOp)
        if self._initializeOp is not None:
            data.opMarkNonPrinting(self._initializeOp)


# =========================================================================
# BlockDoWhile  (inherits BlockGraph)
# =========================================================================

class BlockDoWhile(BlockGraph):
    """A loop structure where the condition is checked at the bottom."""

    def getType(self) -> int: return FlowBlock.t_dowhile
    def emit(self, lng) -> None: lng.emitBlockDoWhile(self)

    def markLabelBumpUp(self, bump: bool) -> None:
        BlockGraph.markLabelBumpUp(self, True)
        if not bump: self.clearFlag(FlowBlock.f_label_bumpup)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0: self.getBlock(0).scopeBreak(-1, curexit)

    def printHeader(self, s) -> None:
        s.write("Dowhile block "); FlowBlock.printHeader(self, s)

    def nextFlowAfter(self, bl): return None


# =========================================================================
# BlockInfLoop  (inherits BlockGraph)
# =========================================================================

class BlockInfLoop(BlockGraph):
    """An infinite loop structure."""

    def getType(self) -> int: return FlowBlock.t_infloop
    def emit(self, lng) -> None: lng.emitBlockInfLoop(self)

    def markLabelBumpUp(self, bump: bool) -> None:
        BlockGraph.markLabelBumpUp(self, True)
        if not bump: self.clearFlag(FlowBlock.f_label_bumpup)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0:
            self.getBlock(0).scopeBreak(self.getBlock(0).getIndex(), curexit)

    def printHeader(self, s) -> None:
        s.write("Infinite loop block "); FlowBlock.printHeader(self, s)

    def nextFlowAfter(self, bl):
        nb = self.getBlock(0) if self.getSize() > 0 else None
        return nb.getFrontLeaf() if nb else None


# =========================================================================
# BlockSwitch  (inherits BlockGraph)
# =========================================================================

class BlockSwitch(BlockGraph):
    """A structured switch construction."""

    class CaseOrder:
        __slots__ = ('block', 'basicblock', 'label', 'depth', 'chain',
                     'outindex', 'gototype', 'isexit', 'isdefault')
        def __init__(self):
            self.block = None; self.basicblock = None; self.label = 0
            self.depth = 0; self.chain = -1; self.outindex = 0
            self.gototype = 0; self.isexit = False; self.isdefault = False

        @staticmethod
        def compare(a, b):
            if a.label != b.label: return a.label < b.label
            return a.depth < b.depth

    def __init__(self, ind: Optional[FlowBlock] = None) -> None:
        super().__init__()
        self._jump = ind.getJumptable() if ind is not None else None
        self._caseblocks: List[BlockSwitch.CaseOrder] = []

    def getSwitchBlock(self): return self.getBlock(0) if self.getSize() > 0 else None
    def getNumCaseBlocks(self) -> int: return len(self._caseblocks)
    def getCaseBlock(self, i: int): return self._caseblocks[i].block
    def isDefaultCase(self, i: int) -> bool: return self._caseblocks[i].isdefault
    def getGotoCaseType(self, i: int) -> int: return self._caseblocks[i].gototype
    def isExit(self, i: int) -> bool: return self._caseblocks[i].isexit
    def getType(self) -> int: return FlowBlock.t_switch
    def emit(self, lng) -> None: lng.emitBlockSwitch(self)

    def getNumLabels(self, i: int) -> int:
        return self._jump.numIndicesByBlock(self._caseblocks[i].basicblock) if self._jump else 0

    def getLabel(self, i: int, j: int) -> int:
        if self._jump:
            return self._jump.getLabelByIndex(
                self._jump.getIndexByBlock(self._caseblocks[i].basicblock, j))
        return 0

    def getSwitchType(self):
        if self._jump:
            op = self._jump.getIndirectOp()
            return op.getIn(0).getHighTypeReadFacing(op)
        return None

    def addCase(self, switchbl, bl, gt: int) -> None:
        c = BlockSwitch.CaseOrder()
        basicbl = bl.getFrontLeaf().subBlock(0)
        c.block = bl; c.basicblock = basicbl
        inindex = basicbl.getInIndex(switchbl)
        if inindex == -1: raise RuntimeError("Case block detached from switch")
        c.outindex = basicbl.getInRevIndex(inindex)
        c.gototype = gt
        c.isexit = False if gt != 0 else (bl.sizeOut() == 1)
        c.isdefault = switchbl.isDefaultBranch(c.outindex)
        self._caseblocks.append(c)

    def grabCaseBasic(self, switchbl, cs: list) -> None:
        casemap = [-1] * switchbl.sizeOut()
        self._caseblocks.clear()
        for i in range(1, len(cs)):
            self.addCase(switchbl, cs[i], 0)
            casemap[self._caseblocks[i - 1].outindex] = i - 1
        for i in range(len(self._caseblocks)):
            cc = self._caseblocks[i]
            if cc.block.getType() == FlowBlock.t_goto:
                tgt = cc.block.getGotoTarget()
                bb = tgt.getFrontLeaf().subBlock(0)
                ii = bb.getInIndex(switchbl)
                if ii == -1: continue
                cc.chain = casemap[bb.getInRevIndex(ii)]
        if cs[0].getType() == FlowBlock.t_multigoto:
            geb = cs[0]
            for i in range(geb.numGotos()):
                self.addCase(switchbl, geb.getGoto(i), FlowBlock.f_goto_goto)

    def markUnstructured(self) -> None:
        BlockGraph.markUnstructured(self)
        for c in self._caseblocks:
            if c.gototype == FlowBlock.f_goto_goto:
                BlockGraph.markCopyBlock(c.block, FlowBlock.f_unstructured_targ)

    def scopeBreak(self, curexit: int, curloopexit: int) -> None:
        if self.getSize() > 0: self.getBlock(0).scopeBreak(-1, curexit)
        for c in self._caseblocks:
            if c.gototype != 0:
                if c.block.getIndex() == curexit: c.gototype = FlowBlock.f_break_goto
            else:
                c.block.scopeBreak(curexit, curexit)

    def printHeader(self, s) -> None:
        s.write("Switch block "); FlowBlock.printHeader(self, s)

    def nextFlowAfter(self, bl):
        if self.getSize() > 0 and self.getBlock(0) is bl: return None
        if bl.getType() != FlowBlock.t_goto: return None
        idx = -1
        for i, c in enumerate(self._caseblocks):
            if c.block is bl: idx = i; break
        if idx == -1: return None
        idx += 1
        if idx < len(self._caseblocks):
            return self._caseblocks[idx].block.getFrontLeaf()
        if self.getParent() is None: return None
        return self.getParent().nextFlowAfter(self)

    def finalizePrinting(self, data) -> None:
        BlockGraph.finalizePrinting(self, data)
        for c in self._caseblocks:
            j = c.chain
            while j != -1:
                if self._caseblocks[j].depth != 0: break
                self._caseblocks[j].depth = -1; j = self._caseblocks[j].chain
        for c in self._caseblocks:
            if self._jump and self._jump.numIndicesByBlock(c.basicblock) > 0:
                if c.depth == 0:
                    ind = self._jump.getIndexByBlock(c.basicblock, 0)
                    c.label = self._jump.getLabelByIndex(ind)
                    j = c.chain; dc = 1
                    while j != -1:
                        if self._caseblocks[j].depth > 0: break
                        self._caseblocks[j].depth = dc; dc += 1
                        self._caseblocks[j].label = c.label
                        j = self._caseblocks[j].chain
            else:
                c.label = 0
        from functools import cmp_to_key
        self._caseblocks.sort(key=cmp_to_key(
            lambda a, b: -1 if BlockSwitch.CaseOrder.compare(a, b) else (1 if BlockSwitch.CaseOrder.compare(b, a) else 0)))


# =========================================================================
# BlockMap  (block factory/resolver for deserialization)
# =========================================================================

class BlockMap:
    """Resolves FlowBlock cross-references during deserialization."""

    def __init__(self) -> None:
        self._sortlist: List[FlowBlock] = []

    def resolveBlock(self, bt: int) -> Optional[FlowBlock]:
        if bt == FlowBlock.t_plain: return FlowBlock()
        if bt == FlowBlock.t_copy: return BlockCopy(None)
        if bt == FlowBlock.t_graph: return BlockGraph()
        return None

    @staticmethod
    def findBlock(lst: list, ind: int) -> Optional[FlowBlock]:
        lo, hi = 0, len(lst) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if lst[mid].getIndex() == ind: return lst[mid]
            if lst[mid].getIndex() < ind: lo = mid + 1
            else: hi = mid - 1
        return None

    def sortList(self) -> None:
        self._sortlist.sort(key=lambda bl: bl.getIndex())

    def createBlock(self, name: str) -> FlowBlock:
        bt = FlowBlock.nameToType(name)
        bl = self.resolveBlock(bt)
        self._sortlist.append(bl); return bl
