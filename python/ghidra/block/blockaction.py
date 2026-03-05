"""
Corresponds to: blockaction.hh / blockaction.cc

Actions and classes for structuring the control-flow graph.
"""

from __future__ import annotations
from typing import List


class FloatingEdge:
    """An edge persisting while graph is manipulated.

    The original FlowBlock nodes that define the end-points of the edge may get
    collapsed, but the edge may still exist between higher level components.
    """
    def __init__(self, top=None, bottom=None):
        self.top = top
        self.bottom = bottom

    def getTop(self):
        return self.top

    def getBottom(self):
        return self.bottom

    def setTop(self, t) -> None:
        self.top = t

    def setBottom(self, b) -> None:
        self.bottom = b

    def getCurrentEdge(self, outedge_ref: list, graph):
        """Get the current form of the edge.

        Returns the FlowBlock that currently represents the top of the edge.
        outedge_ref[0] is set to the output edge index.
        """
        if graph is None:
            return None
        t = self.top
        b = self.bottom
        # Walk up to find current representatives
        while t is not None and hasattr(t, 'getParent') and t.getParent() is not None:
            t = t.getParent()
        while b is not None and hasattr(b, 'getParent') and b.getParent() is not None:
            b = b.getParent()
        if t is not None and b is not None:
            for i in range(t.sizeOut()):
                if t.getOut(i) is b:
                    outedge_ref[0] = i
                    return t
        return None


class LoopBody:
    """A description of the body of a loop.

    Following Tarjan, assuming there are no irreducible edges, a loop body is defined
    by the head (or entry-point) and 1 or more tails, which each have a back edge
    into the head.
    """
    def __init__(self, head=None):
        self.head = head
        self.tails: list = []
        self.depth: int = 0
        self.uniquecount: int = 0
        self.exitblock = None
        self.exitedges: list = []  # List of FloatingEdge
        self.immed_container = None

    def addTail(self, bl):
        self.tails.append(bl)

    def getHead(self):
        return self.head

    def getExitBlock(self):
        return self.exitblock

    def update(self, graph):
        """Update loop body to current view."""
        # Walk head to its current representative
        h = self.head
        while h is not None and hasattr(h, 'getParent') and h.getParent() is not None:
            h = h.getParent()
        self.head = h
        new_tails = []
        for t in self.tails:
            while t is not None and hasattr(t, 'getParent') and t.getParent() is not None:
                t = t.getParent()
            if t is not None and t not in new_tails:
                new_tails.append(t)
        self.tails = new_tails
        return self.head

    def findBase(self, body: list):
        """Mark the body FlowBlocks of this loop."""
        if not self.head:
            return
        self.head.setMark()
        body.append(self.head)
        stack = list(self.tails)
        while stack:
            bl = stack.pop()
            if bl.isMark():
                continue
            bl.setMark()
            body.append(bl)
            for i in range(bl.sizeIn()):
                s = bl.getIn(i)
                if s and not s.isMark():
                    stack.append(s)

    def extend(self, body: list):
        """Extend body (to blocks that never exit)."""
        changed = True
        while changed:
            changed = False
            for bl in list(body):
                for i in range(bl.sizeOut()):
                    o = bl.getOut(i)
                    if o is not None and not o.isMark():
                        # Check if o has all predecessors in body
                        all_in = True
                        for j in range(o.sizeIn()):
                            if not o.getIn(j).isMark():
                                all_in = False
                                break
                        if all_in:
                            o.setMark()
                            body.append(o)
                            changed = True

    def findExit(self, body: list):
        """Choose the exit block for this loop."""
        counts = {}
        for bl in body:
            for i in range(bl.sizeOut()):
                o = bl.getOut(i)
                if o and not o.isMark():
                    k = id(o)
                    counts[k] = counts.get(k, 0) + 1
                    if not self.exitblock or counts[k] > counts.get(id(self.exitblock), 0):
                        self.exitblock = o

    def orderTails(self):
        """Find preferred tail."""
        if len(self.tails) <= 1:
            return
        # Prefer tail closest to exit
        pass

    def labelExitEdges(self, body: list):
        """Label edges that exit the loop."""
        self.exitedges.clear()
        for bl in body:
            for i in range(bl.sizeOut()):
                o = bl.getOut(i)
                if o and not o.isMark():
                    self.exitedges.append(FloatingEdge(bl, o))

    def labelContainments(self, body: list, looporder: list):
        """Label containment relationships between loops."""
        for other in looporder:
            if other is self:
                continue
            if other.head is not None and other.head.isMark():
                if other.immed_container is None or other.immed_container.depth < self.depth:
                    other.immed_container = self

    def emitLikelyEdges(self, likely: list, graph):
        """Collect likely unstructured edges."""
        pass

    def setExitMarks(self, graph):
        """Mark all the exits to this loop."""
        if self.exitblock is not None and hasattr(self.exitblock, 'setMark'):
            self.exitblock.setMark()

    def clearExitMarks(self, graph):
        """Clear the mark on all the exits to this loop."""
        if self.exitblock is not None and hasattr(self.exitblock, 'clearMark'):
            self.exitblock.clearMark()

    def __lt__(self, op2):
        return self.depth > op2.depth

    def extendToContainer(self, container, body: list):
        """Extend body to include everything in the container loop."""
        pass

    @staticmethod
    def clearMarks(body: list):
        for bl in body:
            bl.clearMark()

    @staticmethod
    def mergeIdenticalHeads(looporder: list):
        i = 0
        while i < len(looporder) - 1:
            if looporder[i].head is looporder[i + 1].head:
                for t in looporder[i + 1].tails:
                    if t not in looporder[i].tails:
                        looporder[i].tails.append(t)
                looporder.pop(i + 1)
            else:
                i += 1

    @staticmethod
    def compare_ends(a, b) -> bool:
        """Compare the head then tail."""
        if a.head is not b.head:
            return id(a.head) < id(b.head)
        if a.tails and b.tails:
            return id(a.tails[0]) < id(b.tails[0])
        return False

    @staticmethod
    def compare_head(a, looptop) -> int:
        if a.head is looptop:
            return 0
        return -1 if id(a.head) < id(looptop) else 1

    @staticmethod
    def find(looptop, looporder: list):
        """Find a LoopBody by its head."""
        for lb in looporder:
            if lb.head is looptop:
                return lb
        return None


class TraceDAG:
    """Algorithm for selecting unstructured edges based on Directed Acyclic Graphs.

    With the exception of back edges in loops, structured code tends to form a DAG.
    This class traces edges with this structure. Paths can recursively split at any
    point, starting a new active BranchPoint, but the BranchPoint can't be retired
    until all paths come back together.
    """

    def __init__(self, likelygoto: list):
        self._likelygoto = likelygoto
        self._rootlist: list = []
        self._branchlist: list = []
        self._activecount: int = 0
        self._missedactivecount: int = 0
        self._activetrace: list = []
        self._finishblock = None

    def addRoot(self, root):
        self._rootlist.append(root)

    def setFinishBlock(self, bl):
        self._finishblock = bl

    def getFinishBlock(self):
        return self._finishblock

    def getRootList(self) -> list:
        return self._rootlist

    def initialize(self):
        """Create the initial BranchPoint and BlockTrace objects."""
        pass  # Complex initialization

    def pushBranches(self):
        """Push the trace through, removing edges as necessary."""
        pass  # Complex trace algorithm


class ConditionalJoin:
    """Discover and eliminate split conditions.

    A split condition is when a conditional expression is duplicated across two
    blocks that would otherwise merge.
    """

    def __init__(self, data):
        self._data = data
        self._block1 = None
        self._block2 = None
        self._exita = None
        self._exitb = None
        self._joinblock = None

    def match(self, b1, b2) -> bool:
        """Test blocks for the merge condition."""
        self._block1 = b1
        self._block2 = b2
        # Check if both blocks end with CBRANCH to same targets
        if b1.sizeOut() != 2 or b2.sizeOut() != 2:
            return False
        targets1 = {id(b1.getOut(0)), id(b1.getOut(1))}
        targets2 = {id(b2.getOut(0)), id(b2.getOut(1))}
        if targets1 != targets2:
            return False
        self._exita = b1.getOut(0)
        self._exitb = b1.getOut(1)
        return True

    def execute(self):
        """Execute the merge."""
        pass  # Complex block merging

    def clear(self):
        self._block1 = None
        self._block2 = None
        self._exita = None
        self._exitb = None
        self._joinblock = None

    def getBlock1(self):
        return self._block1

    def getBlock2(self):
        return self._block2


class CollapseStructure:
    """Build a code structure from a control-flow graph.

    This class manages the main control-flow structuring algorithm:
      - Start with a control-flow graph of basic blocks.
      - Repeatedly apply structure element searches and collapse.
      - If stuck, remove appropriate edges marking them as unstructured.
    """

    def __init__(self, graph=None):
        self._graph = graph
        self._finaltrace: bool = False
        self._likelylistfull: bool = False
        self._likelygoto: list = []
        self._loopbody: list = []
        self._dataflow_changecount: int = 0

    def getChangeCount(self) -> int:
        return self._dataflow_changecount

    def collapseAll(self):
        """Run the whole structuring algorithm."""
        if self._graph is None:
            return
        self.orderLoopBodies()
        changed = True
        while changed:
            changed = False
            for i in range(self._graph.getSize()):
                bl = self._graph.getBlock(i)
                result = self.collapseInternal(bl)
                if result > 0:
                    changed = True
                    break
            if not changed:
                goto_bl = self.selectGoto()
                if goto_bl is not None:
                    changed = True

    def collapseInternal(self, targetbl) -> int:
        """The main collapsing loop."""
        count = 0
        if self.ruleBlockGoto(targetbl):
            count += 1
        if self.ruleBlockCat(targetbl):
            count += 1
        if self.ruleBlockProperIf(targetbl):
            count += 1
        if self.ruleBlockIfElse(targetbl):
            count += 1
        if self.ruleBlockWhileDo(targetbl):
            count += 1
        if self.ruleBlockDoWhile(targetbl):
            count += 1
        if self.ruleBlockInfLoop(targetbl):
            count += 1
        if self.ruleBlockSwitch(targetbl):
            count += 1
        return count

    def collapseConditions(self):
        """Simplify conditionals."""
        for i in range(self._graph.getSize()):
            bl = self._graph.getBlock(i)
            self.ruleBlockOr(bl)

    def ruleBlockGoto(self, bl) -> bool:
        """Attempt to apply the BlockGoto structure."""
        if bl.sizeOut() != 1:
            return False
        target = bl.getOut(0)
        if target.sizeIn() != 1:
            return False
        if target is bl:
            return False
        # Would collapse bl -> target into a BlockGoto
        if hasattr(self._graph, 'newBlockGoto'):
            self._graph.newBlockGoto(bl)
            return True
        return False

    def ruleBlockCat(self, bl) -> bool:
        """Attempt to apply a BlockList structure."""
        if bl.sizeOut() != 1:
            return False
        nxt = bl.getOut(0)
        if nxt.sizeIn() != 1 or nxt is bl:
            return False
        if hasattr(self._graph, 'newBlockList'):
            self._graph.newBlockList([bl, nxt])
            return True
        return False

    def ruleBlockOr(self, bl) -> bool:
        """Attempt to apply a BlockCondition structure."""
        return False

    def ruleBlockProperIf(self, bl) -> bool:
        """Attempt to apply a 2 component form of BlockIf."""
        if bl.sizeOut() != 2:
            return False
        t = bl.getOut(0)  # true branch
        f = bl.getOut(1)  # false branch
        # Check if true branch goes directly to false branch (if-then)
        if t.sizeOut() == 1 and t.getOut(0) is f and t.sizeIn() == 1:
            if hasattr(self._graph, 'newBlockIf'):
                self._graph.newBlockIf(bl, t)
                return True
        # Check reverse
        if f.sizeOut() == 1 and f.getOut(0) is t and f.sizeIn() == 1:
            if hasattr(self._graph, 'newBlockIf'):
                self._graph.newBlockIf(bl, f)
                return True
        return False

    def ruleBlockIfElse(self, bl) -> bool:
        """Attempt to apply a 3 component form of BlockIf."""
        if bl.sizeOut() != 2:
            return False
        t = bl.getOut(0)
        f = bl.getOut(1)
        if t.sizeIn() != 1 or f.sizeIn() != 1:
            return False
        if t.sizeOut() != 1 or f.sizeOut() != 1:
            return False
        if t.getOut(0) is not f.getOut(0):
            return False
        # Both branches merge at the same point
        if hasattr(self._graph, 'newBlockIfElse'):
            self._graph.newBlockIfElse(bl, t, f)
            return True
        return False

    def ruleBlockIfNoExit(self, bl) -> bool:
        """Attempt to apply BlockIf where the body does not exit."""
        return False

    def ruleBlockWhileDo(self, bl) -> bool:
        """Attempt to apply the BlockWhileDo structure."""
        if bl.sizeOut() != 2:
            return False
        # Check for back edge to self
        for i in range(bl.sizeOut()):
            if bl.getOut(i) is bl:
                if hasattr(self._graph, 'newBlockWhileDo'):
                    self._graph.newBlockWhileDo(bl)
                    return True
        return False

    def ruleBlockDoWhile(self, bl) -> bool:
        """Attempt to apply the BlockDoWhile structure."""
        if bl.sizeOut() != 2:
            return False
        for i in range(bl.sizeOut()):
            if bl.getOut(i) is bl:
                if hasattr(self._graph, 'newBlockDoWhile'):
                    self._graph.newBlockDoWhile(bl)
                    return True
        return False

    def ruleBlockInfLoop(self, bl) -> bool:
        """Attempt to apply the BlockInfLoop structure."""
        if bl.sizeOut() == 1 and bl.getOut(0) is bl:
            if hasattr(self._graph, 'newBlockInfLoop'):
                self._graph.newBlockInfLoop(bl)
                return True
        return False

    def ruleBlockSwitch(self, bl) -> bool:
        """Attempt to apply the BlockSwitch structure."""
        return False  # Complex switch pattern matching

    def ruleCaseFallthru(self, bl) -> bool:
        return False

    def selectGoto(self):
        """Select an edge to mark as unstructured."""
        if not self._likelygoto:
            return None
        edge = self._likelygoto.pop(0)
        return edge.getTop()

    def labelLoops(self, looporder: list):
        """Identify all the loops in this graph."""
        # Find back edges using DFS
        if self._graph is None:
            return
        visited = set()
        in_stack = set()

        def dfs(bl):
            bid = id(bl)
            visited.add(bid)
            in_stack.add(bid)
            for i in range(bl.sizeOut()):
                s = bl.getOut(i)
                sid = id(s)
                if sid in in_stack:
                    # Back edge found: s is loop head, bl is tail
                    lb = LoopBody.find(s, looporder)
                    if lb is None:
                        lb = LoopBody(s)
                        looporder.append(lb)
                    lb.addTail(bl)
                elif sid not in visited:
                    dfs(s)
            in_stack.discard(bid)

        entry = self._graph.getBlock(0) if self._graph.getSize() > 0 else None
        if entry is not None:
            dfs(entry)

    def orderLoopBodies(self):
        """Identify and label all loop structure for this graph."""
        looporder: list = []
        self.labelLoops(looporder)
        LoopBody.mergeIdenticalHeads(looporder)
        looporder.sort()  # Sort by depth (deepest first)
        self._loopbody = looporder

    def updateLoopBody(self) -> bool:
        """Find likely unstructured edges within the innermost loop body."""
        return False

    def checkSwitchSkips(self, switchbl, exitblock) -> bool:
        return False

    def onlyReachableFromRoot(self, root, body: list):
        """Find blocks only reachable from root."""
        visited = set()
        stack = [root]
        while stack:
            bl = stack.pop()
            bid = id(bl)
            if bid in visited:
                continue
            visited.add(bid)
            body.append(bl)
            for i in range(bl.sizeOut()):
                stack.append(bl.getOut(i))

    def markExitsAsGotos(self, body: list) -> int:
        """Mark edges exiting the body as unstructured gotos."""
        count = 0
        body_ids = set(id(bl) for bl in body)
        for bl in body:
            for i in range(bl.sizeOut()):
                o = bl.getOut(i)
                if id(o) not in body_ids:
                    self._likelygoto.append(FloatingEdge(bl, o))
                    count += 1
        return count

    def clipExtraRoots(self) -> bool:
        """Mark edges between root components as unstructured gotos."""
        return False

    def getGraph(self):
        return self._graph

    def execute(self):
        """Run one pass of structure collapsing. Returns True if changes made."""
        if not self._graph:
            return False
        sz = self._graph.getSize()
        if sz <= 1:
            return False
        changed = False
        for i in range(sz):
            bl = self._graph.getBlock(i)
            if self.collapseInternal(bl) > 0:
                changed = True
                break
        return changed


# =========================================================================
# Action subclasses for block structuring
# =========================================================================

class ActionStructureTransform:
    """Give each control-flow structure an opportunity to make a final transform."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'structuretransform'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return ActionStructureTransform(self._group)

    def apply(self, data) -> int:
        return 0

    def reset(self, data) -> None:
        pass


class ActionNormalizeBranches:
    """Flip conditional control-flow so that preferred comparison operators are used."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'normalizebranches'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return ActionNormalizeBranches(self._group)

    def apply(self, data) -> int:
        return 0

    def reset(self, data) -> None:
        pass


class ActionPreferComplement:
    """Attempt to normalize symmetric block structures."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'prefercomplement'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return ActionPreferComplement(self._group)

    def apply(self, data) -> int:
        return 0

    def reset(self, data) -> None:
        pass


class ActionBlockStructure:
    """Structure control-flow using standard high-level code constructs."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'blockstructure'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return ActionBlockStructure(self._group)

    def apply(self, data) -> int:
        graph = data.getStructure() if hasattr(data, 'getStructure') else None
        if graph is None:
            return 0
        cs = CollapseStructure(graph)
        cs.collapseAll()
        return cs.getChangeCount()

    def reset(self, data) -> None:
        pass


class ActionFinalStructure:
    """Perform final organization of the control-flow structure."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'finalstructure'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return ActionFinalStructure(self._group)

    def apply(self, data) -> int:
        return 0

    def reset(self, data) -> None:
        pass


class ActionReturnSplit:
    """Split the epilog code of the function."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'returnsplit'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return ActionReturnSplit(self._group)

    def apply(self, data) -> int:
        return 0

    def reset(self, data) -> None:
        pass


class ActionNodeJoin:
    """Look for conditional branch expressions that have been split and rejoin them."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'nodejoin'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return ActionNodeJoin(self._group)

    def apply(self, data) -> int:
        return 0

    def reset(self, data) -> None:
        pass
