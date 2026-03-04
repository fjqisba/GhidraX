"""
Corresponds to: graph.hh / graph.cc

Graph algorithms for control-flow analysis beyond Heritage SSA.
Interval analysis, dominance frontier refinement, loop detection,
and DAG-based structuring support.
"""

from __future__ import annotations
from typing import List, Optional, Set, Dict, Tuple


class DomInfo:
    """Dominance information for a single node in the CFG."""
    __slots__ = ('idom', 'dfrontier', 'depth', 'index', 'semi', 'label', 'ancestor', 'parent')

    def __init__(self, idx: int = -1) -> None:
        self.idom: int = -1
        self.dfrontier: List[int] = []
        self.depth: int = 0
        self.index: int = idx
        self.semi: int = idx
        self.label: int = idx
        self.ancestor: int = -1
        self.parent: int = -1


class DominatorTree:
    """Compute and store the dominator tree for a control-flow graph.

    Uses the Lengauer-Tarjan algorithm for O(n * alpha(n)) dominators,
    then computes dominance frontiers.
    """

    def __init__(self, numnodes: int = 0) -> None:
        self._info: List[DomInfo] = [DomInfo(i) for i in range(numnodes)]
        self._order: List[int] = []  # DFS order
        self._numnodes: int = numnodes

    def getIdom(self, idx: int) -> int:
        if 0 <= idx < len(self._info):
            return self._info[idx].idom
        return -1

    def getDFrontier(self, idx: int) -> List[int]:
        if 0 <= idx < len(self._info):
            return self._info[idx].dfrontier
        return []

    def getDepth(self, idx: int) -> int:
        if 0 <= idx < len(self._info):
            return self._info[idx].depth
        return 0

    def dominates(self, a: int, b: int) -> bool:
        """Check if node a dominates node b."""
        cur = b
        while cur >= 0:
            if cur == a:
                return True
            cur = self.getIdom(cur)
        return False

    def computeDominators(self, graph, entry: int) -> None:
        """Compute dominators using Cooper-Harvey-Kennedy algorithm.

        This is a simpler iterative algorithm that works well in practice.
        graph must support: getSize(), getBlock(i), sizeIn()/getIn()/sizeOut()/getOut()
        """
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        if n == 0:
            return
        self._numnodes = n
        self._info = [DomInfo(i) for i in range(n)]

        # Build reverse post-order via DFS
        visited = [False] * n
        rpo = []

        def dfs(idx):
            visited[idx] = True
            bl = graph.getBlock(idx)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if 0 <= sidx < n and not visited[sidx]:
                    dfs(sidx)
            rpo.append(idx)

        dfs(entry)
        rpo.reverse()
        self._order = rpo

        # Build rpo index map
        rpo_num = [-1] * n
        for i, idx in enumerate(rpo):
            rpo_num[idx] = i

        # Initialize
        doms = [-1] * n
        doms[entry] = entry

        def intersect(b1, b2):
            while b1 != b2:
                while rpo_num[b1] > rpo_num[b2]:
                    b1 = doms[b1]
                while rpo_num[b2] > rpo_num[b1]:
                    b2 = doms[b2]
            return b1

        # Iterate until stable
        changed = True
        while changed:
            changed = False
            for idx in rpo:
                if idx == entry:
                    continue
                bl = graph.getBlock(idx)
                new_idom = -1
                for i in range(bl.sizeIn()):
                    pred = bl.getIn(i)
                    pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                    if pidx < 0 or pidx >= n:
                        continue
                    if doms[pidx] == -1:
                        continue
                    if new_idom == -1:
                        new_idom = pidx
                    else:
                        new_idom = intersect(pidx, new_idom)
                if new_idom != -1 and doms[idx] != new_idom:
                    doms[idx] = new_idom
                    changed = True

        # Store results
        for i in range(n):
            self._info[i].idom = doms[i] if doms[i] != i else -1

        # Compute depths
        def computeDepth(idx):
            if self._info[idx].depth > 0 or idx == entry:
                return self._info[idx].depth
            parent = self._info[idx].idom
            if parent < 0:
                return 0
            self._info[idx].depth = computeDepth(parent) + 1
            return self._info[idx].depth

        for i in range(n):
            computeDepth(i)

    def computeDFrontier(self, graph) -> None:
        """Compute dominance frontiers for all nodes."""
        n = self._numnodes
        for i in range(n):
            self._info[i].dfrontier = []

        for idx in range(n):
            bl = graph.getBlock(idx)
            if bl.sizeIn() < 2:
                continue
            for i in range(bl.sizeIn()):
                pred = bl.getIn(i)
                pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                if pidx < 0 or pidx >= n:
                    continue
                runner = pidx
                while runner >= 0 and runner != self._info[idx].idom:
                    if idx not in self._info[runner].dfrontier:
                        self._info[runner].dfrontier.append(idx)
                    runner = self._info[runner].idom


class LoopDetector:
    """Detect natural loops in a control-flow graph.

    A natural loop is defined by a back edge (tail -> head) where
    head dominates tail. The loop body is all nodes that can reach
    tail without going through head.
    """

    def __init__(self) -> None:
        self._loops: List[Tuple[int, List[int]]] = []  # (head, [body nodes])

    def detect(self, graph, domtree: DominatorTree) -> None:
        """Find all natural loops in the graph."""
        self._loops.clear()
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        for idx in range(n):
            bl = graph.getBlock(idx)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if sidx < 0 or sidx >= n:
                    continue
                # Check for back edge: succ dominates idx
                if domtree.dominates(sidx, idx):
                    body = self._findLoopBody(graph, sidx, idx, n)
                    self._loops.append((sidx, body))

    def _findLoopBody(self, graph, head: int, tail: int, n: int) -> List[int]:
        """Find all nodes in the loop body via reverse DFS from tail to head."""
        body = {head}
        if head == tail:
            return list(body)
        stack = [tail]
        while stack:
            node = stack.pop()
            if node in body:
                continue
            body.add(node)
            bl = graph.getBlock(node)
            for i in range(bl.sizeIn()):
                pred = bl.getIn(i)
                pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                if 0 <= pidx < n and pidx not in body:
                    stack.append(pidx)
        return sorted(body)

    def getLoops(self) -> List[Tuple[int, List[int]]]:
        return self._loops

    def numLoops(self) -> int:
        return len(self._loops)

    def isInLoop(self, nodeIdx: int) -> bool:
        for head, body in self._loops:
            if nodeIdx in body:
                return True
        return False

    def getLoopHead(self, nodeIdx: int) -> int:
        for head, body in self._loops:
            if nodeIdx in body:
                return head
        return -1


class IntervalGraph:
    """Interval-based graph analysis for reducibility testing.

    An interval I(h) with header h is the maximal single-entry subgraph
    such that any cycle in the subgraph passes through h.
    """

    def __init__(self) -> None:
        self._intervals: List[Tuple[int, Set[int]]] = []  # (header, {nodes})
        self._isReducible: bool = True

    def compute(self, graph, entry: int) -> None:
        """Compute intervals starting from the entry node."""
        self._intervals.clear()
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        if n == 0:
            return

        inInterval = [-1] * n
        headers = [entry]
        processed = set()

        while headers:
            h = headers.pop(0)
            if h in processed:
                continue
            processed.add(h)

            # Build interval I(h)
            interval = {h}
            inInterval[h] = len(self._intervals)
            worklist = []

            # Add successors of h
            bl = graph.getBlock(h)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if 0 <= sidx < n and sidx != h:
                    worklist.append(sidx)

            changed = True
            while changed:
                changed = False
                new_worklist = []
                for m in worklist:
                    if m in interval:
                        continue
                    # Check if all predecessors of m are in the interval
                    mbl = graph.getBlock(m)
                    allInInterval = True
                    for j in range(mbl.sizeIn()):
                        pred = mbl.getIn(j)
                        pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                        if 0 <= pidx < n and pidx not in interval:
                            allInInterval = False
                            break
                    if allInInterval and inInterval[m] < 0:
                        interval.add(m)
                        inInterval[m] = len(self._intervals)
                        changed = True
                        # Add successors of m
                        mbl2 = graph.getBlock(m)
                        for j in range(mbl2.sizeOut()):
                            succ = mbl2.getOut(j)
                            sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                            if 0 <= sidx < n and sidx not in interval:
                                new_worklist.append(sidx)
                    else:
                        new_worklist.append(m)
                worklist = new_worklist

            self._intervals.append((h, interval))

            # Remaining worklist entries become new headers
            for m in worklist:
                if inInterval[m] < 0 and m not in processed:
                    headers.append(m)

        # Check reducibility: all edges go within or between intervals properly
        self._isReducible = all(inInterval[i] >= 0 for i in range(n))

    def isReducible(self) -> bool:
        return self._isReducible

    def numIntervals(self) -> int:
        return len(self._intervals)

    def getInterval(self, idx: int) -> Tuple[int, Set[int]]:
        return self._intervals[idx] if 0 <= idx < len(self._intervals) else (-1, set())


class SCCDetector:
    """Tarjan's algorithm for finding Strongly Connected Components."""

    def __init__(self) -> None:
        self._sccs: List[List[int]] = []

    def compute(self, graph) -> None:
        """Find all SCCs in the graph."""
        self._sccs.clear()
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        if n == 0:
            return

        index_counter = [0]
        stack = []
        on_stack = [False] * n
        index = [-1] * n
        lowlink = [-1] * n

        def strongconnect(v):
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True

            bl = graph.getBlock(v)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                w = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if w < 0 or w >= n:
                    continue
                if index[w] == -1:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif on_stack[w]:
                    lowlink[v] = min(lowlink[v], index[w])

            if lowlink[v] == index[v]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == v:
                        break
                self._sccs.append(scc)

        for v in range(n):
            if index[v] == -1:
                strongconnect(v)

    def getSCCs(self) -> List[List[int]]:
        return self._sccs

    def numSCCs(self) -> int:
        return len(self._sccs)

    def isInCycle(self, nodeIdx: int) -> bool:
        for scc in self._sccs:
            if len(scc) > 1 and nodeIdx in scc:
                return True
        return False
