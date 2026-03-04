"""
Corresponds to: heritage.hh / heritage.cc

Utilities for building Static Single Assignment (SSA) form.
Core classes: LocationMap, MemRange, TaskList, PriorityQueue, HeritageInfo, LoadGuard, Heritage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List, Dict, Tuple
from collections import defaultdict

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_SPACEBASE, IPTR_INTERNAL, IPTR_PROCESSOR, IPTR_IOP
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.block.block import FlowBlock, BlockBasic, BlockGraph
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.fspec.fspec import FuncCallSpecs


# =========================================================================
# LocationMap
# =========================================================================

class LocationMap:
    """Map object tracking which address ranges have been heritaged.

    Keeps track of when each address range was entered in SSA form.
    An address range is added using add(), which includes the particular
    pass when it was entered. The map can be queried using findPass().
    """

    class SizePass:
        __slots__ = ('size', 'pass_')
        def __init__(self, size: int = 0, pass_: int = 0):
            self.size = size
            self.pass_ = pass_

    def __init__(self) -> None:
        self._map: Dict[Address, LocationMap.SizePass] = {}

    def add(self, addr: Address, size: int, pass_: int, intersect_ref: list = None) -> Address:
        """Mark new address as heritaged. Returns the key of the containing entry.

        intersect_ref[0] is set to:
          0 if only intersection is with range from the same pass
          1 if there is a partial intersection with something old
          2 if the range is contained in an old range
        """
        if intersect_ref is None:
            intersect_ref = [0]
        intersect_ref[0] = 0

        # Find any existing range that overlaps
        for existing_addr, sp in list(self._map.items()):
            where = addr.overlap(0, existing_addr, sp.size)
            if where == -1:
                # Check if existing range overlaps our range
                where2 = existing_addr.overlap(0, addr, size)
                if where2 == -1:
                    continue
                # existing_addr is inside [addr, addr+size)
                # Merge: extend addr's range to cover existing
                end1 = addr.getOffset() + size
                end2 = existing_addr.getOffset() + sp.size
                new_end = max(end1, end2)
                size = new_end - addr.getOffset()
                if sp.pass_ < pass_:
                    intersect_ref[0] = 1
                    pass_ = sp.pass_
                del self._map[existing_addr]
                continue

            # addr overlaps with existing_addr at position 'where'
            if where + size <= sp.size:
                # Completely contained in previous element
                intersect_ref[0] = 2 if sp.pass_ < pass_ else 0
                return existing_addr

            # Partial overlap - extend
            addr_to_use = existing_addr
            new_size = where + size
            if sp.pass_ < pass_:
                intersect_ref[0] = 1
                pass_ = sp.pass_
            del self._map[existing_addr]
            addr = addr_to_use
            size = new_size

        sp = LocationMap.SizePass(size, pass_)
        self._map[addr] = sp
        return addr

    def find(self, addr: Address) -> Optional[Tuple[Address, 'LocationMap.SizePass']]:
        """Look up if/how given address was heritaged."""
        for k, sp in self._map.items():
            if addr.overlap(0, k, sp.size) != -1:
                return (k, sp)
        return None

    def findPass(self, addr: Address) -> int:
        """Look up if/how given address was heritaged. Returns pass number or -1."""
        result = self.find(addr)
        if result is None:
            return -1
        return result[1].pass_

    def erase(self, addr: Address) -> None:
        if addr in self._map:
            del self._map[addr]

    def clear(self) -> None:
        self._map.clear()

    def begin(self):
        return iter(self._map.items())

    def end(self):
        return None

    def __iter__(self):
        return iter(self._map.items())


# =========================================================================
# MemRange
# =========================================================================

class MemRange:
    """An address range to be processed during heritage."""
    new_addresses = 1
    old_addresses = 2

    def __init__(self, addr: Address, size: int, flags: int = 0):
        self.addr = addr
        self.size = size
        self.flags = flags

    def newAddresses(self) -> bool:
        return (self.flags & MemRange.new_addresses) != 0

    def oldAddresses(self) -> bool:
        return (self.flags & MemRange.old_addresses) != 0

    def clearProperty(self, val: int) -> None:
        self.flags &= ~val


# =========================================================================
# TaskList
# =========================================================================

class TaskList:
    """A list of address ranges that need to be converted to SSA form.

    The disjoint list of ranges are built up and processed in a single pass.
    """

    def __init__(self) -> None:
        self._list: List[MemRange] = []

    def add(self, addr: Address, size: int, fl: int) -> None:
        """Add a range to the list (merging with last if overlapping)."""
        if self._list:
            entry = self._list[-1]
            over = addr.overlap(0, entry.addr, entry.size)
            if over >= 0:
                relsize = size + over
                if relsize > entry.size:
                    entry.size = relsize
                entry.flags |= fl
                return
        self._list.append(MemRange(addr, size, fl))

    def insert(self, pos: int, addr: Address, size: int, fl: int) -> int:
        """Insert a disjoint range at position pos."""
        self._list.insert(pos, MemRange(addr, size, fl))
        return pos

    def erase(self, idx: int) -> int:
        del self._list[idx]
        return idx

    def begin(self):
        return iter(self._list)

    def end(self):
        return None

    def clear(self) -> None:
        self._list.clear()

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def __getitem__(self, idx):
        return self._list[idx]


# =========================================================================
# PriorityQueue
# =========================================================================

class PriorityQueue:
    """Priority queue for the phi-node placement algorithm.

    Implemented as a set of stacks with an associated priority.
    """

    def __init__(self) -> None:
        self._queue: List[List[FlowBlock]] = []
        self._curdepth: int = -2

    def reset(self, maxdepth: int) -> None:
        """Reset to an empty queue."""
        self._queue = [[] for _ in range(maxdepth + 1)]
        self._curdepth = -1

    def insert(self, bl: FlowBlock, depth: int) -> None:
        """Insert a block into the queue given its priority."""
        while len(self._queue) <= depth:
            self._queue.append([])
        self._queue[depth].append(bl)
        if depth > self._curdepth:
            self._curdepth = depth

    def extract(self) -> Optional[FlowBlock]:
        """Retrieve the highest priority block."""
        if self._curdepth < 0:
            return None
        res = self._queue[self._curdepth].pop()
        while self._curdepth >= 0 and not self._queue[self._curdepth]:
            self._curdepth -= 1
        return res

    def empty(self) -> bool:
        return self._curdepth == -1


# =========================================================================
# HeritageInfo
# =========================================================================

class HeritageInfo:
    """Information about heritage passes performed for a specific address space."""

    def __init__(self, spc: Optional[AddrSpace] = None) -> None:
        if spc is None:
            self.space: Optional[AddrSpace] = None
            self.delay: int = 0
            self.deadcodedelay: int = 0
            self.hasCallPlaceholders: bool = False
        elif not spc.isHeritaged():
            self.space = None
            self.delay = spc.getDelay()
            self.deadcodedelay = spc.getDeadcodeDelay()
            self.hasCallPlaceholders = False
        else:
            self.space = spc
            self.delay = spc.getDelay()
            self.deadcodedelay = spc.getDeadcodeDelay()
            self.hasCallPlaceholders = (spc.getType() == IPTR_SPACEBASE)
        self.deadremoved: int = 0
        self.warningissued: bool = False
        self.loadGuardSearch: bool = False

    def isHeritaged(self) -> bool:
        return self.space is not None

    def reset(self) -> None:
        self.deadremoved = 0
        if self.space is not None:
            self.hasCallPlaceholders = (self.space.getType() == IPTR_SPACEBASE)
        self.warningissued = False
        self.loadGuardSearch = False


# =========================================================================
# LoadGuard
# =========================================================================

class LoadGuard:
    """Description of a LOAD operation that needs to be guarded.

    Heritage maintains a list of CPUI_LOAD ops that reference the stack
    dynamically. These can potentially alias stack Varnodes.
    """

    def __init__(self) -> None:
        self.op: Optional[PcodeOp] = None
        self.spc: Optional[AddrSpace] = None
        self.pointerBase: int = 0
        self.minimumOffset: int = 0
        self.maximumOffset: int = 0
        self.step: int = 0
        self.analysisState: int = 0  # 0=unanalyzed, 1=analyzed(partial), 2=analyzed(full)

    def set(self, o, s: AddrSpace, off: int) -> None:
        """Set a new unanalyzed LOAD guard that initially guards everything."""
        self.op = o
        self.spc = s
        self.pointerBase = off
        self.minimumOffset = 0
        self.maximumOffset = s.getHighest() if s else 0xFFFFFFFFFFFFFFFF
        self.step = 0
        self.analysisState = 0

    def getOp(self):
        return self.op

    def getMinimum(self) -> int:
        return self.minimumOffset

    def getMaximum(self) -> int:
        return self.maximumOffset

    def getStep(self) -> int:
        return self.step

    def isGuarded(self, addr: Address) -> bool:
        """Does this guard apply to the given address?"""
        if addr.getSpace() is not self.spc:
            return False
        off = addr.getOffset()
        return self.minimumOffset <= off <= self.maximumOffset

    def isRangeLocked(self) -> bool:
        return self.analysisState == 2

    def isValid(self, opc) -> bool:
        """Return True if the record still describes an active LOAD."""
        if self.op is None:
            return False
        if hasattr(self.op, 'isDead') and self.op.isDead():
            return False
        return self.op.code() == opc


class Heritage:
    """Manage the construction of Static Single Assignment (SSA) form.

    With a specific function (Funcdata), this class links the Varnode and
    PcodeOp objects into the formal data-flow graph structure, SSA form.
    The full structure can be built over multiple passes.

    The two big aspects of SSA construction are phi-node placement, performed
    by placeMultiequals(), and the renaming algorithm, performed by rename().

    Phi-node placement algorithm from Bilardi and Pingali.
    Renaming algorithm from Cytron, Ferrante, Rosen, Wegman, Zadeck (1991).
    """

    # Extra boolean properties on basic blocks for Augmented Dominator Tree
    boundary_node = 1
    mark_node = 2
    merged_node = 4

    def __init__(self, fd: Optional[Funcdata] = None) -> None:
        self._fd: Optional[Funcdata] = fd
        self._pass: int = 0
        self._maxdepth: int = -1

        self._globaldisjoint = LocationMap()
        self._disjoint = TaskList()
        self._domchild: List[List] = []
        self._augment: List[List] = []
        self._flags: List[int] = []
        self._depth: List[int] = []

        self._pq = PriorityQueue()
        self._merge: List = []
        self._infolist: List[HeritageInfo] = []
        self._loadGuard: List[LoadGuard] = []
        self._storeGuard: List[LoadGuard] = []
        self._loadCopyOps: List = []

    # ----------------------------------------------------------------
    # Info management
    # ----------------------------------------------------------------

    def getInfo(self, spc: AddrSpace) -> Optional[HeritageInfo]:
        """Get the heritage status for the given address space."""
        idx = spc.getIndex()
        if idx < len(self._infolist):
            return self._infolist[idx]
        return None

    def clearInfoList(self) -> None:
        """Reset heritage status for all address spaces."""
        for info in self._infolist:
            info.reset()

    def buildInfoList(self) -> None:
        """Initialize information for each space."""
        if self._infolist:
            return
        if self._fd is None:
            return
        arch = self._fd.getArch() if hasattr(self._fd, 'getArch') else None
        if arch is None:
            return
        num = arch.numSpaces() if hasattr(arch, 'numSpaces') else 0
        for i in range(num):
            spc = arch.getSpace(i)
            self._infolist.append(HeritageInfo(spc))

    def forceRestructure(self) -> None:
        """Force regeneration of basic block structures."""
        self._maxdepth = -1

    # ----------------------------------------------------------------
    # Public query accessors
    # ----------------------------------------------------------------

    def getPass(self) -> int:
        return self._pass

    def heritagePass(self, addr: Address) -> int:
        """Get the pass number when the given address was heritaged, or -1."""
        return self._globaldisjoint.findPass(addr)

    def numHeritagePasses(self, spc: AddrSpace) -> int:
        """Get number of heritage passes performed for the given space."""
        info = self.getInfo(spc)
        if info is None or not info.isHeritaged():
            return self._pass
        return self._pass - info.delay

    def seenDeadCode(self, spc: AddrSpace) -> None:
        """Inform system of dead code removal in given space."""
        info = self.getInfo(spc)
        if info is not None:
            info.deadremoved = 1

    def getDeadCodeDelay(self, spc: AddrSpace) -> int:
        """Get pass delay for heritaging the given space."""
        info = self.getInfo(spc)
        if info is not None:
            return info.deadcodedelay
        return 0

    def setDeadCodeDelay(self, spc: AddrSpace, delay: int) -> None:
        """Set delay for a specific space."""
        info = self.getInfo(spc)
        if info is not None:
            info.deadcodedelay = delay

    def deadRemovalAllowed(self, spc: AddrSpace) -> bool:
        """Return True if it is safe to remove dead code."""
        info = self.getInfo(spc)
        if info is not None:
            return self._pass > info.deadcodedelay
        return False

    def deadRemovalAllowedSeen(self, spc: AddrSpace) -> bool:
        """Check if dead code removal is safe and mark that removal has happened."""
        info = self.getInfo(spc)
        if info is None:
            return False
        res = self._pass > info.deadcodedelay
        if res:
            info.deadremoved = 1
        return res

    def getLoadGuards(self) -> List[LoadGuard]:
        return self._loadGuard

    def getStoreGuards(self) -> List[LoadGuard]:
        return self._storeGuard

    def getStoreGuard(self, op) -> Optional[LoadGuard]:
        """Get LoadGuard record associated with given PcodeOp."""
        for guard in self._storeGuard:
            if guard.op is op:
                return guard
        return None

    # ----------------------------------------------------------------
    # Dominator tree construction
    # ----------------------------------------------------------------

    def _buildDominatorTree(self) -> None:
        """Build the dominator tree using the iterative algorithm (Cooper, Harvey, Kennedy)."""
        graph = self._fd.getBasicBlocks()
        n = graph.getSize()
        if n == 0:
            return
        entry = graph.getEntryBlock()
        if entry is None:
            return
        # Initialize: every block's idom = None except entry
        for i in range(n):
            bl = graph.getBlock(i)
            bl.setImmedDom(None)
        entry.setImmedDom(entry)
        # Compute RPO (reverse post-order)
        rpo = []
        visited = set()
        stack = [(entry, False)]
        while stack:
            bl, processed = stack.pop()
            if processed:
                rpo.append(bl)
                continue
            if id(bl) in visited:
                continue
            visited.add(id(bl))
            stack.append((bl, True))
            for i in range(bl.sizeOut() - 1, -1, -1):
                s = bl.getOut(i)
                if id(s) not in visited:
                    stack.append((s, False))
        rpo.reverse()
        rpo_index = {id(bl): i for i, bl in enumerate(rpo)}

        def intersect(b1, b2):
            f1, f2 = rpo_index.get(id(b1), n), rpo_index.get(id(b2), n)
            while f1 != f2:
                while f1 > f2:
                    b1 = b1.getImmedDom()
                    f1 = rpo_index.get(id(b1), n) if b1 else n
                while f2 > f1:
                    b2 = b2.getImmedDom()
                    f2 = rpo_index.get(id(b2), n) if b2 else n
            return b1

        changed = True
        while changed:
            changed = False
            for bl in rpo:
                if bl is entry:
                    continue
                new_idom = None
                for j in range(bl.sizeIn()):
                    pred = bl.getIn(j)
                    if pred.getImmedDom() is None:
                        continue
                    if new_idom is None:
                        new_idom = pred
                    else:
                        new_idom = intersect(new_idom, pred)
                if new_idom is not None and bl.getImmedDom() is not new_idom:
                    bl.setImmedDom(new_idom)
                    changed = True
        entry.setImmedDom(None)  # Entry has no dominator
        self._domchildren = {}
        for bl in rpo:
            idom = bl.getImmedDom()
            if idom is not None:
                self._domchildren.setdefault(id(idom), []).append(bl)

    def _computeDominanceFrontier(self) -> Dict:
        """Compute dominance frontier for each block."""
        graph = self._fd.getBasicBlocks()
        df = {}  # block_id -> set of block_ids in dominance frontier
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            df[id(bl)] = set()
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            if bl.sizeIn() < 2:
                continue
            for j in range(bl.sizeIn()):
                runner = bl.getIn(j)
                while runner is not None and runner is not bl.getImmedDom():
                    df.setdefault(id(runner), set()).add(id(bl))
                    runner = runner.getImmedDom()
        return df

    def _collectVarnodes(self):
        """Collect all varnodes grouped by their address for heritage."""
        addr_groups = {}  # (spc_idx, offset, size) -> list of (varnode, is_write)
        for vn in list(self._fd._vbank.beginLoc()):
            if vn.isConstant() or vn.isAnnotation():
                continue
            spc = vn.getSpace()
            if spc is None:
                continue
            key = (spc.getIndex(), vn.getAddr().getOffset(), vn.getSize())
            if key not in addr_groups:
                addr_groups[key] = []
            addr_groups[key].append(vn)
        return addr_groups

    def _placePhiNodes(self, writes, df, graph):
        """Place MULTIEQUAL (phi) nodes at dominance frontiers of write locations."""
        from ghidra.core.opcodes import OpCode
        block_id_map = {}
        for i in range(graph.getSize()):
            block_id_map[id(graph.getBlock(i))] = graph.getBlock(i)
        write_blocks = set()
        for vn in writes:
            if vn.isWritten():
                parent = vn.getDef().getParent()
                if parent is not None:
                    write_blocks.add(id(parent))
            elif vn.isInput():
                entry = graph.getEntryBlock()
                if entry is not None:
                    write_blocks.add(id(entry))
        # Iterated dominance frontier
        worklist = list(write_blocks)
        phi_blocks = set()
        while worklist:
            blid = worklist.pop()
            for frontier_blid in df.get(blid, set()):
                if frontier_blid not in phi_blocks:
                    phi_blocks.add(frontier_blid)
                    worklist.append(frontier_blid)
        # Insert MULTIEQUAL at each phi block
        for phi_blid in phi_blocks:
            bl = block_id_map.get(phi_blid)
            if bl is None:
                continue
            numinputs = bl.sizeIn()
            if numinputs < 2:
                continue
            # Get representative varnode for size/address
            rep = writes[0]
            op = self._fd.newOp(numinputs, bl.getStart())
            self._fd.opSetOpcode(op, OpCode.CPUI_MULTIEQUAL)
            outvn = self._fd.newVarnodeOut(rep.getSize(), rep.getAddr(), op)
            for i in range(numinputs):
                invn = self._fd.newVarnode(rep.getSize(), rep.getAddr())
                self._fd.opSetInput(op, invn, i)
            self._fd.opInsertBegin(op, bl)

    def heritage(self) -> None:
        """Perform one pass of heritage (SSA construction).

        Algorithm (Cytron et al. 1991):
        1. Build dominator tree
        2. Compute dominance frontiers
        3. Collect address ranges that need heritage
        4. Place phi nodes (MULTIEQUAL) at iterated dominance frontiers
        5. Rename variables (SSA renaming)
        """
        self._pass += 1
        if self._fd is None:
            return
        graph = self._fd.getBasicBlocks()
        if graph.getSize() == 0:
            return
        # Step 1: Build dominator tree
        self._buildDominatorTree()
        # Step 2: Compute dominance frontiers
        df = self._computeDominanceFrontier()
        # Step 3: Collect varnodes by address
        addr_groups = self._collectVarnodes()
        # Step 4: Place phi nodes for each address group
        for key, vnlist in addr_groups.items():
            if len(vnlist) > 1:
                self._placePhiNodes(vnlist, df, graph)
        # Step 5: SSA variable renaming
        self._rename(graph)

    def _rename(self, graph) -> None:
        """Perform SSA variable renaming by walking dominator tree."""
        from ghidra.core.opcodes import OpCode
        from collections import defaultdict
        if graph.getSize() == 0:
            return
        entry = graph.getEntryBlock()
        if entry is None:
            return
        varstack = defaultdict(list)  # Address key -> stack of defining Varnodes
        self._renameRecurse(entry, varstack)

    def _renameRecurse(self, bl, varstack) -> None:
        """Recursive SSA rename walk down the dominator tree."""
        from ghidra.core.opcodes import OpCode
        writelist = []
        if not hasattr(bl, 'getOpList'):
            return
        # Process each op in the block
        for op in list(bl.getOpList()):
            if op.code() != OpCode.CPUI_MULTIEQUAL:
                # Replace reads of free varnodes with top of stack
                for slot in range(op.numInput()):
                    vnin = op.getIn(slot)
                    if vnin.isHeritageKnown():
                        continue
                    if vnin.isFree() and not vnin.isConstant():
                        key = (vnin.getAddr().getOffset(), vnin.getSize())
                        stack = varstack[key]
                        if not stack:
                            # Create input varnode
                            vnnew = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                            vnnew = self._fd.setInputVarnode(vnnew)
                            stack.append(vnnew)
                        else:
                            vnnew = stack[-1]
                        self._fd.opSetInput(op, vnnew, slot)
            # Push writes onto stack
            vnout = op.getOut()
            if vnout is not None and not vnout.isHeritageKnown():
                key = (vnout.getAddr().getOffset(), vnout.getSize())
                varstack[key].append(vnout)
                writelist.append(vnout)
        # Process MULTIEQUAL inputs in successor blocks
        for i in range(bl.sizeOut()):
            subbl = bl.getOut(i)
            slot = bl.getOutRevIndex(i)
            if not hasattr(subbl, 'getOpList'):
                continue
            for op in subbl.getOpList():
                if op.code() != OpCode.CPUI_MULTIEQUAL:
                    break
                if slot < op.numInput():
                    vnin = op.getIn(slot)
                    if not vnin.isHeritageKnown() and vnin.isFree() and not vnin.isConstant():
                        key = (vnin.getAddr().getOffset(), vnin.getSize())
                        stack = varstack[key]
                        if not stack:
                            vnnew = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                            vnnew = self._fd.setInputVarnode(vnnew)
                            stack.append(vnnew)
                        else:
                            vnnew = stack[-1]
                        self._fd.opSetInput(op, vnnew, slot)
        # Recurse to dominator tree children
        for child in self._domchildren.get(id(bl), []):
            self._renameRecurse(child, varstack)
        # Pop this block's writes off the stack
        for vnout in writelist:
            key = (vnout.getAddr().getOffset(), vnout.getSize())
            if varstack[key]:
                varstack[key].pop()

    # ----------------------------------------------------------------
    # Guard methods (data-flow across calls/stores/loads/returns)
    # ----------------------------------------------------------------

    def guard(self, addr: Address, size: int, guardPerformed: bool,
              read: list, write: list, inputvars: list) -> None:
        """Normalize p-code ops so that phi-node placement and renaming works.

        For reads smaller than the range, add SUBPIECE. For writes smaller,
        add PIECE. If guardPerformed, add INDIRECTs for CALL/STORE/LOAD effects.
        """
        from ghidra.ir.varnode import Varnode as VnCls
        for i, vn in enumerate(read):
            descs = list(vn.beginDescend())
            if not descs:
                continue
            if vn.getSize() < size:
                read[i] = vn = self.normalizeReadSize(vn, descs[0], addr, size)
            vn.setActiveHeritage()
        for i, vn in enumerate(write):
            if vn.getSize() < size:
                write[i] = vn = self.normalizeWriteSize(vn, addr, size)
            vn.setActiveHeritage()
        if guardPerformed:
            fl = 0
            if hasattr(self._fd, 'getScopeLocal'):
                scope = self._fd.getScopeLocal()
                if hasattr(scope, 'queryProperties'):
                    scope.queryProperties(addr, size, Address(), fl)
            self.guardCalls(fl, addr, size, write)
            self.guardReturns(fl, addr, size, write)
            self.guardStores(addr, size, write)
            self.guardLoads(fl, addr, size, write)

    def guardInput(self, addr: Address, size: int, inputvars: list) -> None:
        """Make sure existing inputs for the given range fill it entirely."""
        if not inputvars:
            return
        if len(inputvars) == 1 and inputvars[0].getSize() == size:
            return
        # Fill holes with new input Varnodes
        cur = addr.getOffset()
        end = cur + size
        newinput = []
        i = 0
        while cur < end:
            if i < len(inputvars):
                vn = inputvars[i]
                if vn.getOffset() > cur:
                    sz = vn.getOffset() - cur
                    newvn = self._fd.newVarnode(sz, Address(addr.getSpace(), cur))
                    newvn = self._fd.setInputVarnode(newvn)
                    newinput.append(newvn)
                    cur += sz
                else:
                    newinput.append(vn)
                    cur += vn.getSize()
                    i += 1
            else:
                sz = end - cur
                newvn = self._fd.newVarnode(sz, Address(addr.getSpace(), cur))
                newvn = self._fd.setInputVarnode(newvn)
                newinput.append(newvn)
                cur += sz
        if len(newinput) <= 1:
            return
        for vn in newinput:
            vn.setWriteMask()
        newout = self._fd.newVarnode(size, addr)
        result = self.concatPieces(newinput, None, newout)
        if result is not None:
            result.setActiveHeritage()

    def guardCalls(self, fl: int, addr: Address, size: int, write: list) -> None:
        """Guard CALL/CALLIND ops in preparation for renaming algorithm."""
        if self._fd is None or not hasattr(self._fd, 'numCalls'):
            return
        from ghidra.ir.varnode import Varnode as VnCls
        holdind = (fl & VnCls.addrtied) != 0
        for i in range(self._fd.numCalls()):
            fc = self._fd.getCallSpecs(i)
            if fc is None:
                continue
            effecttype = 'unknown'
            if hasattr(fc, 'hasEffect'):
                effecttype = fc.hasEffect(addr, size)
            if effecttype == 'unknown' or effecttype == 'return_address':
                if hasattr(self._fd, 'newIndirectOp'):
                    indop = self._fd.newIndirectOp(fc.getOp(), addr, size, 0)
                    if indop is not None:
                        indop.getIn(0).setActiveHeritage()
                        indop.getOut().setActiveHeritage()
                        write.append(indop.getOut())
                        if holdind:
                            indop.getOut().setAddrForce()
            elif effecttype == 'killedbycall':
                if hasattr(self._fd, 'newIndirectCreation'):
                    indop = self._fd.newIndirectCreation(fc.getOp(), addr, size, False)
                    if indop is not None:
                        indop.getOut().setActiveHeritage()
                        write.append(indop.getOut())

    def guardStores(self, addr: Address, size: int, write: list) -> None:
        """Guard STORE ops in preparation for the renaming algorithm."""
        if self._fd is None:
            return
        if not hasattr(self._fd, 'beginOp'):
            return
        spc = addr.getSpace()
        for op in self._fd.beginOp(OpCode.CPUI_STORE):
            if hasattr(op, 'isDead') and op.isDead():
                continue
            storeSpc = op.getIn(0).getSpaceFromConst() if hasattr(op.getIn(0), 'getSpaceFromConst') else None
            if storeSpc is spc or (hasattr(spc, 'getContain') and spc.getContain() is storeSpc):
                if hasattr(self._fd, 'newIndirectOp'):
                    indop = self._fd.newIndirectOp(op, addr, size, 0)
                    if indop is not None:
                        indop.getIn(0).setActiveHeritage()
                        indop.getOut().setActiveHeritage()
                        write.append(indop.getOut())

    def guardLoads(self, fl: int, addr: Address, size: int, write: list) -> None:
        """Guard LOAD ops in preparation for the renaming algorithm."""
        from ghidra.ir.varnode import Varnode as VnCls
        if (fl & VnCls.addrtied) == 0:
            return
        i = 0
        while i < len(self._loadGuard):
            guard = self._loadGuard[i]
            if not guard.isValid(OpCode.CPUI_LOAD):
                del self._loadGuard[i]
                continue
            i += 1
            if guard.spc is not addr.getSpace():
                continue
            if addr.getOffset() < guard.minimumOffset or addr.getOffset() > guard.maximumOffset:
                continue
            if hasattr(self._fd, 'newOp'):
                copyop = self._fd.newOp(1, guard.op.getAddr())
                vn = self._fd.newVarnodeOut(size, addr, copyop)
                vn.setActiveHeritage()
                vn.setAddrForce()
                self._fd.opSetOpcode(copyop, OpCode.CPUI_COPY)
                invn = self._fd.newVarnode(size, addr)
                invn.setActiveHeritage()
                self._fd.opSetInput(copyop, invn, 0)
                self._fd.opInsertBefore(copyop, guard.op)
                self._loadCopyOps.append(copyop)

    def guardReturns(self, fl: int, addr: Address, size: int, write: list) -> None:
        """Guard global data-flow at RETURN ops in preparation for renaming."""
        from ghidra.ir.varnode import Varnode as VnCls
        if (fl & VnCls.persist) == 0:
            return
        if not hasattr(self._fd, 'beginOp'):
            return
        for op in self._fd.beginOp(OpCode.CPUI_RETURN):
            if hasattr(op, 'isDead') and op.isDead():
                continue
            if hasattr(self._fd, 'newOp'):
                copyop = self._fd.newOp(1, op.getAddr())
                vn = self._fd.newVarnodeOut(size, addr, copyop)
                vn.setAddrForce()
                vn.setActiveHeritage()
                self._fd.opSetOpcode(copyop, OpCode.CPUI_COPY)
                invn = self._fd.newVarnode(size, addr)
                invn.setActiveHeritage()
                self._fd.opSetInput(copyop, invn, 0)
                self._fd.opInsertBefore(copyop, op)

    def guardReturnsOverlapping(self, addr: Address, size: int) -> None:
        """Guard data-flow at RETURN ops, where range properly contains return storage."""
        pass  # Requires FuncProto.getBiggestContainedOutput

    def guardCallOverlappingInput(self, fc, addr: Address, transAddr: Address, size: int) -> None:
        """Guard address range larger than any single parameter at a call."""
        pass  # Requires FuncCallSpecs.getBiggestContainedInputParam

    def guardOutputOverlap(self, callOp, addr: Address, size: int, retAddr: Address, retSize: int, write: list) -> None:
        """Insert created INDIRECT ops to guard the output of a call."""
        pass  # Complex PIECE/INDIRECT construction

    def tryOutputOverlapGuard(self, fc, addr, transAddr, size, write) -> bool:
        return False

    def tryOutputStackGuard(self, fc, addr, transAddr, size, outputCharacter, write) -> bool:
        return False

    def guardOutputOverlapStack(self, callOp, addr, size, retAddr, retSize, write) -> None:
        pass

    # ----------------------------------------------------------------
    # Collect and normalize
    # ----------------------------------------------------------------

    def collect(self, memrange: MemRange, read: list, write: list,
                inputvars: list, remove: list) -> int:
        """Collect free reads, writes, and inputs in the given address range.

        Returns the maximum size of a write.
        """
        read.clear()
        write.clear()
        inputvars.clear()
        remove.clear()
        if self._fd is None:
            return 0
        maxsize = 0
        # Iterate varnodes overlapping the memory range
        for vn in list(self._fd._vbank.beginLoc()):
            if vn.getSpace() is not memrange.addr.getSpace():
                continue
            vn_off = vn.getOffset()
            range_off = memrange.addr.getOffset()
            range_end = range_off + memrange.size
            if vn_off + vn.getSize() <= range_off or vn_off >= range_end:
                continue
            if vn.isWriteMask():
                continue
            if vn.isWritten():
                op = vn.getDef()
                if (op.isMarker() or (hasattr(op, 'isReturnCopy') and op.isReturnCopy())):
                    if vn.getSize() < memrange.size:
                        remove.append(vn)
                        continue
                    memrange.clearProperty(MemRange.new_addresses)
                if vn.getSize() > maxsize:
                    maxsize = vn.getSize()
                write.append(vn)
            elif not vn.isHeritageKnown() and not vn.hasNoDescend():
                read.append(vn)
            elif vn.isInput():
                inputvars.append(vn)
        return maxsize

    def normalizeReadSize(self, vn, op, addr: Address, size: int):
        """Normalize the size of a read Varnode, prior to heritage."""
        if not hasattr(self._fd, 'newOp'):
            return vn
        newop = self._fd.newOp(2, op.getAddr())
        self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
        vn1 = self._fd.newVarnode(size, addr)
        overlap = vn.overlap(addr, size)
        vn2 = self._fd.newConstant(4, overlap if overlap >= 0 else 0)
        self._fd.opSetInput(newop, vn1, 0)
        self._fd.opSetInput(newop, vn2, 1)
        self._fd.opSetOutput(newop, vn)
        if hasattr(newop.getOut(), 'setWriteMask'):
            newop.getOut().setWriteMask()
        self._fd.opInsertBefore(newop, op)
        return vn1

    def normalizeWriteSize(self, vn, addr: Address, size: int):
        """Normalize the size of a written Varnode, prior to heritage.

        Given a Varnode that is written that does not match the (larger) size
        of the address range currently being linked, create the missing pieces
        and concatenate everything into a new Varnode of the correct size.
        """
        if not hasattr(self._fd, 'newOp'):
            return vn

        op = vn.getDef()
        if op is None:
            return vn

        overlap = vn.overlap(addr, size) if hasattr(vn, 'overlap') else 0
        if overlap < 0:
            overlap = 0
        mostsigsize = size - (overlap + vn.getSize())

        mostvn = None
        leastvn = None
        bigendian = addr.isBigEndian() if hasattr(addr, 'isBigEndian') else False

        # Create most significant piece if needed
        if mostsigsize > 0:
            if bigendian:
                pieceaddr = addr
            else:
                pieceaddr = addr + (overlap + vn.getSize())

            isCall = op.isCall() if hasattr(op, 'isCall') else False
            if isCall and self.callOpIndirectEffect(pieceaddr, mostsigsize, op):
                newop = self._fd.newIndirectCreation(op, pieceaddr, mostsigsize, False)
                mostvn = newop.getOut()
            else:
                newop = self._fd.newOp(2, op.getAddr())
                mostvn = self._fd.newVarnodeOut(mostsigsize, pieceaddr, newop)
                big = self._fd.newVarnode(size, addr)
                big.setActiveHeritage()
                self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
                self._fd.opSetInput(newop, big, 0)
                self._fd.opSetInput(newop, self._fd.newConstant(4, overlap + vn.getSize()), 1)
                self._fd.opInsertBefore(newop, op)

        # Create least significant piece if needed
        if overlap > 0:
            if bigendian:
                pieceaddr = addr + (size - overlap)
            else:
                pieceaddr = addr

            isCall = op.isCall() if hasattr(op, 'isCall') else False
            if isCall and self.callOpIndirectEffect(pieceaddr, overlap, op):
                newop = self._fd.newIndirectCreation(op, pieceaddr, overlap, False)
                leastvn = newop.getOut()
            else:
                newop = self._fd.newOp(2, op.getAddr())
                leastvn = self._fd.newVarnodeOut(overlap, pieceaddr, newop)
                big = self._fd.newVarnode(size, addr)
                big.setActiveHeritage()
                self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
                self._fd.opSetInput(newop, big, 0)
                self._fd.opSetInput(newop, self._fd.newConstant(4, 0), 1)
                self._fd.opInsertBefore(newop, op)

        # Concatenate least significant piece with vn
        if overlap > 0 and leastvn is not None:
            newop = self._fd.newOp(2, op.getAddr())
            if bigendian:
                midvn = self._fd.newVarnodeOut(overlap + vn.getSize(), vn.getAddr(), newop)
            else:
                midvn = self._fd.newVarnodeOut(overlap + vn.getSize(), addr, newop)
            self._fd.opSetOpcode(newop, OpCode.CPUI_PIECE)
            self._fd.opSetInput(newop, vn, 0)
            self._fd.opSetInput(newop, leastvn, 1)
            self._fd.opInsertAfter(newop, op)
        else:
            midvn = vn

        # Concatenate most significant piece
        if mostsigsize > 0 and mostvn is not None:
            newop = self._fd.newOp(2, op.getAddr())
            bigout = self._fd.newVarnodeOut(size, addr, newop)
            self._fd.opSetOpcode(newop, OpCode.CPUI_PIECE)
            self._fd.opSetInput(newop, mostvn, 0)
            self._fd.opSetInput(newop, midvn, 1)
            defop = midvn.getDef() if midvn is not vn else op
            if defop is not None:
                self._fd.opInsertAfter(newop, defop)
        else:
            bigout = midvn

        vn.setWriteMask()
        return bigout

    def concatPieces(self, vnlist: list, insertop, finalvn):
        """Concatenate a list of Varnodes together using PIECE ops."""
        if not vnlist or not hasattr(self._fd, 'newOp'):
            return finalvn
        if len(vnlist) == 1:
            return vnlist[0]
        preexist = vnlist[0]
        bigendian = preexist.getAddr().isBigEndian() if hasattr(preexist.getAddr(), 'isBigEndian') else False
        opaddr = self._fd.getAddress() if insertop is None else insertop.getAddr()
        bl = self._fd.getBasicBlocks().getStartBlock() if insertop is None else insertop.getParent()
        for i in range(1, len(vnlist)):
            vn = vnlist[i]
            newop = self._fd.newOp(2, opaddr)
            self._fd.opSetOpcode(newop, OpCode.CPUI_PIECE)
            if i == len(vnlist) - 1:
                newvn = finalvn
                self._fd.opSetOutput(newop, newvn)
            else:
                newvn = self._fd.newUniqueOut(preexist.getSize() + vn.getSize(), newop)
            if bigendian:
                self._fd.opSetInput(newop, preexist, 0)
                self._fd.opSetInput(newop, vn, 1)
            else:
                self._fd.opSetInput(newop, vn, 0)
                self._fd.opSetInput(newop, preexist, 1)
            if insertop is None and bl is not None:
                self._fd.opInsertBegin(newop, bl)
            elif insertop is not None:
                self._fd.opInsertBefore(newop, insertop)
            preexist = newvn
        return preexist

    def splitPieces(self, vnlist: list, insertop, addr: Address, size: int, startvn) -> None:
        """Build a set of Varnode piece expressions at the given location."""
        if not vnlist or not hasattr(self._fd, 'newOp'):
            return
        bigendian = addr.isBigEndian() if hasattr(addr, 'isBigEndian') else False
        baseoff = addr.getOffset() + size if bigendian else addr.getOffset()
        opaddr = self._fd.getAddress() if insertop is None else insertop.getAddr()
        bl = self._fd.getBasicBlocks().getStartBlock() if insertop is None else insertop.getParent()
        for vn in vnlist:
            newop = self._fd.newOp(2, opaddr)
            self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
            if bigendian:
                diff = baseoff - (vn.getOffset() + vn.getSize())
            else:
                diff = vn.getOffset() - baseoff
            self._fd.opSetInput(newop, startvn, 0)
            self._fd.opSetInput(newop, self._fd.newConstant(4, diff), 1)
            self._fd.opSetOutput(newop, vn)
            if insertop is None and bl is not None:
                self._fd.opInsertBegin(newop, bl)
            elif insertop is not None:
                self._fd.opInsertAfter(newop, insertop)

    @staticmethod
    def buildRefinement(refine: list, addr: Address, vnlist: list) -> None:
        """Build a refinement array given an address range and a list of Varnodes."""
        for vn in vnlist:
            curaddr = vn.getAddr()
            sz = vn.getSize()
            diff = curaddr.getOffset() - addr.getOffset()
            if 0 <= diff < len(refine):
                refine[diff] = 1
            endpos = diff + sz
            if 0 <= endpos < len(refine):
                refine[endpos] = 1

    @staticmethod
    def remove13Refinement(refine: list) -> None:
        """If we see 1-3 or 3-1 pieces in the partition, replace with a 4."""
        if not refine:
            return
        pos = 0
        lastsize = refine[pos]
        if lastsize == 0:
            return
        pos += lastsize
        while pos < len(refine):
            cursize = refine[pos]
            if cursize == 0:
                break
            if (lastsize == 1 and cursize == 3) or (lastsize == 3 and cursize == 1):
                refine[pos - lastsize] = 4
                lastsize = 4
                pos += cursize
            else:
                lastsize = cursize
                pos += lastsize

    def callOpIndirectEffect(self, addr: Address, size: int, op) -> bool:
        """Determine if the address range is affected by the given call p-code op."""
        if op.code() in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            if hasattr(self._fd, 'getCallSpecs'):
                fc = self._fd.getCallSpecs(op)
                if fc is None:
                    return True
                if hasattr(fc, 'hasEffectTranslate'):
                    return fc.hasEffectTranslate(addr, size) != 'unaffected'
            return True
        return False

    def bumpDeadcodeDelay(self, spc: AddrSpace) -> None:
        """Increase the heritage delay for the given AddrSpace and request a restart."""
        if spc.getType() not in (IPTR_PROCESSOR, IPTR_SPACEBASE):
            return
        if spc.getDelay() != spc.getDeadcodeDelay():
            return
        if hasattr(self._fd, 'getOverride'):
            override = self._fd.getOverride()
            if hasattr(override, 'hasDeadcodeDelay') and override.hasDeadcodeDelay(spc):
                return
            if hasattr(override, 'insertDeadcodeDelay'):
                override.insertDeadcodeDelay(spc, spc.getDeadcodeDelay() + 1)
        if hasattr(self._fd, 'setRestartPending'):
            self._fd.setRestartPending(True)

    def removeRevisitedMarkers(self, remove: list, addr: Address, size: int) -> None:
        """Remove deprecated MULTIEQUAL/INDIRECT/COPY ops, preparing to re-heritage.

        If a previous Varnode was heritaged through a MULTIEQUAL or INDIRECT op, but now
        a larger range containing the Varnode is being heritaged, we throw away the op,
        letting the data-flow for the new larger range determine the data-flow for the
        old Varnode. The original Varnode is redefined as the output of a SUBPIECE
        of a larger free Varnode.
        """
        info = self.getInfo(addr.getSpace())
        if info is not None and info.deadremoved > 0:
            self.bumpDeadcodeDelay(addr.getSpace())
            if not info.warningissued:
                info.warningissued = True
                if hasattr(self._fd, 'warningHeader'):
                    self._fd.warningHeader(f"Heritage AFTER dead removal. Revisit: {addr}")

        for vn in remove:
            op = vn.getDef()
            if op is None:
                continue
            bl = op.getParent()
            opc = op.code()

            if opc == OpCode.CPUI_INDIRECT:
                # Insert SUBPIECE after target of INDIRECT
                if hasattr(vn, 'clearAddrForce'):
                    vn.clearAddrForce()
            elif opc == OpCode.CPUI_MULTIEQUAL:
                pass  # Insert SUBPIECE after all MULTIEQUALs in block
            else:
                # Remove return form COPY
                if hasattr(self._fd, 'opUnlink'):
                    self._fd.opUnlink(op)
                continue

            # Calculate overlap offset
            offset = vn.overlap(addr, size) if hasattr(vn, 'overlap') else 0
            if offset < 0:
                offset = 0

            # Uninsert the old op, replace with SUBPIECE from larger free varnode
            if hasattr(self._fd, 'opUninsert'):
                self._fd.opUninsert(op)

            newInputs = []
            big = self._fd.newVarnode(size, addr)
            big.setActiveHeritage()
            newInputs.append(big)
            newInputs.append(self._fd.newConstant(4, offset))

            self._fd.opSetOpcode(op, OpCode.CPUI_SUBPIECE)
            if hasattr(op, 'setAllInput'):
                op.setAllInput(newInputs)
            else:
                self._fd.opSetInput(op, newInputs[0], 0)
                self._fd.opSetInput(op, newInputs[1], 1)

            if bl is not None and hasattr(self._fd, 'opInsertBegin'):
                self._fd.opInsertBegin(op, bl)

            vn.setWriteMask()

    def clearStackPlaceholders(self, info: HeritageInfo) -> None:
        """Clear any placeholder LOADs associated with calls."""
        if self._fd is None:
            return
        if hasattr(self._fd, 'numCalls'):
            for i in range(self._fd.numCalls()):
                fc = self._fd.getCallSpecs(i)
                if fc is not None and hasattr(fc, 'abortSpacebaseRelative'):
                    fc.abortSpacebaseRelative(self._fd)
        info.hasCallPlaceholders = False

    def processJoins(self) -> None:
        """Split join-space Varnodes up into their real components."""
        pass  # Requires JoinRecord support

    def generateLoadGuard(self, node, op, spc: AddrSpace) -> None:
        """Generate a guard record given an indexed LOAD into a stack space."""
        if hasattr(op, 'usesSpacebasePtr') and not op.usesSpacebasePtr():
            guard = LoadGuard()
            guard.set(op, spc, node.get('offset', 0) if isinstance(node, dict) else 0)
            self._loadGuard.append(guard)
            if hasattr(self._fd, 'opMarkSpacebasePtr'):
                self._fd.opMarkSpacebasePtr(op)

    def generateStoreGuard(self, node, op, spc: AddrSpace) -> None:
        """Generate a guard record given an indexed STORE to a stack space."""
        if hasattr(op, 'usesSpacebasePtr') and not op.usesSpacebasePtr():
            guard = LoadGuard()
            guard.set(op, spc, node.get('offset', 0) if isinstance(node, dict) else 0)
            self._storeGuard.append(guard)
            if hasattr(self._fd, 'opMarkSpacebasePtr'):
                self._fd.opMarkSpacebasePtr(op)

    def protectFreeStores(self, spc: AddrSpace, freeStores: list) -> bool:
        """Identify any STORE ops that use a free pointer from a given address space."""
        return False

    def discoverIndexedStackPointers(self, spc: AddrSpace, freeStores: list, checkFreeStores: bool) -> bool:
        """Trace input stack-pointer to any indexed loads."""
        return False

    def reprocessFreeStores(self, spc: AddrSpace, freeStores: list) -> None:
        """Revisit STOREs with free pointers now that a heritage pass has completed."""
        pass

    def findAddressForces(self, copySinks: list, forces: list) -> None:
        """Find the last PcodeOps that write to specific addresses that flow to specific sites."""
        pass  # Complex backward reachability analysis

    def propagateCopyAway(self, op) -> None:
        """Eliminate a COPY sink preserving its data-flow."""
        if hasattr(self._fd, 'totalReplace') and hasattr(self._fd, 'opDestroy'):
            inVn = op.getIn(0)
            while inVn.isWritten():
                nextOp = inVn.getDef()
                if nextOp.code() != OpCode.CPUI_COPY:
                    break
                nextIn = nextOp.getIn(0)
                if nextIn.getAddr() != inVn.getAddr():
                    break
                inVn = nextIn
            self._fd.totalReplace(op.getOut(), inVn)
            self._fd.opDestroy(op)

    def handleNewLoadCopies(self) -> None:
        """Mark the boundary of artificial ops introduced by load guards."""
        self._loadCopyOps.clear()

    def analyzeNewLoadGuards(self) -> None:
        """Make final determination of what range new LoadGuards are protecting."""
        pass  # Requires ValueSetSolver

    # ----------------------------------------------------------------
    # ADT and phi-node placement
    # ----------------------------------------------------------------

    def buildADT(self) -> None:
        """Build the augmented dominator tree (Bilardi-Pingali algorithm).

        Assumes the dominator tree is already built. Computes the augment
        array which stores, for each block, the list of blocks in its
        dominance frontier that need phi-nodes. Also computes boundary
        nodes to limit the recursive walk during phi-node placement.
        """
        graph = self._fd.getBasicBlocks()
        size = graph.getSize()
        if size == 0:
            return

        # Step 1: Build dominator tree
        self._buildDominatorTree()

        # Build domchild from the dominator tree
        self._domchild = [[] for _ in range(size)]
        for i in range(size):
            bl = graph.getBlock(i)
            idom = bl.getImmedDom() if hasattr(bl, 'getImmedDom') else None
            if idom is not None:
                pidx = idom.getIndex()
                if 0 <= pidx < size:
                    self._domchild[pidx].append(bl)

        # Compute depth via BFS from root
        self._depth = [0] * size
        self._maxdepth = 0
        stack = [(0, 0)]
        while stack:
            idx, d = stack.pop()
            self._depth[idx] = d
            if d > self._maxdepth:
                self._maxdepth = d
            for child in self._domchild[idx]:
                stack.append((child.getIndex(), d + 1))

        # Step 2: Initialize augment and flags
        self._augment = [[] for _ in range(size)]
        self._flags = [0] * size

        # Step 3: Find up-edges and compute boundary nodes
        a = [0] * size
        b = [0] * size
        t = [0] * size
        z = [0] * size
        upstart = []
        upend = []

        for i in range(size):
            x = graph.getBlock(i)
            for child in self._domchild[i]:
                for k in range(child.sizeIn()):
                    u = child.getIn(k)
                    idom = child.getImmedDom() if hasattr(child, 'getImmedDom') else None
                    if u is not idom:  # u->child is an up-edge
                        upstart.append(u)
                        upend.append(child)
                        b[u.getIndex()] += 1
                        t[x.getIndex()] += 1

        # Bottom-up pass to determine boundary nodes
        for i in range(size - 1, -1, -1):
            k_sum = 0
            l_sum = 0
            for child in self._domchild[i]:
                cidx = child.getIndex()
                k_sum += a[cidx]
                l_sum += z[cidx]
            a[i] = b[i] - t[i] + k_sum
            z[i] = 1 + l_sum
            if len(self._domchild[i]) == 0 or z[i] > a[i] + 1:
                self._flags[i] |= Heritage.boundary_node
                z[i] = 1

        # Compute z[] for path compression
        z[0] = -1
        for i in range(1, size):
            bl = graph.getBlock(i)
            idom = bl.getImmedDom() if hasattr(bl, 'getImmedDom') else None
            if idom is not None:
                j = idom.getIndex()
                if (self._flags[j] & Heritage.boundary_node) != 0:
                    z[i] = j
                else:
                    z[i] = z[j]

        # Build the augment array from up-edges
        for i in range(len(upstart)):
            v = upend[i]
            idom = v.getImmedDom() if hasattr(v, 'getImmedDom') else None
            j = idom.getIndex() if idom is not None else 0
            k = upstart[i].getIndex()
            while j < k:  # while idom(v) properly dominates u
                self._augment[k].append(v)
                k = z[k]

    def visitIncr(self, qnode, vnode) -> None:
        """The heart of the phi-node placement algorithm."""
        i = vnode.getIndex()
        j = qnode.getIndex()
        if i >= len(self._augment):
            return
        for v in self._augment[i]:
            if v.getImmedDom() is not None and v.getImmedDom().getIndex() < j:
                k = v.getIndex()
                if k < len(self._flags):
                    if (self._flags[k] & Heritage.merged_node) == 0:
                        self._merge.append(v)
                        self._flags[k] |= Heritage.merged_node
                    if (self._flags[k] & Heritage.mark_node) == 0:
                        self._flags[k] |= Heritage.mark_node
                        self._pq.insert(v, self._depth[k] if k < len(self._depth) else 0)
            else:
                break
        if i < len(self._flags) and (self._flags[i] & Heritage.boundary_node) == 0:
            children = self._domchildren.get(id(vnode), [])
            for child in children:
                cidx = child.getIndex()
                if cidx < len(self._flags) and (self._flags[cidx] & Heritage.mark_node) == 0:
                    self.visitIncr(qnode, child)

    def calcMultiequals(self, write: list) -> None:
        """Calculate blocks that should contain MULTIEQUALs for one address range."""
        self._pq.reset(self._maxdepth if self._maxdepth >= 0 else 0)
        self._merge.clear()
        graph = self._fd.getBasicBlocks()
        for vn in write:
            if vn.getDef() is None:
                continue
            bl = vn.getDef().getParent()
            if bl is None:
                continue
            j = bl.getIndex()
            if j < len(self._flags) and (self._flags[j] & Heritage.mark_node) != 0:
                continue
            self._pq.insert(bl, self._depth[j] if j < len(self._depth) else 0)
            if j < len(self._flags):
                self._flags[j] |= Heritage.mark_node
        # Make sure start node is in input
        if 0 < len(self._flags) and (self._flags[0] & Heritage.mark_node) == 0:
            self._pq.insert(graph.getBlock(0), self._depth[0] if self._depth else 0)
            self._flags[0] |= Heritage.mark_node
        while not self._pq.empty():
            bl = self._pq.extract()
            self.visitIncr(bl, bl)
        for i in range(len(self._flags)):
            self._flags[i] &= ~(Heritage.mark_node | Heritage.merged_node)

    def placeMultiequals(self) -> None:
        """Perform phi-node placement for the current set of address ranges."""
        readvars: list = []
        writevars: list = []
        inputvars: list = []
        removevars: list = []
        for memrange in self._disjoint:
            self.collect(memrange, readvars, writevars, inputvars, removevars)
            size = memrange.size
            if not readvars:
                if not writevars and not inputvars:
                    continue
                if memrange.addr.getSpace().getType() == IPTR_INTERNAL or memrange.oldAddresses():
                    continue
            if removevars:
                self.removeRevisitedMarkers(removevars, memrange.addr, size)
            self.guardInput(memrange.addr, size, inputvars)
            self.guard(memrange.addr, size, memrange.newAddresses(), readvars, writevars, inputvars)
            self.calcMultiequals(writevars)
            for bl in self._merge:
                numinputs = bl.sizeIn()
                multiop = self._fd.newOp(numinputs, bl.getStart())
                vnout = self._fd.newVarnodeOut(size, memrange.addr, multiop)
                vnout.setActiveHeritage()
                self._fd.opSetOpcode(multiop, OpCode.CPUI_MULTIEQUAL)
                for j in range(numinputs):
                    vnin = self._fd.newVarnode(size, memrange.addr)
                    self._fd.opSetInput(multiop, vnin, j)
                self._fd.opInsertBegin(multiop, bl)
        self._merge.clear()

    def rename(self) -> None:
        """Perform the renaming algorithm for the current set of address ranges."""
        varstack: Dict[Address, List] = defaultdict(list)
        entry = self._fd.getBasicBlocks().getBlock(0)
        if entry is not None:
            self.renameRecurse(entry, varstack)
        self._disjoint.clear()

    def renameRecurse(self, bl, varstack: dict) -> None:
        """The heart of the renaming algorithm.

        From the given block, recursively walk the dominance tree. At each
        block, visit PcodeOps in execution order looking for Varnodes that
        need to be renamed.
        """
        writelist = []
        if not hasattr(bl, 'getOpRange'):
            # Fallback: use getOpList if available
            ops = list(bl.getOpList()) if hasattr(bl, 'getOpList') else []
        else:
            ops = list(bl.getOpRange())

        for op in ops:
            if op.code() != OpCode.CPUI_MULTIEQUAL:
                for slot in range(op.numInput()):
                    vnin = op.getIn(slot)
                    if vnin.isHeritageKnown():
                        continue
                    if not vnin.isActiveHeritage():
                        continue
                    vnin.clearActiveHeritage()
                    addr_key = vnin.getAddr()
                    stack = varstack[addr_key]
                    if not stack:
                        vnnew = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                        vnnew = self._fd.setInputVarnode(vnnew)
                        stack.append(vnnew)
                    else:
                        vnnew = stack[-1]
                    # Check for INDIRECT at-same-time issue
                    if vnnew.isWritten() and vnnew.getDef().code() == OpCode.CPUI_INDIRECT:
                        from ghidra.ir.op import PcodeOp as PcodeOpCls
                        if hasattr(PcodeOpCls, 'getOpFromConst'):
                            iop_addr = vnnew.getDef().getIn(1).getAddr()
                            if PcodeOpCls.getOpFromConst(iop_addr) is op:
                                if len(stack) == 1:
                                    vnnew2 = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                                    vnnew2 = self._fd.setInputVarnode(vnnew2)
                                    stack.insert(0, vnnew2)
                                    vnnew = vnnew2
                                else:
                                    vnnew = stack[-2]
                    self._fd.opSetInput(op, vnnew, slot)
                    if vnin.hasNoDescend() and hasattr(self._fd, 'deleteVarnode'):
                        self._fd.deleteVarnode(vnin)
            # Push writes onto stack
            vnout = op.getOut()
            if vnout is None:
                continue
            if not vnout.isActiveHeritage():
                continue
            vnout.clearActiveHeritage()
            varstack[vnout.getAddr()].append(vnout)
            writelist.append(vnout)

        # Process MULTIEQUAL inputs in successor blocks
        for i in range(bl.sizeOut()):
            subbl = bl.getOut(i)
            slot = bl.getOutRevIndex(i) if hasattr(bl, 'getOutRevIndex') else i
            sub_ops = list(subbl.getOpList()) if hasattr(subbl, 'getOpList') else []
            for multiop in sub_ops:
                if multiop.code() != OpCode.CPUI_MULTIEQUAL:
                    break
                if slot >= multiop.numInput():
                    continue
                vnin = multiop.getIn(slot)
                if vnin.isHeritageKnown():
                    continue
                addr_key = vnin.getAddr()
                stack = varstack[addr_key]
                if not stack:
                    vnnew = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                    vnnew = self._fd.setInputVarnode(vnnew)
                    stack.append(vnnew)
                else:
                    vnnew = stack[-1]
                self._fd.opSetInput(multiop, vnnew, slot)
                if vnin.hasNoDescend() and hasattr(self._fd, 'deleteVarnode'):
                    self._fd.deleteVarnode(vnin)

        # Recurse to dominator tree children
        for child in self._domchildren.get(id(bl), []):
            self.renameRecurse(child, varstack)

        # Pop this block's writes off the stack
        for vnout in writelist:
            addr_key = vnout.getAddr()
            if varstack[addr_key]:
                varstack[addr_key].pop()

    # ----------------------------------------------------------------
    # Main heritage entry point
    # ----------------------------------------------------------------

    def heritage(self) -> None:
        """Perform one pass of heritage (SSA construction).

        From any address space that is active for this pass, free Varnodes
        are collected and then fully integrated into SSA form.
        """
        if self._fd is None:
            return
        graph = self._fd.getBasicBlocks()
        if graph.getSize() == 0:
            return

        if self._maxdepth == -1:
            self.buildADT()

        self.processJoins()

        # For each heritaged address space
        for info in self._infolist:
            if not info.isHeritaged():
                continue
            if self._pass < info.delay:
                continue
            if info.hasCallPlaceholders:
                self.clearStackPlaceholders(info)
            if not info.loadGuardSearch:
                info.loadGuardSearch = True
                self.discoverIndexedStackPointers(info.space, [], True)

            # Collect free varnodes in this space
            for vn in list(self._fd._vbank.beginLoc()):
                if vn.getSpace() is not info.space:
                    continue
                if not vn.isWritten() and vn.hasNoDescend() and not vn.isUnaffected() and not vn.isInput():
                    continue
                if vn.isWriteMask():
                    continue
                intersect_ref = [0]
                self._globaldisjoint.add(vn.getAddr(), vn.getSize(), self._pass, intersect_ref)
                prev = intersect_ref[0]
                if prev == 0:
                    self._disjoint.add(vn.getAddr(), vn.getSize(), MemRange.new_addresses)
                elif prev == 2:
                    if vn.isHeritageKnown():
                        continue
                    if vn.hasNoDescend():
                        continue
                    self._disjoint.add(vn.getAddr(), vn.getSize(), MemRange.old_addresses)
                else:
                    self._disjoint.add(vn.getAddr(), vn.getSize(),
                                       MemRange.old_addresses | MemRange.new_addresses)

        self.placeMultiequals()
        self.rename()
        self.analyzeNewLoadGuards()
        self.handleNewLoadCopies()
        self._pass += 1

    def clear(self) -> None:
        """Reset all analysis of heritage."""
        self._disjoint.clear()
        self._globaldisjoint.clear()
        self._domchild = []
        self._augment = []
        self._flags = []
        self._depth = []
        self._merge = []
        self.clearInfoList()
        self._loadGuard.clear()
        self._storeGuard.clear()
        self._maxdepth = -1
        self._pass = 0

    def __repr__(self) -> str:
        return f"Heritage(pass={self._pass})"
