"""
Corresponds to: jumptable.hh / jumptable.cc

Classes to support jump-tables and their recovery.
JumpTable, JumpModel, JumpBasic, LoadTable, PathMeld, GuardRecord.
"""

from __future__ import annotations
from typing import Optional, List, Dict, Set
from ghidra.core.address import Address


class LoadTable:
    """A description of where and how data was loaded from memory."""

    def __init__(self, addr: Optional[Address] = None, sz: int = 0, nm: int = 1) -> None:
        self.addr: Address = addr if addr is not None else Address()
        self.size: int = sz
        self.num: int = nm

    def __lt__(self, other):
        return self.addr < other.addr

    @staticmethod
    def collapseTable(table: list) -> None:
        """Collapse adjacent table entries."""
        if len(table) <= 1:
            return
        table.sort()
        i = 0
        while i < len(table) - 1:
            cur = table[i]
            nxt = table[i + 1]
            endaddr = cur.addr + cur.size * cur.num
            if endaddr == nxt.addr and cur.size == nxt.size:
                cur.num += nxt.num
                table.pop(i + 1)
            else:
                i += 1


class PathMeld:
    """All paths from a switch variable to the BRANCHIND."""

    def __init__(self) -> None:
        self._commonVn: list = []
        self._opMeld: list = []

    def clear(self) -> None:
        self._commonVn.clear()
        self._opMeld.clear()

    def empty(self) -> bool:
        return len(self._commonVn) == 0

    def numCommonVarnode(self) -> int:
        return len(self._commonVn)

    def numOps(self) -> int:
        return len(self._opMeld)

    def getVarnode(self, i: int):
        return self._commonVn[i]

    def getOp(self, i: int):
        return self._opMeld[i][0]

    def getOpParent(self, i: int):
        rootIdx = self._opMeld[i][1]
        return self._commonVn[rootIdx]

    def set(self, op_or_path, vn=None):
        self.clear()
        if vn is not None:
            self._commonVn.append(vn)
            self._opMeld.append((op_or_path, 0))
        elif isinstance(op_or_path, PathMeld):
            self._commonVn = list(op_or_path._commonVn)
            self._opMeld = list(op_or_path._opMeld)
        elif isinstance(op_or_path, list):
            for item in op_or_path:
                if hasattr(item, 'op'):
                    self._opMeld.append((item.op, 0))

    def markPaths(self, val: bool, startVarnode: int = 0) -> None:
        for i in range(len(self._opMeld)):
            op = self._opMeld[i][0]
            if hasattr(op, 'setMark') and hasattr(op, 'clearMark'):
                if val:
                    op.setMark()
                else:
                    op.clearMark()


class GuardRecord:
    """A switch variable Varnode and a constraint from a CBRANCH."""

    def __init__(self, cbranch=None, readOp=None, path: int = 0,
                 rng=None, vn=None, unrolled: bool = False) -> None:
        self.cbranch = cbranch
        self.readOp = readOp
        self.vn = vn
        self.baseVn = vn
        self.indpath: int = path
        self.bitsPreserved: int = 0
        self.range = rng
        self.unrolled: bool = unrolled

    def isUnrolled(self) -> bool:
        return self.unrolled

    def getBranch(self):
        return self.cbranch

    def getReadOp(self):
        return self.readOp

    def getPath(self) -> int:
        return self.indpath

    def getRange(self):
        return self.range

    def clear(self) -> None:
        self.cbranch = None


class JumpModel:
    """Base class for jump-table execution models."""

    def __init__(self, jt=None) -> None:
        self.jumptable = jt

    def isOverride(self) -> bool:
        return False

    def getTableSize(self) -> int:
        return 0

    def recoverModel(self, fd, indop, matchsize: int = 0, maxtablesize: int = 1024) -> bool:
        return False

    def buildAddresses(self, fd, indop, addresstable: list,
                       loadpoints=None, loadcounts=None) -> None:
        pass

    def findUnnormalized(self, maxaddsub: int = 0, maxleftright: int = 0, maxext: int = 0) -> None:
        pass

    def buildLabels(self, fd, addresstable: list, label: list, orig=None) -> None:
        pass

    def foldInNormalization(self, fd, indop):
        return None

    def foldInGuards(self, fd, jump) -> bool:
        return False

    def sanityCheck(self, fd, indop, addresstable: list,
                    loadpoints: list = None, loadcounts=None) -> bool:
        return True

    def clone(self, jt):
        return JumpModel(jt)

    def clear(self) -> None:
        pass


class JumpModelTrivial(JumpModel):
    """Trivial model where the BRANCHIND input is the switch variable."""

    def __init__(self, jt=None) -> None:
        super().__init__(jt)
        self._size: int = 0

    def getTableSize(self) -> int:
        return self._size

    def recoverModel(self, fd, indop, matchsize=0, maxtablesize=1024) -> bool:
        if indop is None:
            return False
        parent = indop.getParent() if hasattr(indop, 'getParent') else None
        if parent is None:
            return False
        self._size = parent.sizeOut()
        return self._size > 0

    def buildAddresses(self, fd, indop, addresstable, loadpoints=None, loadcounts=None):
        if indop is None:
            return
        parent = indop.getParent() if hasattr(indop, 'getParent') else None
        if parent is None:
            return
        for i in range(parent.sizeOut()):
            bl = parent.getOut(i)
            if bl is not None:
                addresstable.append(bl.getStart() if hasattr(bl, 'getStart') else Address())

    def buildLabels(self, fd, addresstable, label, orig=None):
        for i in range(len(addresstable)):
            label.append(i)

    def clone(self, jt):
        m = JumpModelTrivial(jt)
        m._size = self._size
        return m


class JumpTable:
    """A map from switch variable values to control-flow targets.

    Attached to a CPUI_BRANCHIND, encapsulates all info to model
    the indirect jump as a switch statement.
    """

    # Recovery status
    success = 0
    fail_normal = 1
    fail_thunk = 2
    fail_return = 3
    fail_callother = 4

    def __init__(self, glb=None, addr: Optional[Address] = None) -> None:
        self.glb = glb
        self.opaddress: Address = addr if addr is not None else Address()
        self.indirect = None  # PcodeOp
        self.jmodel: Optional[JumpModel] = None
        self.origmodel: Optional[JumpModel] = None
        self.addresstable: List[Address] = []
        self.label: List[int] = []
        self.loadpoints: List[LoadTable] = []
        self.defaultBlock: int = -1
        self.lastBlock: int = -1
        self.switchVarConsume: int = 0xFFFFFFFFFFFFFFFF
        self.maxaddsub: int = 1
        self.maxleftright: int = 1
        self.maxext: int = 1
        self.partialTable: bool = False
        self.collectloads: bool = False
        self.defaultIsFolded: bool = False

    def isRecovered(self) -> bool:
        return len(self.addresstable) > 0

    def isLabelled(self) -> bool:
        return len(self.label) > 0

    def isOverride(self) -> bool:
        return self.jmodel is not None and self.jmodel.isOverride()

    def isPartial(self) -> bool:
        return self.partialTable

    def markComplete(self) -> None:
        self.partialTable = False

    def numEntries(self) -> int:
        return len(self.addresstable)

    def getSwitchVarConsume(self) -> int:
        return self.switchVarConsume

    def getDefaultBlock(self) -> int:
        return self.defaultBlock

    def getOpAddress(self) -> Address:
        return self.opaddress

    def getIndirectOp(self):
        return self.indirect

    def setIndirectOp(self, ind) -> None:
        self.opaddress = ind.getAddr() if hasattr(ind, 'getAddr') else Address()
        self.indirect = ind

    def setNormMax(self, maddsub: int, mleftright: int, mext: int) -> None:
        self.maxaddsub = maddsub
        self.maxleftright = mleftright
        self.maxext = mext

    def setLastAsDefault(self) -> None:
        if self.addresstable:
            self.lastBlock = len(self.addresstable) - 1

    def setDefaultBlock(self, bl: int) -> None:
        self.defaultBlock = bl

    def setLoadCollect(self, val: bool) -> None:
        self.collectloads = val

    def setFoldedDefault(self) -> None:
        self.defaultIsFolded = True

    def hasFoldedDefault(self) -> bool:
        return self.defaultIsFolded

    def getAddressByIndex(self, i: int) -> Address:
        return self.addresstable[i] if i < len(self.addresstable) else Address()

    def getLabelByIndex(self, i: int) -> int:
        return self.label[i] if i < len(self.label) else 0

    def numIndicesByBlock(self, bl) -> int:
        count = 0
        blstart = bl.getStart() if hasattr(bl, 'getStart') else None
        if blstart is None:
            return 0
        for addr in self.addresstable:
            if addr == blstart:
                count += 1
        return count

    def recoverAddresses(self, fd) -> None:
        """Recover the raw jump-table addresses."""
        if self.jmodel is None:
            self.jmodel = JumpModelTrivial(self)
        if not self.jmodel.recoverModel(fd, self.indirect, 0, 1024):
            return
        self.addresstable.clear()
        self.jmodel.buildAddresses(fd, self.indirect, self.addresstable,
                                   self.loadpoints if self.collectloads else None)

    def recoverLabels(self, fd) -> None:
        """Recover case labels for this jump-table."""
        if self.jmodel is None:
            return
        self.label.clear()
        self.jmodel.buildLabels(fd, self.addresstable, self.label, self.jmodel)

    def foldInNormalization(self, fd) -> None:
        """Hide the normalization code."""
        if self.jmodel is not None:
            self.jmodel.foldInNormalization(fd, self.indirect)

    def foldInGuards(self, fd) -> bool:
        if self.jmodel is not None:
            return self.jmodel.foldInGuards(fd, self)
        return False

    def getLastBlock(self) -> int:
        return self.lastBlock

    def getModel(self):
        return self.jmodel

    def setModel(self, model) -> None:
        self.jmodel = model

    def getLoadTable(self) -> list:
        return self.loadpoints

    def isBadJumpTable(self) -> bool:
        return getattr(self, '_badJumpTable', False)

    def setBadJumpTable(self, val: bool) -> None:
        self._badJumpTable = val

    def checkForMultistage(self, fd) -> bool:
        """Check if this jump-table needs multistage recovery."""
        return False

    def switchOver(self, flow) -> None:
        """Convert jump-table addresses to basic block indices."""
        pass

    def recoverModel(self, fd) -> bool:
        """Recover the model for this jump-table."""
        if self.jmodel is None:
            self.jmodel = JumpModelTrivial(self)
        return self.jmodel.recoverModel(fd, self.indirect, 0, 1024)

    def sanityCheck(self, fd) -> bool:
        """Verify the recovered jump-table."""
        if self.jmodel is None:
            return False
        return self.jmodel.sanityCheck(fd, self.indirect, self.addresstable)

    def trivialSwitchOver(self) -> None:
        """Simple switch-over when table is already complete."""
        pass

    def recoverMultistage(self, fd) -> bool:
        """Attempt multistage recovery."""
        return False

    def encode(self, encoder) -> None:
        """Encode this jump-table to a stream."""
        pass

    def decode(self, decoder) -> None:
        """Decode this jump-table from a stream."""
        pass

    def clear(self) -> None:
        self.addresstable.clear()
        self.label.clear()
        self.loadpoints.clear()
        self.defaultBlock = -1
        self.lastBlock = -1
        if self.jmodel is not None:
            self.jmodel.clear()


# RecoveryMode as class-level enum on JumpTable
JumpTable.RecoveryMode = type('RecoveryMode', (), {
    'success': 0,
    'fail_normal': 1,
    'fail_thunk': 2,
    'fail_return': 3,
    'fail_callother': 4,
})


class JumptableThunkError(Exception):
    """Exception thrown for a thunk mechanism that looks like a jump-table."""
    pass


class JumpValues:
    """An iterator over values a switch variable can take."""
    NO_LABEL = 0xFFFFFFFFFFFFFFFF

    def truncate(self, nm: int) -> None:
        pass

    def getSize(self) -> int:
        return 0

    def contains(self, val: int) -> bool:
        return False

    def initializeForReading(self) -> bool:
        return False

    def next(self) -> bool:
        return False

    def getValue(self) -> int:
        return 0

    def getStartVarnode(self):
        return None

    def getStartOp(self):
        return None

    def isReversible(self) -> bool:
        return False

    def clone(self):
        return JumpValues()


class JumpValuesRange(JumpValues):
    """Single entry switch variable that can take a range of values."""

    def __init__(self) -> None:
        from ghidra.analysis.rangeutil import CircleRange
        self.range = CircleRange()
        self.normqvn = None
        self.startop = None
        self._curval: int = 0

    def setRange(self, rng) -> None:
        self.range = rng

    def setStartVn(self, vn) -> None:
        self.normqvn = vn

    def setStartOp(self, op) -> None:
        self.startop = op

    def getSize(self) -> int:
        return self.range.getSize()

    def contains(self, val: int) -> bool:
        return self.range.contains(val)

    def initializeForReading(self) -> bool:
        if self.range.isEmpty():
            return False
        self._curval = self.range.getMin()
        return True

    def next(self) -> bool:
        self._curval, still_in = self.range.getNext(self._curval)
        return still_in

    def getValue(self) -> int:
        return self._curval

    def getStartVarnode(self):
        return self.normqvn

    def getStartOp(self):
        return self.startop

    def isReversible(self) -> bool:
        return True

    def clone(self):
        r = JumpValuesRange()
        r.range = self.range
        r.normqvn = self.normqvn
        r.startop = self.startop
        return r


class JumpValuesRangeDefault(JumpValuesRange):
    """A jump-table starting range with two possible execution paths."""

    def __init__(self) -> None:
        super().__init__()
        self._extravalue: int = 0
        self._extravn = None
        self._extraop = None
        self._lastvalue: bool = False

    def setExtraValue(self, val: int) -> None:
        self._extravalue = val

    def setDefaultVn(self, vn) -> None:
        self._extravn = vn

    def setDefaultOp(self, op) -> None:
        self._extraop = op

    def getSize(self) -> int:
        return super().getSize() + 1

    def contains(self, val: int) -> bool:
        if val == self._extravalue:
            return True
        return super().contains(val)

    def initializeForReading(self) -> bool:
        self._lastvalue = False
        return super().initializeForReading()

    def next(self) -> bool:
        if self._lastvalue:
            return False
        result = super().next()
        if not result:
            self._lastvalue = True
            self._curval = self._extravalue
            return True
        return True

    def getStartVarnode(self):
        if self._lastvalue:
            return self._extravn
        return self.normqvn

    def getStartOp(self):
        if self._lastvalue:
            return self._extraop
        return self.startop

    def isReversible(self) -> bool:
        return not self._lastvalue

    def clone(self):
        r = JumpValuesRangeDefault()
        r.range = self.range
        r.normqvn = self.normqvn
        r.startop = self.startop
        r._extravalue = self._extravalue
        r._extravn = self._extravn
        r._extraop = self._extraop
        return r


class EmulateFunction:
    """A light-weight emulator to calculate switch targets from switch variables."""

    def __init__(self, fd=None) -> None:
        self._fd = fd
        self._varnodeMap: dict = {}
        self._loadpoints = None

    def setLoadCollect(self, val) -> None:
        self._loadpoints = val

    def getVarnodeValue(self, vn) -> int:
        return self._varnodeMap.get(id(vn), 0)

    def setVarnodeValue(self, vn, val: int) -> None:
        self._varnodeMap[id(vn)] = val

    def emulatePath(self, val: int, pathMeld, startop, startvn) -> int:
        """Emulate a path through the function, returning the destination address offset."""
        if startvn is not None:
            self.setVarnodeValue(startvn, val)
        # Would execute ops along the path here
        return val


class JumpBasic(JumpModel):
    """The basic jump-table model: a normalized switch variable with a linear map to addresses."""

    def __init__(self, jt=None) -> None:
        super().__init__(jt)
        self._pathMeld = PathMeld()
        self._jrange = None  # JumpValuesRange
        self._varnodeIndex = None
        self._normqvn = None
        self._switchvn = None

    def isOverride(self) -> bool:
        return False

    def getTableSize(self) -> int:
        if self._jrange is not None:
            return self._jrange.getSize()
        return 0

    def recoverModel(self, fd, indop, matchsize=0, maxtablesize=1024) -> bool:
        return False  # Full implementation requires emulation

    def buildAddresses(self, fd, indop, addresstable, loadpoints=None, loadcounts=None):
        pass

    def findUnnormalized(self, maxaddsub=0, maxleftright=0, maxext=0):
        pass

    def buildLabels(self, fd, addresstable, label, orig=None):
        for i in range(len(addresstable)):
            label.append(i)

    def foldInNormalization(self, fd, indop):
        return None

    def foldInGuards(self, fd, jump) -> bool:
        return False

    def sanityCheck(self, fd, indop, addresstable, loadpoints=None, loadcounts=None) -> bool:
        return True

    def clone(self, jt):
        return JumpBasic(jt)

    def clear(self):
        self._pathMeld.clear()


class JumpBasicOverride(JumpModel):
    """A jump-table model where addresses are explicitly provided by an override."""

    def __init__(self, jt=None) -> None:
        super().__init__(jt)
        self._addrOverride: list = []

    def isOverride(self) -> bool:
        return True

    def getTableSize(self) -> int:
        return len(self._addrOverride)

    def recoverModel(self, fd, indop, matchsize=0, maxtablesize=1024) -> bool:
        return len(self._addrOverride) > 0

    def buildAddresses(self, fd, indop, addresstable, loadpoints=None, loadcounts=None):
        addresstable.extend(self._addrOverride)

    def findUnnormalized(self, maxaddsub=0, maxleftright=0, maxext=0):
        pass

    def buildLabels(self, fd, addresstable, label, orig=None):
        for i in range(len(addresstable)):
            label.append(i)

    def foldInNormalization(self, fd, indop):
        return None

    def foldInGuards(self, fd, jump) -> bool:
        return False

    def sanityCheck(self, fd, indop, addresstable, loadpoints=None, loadcounts=None) -> bool:
        return True

    def clone(self, jt):
        m = JumpBasicOverride(jt)
        m._addrOverride = list(self._addrOverride)
        return m

    def clear(self):
        self._addrOverride.clear()
