"""
Corresponds to: varmap.hh / varmap.cc

Classes for tracking local variables and reconstructing stack layout.
ScopeLocal, MapState, RangeHint, NameRecommend, DynamicRecommend, TypeRecommend.
"""

from __future__ import annotations
from typing import Optional, List, Dict, Tuple
from ghidra.core.address import Address
from ghidra.database.database import ScopeInternal


class NameRecommend:
    """A symbol name recommendation with its associated storage location."""

    def __init__(self, addr: Address = None, useaddr: Address = None,
                 sz: int = 0, nm: str = "", symId: int = 0) -> None:
        self.addr: Address = addr if addr is not None else Address()
        self.useaddr: Address = useaddr if useaddr is not None else Address()
        self.size: int = sz
        self.name: str = nm
        self.symbolId: int = symId

    def getAddr(self) -> Address: return self.addr
    def getUseAddr(self) -> Address: return self.useaddr
    def getSize(self) -> int: return self.size
    def getName(self) -> str: return self.name
    def getSymbolId(self) -> int: return self.symbolId
    def setName(self, nm: str) -> None: self.name = nm


class DynamicRecommend:
    """A name recommendation for a dynamic storage location."""

    def __init__(self, addr: Address = None, h: int = 0,
                 nm: str = "", symId: int = 0) -> None:
        self.usePoint: Address = addr if addr is not None else Address()
        self.hash: int = h
        self.name: str = nm
        self.symbolId: int = symId

    def getAddress(self) -> Address: return self.usePoint
    def getHash(self) -> int: return self.hash
    def getName(self) -> str: return self.name
    def getSymbolId(self) -> int: return self.symbolId
    def setName(self, nm: str) -> None: self.name = nm


class TypeRecommend:
    """Data-type recommendation for a storage location without a Symbol."""

    def __init__(self, addr: Address = None, dt=None) -> None:
        self.addr: Address = addr if addr is not None else Address()
        self.dataType = dt

    def getAddress(self) -> Address: return self.addr
    def getType(self): return self.dataType
    def setType(self, dt) -> None: self.dataType = dt


class RangeHint:
    """Partial data-type info mapped to a specific byte range (typically stack)."""

    fixed = 0
    open = 1
    endpoint = 2

    def __init__(self, sstart: int = 0, sz: int = 0, stype: int = 0,
                 dt=None, flags: int = 0, hstart: int = 0, hstop: int = 0) -> None:
        self.sstart: int = sstart
        self.size: int = sz
        self.type: int = stype
        self.dataType = dt
        self.flags: int = flags
        self.highind: int = hstart
        self.highstop: int = hstop

    def getType(self): return self.dataType
    def getStart(self) -> int: return self.sstart
    def getSize(self) -> int: return self.size
    def getRangeType(self) -> int: return self.type
    def getHighIndex(self) -> int: return self.highind
    def setHighIndex(self, val: int) -> None: self.highind = val

    def absorb(self, other: 'RangeHint') -> bool:
        if self.sstart + self.size == other.sstart:
            self.size += other.size
            return True
        return False

    def merge(self, other: 'RangeHint') -> bool:
        if self.sstart == other.sstart and self.size == other.size:
            if other.type == RangeHint.fixed:
                self.type = RangeHint.fixed
                self.dataType = other.dataType
            return True
        return False

    def preferred(self, other: 'RangeHint') -> bool:
        if self.type == RangeHint.fixed and other.type != RangeHint.fixed:
            return True
        if self.type != RangeHint.fixed and other.type == RangeHint.fixed:
            return False
        return self.size >= other.size


class MapState:
    """Gather raw pieces of a parameter/local variable map.

    Collects range hints from the Varnodes in a function and
    organizes them for final variable layout.
    """

    def __init__(self, spc, fd, rangelist, glb) -> None:
        self._spc = spc
        self._fd = fd
        self._rangelist = rangelist
        self._glb = glb
        self._range: List[RangeHint] = []

    def addRange(self, start: int, ct, flags: int = 0, rtype: int = 0, off: int = -1) -> None:
        sz = ct.getSize() if ct is not None else 1
        rh = RangeHint(start, sz, rtype, ct, flags)
        self._range.append(rh)

    def addGuard(self, addr: Address, flags: int, dt) -> None:
        pass

    def gatherVarnodes(self, fd) -> None:
        """Collect storage info from all Varnodes in the function."""
        if fd is None:
            return
        vbank = fd.getVarnodeBank() if hasattr(fd, 'getVarnodeBank') else None
        if vbank is None:
            return
        if not hasattr(vbank, 'allVarnodes'):
            return
        for vn in vbank.allVarnodes():
            spc = vn.getSpace() if hasattr(vn, 'getSpace') else None
            if spc is not self._spc:
                continue
            off = vn.getAddr().getOffset() if hasattr(vn, 'getAddr') else 0
            sz = vn.getSize()
            tp = vn.getType() if hasattr(vn, 'getType') else None
            self.addRange(off, tp, 0, RangeHint.fixed)

    def gatherHighs(self, fd) -> None:
        """Collect storage info from all HighVariables."""
        pass

    def gatherOpen(self, fd) -> None:
        """Add open ranges for uncovered bytes."""
        pass

    def sortAlias(self) -> None:
        """Sort ranges and resolve aliasing."""
        self._range.sort(key=lambda r: r.sstart)

    def getRanges(self) -> List[RangeHint]:
        return self._range

    def initialize(self) -> None:
        self._range.clear()

    def gatherSymbols(self, scope) -> None:
        if scope is None:
            return
        if not hasattr(scope, '_entriesByAddr'):
            return
        for entries in scope._entriesByAddr.values():
            for entry in entries:
                addr = entry.addr
                off = addr.getOffset() if hasattr(addr, 'getOffset') else 0
                tp = entry.symbol.type if hasattr(entry.symbol, 'type') else None
                sz = entry.size
                self.addRange(off, tp, 0, RangeHint.fixed)

    def reconcileDatatypes(self) -> None:
        prev = None
        merged = []
        for rh in self._range:
            if prev is not None and prev.absorb(rh):
                continue
            merged.append(rh)
            prev = rh
        self._range = merged


class ScopeLocal(ScopeInternal):
    """A scope that holds the local variables of a function.

    Extends ScopeInternal with variable map reconstruction:
    reads Varnodes, collects RangeHints, and lays out the stack frame.
    """

    def __init__(self, idval: int = 0, spc=None, fd=None, glb=None) -> None:
        nm = fd.getName() if fd is not None and hasattr(fd, 'getName') else "local"
        super().__init__(idval, nm, glb)
        self._space = spc
        self._fd = fd
        self._stackAddr: Address = Address()
        self._nameRecommend: List[NameRecommend] = []
        self._dynRecommend: List[DynamicRecommend] = []
        self._typeRecommend: List[TypeRecommend] = []
        self._adjustFit: bool = True

    def getSpace(self):
        return self._space

    def getFd(self):
        return self._fd

    def getStackAddr(self) -> Address:
        return self._stackAddr

    def setStackAddr(self, addr: Address) -> None:
        self._stackAddr = addr

    def addNameRecommend(self, addr: Address, useaddr: Address, sz: int, nm: str, symId: int = 0) -> None:
        self._nameRecommend.append(NameRecommend(addr, useaddr, sz, nm, symId))

    def addDynamicRecommend(self, addr: Address, h: int, nm: str, symId: int = 0) -> None:
        self._dynRecommend.append(DynamicRecommend(addr, h, nm, symId))

    def addTypeRecommend(self, addr: Address, dt) -> None:
        self._typeRecommend.append(TypeRecommend(addr, dt))

    def applyNameRecommend(self) -> None:
        """Apply all name recommendations to symbols in this scope."""
        for rec in self._nameRecommend:
            sym = self.queryByAddr(rec.addr, rec.size)
            if sym is not None and hasattr(sym, 'setName'):
                if not sym.getName():
                    sym.setName(rec.name)

    def queryByAddr(self, addr: Address, sz: int):
        """Query for a symbol at the given address."""
        return None

    def restructureVarnode(self, fd) -> None:
        """Restructure local variables based on the current Varnode set."""
        if self._space is None:
            return
        from ghidra.core.address import RangeList
        rl = RangeList()
        ms = MapState(self._space, fd, rl, self._glb)
        ms.gatherVarnodes(fd)
        ms.sortAlias()

    def applyDynamicRecommend(self) -> None:
        """Apply all dynamic name recommendations."""
        pass  # Would use DynamicHash to find matching Varnodes

    def applyTypeRecommend(self) -> None:
        """Apply all type recommendations to matching Varnodes."""
        pass  # Would set data-type on matching input Varnodes

    def collectNameRecs(self) -> None:
        """Collect name recommendations from the function's Varnodes."""
        pass

    def recoverNameRecommendationsForSymbols(self) -> None:
        """Recover name recommendations for existing symbols."""
        pass

    def addRecommendForSymbol(self, sym) -> None:
        """Add a name recommendation based on a Symbol."""
        pass

    def makeNameRecommendationsForSymbols(self) -> None:
        """Make name recommendations for symbols that don't have names."""
        pass

    def addMapInternal(self, vn, tp, addr, usepoint, nm: str = "") -> None:
        """Add a mapping of a Varnode to a local variable."""
        pass

    def addDynamicMapInternal(self, vn, tp, addr, usepoint, nm: str = "", hashval: int = 0) -> None:
        """Add a dynamic mapping for a Varnode."""
        pass

    def fakeInputSymbols(self) -> None:
        """Create fake input symbols for unmapped input Varnodes."""
        pass

    def adjustFit(self, entry) -> bool:
        """Adjust fit of a SymbolEntry to match Varnode boundaries."""
        return True

    def resetLocalWindow(self) -> None:
        """Reset the local variable analysis window."""
        self._nameRecommend.clear()
        self._dynRecommend.clear()
        self._typeRecommend.clear()

    def markNotMapped(self, spc, first: int, sz: int, param: bool) -> None:
        """Mark an address range as not mapped."""
        pass

    def queryProperties(self, addr, size: int, usepoint, flags_ref) -> None:
        """Query boolean properties of the given address range."""
        pass

    def restructureHigh(self, fd) -> None:
        """Restructure variables using HighVariable information."""
        if self._space is None:
            return
        from ghidra.core.address import RangeList
        rl = RangeList()
        ms = MapState(self._space, fd, rl, self._glb)
        ms.gatherHighs(fd)
        ms.sortAlias()

    def negotiateTypeLock(self, entry) -> bool:
        """Negotiate type lock between a SymbolEntry and its Varnode."""
        if entry is None:
            return False
        sym = entry.symbol if hasattr(entry, 'symbol') else None
        if sym is None:
            return False
        return hasattr(sym, 'isTypeLocked') and sym.isTypeLocked()

    def isUnmappedUnlocked(self, addr: Address, sz: int) -> bool:
        """Check if an address range is unmapped and unlocked."""
        key = (addr.getSpaceIndex() if hasattr(addr, 'getSpaceIndex') else 0,
               addr.getOffset() if hasattr(addr, 'getOffset') else 0)
        if key in self._entriesByAddr:
            return False
        return True

    def encode(self, encoder) -> None:
        """Encode this scope to a stream."""
        pass

    def decode(self, decoder) -> None:
        """Decode this scope from a stream."""
        pass
