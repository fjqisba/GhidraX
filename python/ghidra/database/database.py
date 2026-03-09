"""
Corresponds to: database.hh / database.cc

Symbol and Scope objects for the decompiler.
Core classes: SymbolEntry, Symbol, FunctionSymbol, Scope, ScopeInternal, Database.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, List, Dict, Iterator

from ghidra.core.address import Address, RangeList
from ghidra.core.error import LowlevelError, RecovError
from ghidra.ir.varnode import Varnode

if TYPE_CHECKING:
    from ghidra.types.datatype import Datatype, TypeFactory
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder


# =========================================================================
# SymbolEntry
# =========================================================================

class SymbolEntry:
    """A storage location for a particular Symbol.

    Where a Symbol is stored, as a byte address and a size.
    """

    def __init__(self, symbol: Symbol, addr: Optional[Address] = None,
                 size: int = 0, offset: int = 0,
                 extraflags: int = 0, hash_: int = 0) -> None:
        self.symbol: Symbol = symbol
        self.extraflags: int = extraflags
        self.addr: Address = addr if addr is not None else Address()
        self.hash: int = hash_
        self.offset: int = offset
        self.size: int = size
        self.uselimit: RangeList = RangeList()

    def isPiece(self) -> bool:
        return (self.extraflags & (Varnode.precislo | Varnode.precishi)) != 0

    def isDynamic(self) -> bool:
        return self.addr.isInvalid()

    def isInvalid(self) -> bool:
        return self.addr.isInvalid() and self.hash == 0

    def getAllFlags(self) -> int:
        return self.extraflags | self.symbol.getFlags()

    def getOffset(self) -> int:
        return self.offset

    def getFirst(self) -> int:
        return self.addr.getOffset()

    def getLast(self) -> int:
        return self.addr.getOffset() + self.size - 1

    def getSymbol(self) -> Symbol:
        return self.symbol

    def getAddr(self) -> Address:
        return self.addr

    def getHash(self) -> int:
        return self.hash

    def getSize(self) -> int:
        return self.size

    def inUse(self, usepoint: Address) -> bool:
        if self.uselimit.empty():
            return True
        return self.uselimit.inRange(usepoint, 1)

    def getUseLimit(self) -> RangeList:
        return self.uselimit

    def setUseLimit(self, uselim: RangeList) -> None:
        self.uselimit = uselim

    def isAddrTied(self) -> bool:
        return (self.symbol.getFlags() & Varnode.addrtied) != 0

    def getFirstUseAddress(self) -> Address:
        first = self.uselimit.getFirstRange()
        if first is not None:
            return first.getFirstAddr()
        return Address()

    def getSizedType(self, addr: Address, sz: int) -> Optional[Datatype]:
        """Get the data-type associated with (a piece of) this."""
        tp = self.symbol.getType()
        if tp is None:
            return None
        if sz == tp.getSize() and self.offset == 0:
            return tp
        return None  # Simplified - full impl would do sub-type lookup

    def __repr__(self) -> str:
        sname = self.symbol.getName() if self.symbol else "?"
        return f"SymbolEntry({sname} @ {self.addr}, size={self.size})"


# =========================================================================
# Symbol
# =========================================================================

class Symbol:
    """The base class for a symbol in a symbol table or scope.

    At its most basic, a Symbol is a name and a data-type.
    """

    # Display flags
    force_hex = 1
    force_dec = 2
    force_oct = 3
    force_bin = 4
    force_char = 5
    size_typelock = 8
    isolate = 16
    merge_problems = 32
    is_this_ptr = 64

    # Categories
    no_category = -1
    function_parameter = 0
    equate = 1
    union_facet = 2
    fake_input = 3

    ID_BASE: int = 0x4000000000000000

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 ct: Optional[Datatype] = None) -> None:
        self.scope: Optional[Scope] = scope
        self.name: str = name
        self.displayName: str = name
        self.type: Optional[Datatype] = ct
        self.nameDedup: int = 0
        self.flags: int = 0
        self.dispflags: int = 0
        self.category: int = Symbol.no_category
        self.catindex: int = 0
        self.symbolId: int = 0
        self.mapentry: List[SymbolEntry] = []
        self.wholeCount: int = 0

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName if self.displayName else self.name

    def getType(self) -> Optional[Datatype]:
        return self.type

    def getId(self) -> int:
        return self.symbolId

    def getFlags(self) -> int:
        return self.flags

    def getDisplayFormat(self) -> int:
        return self.dispflags & 7

    def setDisplayFormat(self, val: int) -> None:
        self.dispflags = (self.dispflags & 0xFFFFFFF8) | val

    def getCategory(self) -> int:
        return self.category

    def getCategoryIndex(self) -> int:
        return self.catindex

    def isTypeLocked(self) -> bool:
        return (self.flags & Varnode.typelock) != 0

    def isNameLocked(self) -> bool:
        return (self.flags & Varnode.namelock) != 0

    def isSizeTypeLocked(self) -> bool:
        return (self.dispflags & Symbol.size_typelock) != 0

    def isVolatile(self) -> bool:
        return (self.flags & Varnode.volatil) != 0

    def isThisPointer(self) -> bool:
        return (self.dispflags & Symbol.is_this_ptr) != 0

    def isIndirectStorage(self) -> bool:
        return (self.flags & Varnode.indirectstorage) != 0

    def isHiddenReturn(self) -> bool:
        return (self.flags & Varnode.hiddenretparm) != 0

    def isNameUndefined(self) -> bool:
        return len(self.name) == 0 or self.name.startswith("$$undef")

    def isMultiEntry(self) -> bool:
        return self.wholeCount > 1

    def hasMergeProblems(self) -> bool:
        return (self.dispflags & Symbol.merge_problems) != 0

    def isIsolated(self) -> bool:
        return (self.dispflags & Symbol.isolate) != 0

    def setIsolated(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.isolate
        else:
            self.dispflags &= ~Symbol.isolate

    def getScope(self) -> Optional[Scope]:
        return self.scope

    def numEntries(self) -> int:
        return len(self.mapentry)

    def getMapEntry(self, i_or_addr=None) -> Optional[SymbolEntry]:
        if i_or_addr is None:
            return self.mapentry[0] if self.mapentry else None
        if isinstance(i_or_addr, int):
            if 0 <= i_or_addr < len(self.mapentry):
                return self.mapentry[i_or_addr]
            return None
        # Address lookup
        for entry in self.mapentry:
            if not entry.isDynamic():
                if entry.addr.getSpace() is i_or_addr.getSpace():
                    if entry.getFirst() <= i_or_addr.getOffset() <= entry.getLast():
                        return entry
        return None

    def getFirstWholeMap(self) -> Optional[SymbolEntry]:
        for entry in self.mapentry:
            if entry.offset == 0 and entry.size == (self.type.getSize() if self.type else 0):
                return entry
        return self.mapentry[0] if self.mapentry else None

    def getBytesConsumed(self) -> int:
        if self.type is not None:
            return self.type.getSize()
        return 0

    def setName(self, nm: str) -> None:
        self.name = nm

    def setDisplayName(self, nm: str) -> None:
        self.displayName = nm

    def setType(self, ct) -> None:
        self.type = ct

    def setFlags(self, fl: int) -> None:
        self.flags |= fl

    def clearFlags(self, fl: int) -> None:
        self.flags &= ~fl

    def setCategory(self, cat: int, ind: int) -> None:
        self.category = cat
        self.catindex = ind

    def setTypeLock(self, val: bool) -> None:
        if val:
            self.flags |= Varnode.typelock
        else:
            self.flags &= ~Varnode.typelock

    def setNameLock(self, val: bool) -> None:
        if val:
            self.flags |= Varnode.namelock
        else:
            self.flags &= ~Varnode.namelock

    def setVolatile(self, val: bool) -> None:
        if val:
            self.flags |= Varnode.volatil
        else:
            self.flags &= ~Varnode.volatil

    def setThisPointer(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.is_this_ptr
        else:
            self.dispflags &= ~Symbol.is_this_ptr

    def setMergeProblems(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.merge_problems
        else:
            self.dispflags &= ~Symbol.merge_problems

    def checkSizeTypeLock(self) -> bool:
        return self.isSizeTypeLocked()

    def setSizeTypeLock(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.size_typelock
        else:
            self.dispflags &= ~Symbol.size_typelock

    def setScope(self, sc) -> None:
        self.scope = sc

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    def __repr__(self) -> str:
        tname = self.type.getName() if self.type else "?"
        return f"Symbol({self.name!r}, type={tname}, id={self.symbolId:#x})"


# =========================================================================
# FunctionSymbol
# =========================================================================

class FunctionSymbol(Symbol):
    """A Symbol representing an executable function."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 size: int = 1) -> None:
        super().__init__(scope, name)
        self.fd = None  # Funcdata (set later)
        self.consumeSize: int = size

    def getFunction(self):
        return self.fd

    def setFunction(self, fd) -> None:
        self.fd = fd

    def getBytesConsumed(self) -> int:
        return self.consumeSize

    def setBytesConsumed(self, sz: int) -> None:
        self.consumeSize = sz


# =========================================================================
# EquateSymbol
# =========================================================================

class EquateSymbol(Symbol):
    """A Symbol that holds equate information for a constant."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 format_: int = 0, val: int = 0) -> None:
        super().__init__(scope, name)
        self.value: int = val
        self.category = Symbol.equate
        if format_ > 0:
            self.setDisplayFormat(format_)

    def getValue(self) -> int:
        return self.value

    def setValue(self, val: int) -> None:
        self.value = val


# =========================================================================
# LabSymbol
# =========================================================================

class LabSymbol(Symbol):
    """A Symbol that labels code internal to a function."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "") -> None:
        super().__init__(scope, name)

    def getType(self) -> int:
        return 4  # label type


# =========================================================================
# ExternRefSymbol
# =========================================================================

class ExternRefSymbol(Symbol):
    """A function Symbol referring to an external location."""

    def __init__(self, scope: Optional[Scope] = None,
                 ref: Optional[Address] = None, name: str = "") -> None:
        super().__init__(scope, name)
        self.refaddr: Address = ref if ref is not None else Address()

    def getRefAddr(self) -> Address:
        return self.refaddr

    def setRefAddr(self, addr: Address) -> None:
        self.refaddr = addr


# =========================================================================
# DuplicateFunctionError
# =========================================================================

class DuplicateFunctionError(RecovError):
    """Exception thrown when a function is added more than once."""

    def __init__(self, addr: Address, nm: str) -> None:
        super().__init__("Duplicate Function")
        self.address: Address = addr
        self.functionName: str = nm

    def getAddress(self) -> Address:
        return self.address

    def getFunctionName(self) -> str:
        return self.functionName


# =========================================================================
# Scope (abstract base)
# =========================================================================

class Scope(ABC):
    """A collection of Symbol objects within a single scope.

    Supports search by name, by storage address, insertion/removal
    of Symbols, and management of child scopes.
    """

    def __init__(self, id_: int = 0, name: str = "",
                 glb=None, fd=None) -> None:
        self.uniqueId: int = id_
        self.name: str = name
        self.displayName: str = name
        self.glb = glb  # Architecture
        self.fd = fd    # Funcdata
        self.parent: Optional[Scope] = None
        self.owner: Optional[Scope] = None
        self.children: Dict[int, Scope] = {}
        self.rangetree: RangeList = RangeList()

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName

    def getId(self) -> int:
        return self.uniqueId

    def getParent(self) -> Optional[Scope]:
        return self.parent

    def getFuncdata(self):
        return self.fd

    def getArch(self):
        return self.glb

    def numChildren(self) -> int:
        return len(self.children)

    def getChild(self, id_: int) -> Optional[Scope]:
        return self.children.get(id_)

    def attachScope(self, child: Scope) -> None:
        child.parent = self
        self.children[child.uniqueId] = child

    def detachScope(self, child_id: int) -> None:
        child = self.children.pop(child_id, None)
        if child is not None:
            child.parent = None

    # --- Abstract methods ---

    @abstractmethod
    def addSymbol(self, sym: Symbol) -> None:
        ...

    @abstractmethod
    def removeSymbol(self, sym: Symbol) -> None:
        ...

    @abstractmethod
    def findByName(self, name: str) -> Optional[Symbol]:
        ...

    @abstractmethod
    def findAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        ...

    @abstractmethod
    def findContainer(self, addr: Address, size: int,
                      usepoint: Address) -> Optional[SymbolEntry]:
        ...

    @abstractmethod
    def addMapEntry(self, sym: Symbol, entry: SymbolEntry) -> SymbolEntry:
        ...

    def isGlobal(self) -> bool:
        return self.parent is None or self.fd is None

    def setOwner(self, owner) -> None:
        self.owner = owner

    def getOwner(self):
        return self.owner

    def getRangeTree(self) -> RangeList:
        return self.rangetree

    # --- Query methods (virtual in C++) ---

    def queryByName(self, name: str) -> Optional[Symbol]:
        return self.findByName(name)

    def queryByAddr(self, addr: Address, sz: int) -> Optional[Symbol]:
        entry = self.findAddr(addr, Address())
        return entry.getSymbol() if entry else None

    def queryContainer(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        return self.findContainer(addr, size, usepoint)

    def queryFunction(self, addr: Address) -> Optional[FunctionSymbol]:
        return None

    def queryExternalRefFunction(self, addr: Address) -> Optional[ExternRefSymbol]:
        return None

    def queryCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        return None

    def queryProperties(self, addr: Address, size: int, usepoint, flags_ref) -> None:
        pass

    # --- Symbol creation methods ---

    def addFunction(self, addr: Address, name: str, size: int = 1) -> Optional[FunctionSymbol]:
        return None

    def addEquateSymbol(self, name: str, format_: int, val: int) -> Optional[EquateSymbol]:
        return None

    def addCodeLabel(self, addr: Address, name: str) -> Optional[LabSymbol]:
        return None

    def addDynamicSymbol(self, name: str, ct, addr: Address, hash_: int) -> Optional[Symbol]:
        return None

    def addExternalRef(self, addr: Address, refaddr: Address, name: str) -> Optional[ExternRefSymbol]:
        return None

    def addUnionFacetSymbol(self, name: str, ct, fieldNum: int) -> Optional[Symbol]:
        return None

    def addMapPoint(self, sym: Symbol, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        return None

    def addMapSym(self, decoder) -> Optional[SymbolEntry]:
        return None

    # --- Symbol modification ---

    def renameSymbol(self, sym: Symbol, newname: str) -> None:
        sym.setName(newname)

    def retypeSymbol(self, sym: Symbol, ct) -> None:
        sym.setType(ct)

    def setAttribute(self, sym: Symbol, attr: int) -> None:
        sym.setFlags(attr)

    def clearAttribute(self, sym: Symbol, attr: int) -> None:
        sym.clearFlags(attr)

    def setCategory(self, sym: Symbol, cat: int, ind: int) -> None:
        sym.setCategory(cat, ind)

    def setDisplayFormat(self, sym: Symbol, val: int) -> None:
        sym.setDisplayFormat(val)

    def setThisPointer(self, sym: Symbol, val: bool) -> None:
        sym.setThisPointer(val)

    def overrideSizeLockType(self, sym: Symbol, ct) -> None:
        pass

    def resetSizeLockType(self, sym: Symbol) -> None:
        pass

    def removeSymbolMappings(self, sym: Symbol) -> None:
        sym.mapentry.clear()

    # --- Scope query/search ---

    def findOverlap(self, addr: Address, size: int) -> Optional[SymbolEntry]:
        return None

    def findClosestFit(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        return self.findContainer(addr, size, usepoint)

    def findFunction(self, addr: Address) -> Optional[FunctionSymbol]:
        return None

    def findExternalRef(self, addr: Address) -> Optional[ExternRefSymbol]:
        return None

    def findCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        return None

    def findDistinguishingScope(self, sym: Symbol) -> Optional['Scope']:
        return self

    # --- Scope hierarchy ---

    def isSubScope(self, other: 'Scope') -> bool:
        cur = self
        while cur is not None:
            if cur is other:
                return True
            cur = cur.parent
        return False

    def discoverScope(self, addr: Address, sz: int, usepoint: Address) -> Optional['Scope']:
        return self

    def resolveScope(self, addr: Address) -> Optional['Scope']:
        return self

    def getFullName(self) -> str:
        parts = []
        cur = self
        while cur is not None:
            parts.append(cur.name)
            cur = cur.parent
        parts.reverse()
        return "::".join(parts)

    def getScopePath(self) -> List[str]:
        parts = []
        cur = self
        while cur is not None:
            parts.append(cur.name)
            cur = cur.parent
        parts.reverse()
        return parts

    # --- Iterators ---

    def begin(self):
        return iter([])

    def end(self):
        return None

    def beginDynamic(self):
        return iter([])

    def endDynamic(self):
        return None

    def childrenBegin(self):
        return iter(self.children.values())

    def childrenEnd(self):
        return None

    # --- Scope-level operations ---

    def clear(self) -> None:
        pass

    def clearUnlocked(self) -> None:
        pass

    def clearUnlockedCategory(self, cat: int) -> None:
        pass

    def clearCategory(self, cat: int) -> None:
        pass

    def adjustCaches(self) -> None:
        pass

    def getCategorySize(self, cat: int) -> int:
        return 0

    def getCategorySymbol(self, cat: int, index: int) -> Optional[Symbol]:
        return None

    # --- Encode / Decode ---

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    def encodeRecursive(self, encoder) -> None:
        self.encode(encoder)
        for child in self.children.values():
            child.encodeRecursive(encoder)

    def decodeWrappingAttributes(self, decoder) -> None:
        pass

    # --- Misc ---

    def inScope(self, addr: Address, size: int, usepoint: Address) -> bool:
        return self.findContainer(addr, size, usepoint) is not None

    def inRange(self, addr: Address, size: int) -> bool:
        return False

    def isNameUsed(self, name: str, scope: Optional['Scope'] = None) -> bool:
        return self.findByName(name) is not None

    def isReadOnly(self) -> bool:
        return False

    def makeNameUnique(self, name: str) -> str:
        if not self.isNameUsed(name):
            return name
        i = 1
        while True:
            candidate = f"{name}_{i}"
            if not self.isNameUsed(candidate):
                return candidate
            i += 1

    def buildDefaultName(self, sym: Symbol, base: int, addr: Address) -> str:
        return f"DAT_{addr.getOffset():08x}"

    def buildUndefinedName(self) -> str:
        return "$$undef"

    def buildVariableName(self, addr: Address, pc: Address, ct, index: int, flags: int) -> str:
        return f"local_{addr.getOffset():x}"

    def printBounds(self, s) -> None:
        s.write(f"Scope {self.name}")

    def printEntries(self, s) -> None:
        pass

    def turnOnDebug(self) -> None:
        pass

    def turnOffDebug(self) -> None:
        pass

    def __repr__(self) -> str:
        return f"Scope({self.name!r}, id={self.uniqueId:#x})"


# =========================================================================
# ScopeInternal - in-memory Scope implementation
# =========================================================================

class ScopeInternal(Scope):
    """An in-memory implementation of a Scope.

    Stores symbols in dictionaries for quick lookup by name and address.
    """

    def __init__(self, id_: int = 0, name: str = "",
                 glb=None, fd=None) -> None:
        super().__init__(id_, name, glb, fd)
        self._symbolsByName: Dict[str, List[Symbol]] = {}
        self._symbolsById: Dict[int, Symbol] = {}
        self._entriesByAddr: Dict[tuple, List[SymbolEntry]] = {}  # (space_idx, offset) -> entries
        self._nextSymId: int = Symbol.ID_BASE
        self._categoryMap: Dict[int, List[Symbol]] = {}

    def _assignSymbolId(self, sym: Symbol) -> None:
        if sym.symbolId == 0:
            sym.symbolId = self._nextSymId
            self._nextSymId += 1

    def addSymbol(self, sym: Symbol) -> None:
        self._assignSymbolId(sym)
        sym.scope = self
        self._symbolsById[sym.symbolId] = sym
        if sym.name not in self._symbolsByName:
            self._symbolsByName[sym.name] = []
        self._symbolsByName[sym.name].append(sym)
        if sym.category != Symbol.no_category:
            if sym.category not in self._categoryMap:
                self._categoryMap[sym.category] = []
            lst = self._categoryMap[sym.category]
            sym.catindex = len(lst)
            lst.append(sym)

    def removeSymbol(self, sym: Symbol) -> None:
        self._symbolsById.pop(sym.symbolId, None)
        lst = self._symbolsByName.get(sym.name)
        if lst:
            try:
                lst.remove(sym)
            except ValueError:
                pass
        # Remove entries
        for entry in sym.mapentry:
            if not entry.isDynamic():
                key = (entry.addr.getSpace().getIndex(), entry.addr.getOffset())
                elst = self._entriesByAddr.get(key)
                if elst:
                    try:
                        elst.remove(entry)
                    except ValueError:
                        pass
        sym.mapentry.clear()

    def findByName(self, name: str) -> Optional[Symbol]:
        lst = self._symbolsByName.get(name)
        if lst:
            return lst[0]
        return None

    def findById(self, id_: int) -> Optional[Symbol]:
        return self._symbolsById.get(id_)

    def findAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        key = (addr.getSpace().getIndex(), addr.getOffset())
        entries = self._entriesByAddr.get(key)
        if entries is None:
            return None
        for entry in entries:
            if entry.inUse(usepoint):
                return entry
        return None

    def findContainer(self, addr: Address, size: int,
                      usepoint: Address) -> Optional[SymbolEntry]:
        # Simplified: linear scan
        for entries_list in self._entriesByAddr.values():
            for entry in entries_list:
                if entry.addr.getSpace() is not addr.getSpace():
                    continue
                if entry.getFirst() <= addr.getOffset() and \
                   addr.getOffset() + size - 1 <= entry.getLast():
                    if entry.inUse(usepoint):
                        return entry
        return None

    def addMapEntry(self, sym: Symbol, entry: SymbolEntry) -> SymbolEntry:
        entry.symbol = sym
        sym.mapentry.append(entry)
        if entry.offset == 0 and sym.type is not None and entry.size == sym.type.getSize():
            sym.wholeCount += 1
        if not entry.isDynamic():
            key = (entry.addr.getSpace().getIndex(), entry.addr.getOffset())
            if key not in self._entriesByAddr:
                self._entriesByAddr[key] = []
            self._entriesByAddr[key].append(entry)
        return entry

    def addSymbolInternal(self, sym: Symbol, addr: Address, size: int) -> SymbolEntry:
        """Convenience: add a symbol and its primary map entry."""
        self.addSymbol(sym)
        entry = SymbolEntry(sym, addr, size)
        return self.addMapEntry(sym, entry)

    def getCategorySize(self, cat: int) -> int:
        lst = self._categoryMap.get(cat)
        return len(lst) if lst else 0

    def getCategorySymbol(self, cat: int, index: int) -> Optional[Symbol]:
        lst = self._categoryMap.get(cat)
        if lst and 0 <= index < len(lst):
            return lst[index]
        return None

    def getAllSymbols(self) -> Iterator[Symbol]:
        return iter(self._symbolsById.values())

    def getSymbolList(self) -> List[Symbol]:
        return list(self._symbolsById.values())

    def findFunction(self, addr: Address) -> Optional[FunctionSymbol]:
        """Find a FunctionSymbol by entry address."""
        for sym in self._symbolsById.values():
            if isinstance(sym, FunctionSymbol):
                for entry in sym.mapentry:
                    if entry.addr == addr:
                        return sym
        return None

    def addFunction(self, addr: Address, name: str, size: int = 1) -> FunctionSymbol:
        """Create and add a FunctionSymbol."""
        fsym = FunctionSymbol(self, name, size)
        entry = SymbolEntry(fsym, addr, size)
        self.addSymbol(fsym)
        self.addMapEntry(fsym, entry)
        return fsym

    def queryByAddr(self, addr: Address, sz: int) -> Optional[Symbol]:
        """Find a symbol that covers the given address range."""
        entry = self.findContainer(addr, sz, Address())
        if entry is not None:
            return entry.getSymbol()
        return None

    def queryProperties(self, addr: Address, size: int, usepoint, flags_ref) -> None:
        """Query boolean properties of the given address range."""
        entry = self.findAddr(addr, usepoint if usepoint else Address())
        if entry is not None:
            if isinstance(flags_ref, list) and flags_ref:
                flags_ref[0] = entry.getAllFlags()
            elif isinstance(flags_ref, int):
                pass  # Can't mutate int

    def renameSymbol(self, sym: Symbol, newname: str) -> None:
        """Rename a symbol."""
        oldname = sym.name
        lst = self._symbolsByName.get(oldname)
        if lst:
            try:
                lst.remove(sym)
            except ValueError:
                pass
        sym.setName(newname)
        if newname not in self._symbolsByName:
            self._symbolsByName[newname] = []
        self._symbolsByName[newname].append(sym)

    def retypeSymbol(self, sym: Symbol, ct) -> None:
        """Change the data-type of a symbol."""
        sym.setType(ct)

    def setAttribute(self, sym: Symbol, attr: int) -> None:
        sym.setFlags(attr)

    def clearAttribute(self, sym: Symbol, attr: int) -> None:
        sym.clearFlags(attr)

    def setCategory(self, sym: Symbol, cat: int, ind: int) -> None:
        sym.setCategory(cat, ind)

    def findOverlap(self, addr: Address, size: int) -> Optional[SymbolEntry]:
        """Find any symbol entry that overlaps the given range."""
        for entries_list in self._entriesByAddr.values():
            for entry in entries_list:
                if entry.addr.getSpace() is not addr.getSpace():
                    continue
                e_start = entry.getFirst()
                e_end = entry.getLast()
                a_start = addr.getOffset()
                a_end = a_start + size - 1
                if e_start <= a_end and a_start <= e_end:
                    return entry
        return None

    def findClosestFit(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        """Find the closest fitting symbol entry for the given range."""
        return self.findContainer(addr, size, usepoint)

    def setProperties(self, addr: Address, size: int, flags: int) -> None:
        pass

    def adjustCaches(self) -> None:
        pass

    def clearUnlocked(self) -> None:
        """Remove all symbols that aren't type-locked or name-locked."""
        to_remove = [s for s in self._symbolsById.values()
                     if not s.isTypeLocked() and not s.isNameLocked()]
        for sym in to_remove:
            self.removeSymbol(sym)

    def clearUnlockedCategory(self, cat: int) -> None:
        """Remove unlocked symbols in the given category."""
        lst = self._categoryMap.get(cat, [])
        to_remove = [s for s in lst if not s.isTypeLocked() and not s.isNameLocked()]
        for sym in to_remove:
            self.removeSymbol(sym)

    def removeRange(self, spc, first: int, last: int) -> None:
        pass

    def addRange(self, spc, first: int, last: int) -> None:
        pass

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    def getNumSymbols(self) -> int:
        return len(self._symbolsById)

    def getNextSymbolId(self) -> int:
        return self._nextSymId


# =========================================================================
# Database
# =========================================================================

class Database:
    """The main symbol table container managing all Scopes.

    Contains the global scope and manages the full hierarchy of scopes
    (global, function-local, etc.).
    """

    def __init__(self, glb=None) -> None:
        self.glb = glb  # Architecture
        self._globalScope: Optional[ScopeInternal] = None
        self._scopeMap: Dict[int, Scope] = {}
        self._nextScopeId: int = 1

    def getGlobalScope(self) -> Optional[ScopeInternal]:
        return self._globalScope

    def setGlobalScope(self, scope: ScopeInternal) -> None:
        self._globalScope = scope
        self._scopeMap[scope.uniqueId] = scope

    def createGlobalScope(self, name: str = "global") -> ScopeInternal:
        scope = ScopeInternal(self._nextScopeId, name, self.glb)
        self._nextScopeId += 1
        self.setGlobalScope(scope)
        return scope

    def createScope(self, name: str, parent: Scope, fd=None) -> ScopeInternal:
        scope = ScopeInternal(self._nextScopeId, name, self.glb, fd)
        self._nextScopeId += 1
        self._scopeMap[scope.uniqueId] = scope
        parent.attachScope(scope)
        return scope

    def findScope(self, id_: int) -> Optional[Scope]:
        return self._scopeMap.get(id_)

    def resolveScope(self, addr: Address) -> Optional[Scope]:
        """Find the most specific scope owning the given address."""
        # Simplified: just return global scope
        return self._globalScope

    def removeScope(self, scope: Scope) -> None:
        """Remove a scope and all its children."""
        for child_id in list(scope.children.keys()):
            child = scope.children[child_id]
            self.removeScope(child)
        self._scopeMap.pop(scope.uniqueId, None)
        if scope.parent is not None:
            scope.parent.detachScope(scope.uniqueId)

    def renameScope(self, scope: Scope, newname: str) -> None:
        scope.name = newname
        scope.displayName = newname

    def mapScope(self, scope: Scope, spc, first: int, last: int) -> None:
        """Associate an address range with a scope."""
        pass

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    def clear(self) -> None:
        self._scopeMap.clear()
        self._globalScope = None

    def getNumScopes(self) -> int:
        return len(self._scopeMap)

    def getArch(self):
        return self.glb

    def getScopeMap(self) -> dict:
        return self._scopeMap

    def getNextScopeId(self) -> int:
        return self._nextScopeId

    def isReadOnly(self) -> bool:
        return getattr(self, '_readonly', False)

    def setReadOnly(self, val: bool) -> None:
        self._readonly = val

    def deleteSubScopes(self, scope) -> None:
        pass

    def findByName(self, nm: str):
        for s in self._scopeMap.values():
            if hasattr(s, 'getName') and s.getName() == nm:
                return s
        return None

    def queryScopesBy(self, addr) -> list:
        result = []
        for s in self._scopeMap.values():
            result.append(s)
        return result

    def getScopeById(self, uid: int):
        return self._scopeMap.get(uid, None)

    def __repr__(self) -> str:
        n = len(self._scopeMap)
        return f"Database({n} scopes)"
