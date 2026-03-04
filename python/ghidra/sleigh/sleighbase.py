"""
Corresponds to: sleighbase.hh / sleighbase.cc

Base class for applications that process SLEIGH format specifications.
"""

from __future__ import annotations
from typing import Optional, List, Dict
from ghidra.core.translate import Translate
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.space import AddrSpace
from ghidra.core.marshal import Decoder, Encoder


class SourceFileIndexer:
    """Records source file information for SLEIGH constructors."""

    def __init__(self) -> None:
        self._leastUnusedIndex: int = 0
        self._indexToFile: Dict[int, str] = {}
        self._fileToIndex: Dict[str, int] = {}

    def index(self, filename: str) -> int:
        if filename in self._fileToIndex:
            return self._fileToIndex[filename]
        idx = self._leastUnusedIndex
        self._leastUnusedIndex += 1
        self._indexToFile[idx] = filename
        self._fileToIndex[filename] = idx
        return idx

    def getIndex(self, filename: str) -> int:
        return self._fileToIndex.get(filename, -1)

    def getFilename(self, idx: int) -> str:
        return self._indexToFile.get(idx, "")


class SleighBase(Translate):
    """Common core of classes that read or write SLEIGH specification files.

    Extends Translate with SLEIGH-specific symbol table, root decoding
    symbol, and register cross-reference map.
    """

    MAX_UNIQUE_SIZE: int = 128

    def __init__(self) -> None:
        super().__init__()
        self._userop: List[str] = []
        self._varnode_xref: Dict[tuple, str] = {}  # (spc_idx, offset, size) -> name
        self._root = None  # SubtableSymbol
        self._symtab = SymbolTable()
        self._maxdelayslotbytes: int = 0
        self._unique_allocatemask: int = 0
        self._numSections: int = 0
        self._indexer: SourceFileIndexer = SourceFileIndexer()

    def isInitialized(self) -> bool:
        return self._root is not None

    def getRegisterName(self, base: AddrSpace, off: int, size: int) -> str:
        key = (base.getIndex(), off, size)
        return self._varnode_xref.get(key, "")

    def getRegister(self, nm: str) -> VarnodeData:
        sym = self._symtab.findSymbol(nm)
        if sym is not None and hasattr(sym, 'getFixedVarnode'):
            return sym.getFixedVarnode()
        from ghidra.core.error import LowlevelError
        raise LowlevelError(f"No register named: {nm}")

    def getAllRegisters(self) -> Dict[str, VarnodeData]:
        result = {}
        for key, name in self._varnode_xref.items():
            vd = VarnodeData()
            spc = self.getSpaceByIndex(key[0])
            if spc is not None:
                vd.space = spc
                vd.offset = key[1]
                vd.size = key[2]
                result[name] = vd
        return result

    def getUserOpNames(self) -> List[str]:
        return list(self._userop)

    def findSymbol(self, nm_or_id):
        if isinstance(nm_or_id, str):
            return self._symtab.findSymbol(nm_or_id)
        return self._symtab.findSymbolById(nm_or_id)

    def findGlobalSymbol(self, nm: str):
        return self._symtab.findGlobalSymbol(nm)

    def oneInstruction(self, emit, addr):
        raise NotImplementedError("SleighBase.oneInstruction must be overridden")

    def printAssembly(self, emit, addr):
        raise NotImplementedError("SleighBase.printAssembly must be overridden")


class SleighSymbol:
    """Base class for all symbols in the SLEIGH symbol table."""

    # Symbol types
    space_symbol = 0
    token_symbol = 1
    userop_symbol = 2
    value_symbol = 3
    valuemap_symbol = 4
    name_symbol = 5
    varnode_symbol = 6
    varnodelist_symbol = 7
    operand_symbol = 8
    start_symbol = 9
    end_symbol = 10
    next2_symbol = 11
    subtable_symbol = 12
    macro_symbol = 13
    section_symbol = 14
    bitrange_symbol = 15
    context_symbol = 16
    epsilon_symbol = 17
    label_symbol = 18
    dummy_symbol = 19
    flow_dest_symbol = 20
    flow_ref_symbol = 21

    def __init__(self, nm: str = "", tp: int = -1, id_: int = 0) -> None:
        self.name: str = nm
        self.type: int = tp
        self.id: int = id_
        self.scopeid: int = 0

    def getName(self) -> str:
        return self.name

    def getType(self) -> int:
        return self.type

    def getId(self) -> int:
        return self.id

    def __repr__(self) -> str:
        return f"SleighSymbol({self.name!r}, type={self.type}, id={self.id})"


class SubtableSymbol(SleighSymbol):
    """A symbol representing a decoding subtable (constructor table)."""

    def __init__(self, nm: str = "", id_: int = 0) -> None:
        super().__init__(nm, SleighSymbol.subtable_symbol, id_)
        self.constructors: list = []
        self.decisiontree = None

    def getNumConstructors(self) -> int:
        return len(self.constructors)


class VarnodeSymbol(SleighSymbol):
    """A symbol representing a specific Varnode (register)."""

    def __init__(self, nm: str = "", id_: int = 0) -> None:
        super().__init__(nm, SleighSymbol.varnode_symbol, id_)
        self._fix: VarnodeData = VarnodeData()

    def getFixedVarnode(self) -> VarnodeData:
        return self._fix

    def setFixedVarnode(self, spc: AddrSpace, off: int, sz: int) -> None:
        self._fix.space = spc
        self._fix.offset = off
        self._fix.size = sz


class UserOpSymbol(SleighSymbol):
    """A symbol representing a user-defined p-code operation."""

    def __init__(self, nm: str = "", id_: int = 0, index: int = 0) -> None:
        super().__init__(nm, SleighSymbol.userop_symbol, id_)
        self.index: int = index


class SymbolTable:
    """The SLEIGH symbol table containing all defined symbols."""

    def __init__(self) -> None:
        self._symbolList: List[Optional[SleighSymbol]] = []
        self._nameMap: Dict[str, SleighSymbol] = {}
        self._scopeList: list = []  # List of scope boundaries
        self._curScope: int = 0

    def addSymbol(self, sym: SleighSymbol) -> None:
        sym.id = len(self._symbolList)
        self._symbolList.append(sym)
        self._nameMap[sym.name] = sym

    def findSymbol(self, nm: str) -> Optional[SleighSymbol]:
        return self._nameMap.get(nm)

    def findSymbolById(self, id_: int) -> Optional[SleighSymbol]:
        if 0 <= id_ < len(self._symbolList):
            return self._symbolList[id_]
        return None

    def findGlobalSymbol(self, nm: str) -> Optional[SleighSymbol]:
        return self._nameMap.get(nm)

    def getSymbol(self, id_: int) -> Optional[SleighSymbol]:
        return self.findSymbolById(id_)

    def numSymbols(self) -> int:
        return len(self._symbolList)

    def clear(self) -> None:
        self._symbolList.clear()
        self._nameMap.clear()

    def __repr__(self) -> str:
        return f"SymbolTable({len(self._symbolList)} symbols)"
