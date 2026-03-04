"""
Corresponds to: globalcontext.hh / globalcontext.cc

Map from addresses to context settings. Context is used to affect
disassembly depending on processor state (e.g. ARM/Thumb mode).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Tuple

from ghidra.core.address import Address, Range, RangeList
from ghidra.core.space import AddrSpace
from ghidra.core.marshal import Decoder, Encoder


class ContextBitRange:
    """Description of a context variable as a range of bits within the context blob.

    A context variable is a contiguous range of bits that can be set or read
    from a context blob (an array of bytes).
    """

    def __init__(self, sbit: int = 0, ebit: int = 0) -> None:
        self.word: int = sbit // 32
        self.startbit: int = sbit % 32
        self.endbit: int = ebit % 32
        self.shift: int = 31 - self.endbit
        self.mask: int = 0
        if sbit // 32 == ebit // 32:
            self.mask = (0xFFFFFFFF >> (self.startbit + 31 - self.endbit)) << self.shift
        else:
            self.mask = 0xFFFFFFFF >> self.startbit

    def setValue(self, vec: List[int], val: int) -> None:
        """Set the value of this variable in a context blob."""
        while len(vec) <= self.word:
            vec.append(0)
        vec[self.word] = (vec[self.word] & ~self.mask) | ((val << self.shift) & self.mask)

    def getValue(self, vec: List[int]) -> int:
        """Get the value of this variable from a context blob."""
        if self.word >= len(vec):
            return 0
        return (vec[self.word] & self.mask) >> self.shift


class ContextDatabase(ABC):
    """Abstract interface for the context database.

    A ContextDatabase stores context variable settings associated with
    address ranges. Different implementations may store the data in
    different ways (e.g. in memory, or via Ghidra's database).
    """

    @abstractmethod
    def getVariable(self, name: str) -> Optional[ContextBitRange]:
        """Get the bit range for a named context variable."""
        ...

    @abstractmethod
    def setVariable(self, name: str, addr: Address, val: int) -> None:
        """Set a context variable at a specific address."""
        ...

    @abstractmethod
    def setVariableRegion(self, name: str, addr1: Address, addr2: Address, val: int) -> None:
        """Set a context variable over a range of addresses."""
        ...

    @abstractmethod
    def getContext(self, addr: Address) -> List[int]:
        """Retrieve the context blob for a given address."""
        ...

    @abstractmethod
    def registerVariable(self, name: str, sbit: int, ebit: int) -> None:
        """Register a new context variable occupying the given bit range."""
        ...


class ContextInternal(ContextDatabase):
    """A simple in-memory implementation of ContextDatabase.

    Stores context as a default blob plus address-specific overrides.
    """

    def __init__(self) -> None:
        self._variables: Dict[str, ContextBitRange] = {}
        self._contextSize: int = 0  # Number of 32-bit words in context
        self._defaultContext: List[int] = []
        # Mapping from (space_index, offset) -> context blob override
        self._contextMap: Dict[Tuple[int, int], List[int]] = {}

    def registerVariable(self, name: str, sbit: int, ebit: int) -> None:
        cbr = ContextBitRange(sbit, ebit)
        self._variables[name] = cbr
        needed = cbr.word + 1
        if needed > self._contextSize:
            self._contextSize = needed
            while len(self._defaultContext) < self._contextSize:
                self._defaultContext.append(0)

    def getVariable(self, name: str) -> Optional[ContextBitRange]:
        return self._variables.get(name)

    def setVariable(self, name: str, addr: Address, val: int) -> None:
        cbr = self._variables.get(name)
        if cbr is None:
            return
        key = (addr.getSpace().getIndex(), addr.getOffset())
        if key not in self._contextMap:
            self._contextMap[key] = list(self._defaultContext)
        cbr.setValue(self._contextMap[key], val)

    def setVariableRegion(self, name: str, addr1: Address, addr2: Address, val: int) -> None:
        # Simplified: just set at the start address
        self.setVariable(name, addr1, val)

    def getTrackedSet(self, addr: Address):
        """Get tracked register set at the given address. Returns empty list."""
        return []

    def getContext(self, addr: Address) -> List[int]:
        key = (addr.getSpace().getIndex(), addr.getOffset())
        return self._contextMap.get(key, list(self._defaultContext))

    def setVariableDefault(self, name: str, val: int) -> None:
        """Set a default value for a context variable."""
        cbr = self._variables.get(name)
        if cbr is None:
            return
        while len(self._defaultContext) <= cbr.word:
            self._defaultContext.append(0)
        cbr.setValue(self._defaultContext, val)

    def getDefaultValue(self, name: str) -> int:
        """Get the default value for a context variable."""
        cbr = self._variables.get(name)
        if cbr is None:
            return 0
        return cbr.getValue(self._defaultContext)
