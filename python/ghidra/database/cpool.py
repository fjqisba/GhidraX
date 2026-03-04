"""
Corresponds to: cpool.hh / cpool.cc

Definitions to support a constant pool for deferred compilation languages (e.g. Java byte-code).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Tuple

from ghidra.types.datatype import Datatype


class CPoolRecord:
    """A description of a byte-code object referenced by a constant."""

    # Tag types
    primitive = 0
    string_literal = 1
    class_reference = 2
    pointer_method = 3
    pointer_field = 4
    array_length = 5
    instance_of = 6
    check_cast = 7

    # Flags
    is_constructor = 0x1
    is_destructor = 0x2

    def __init__(self) -> None:
        self.tag: int = 0
        self.flags: int = 0
        self.token: str = ""
        self.value: int = 0
        self.type: Optional[Datatype] = None
        self.byteData: Optional[bytes] = None

    def getTag(self) -> int:
        return self.tag

    def getToken(self) -> str:
        return self.token

    def getByteData(self) -> Optional[bytes]:
        return self.byteData

    def getByteDataLength(self) -> int:
        return len(self.byteData) if self.byteData else 0

    def getType(self) -> Optional[Datatype]:
        return self.type

    def getValue(self) -> int:
        return self.value

    def isConstructor(self) -> bool:
        return (self.flags & CPoolRecord.is_constructor) != 0

    def isDestructor(self) -> bool:
        return (self.flags & CPoolRecord.is_destructor) != 0


class ConstantPool(ABC):
    """An interface to the pool of constant objects for byte-code languages."""

    @abstractmethod
    def getRecord(self, refs: List[int]) -> Optional[CPoolRecord]: ...

    @abstractmethod
    def empty(self) -> bool: ...

    @abstractmethod
    def clear(self) -> None: ...

    def putRecord(self, refs: List[int], tag: int, tok: str, ct: Optional[Datatype]) -> None:
        rec = self._createRecord(refs)
        if rec is not None:
            rec.tag = tag
            rec.token = tok
            rec.type = ct

    @abstractmethod
    def _createRecord(self, refs: List[int]) -> Optional[CPoolRecord]: ...


class ConstantPoolInternal(ConstantPool):
    """In-memory ConstantPool implementation."""

    def __init__(self) -> None:
        self._pool: Dict[Tuple[int, ...], CPoolRecord] = {}

    def _createRecord(self, refs: List[int]) -> Optional[CPoolRecord]:
        key = tuple(refs)
        if key in self._pool:
            return self._pool[key]
        rec = CPoolRecord()
        self._pool[key] = rec
        return rec

    def getRecord(self, refs: List[int]) -> Optional[CPoolRecord]:
        return self._pool.get(tuple(refs))

    def empty(self) -> bool:
        return len(self._pool) == 0

    def clear(self) -> None:
        self._pool.clear()
