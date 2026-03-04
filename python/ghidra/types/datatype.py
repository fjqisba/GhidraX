"""
Corresponds to: type.hh / type.cc

Classes for describing and printing data-types.
Core Datatype hierarchy and TypeFactory.
"""

from __future__ import annotations

from abc import abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List, Dict, Tuple

from ghidra.core.error import LowlevelError
from ghidra.core.marshal import (
    AttributeId, ElementId, Encoder, Decoder,
    ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_METATYPE, ATTRIB_ID,
)

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace


# =========================================================================
# Metatype enums
# =========================================================================

class MetaType(IntEnum):
    """The core meta-types supported by the decompiler."""
    TYPE_PARTIALUNION = 0
    TYPE_PARTIALSTRUCT = 1
    TYPE_PARTIALENUM = 2
    TYPE_UNION = 3
    TYPE_STRUCT = 4
    TYPE_ENUM_INT = 5
    TYPE_ENUM_UINT = 6
    TYPE_ARRAY = 7
    TYPE_PTRREL = 8
    TYPE_PTR = 9
    TYPE_FLOAT = 10
    TYPE_CODE = 11
    TYPE_BOOL = 12
    TYPE_UINT = 13
    TYPE_INT = 14
    TYPE_UNKNOWN = 15
    TYPE_SPACEBASE = 16
    TYPE_VOID = 17


# Re-export for C-style access
TYPE_VOID = MetaType.TYPE_VOID
TYPE_SPACEBASE = MetaType.TYPE_SPACEBASE
TYPE_UNKNOWN = MetaType.TYPE_UNKNOWN
TYPE_INT = MetaType.TYPE_INT
TYPE_UINT = MetaType.TYPE_UINT
TYPE_BOOL = MetaType.TYPE_BOOL
TYPE_CODE = MetaType.TYPE_CODE
TYPE_FLOAT = MetaType.TYPE_FLOAT
TYPE_PTR = MetaType.TYPE_PTR
TYPE_PTRREL = MetaType.TYPE_PTRREL
TYPE_ARRAY = MetaType.TYPE_ARRAY
TYPE_ENUM_UINT = MetaType.TYPE_ENUM_UINT
TYPE_ENUM_INT = MetaType.TYPE_ENUM_INT
TYPE_STRUCT = MetaType.TYPE_STRUCT
TYPE_UNION = MetaType.TYPE_UNION
TYPE_PARTIALENUM = MetaType.TYPE_PARTIALENUM
TYPE_PARTIALSTRUCT = MetaType.TYPE_PARTIALSTRUCT
TYPE_PARTIALUNION = MetaType.TYPE_PARTIALUNION


class SubMetaType(IntEnum):
    """Specializations of the core meta-types."""
    SUB_PARTIALUNION = 0
    SUB_UNION = 1
    SUB_STRUCT = 2
    SUB_ARRAY = 3
    SUB_PTR_STRUCT = 4
    SUB_PTRREL = 5
    SUB_PTR = 6
    SUB_PTRREL_UNK = 7
    SUB_FLOAT = 8
    SUB_CODE = 9
    SUB_BOOL = 10
    SUB_UINT_UNICODE = 11
    SUB_INT_UNICODE = 12
    SUB_UINT_ENUM = 13
    SUB_UINT_PARTIALENUM = 14
    SUB_INT_ENUM = 15
    SUB_UINT_PLAIN = 16
    SUB_INT_PLAIN = 17
    SUB_UINT_CHAR = 18
    SUB_INT_CHAR = 19
    SUB_PARTIALSTRUCT = 20
    SUB_UNKNOWN = 21
    SUB_SPACEBASE = 22
    SUB_VOID = 23


class TypeClass(IntEnum):
    """Data-type classes for the purpose of assigning storage."""
    TYPECLASS_GENERAL = 0
    TYPECLASS_FLOAT = 1
    TYPECLASS_PTR = 2
    TYPECLASS_HIDDENRET = 3
    TYPECLASS_VECTOR = 4


# Re-export TypeClass members at module level
TYPECLASS_GENERAL = TypeClass.TYPECLASS_GENERAL
TYPECLASS_FLOAT = TypeClass.TYPECLASS_FLOAT
TYPECLASS_PTR = TypeClass.TYPECLASS_PTR
TYPECLASS_HIDDENRET = TypeClass.TYPECLASS_HIDDENRET
TYPECLASS_VECTOR = TypeClass.TYPECLASS_VECTOR


# Mapping from MetaType to default SubMetaType
_BASE2SUB: Dict[int, SubMetaType] = {
    MetaType.TYPE_VOID: SubMetaType.SUB_VOID,
    MetaType.TYPE_SPACEBASE: SubMetaType.SUB_SPACEBASE,
    MetaType.TYPE_UNKNOWN: SubMetaType.SUB_UNKNOWN,
    MetaType.TYPE_INT: SubMetaType.SUB_INT_PLAIN,
    MetaType.TYPE_UINT: SubMetaType.SUB_UINT_PLAIN,
    MetaType.TYPE_BOOL: SubMetaType.SUB_BOOL,
    MetaType.TYPE_CODE: SubMetaType.SUB_CODE,
    MetaType.TYPE_FLOAT: SubMetaType.SUB_FLOAT,
    MetaType.TYPE_PTR: SubMetaType.SUB_PTR,
    MetaType.TYPE_PTRREL: SubMetaType.SUB_PTRREL,
    MetaType.TYPE_ARRAY: SubMetaType.SUB_ARRAY,
    MetaType.TYPE_STRUCT: SubMetaType.SUB_STRUCT,
    MetaType.TYPE_UNION: SubMetaType.SUB_UNION,
    MetaType.TYPE_ENUM_INT: SubMetaType.SUB_INT_ENUM,
    MetaType.TYPE_ENUM_UINT: SubMetaType.SUB_UINT_ENUM,
    MetaType.TYPE_PARTIALENUM: SubMetaType.SUB_UINT_PARTIALENUM,
    MetaType.TYPE_PARTIALSTRUCT: SubMetaType.SUB_PARTIALSTRUCT,
    MetaType.TYPE_PARTIALUNION: SubMetaType.SUB_PARTIALUNION,
}


def metatype2string(mt: MetaType) -> str:
    _map = {
        TYPE_VOID: "void", TYPE_SPACEBASE: "spacebase", TYPE_UNKNOWN: "unknown",
        TYPE_INT: "int", TYPE_UINT: "uint", TYPE_BOOL: "bool",
        TYPE_CODE: "code", TYPE_FLOAT: "float", TYPE_PTR: "ptr",
        TYPE_PTRREL: "ptrrel", TYPE_ARRAY: "array", TYPE_STRUCT: "struct",
        TYPE_UNION: "union", TYPE_ENUM_INT: "enum", TYPE_ENUM_UINT: "enum",
        TYPE_PARTIALENUM: "partialenum", TYPE_PARTIALSTRUCT: "partialstruct",
        TYPE_PARTIALUNION: "partialunion",
    }
    return _map.get(mt, "unknown")


def string2metatype(s: str) -> MetaType:
    _map = {
        "void": TYPE_VOID, "spacebase": TYPE_SPACEBASE, "unknown": TYPE_UNKNOWN,
        "int": TYPE_INT, "uint": TYPE_UINT, "bool": TYPE_BOOL,
        "code": TYPE_CODE, "float": TYPE_FLOAT, "ptr": TYPE_PTR,
        "ptrrel": TYPE_PTRREL, "array": TYPE_ARRAY, "struct": TYPE_STRUCT,
        "union": TYPE_UNION, "enum": TYPE_ENUM_INT,
        "partialstruct": TYPE_PARTIALSTRUCT, "partialunion": TYPE_PARTIALUNION,
    }
    return _map.get(s, TYPE_UNKNOWN)


def metatype2typeclass(meta: MetaType) -> TypeClass:
    if meta == TYPE_FLOAT:
        return TypeClass.TYPECLASS_FLOAT
    if meta in (TYPE_PTR, TYPE_PTRREL):
        return TypeClass.TYPECLASS_PTR
    return TypeClass.TYPECLASS_GENERAL


# =========================================================================
# TypeField
# =========================================================================

class TypeField:
    """A field within a structure or union."""

    def __init__(self, ident: int = 0, offset: int = 0,
                 name: str = "", type_: Optional[Datatype] = None) -> None:
        self.ident: int = ident
        self.offset: int = offset
        self.name: str = name
        self.type: Optional[Datatype] = type_

    def __lt__(self, other: TypeField) -> bool:
        return self.offset < other.offset

    def __repr__(self) -> str:
        tname = self.type.getName() if self.type else "?"
        return f"TypeField({self.name}, off={self.offset}, type={tname})"


# =========================================================================
# Datatype (base class)
# =========================================================================

class Datatype:
    """The base datatype class for the decompiler.

    Used for symbols, function prototypes, type propagation, etc.
    """

    # Boolean properties
    coretype = 1
    chartype = 2
    enumtype = 4
    poweroftwo = 8
    utf16 = 16
    utf32 = 32
    opaque_string = 64
    variable_length = 128
    has_stripped = 0x100
    is_ptrrel = 0x200
    type_incomplete = 0x400
    needs_resolution = 0x800
    force_format = 0x7000
    truncate_bigendian = 0x8000
    pointer_to_array = 0x10000
    warning_issued = 0x20000

    def __init__(self, size: int = 0, align: int = -1,
                 metatype: MetaType = TYPE_UNKNOWN) -> None:
        self.id: int = 0
        self.size: int = size
        self.flags: int = 0
        self.name: str = ""
        self.displayName: str = ""
        self.metatype: MetaType = metatype
        self.submeta: SubMetaType = _BASE2SUB.get(metatype, SubMetaType.SUB_UNKNOWN)
        self.typedefImm: Optional[Datatype] = None
        self.alignment: int = align if align > 0 else 0
        self.alignSize: int = size

    # --- Property queries ---

    def isCoreType(self) -> bool:
        return (self.flags & Datatype.coretype) != 0

    def isCharPrint(self) -> bool:
        return (self.flags & (Datatype.chartype | Datatype.utf16 | Datatype.utf32 | Datatype.opaque_string)) != 0

    def isEnumType(self) -> bool:
        return (self.flags & Datatype.enumtype) != 0

    def isASCII(self) -> bool:
        return (self.flags & Datatype.chartype) != 0

    def isUTF16(self) -> bool:
        return (self.flags & Datatype.utf16) != 0

    def isUTF32(self) -> bool:
        return (self.flags & Datatype.utf32) != 0

    def isVariableLength(self) -> bool:
        return (self.flags & Datatype.variable_length) != 0

    def isOpaqueString(self) -> bool:
        return (self.flags & Datatype.opaque_string) != 0

    def isPointerToArray(self) -> bool:
        return (self.flags & Datatype.pointer_to_array) != 0

    def isPointerRel(self) -> bool:
        return (self.flags & Datatype.is_ptrrel) != 0

    def hasStripped(self) -> bool:
        return (self.flags & Datatype.has_stripped) != 0

    def isIncomplete(self) -> bool:
        return (self.flags & Datatype.type_incomplete) != 0

    def needsResolution(self) -> bool:
        return (self.flags & Datatype.needs_resolution) != 0

    def getInheritable(self) -> int:
        return self.flags & Datatype.coretype

    def getDisplayFormat(self) -> int:
        return (self.flags & Datatype.force_format) >> 12

    def setDisplayFormat(self, fmt: int) -> None:
        self.flags = (self.flags & ~Datatype.force_format) | ((fmt & 0x7) << 12)

    def getMetatype(self) -> MetaType:
        return self.metatype

    def getSubMeta(self) -> SubMetaType:
        return self.submeta

    def getId(self) -> int:
        return self.id

    def getSize(self) -> int:
        return self.size

    def getAlignSize(self) -> int:
        return self.alignSize

    def getAlignment(self) -> int:
        return self.alignment

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName if self.displayName else self.name

    def getTypedef(self) -> Optional[Datatype]:
        return self.typedefImm

    # --- Virtual methods ---

    def printRaw(self) -> str:
        return self.name if self.name else metatype2string(self.metatype)

    def getSubType(self, off: int) -> Tuple[Optional[Datatype], int]:
        """Recover component data-type one-level down. Returns (subtype, newoff)."""
        return None, off

    def numDepend(self) -> int:
        return 0

    def getDepend(self, index: int) -> Optional[Datatype]:
        return None

    def getHoleSize(self, off: int) -> int:
        return 0

    @abstractmethod
    def clone(self) -> Datatype:
        ...

    def compare(self, op: Datatype, level: int) -> int:
        """Order types for propagation."""
        if self.submeta != op.submeta:
            return -1 if self.submeta < op.submeta else 1
        if self.size != op.size:
            return -1 if self.size < op.size else 1
        return 0

    def compareDependency(self, op: Datatype) -> int:
        """Compare for storage in tree structure."""
        if self.submeta != op.submeta:
            return -1 if self.submeta < op.submeta else 1
        if self.size != op.size:
            return -1 if self.size < op.size else 1
        return 0

    def typeOrder(self, op: Datatype) -> int:
        if self is op:
            return 0
        return self.compare(op, 10)

    def getStripped(self) -> Optional[Datatype]:
        return None

    def isPieceStructured(self) -> bool:
        return False

    def isPrimitiveWhole(self) -> bool:
        if self.metatype in (TYPE_STRUCT, TYPE_UNION, TYPE_ARRAY):
            return False
        return True

    def markComplete(self) -> None:
        self.flags &= ~Datatype.type_incomplete

    @staticmethod
    def hashName(nm: str) -> int:
        h = 123
        for ch in nm:
            h = (h * 301 + ord(ch)) & 0xFFFFFFFFFFFFFFFF
        return h

    @staticmethod
    def hashSize(id_: int, size: int) -> int:
        return (id_ * 0x100000001b3 + size) & 0xFFFFFFFFFFFFFFFF

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.name!r}, size={self.size}, meta={self.metatype.name})"


# =========================================================================
# Concrete Datatype subclasses
# =========================================================================

class TypeBase(Datatype):
    """Base class for the fundamental atomic types."""

    def __init__(self, size: int = 0, metatype: MetaType = TYPE_UNKNOWN,
                 name: str = "") -> None:
        super().__init__(size, -1, metatype)
        if name:
            self.name = name
            self.displayName = name

    def clone(self) -> TypeBase:
        t = TypeBase(self.size, self.metatype, self.name)
        t.id = self.id
        t.flags = self.flags
        t.submeta = self.submeta
        return t


class TypeChar(TypeBase):
    """Base type for character data-types (UTF-8 encoded)."""

    def __init__(self, name: str = "char") -> None:
        super().__init__(1, TYPE_INT, name)
        self.flags |= Datatype.chartype
        self.submeta = SubMetaType.SUB_INT_CHAR

    def clone(self) -> TypeChar:
        t = TypeChar(self.name)
        t.id = self.id
        t.flags = self.flags
        return t


class TypeUnicode(TypeBase):
    """The unicode data-type (wchar)."""

    def __init__(self, name: str = "wchar", size: int = 2,
                 metatype: MetaType = TYPE_INT) -> None:
        super().__init__(size, metatype, name)
        if size == 2:
            self.flags |= Datatype.utf16
            self.submeta = SubMetaType.SUB_INT_UNICODE
        elif size == 4:
            self.flags |= Datatype.utf32
            self.submeta = SubMetaType.SUB_INT_UNICODE

    def clone(self) -> TypeUnicode:
        t = TypeUnicode(self.name, self.size, self.metatype)
        t.id = self.id
        t.flags = self.flags
        return t


class TypeVoid(Datatype):
    """Formal "void" data-type object."""

    def __init__(self) -> None:
        super().__init__(0, 1, TYPE_VOID)
        self.name = "void"
        self.displayName = "void"
        self.flags |= Datatype.coretype

    def clone(self) -> TypeVoid:
        t = TypeVoid()
        t.id = self.id
        return t


class TypePointer(Datatype):
    """Datatype object representing a pointer."""

    def __init__(self, size: int = 0, ptrto: Optional[Datatype] = None,
                 wordsize: int = 1, spaceid: Optional[AddrSpace] = None) -> None:
        super().__init__(size, -1, TYPE_PTR)
        self.ptrto: Optional[Datatype] = ptrto
        self.wordsize: int = wordsize
        self.spaceid: Optional[AddrSpace] = spaceid
        self.truncate: Optional[TypePointer] = None
        if ptrto is not None:
            self.flags = ptrto.getInheritable()
        self._calcSubmeta()

    def _calcSubmeta(self) -> None:
        if self.ptrto is None:
            self.submeta = SubMetaType.SUB_PTR
            return
        mt = self.ptrto.getMetatype()
        if mt == TYPE_STRUCT:
            self.submeta = SubMetaType.SUB_PTR_STRUCT
        elif mt == TYPE_ARRAY:
            self.submeta = SubMetaType.SUB_PTR
            self.flags |= Datatype.pointer_to_array
        else:
            self.submeta = SubMetaType.SUB_PTR

    def getPtrTo(self) -> Optional[Datatype]:
        return self.ptrto

    def getWordSize(self) -> int:
        return self.wordsize

    def getSpace(self) -> Optional[AddrSpace]:
        return self.spaceid

    def numDepend(self) -> int:
        return 1

    def getDepend(self, index: int) -> Optional[Datatype]:
        return self.ptrto

    def getSubType(self, off: int) -> Tuple[Optional[Datatype], int]:
        if self.ptrto is not None:
            return self.ptrto, off
        return None, off

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypePointer):
            return 0
        if level <= 0:
            return 0
        if self.ptrto is not None and op.ptrto is not None:
            return self.ptrto.compare(op.ptrto, level - 1)
        return 0

    def compareDependency(self, op: Datatype) -> int:
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypePointer):
            return 0
        if self.wordsize != op.wordsize:
            return -1 if self.wordsize < op.wordsize else 1
        # Compare pointed-to types by id
        a_id = self.ptrto.getId() if self.ptrto else 0
        b_id = op.ptrto.getId() if op.ptrto else 0
        if a_id != b_id:
            return -1 if a_id < b_id else 1
        return 0

    def clone(self) -> TypePointer:
        t = TypePointer(self.size, self.ptrto, self.wordsize, self.spaceid)
        t.id = self.id
        t.flags = self.flags
        t.name = self.name
        t.displayName = self.displayName
        return t

    def printRaw(self) -> str:
        base = self.ptrto.printRaw() if self.ptrto else "?"
        return f"{base} *"


class TypeArray(Datatype):
    """Datatype object representing an array of elements."""

    def __init__(self, num_elements: int = 0,
                 arrayof: Optional[Datatype] = None) -> None:
        elem_size = arrayof.getSize() if arrayof else 0
        super().__init__(num_elements * elem_size, -1, TYPE_ARRAY)
        self.arrayof: Optional[Datatype] = arrayof
        self.arraysize: int = num_elements

    def getBase(self) -> Optional[Datatype]:
        return self.arrayof

    def numElements(self) -> int:
        return self.arraysize

    def numDepend(self) -> int:
        return 1

    def getDepend(self, index: int) -> Optional[Datatype]:
        return self.arrayof

    def getSubType(self, off: int) -> Tuple[Optional[Datatype], int]:
        if self.arrayof is not None and self.arrayof.getSize() > 0:
            newoff = off % self.arrayof.getSize()
            return self.arrayof, newoff
        return None, off

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypeArray):
            return 0
        if self.arraysize != op.arraysize:
            return -1 if self.arraysize < op.arraysize else 1
        if level <= 0:
            return 0
        if self.arrayof and op.arrayof:
            return self.arrayof.compare(op.arrayof, level - 1)
        return 0

    def compareDependency(self, op: Datatype) -> int:
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypeArray):
            return 0
        if self.arraysize != op.arraysize:
            return -1 if self.arraysize < op.arraysize else 1
        a_id = self.arrayof.getId() if self.arrayof else 0
        b_id = op.arrayof.getId() if op.arrayof else 0
        if a_id != b_id:
            return -1 if a_id < b_id else 1
        return 0

    def clone(self) -> TypeArray:
        t = TypeArray(self.arraysize, self.arrayof)
        t.id = self.id
        t.flags = self.flags
        t.name = self.name
        return t

    def printRaw(self) -> str:
        base = self.arrayof.printRaw() if self.arrayof else "?"
        return f"{base}[{self.arraysize}]"


class TypeEnum(TypeBase):
    """An enumerated Datatype: an integer with named values."""

    def __init__(self, size: int = 0, metatype: MetaType = TYPE_UINT,
                 name: str = "") -> None:
        super().__init__(size, metatype, name)
        self.flags |= Datatype.enumtype
        if metatype == TYPE_ENUM_INT:
            self.metatype = TYPE_INT
            self.submeta = SubMetaType.SUB_INT_ENUM
        else:
            self.metatype = TYPE_UINT
            self.submeta = SubMetaType.SUB_UINT_ENUM
        self.namemap: Dict[int, str] = {}

    def setNameMap(self, nmap: Dict[int, str]) -> None:
        self.namemap = dict(nmap)

    def hasNamedValue(self, val: int) -> bool:
        return val in self.namemap

    def getValueName(self, val: int) -> Optional[str]:
        return self.namemap.get(val)

    def clone(self) -> TypeEnum:
        t = TypeEnum(self.size, self.metatype, self.name)
        t.id = self.id
        t.flags = self.flags
        t.namemap = dict(self.namemap)
        return t


class TypeStruct(Datatype):
    """Structure data-type, made up of component datatypes."""

    def __init__(self, name: str = "", size: int = 0) -> None:
        super().__init__(size, -1, TYPE_STRUCT)
        self.name = name
        self.displayName = name
        self.field: List[TypeField] = []

    def numDepend(self) -> int:
        return len(self.field)

    def getDepend(self, index: int) -> Optional[Datatype]:
        if 0 <= index < len(self.field):
            return self.field[index].type
        return None

    def getField(self, i: int) -> TypeField:
        return self.field[i]

    def numFields(self) -> int:
        return len(self.field)

    def getSubType(self, off: int) -> Tuple[Optional[Datatype], int]:
        for f in reversed(self.field):
            if f.offset <= off:
                if f.type is not None and off < f.offset + f.type.getSize():
                    return f.type, off - f.offset
                break
        return None, off

    def getHoleSize(self, off: int) -> int:
        for i, f in enumerate(self.field):
            if f.offset <= off < f.offset + (f.type.getSize() if f.type else 0):
                return 0  # Not in a hole
            if f.offset > off:
                return f.offset - off  # Hole before this field
        return 0

    def setFields(self, fields: List[TypeField]) -> None:
        self.field = sorted(fields, key=lambda f: f.offset)
        if self.field:
            last = self.field[-1]
            end = last.offset + (last.type.getSize() if last.type else 0)
            if end > self.size:
                self.size = end

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypeStruct):
            return 0
        if len(self.field) != len(op.field):
            return -1 if len(self.field) < len(op.field) else 1
        if level <= 0:
            return 0
        for f1, f2 in zip(self.field, op.field):
            if f1.offset != f2.offset:
                return -1 if f1.offset < f2.offset else 1
            if f1.type and f2.type:
                r = f1.type.compare(f2.type, level - 1)
                if r != 0:
                    return r
        return 0

    def compareDependency(self, op: Datatype) -> int:
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypeStruct):
            return 0
        if self.name != op.name:
            return -1 if self.name < op.name else 1
        return 0

    def clone(self) -> TypeStruct:
        t = TypeStruct(self.name, self.size)
        t.id = self.id
        t.flags = self.flags
        t.field = list(self.field)
        return t

    def printRaw(self) -> str:
        return f"struct {self.name}"


class TypeUnion(Datatype):
    """An overlapping union of multiple datatypes."""

    def __init__(self, name: str = "", size: int = 0) -> None:
        super().__init__(size, -1, TYPE_UNION)
        self.name = name
        self.displayName = name
        self.field: List[TypeField] = []
        self.flags |= Datatype.needs_resolution

    def numDepend(self) -> int:
        return len(self.field)

    def getDepend(self, index: int) -> Optional[Datatype]:
        if 0 <= index < len(self.field):
            return self.field[index].type
        return None

    def getField(self, i: int) -> TypeField:
        return self.field[i]

    def numFields(self) -> int:
        return len(self.field)

    def setFields(self, fields: List[TypeField]) -> None:
        self.field = list(fields)
        for f in self.field:
            if f.type and f.type.getSize() > self.size:
                self.size = f.type.getSize()

    def clone(self) -> TypeUnion:
        t = TypeUnion(self.name, self.size)
        t.id = self.id
        t.flags = self.flags
        t.field = list(self.field)
        return t

    def printRaw(self) -> str:
        return f"union {self.name}"


class TypeCode(Datatype):
    """Data-type representing executable code (function prototype)."""

    def __init__(self, size: int = 1) -> None:
        super().__init__(size, -1, TYPE_CODE)
        self.name = "code"
        self.displayName = "code"
        self.proto = None  # FuncProto placeholder

    def clone(self) -> TypeCode:
        t = TypeCode(self.size)
        t.id = self.id
        t.flags = self.flags
        t.proto = self.proto
        return t


class TypeSpacebase(Datatype):
    """Special Datatype for symbol/type look-up calculations."""

    def __init__(self, size: int = 0) -> None:
        super().__init__(size, -1, TYPE_SPACEBASE)

    def clone(self) -> TypeSpacebase:
        t = TypeSpacebase(self.size)
        t.id = self.id
        return t


# =========================================================================
# TypeFactory
# =========================================================================

class TypeFactory:
    """A container for Datatype objects.

    Manages creation, caching, and lookup of all data-types used
    during decompilation.
    """

    def __init__(self) -> None:
        self._typeById: Dict[int, Datatype] = {}
        self._typeByName: Dict[str, Datatype] = {}
        self._nextId: int = 1
        self._sizeOfInt: int = 4
        self._sizeOfLong: int = 8
        self._sizeOfPointer: int = 8
        self._align: int = 1
        self._enumSize: int = 4

        # Core types
        self._typeVoid: TypeVoid = TypeVoid()
        self._typeBool: Optional[Datatype] = None
        self._typeChar: Optional[TypeChar] = None
        self._defaultInt: Optional[Datatype] = None
        self._defaultUint: Optional[Datatype] = None
        self._defaultFloat: Optional[Datatype] = None

        self._cacheType(self._typeVoid)

    def _assignId(self, dt: Datatype) -> None:
        if dt.id == 0:
            dt.id = self._nextId
            self._nextId += 1

    def _cacheType(self, dt: Datatype) -> None:
        self._assignId(dt)
        self._typeById[dt.id] = dt
        if dt.name:
            self._typeByName[dt.name] = dt

    def clear(self) -> None:
        self._typeById.clear()
        self._typeByName.clear()
        self._nextId = 1
        self._typeVoid = TypeVoid()
        self._cacheType(self._typeVoid)

    # --- Core type accessors ---

    def getTypeVoid(self) -> TypeVoid:
        return self._typeVoid

    def getBase(self, size: int, metatype: MetaType, name: str = "") -> Datatype:
        """Get or create a base type of given size and metatype."""
        if not name:
            name = f"{metatype2string(metatype)}{size}"
        existing = self._typeByName.get(name)
        if existing is not None:
            return existing
        dt = TypeBase(size, metatype, name)
        self._cacheType(dt)
        return dt

    def getTypePointer(self, size: int, ptrto: Datatype, ws: int = 1) -> TypePointer:
        """Get or create a pointer type."""
        dt = TypePointer(size, ptrto, ws)
        dt.name = f"{ptrto.getName()} *"
        dt.displayName = dt.name
        self._cacheType(dt)
        return dt

    def getTypeArray(self, num_elements: int, arrayof: Datatype) -> TypeArray:
        """Get or create an array type."""
        dt = TypeArray(num_elements, arrayof)
        dt.name = f"{arrayof.getName()}[{num_elements}]"
        dt.displayName = dt.name
        self._cacheType(dt)
        return dt

    def getTypeStruct(self, name: str) -> TypeStruct:
        """Get or create a structure type."""
        existing = self._typeByName.get(name)
        if existing is not None and isinstance(existing, TypeStruct):
            return existing
        dt = TypeStruct(name)
        dt.flags |= Datatype.type_incomplete
        self._cacheType(dt)
        return dt

    def getTypeUnion(self, name: str) -> TypeUnion:
        """Get or create a union type."""
        existing = self._typeByName.get(name)
        if existing is not None and isinstance(existing, TypeUnion):
            return existing
        dt = TypeUnion(name)
        dt.flags |= Datatype.type_incomplete
        self._cacheType(dt)
        return dt

    def getTypeEnum(self, size: int, metatype: MetaType, name: str) -> TypeEnum:
        dt = TypeEnum(size, metatype, name)
        self._cacheType(dt)
        return dt

    def getTypeCode(self) -> TypeCode:
        return TypeCode()

    # --- Lookup ---

    def findById(self, id_: int) -> Optional[Datatype]:
        return self._typeById.get(id_)

    def findByName(self, name: str) -> Optional[Datatype]:
        return self._typeByName.get(name)

    # --- Core type setup ---

    def setCoreType(self, name: str, size: int, metatype: MetaType, ischar: bool = False) -> Datatype:
        """Set up a core type."""
        if ischar:
            if size == 1:
                dt = TypeChar(name)
            else:
                dt = TypeUnicode(name, size, metatype)
        else:
            dt = TypeBase(size, metatype, name)
        dt.flags |= Datatype.coretype
        self._cacheType(dt)

        if metatype == TYPE_VOID:
            self._typeVoid = dt  # type: ignore
        elif metatype == TYPE_BOOL:
            self._typeBool = dt
        elif ischar and size == 1:
            self._typeChar = dt  # type: ignore

        return dt

    def setupCoreTypes(self) -> None:
        """Set up standard core types."""
        self.setCoreType("void", 0, TYPE_VOID)
        self.setCoreType("bool", 1, TYPE_BOOL)
        self.setCoreType("uint1", 1, TYPE_UINT)
        self.setCoreType("uint2", 2, TYPE_UINT)
        self.setCoreType("uint4", 4, TYPE_UINT)
        self.setCoreType("uint8", 8, TYPE_UINT)
        self.setCoreType("int1", 1, TYPE_INT)
        self.setCoreType("int2", 2, TYPE_INT)
        self.setCoreType("int4", 4, TYPE_INT)
        self.setCoreType("int8", 8, TYPE_INT)
        self.setCoreType("float4", 4, TYPE_FLOAT)
        self.setCoreType("float8", 8, TYPE_FLOAT)
        self.setCoreType("float10", 10, TYPE_FLOAT)
        self.setCoreType("float16", 16, TYPE_FLOAT)
        self.setCoreType("char", 1, TYPE_INT, ischar=True)
        self.setCoreType("wchar2", 2, TYPE_INT, ischar=True)
        self.setCoreType("wchar4", 4, TYPE_INT, ischar=True)
        self.setCoreType("undefined", 1, TYPE_UNKNOWN)
        self.setCoreType("undefined2", 2, TYPE_UNKNOWN)
        self.setCoreType("undefined4", 4, TYPE_UNKNOWN)
        self.setCoreType("undefined8", 8, TYPE_UNKNOWN)
        self.setCoreType("code", 1, TYPE_CODE)
        self._defaultInt = self.findByName("int4")
        self._defaultUint = self.findByName("uint4")
        self._defaultFloat = self.findByName("float8")

    def getSizeOfInt(self) -> int:
        return self._sizeOfInt

    def getSizeOfLong(self) -> int:
        return self._sizeOfLong

    def getSizeOfPointer(self) -> int:
        return self._sizeOfPointer

    def __repr__(self) -> str:
        return f"TypeFactory({len(self._typeById)} types)"
