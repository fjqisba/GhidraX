"""
Corresponds to: marshal.hh / marshal.cc

Encoder/Decoder abstractions and AttributeId/ElementId labelling system.
Provides both XML-based and packed binary serialization formats.
"""

from __future__ import annotations

import io
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional
from xml.etree.ElementTree import Element, parse as xml_parse, fromstring as xml_fromstring

from ghidra.core.opcodes import OpCode, get_opname, get_opcode

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace, AddrSpaceManager


# =========================================================================
# AttributeId
# =========================================================================

class AttributeId:
    """An annotation for a data element being transferred to/from a stream.

    Parallels the XML concept of an attribute on an element.
    """
    _lookup: dict[str, int] = {}
    _list: list[AttributeId] = []

    def __init__(self, name: str, id_: int, scope: int = 0) -> None:
        self.name: str = name
        self.id: int = id_
        AttributeId._lookup[name] = id_
        AttributeId._list.append(self)

    def getName(self) -> str:
        return self.name

    def getId(self) -> int:
        return self.id

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AttributeId):
            return self.id == other.id
        if isinstance(other, int):
            return self.id == other
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"AttributeId({self.name!r}, {self.id})"

    @staticmethod
    def find(name: str, scope: int = 0) -> int:
        return AttributeId._lookup.get(name, 0)

    @staticmethod
    def initialize() -> None:
        pass  # All registrations happen at import-time in Python


# =========================================================================
# ElementId
# =========================================================================

class ElementId:
    """An annotation for a specific collection of hierarchical data.

    Parallels the XML concept of an element.
    """
    _lookup: dict[str, int] = {}
    _list: list[ElementId] = []

    def __init__(self, name: str, id_: int, scope: int = 0) -> None:
        self.name: str = name
        self.id: int = id_
        ElementId._lookup[name] = id_
        ElementId._list.append(self)

    def getName(self) -> str:
        return self.name

    def getId(self) -> int:
        return self.id

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ElementId):
            return self.id == other.id
        if isinstance(other, int):
            return self.id == other
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"ElementId({self.name!r}, {self.id})"

    @staticmethod
    def find(name: str, scope: int = 0) -> int:
        return ElementId._lookup.get(name, 0)

    @staticmethod
    def initialize() -> None:
        pass


# =========================================================================
# Well-known AttributeIds and ElementIds (global singletons)
# These are defined across many C++ files; we centralise them here.
# =========================================================================

ATTRIB_UNKNOWN = AttributeId("unknown", 0)
ATTRIB_CONTENT = AttributeId("content", 1)
ATTRIB_ALIGN = AttributeId("align", 2)
ATTRIB_BIGENDIAN = AttributeId("bigendian", 3)
ATTRIB_CONSTRUCTOR = AttributeId("constructor", 4)
ATTRIB_DESTRUCTOR = AttributeId("destructor", 5)
ATTRIB_EXTRAPOP = AttributeId("extrapop", 6)
ATTRIB_FORMAT = AttributeId("format", 7)
ATTRIB_HIDDENRETPARM = AttributeId("hiddenretparm", 8)
ATTRIB_ID = AttributeId("id", 9)
ATTRIB_INDEX = AttributeId("index", 10)
ATTRIB_INDIRECTSTORAGE = AttributeId("indirectstorage", 11)
ATTRIB_METATYPE = AttributeId("metatype", 12)
ATTRIB_MODEL = AttributeId("model", 13)
ATTRIB_NAME = AttributeId("name", 14)
ATTRIB_NAMELOCK = AttributeId("namelock", 15)
ATTRIB_OFFSET = AttributeId("offset", 16)
ATTRIB_READONLY = AttributeId("readonly", 17)
ATTRIB_REF = AttributeId("ref", 18)
ATTRIB_SIZE = AttributeId("size", 19)
ATTRIB_SPACE = AttributeId("space", 20)
ATTRIB_THISPTR = AttributeId("thisptr", 21)
ATTRIB_TYPE = AttributeId("type", 22)
ATTRIB_TYPELOCK = AttributeId("typelock", 23)
ATTRIB_VAL = AttributeId("val", 24)
ATTRIB_VALUE = AttributeId("value", 25)
ATTRIB_WORDSIZE = AttributeId("wordsize", 26)

# From address.cc
ATTRIB_FIRST = AttributeId("first", 27)
ATTRIB_LAST = AttributeId("last", 28)
ATTRIB_UNIQ = AttributeId("uniq", 29)

# From translate.cc
ATTRIB_CODE = AttributeId("code", 30)
ATTRIB_CONTAIN = AttributeId("contain", 31)
ATTRIB_DEFAULTSPACE = AttributeId("defaultspace", 32)
ATTRIB_UNIQBASE = AttributeId("uniqbase", 33)

# From space.cc
ATTRIB_BASE = AttributeId("base", 34)
ATTRIB_DEADCODEDELAY = AttributeId("deadcodedelay", 35)
ATTRIB_DELAY = AttributeId("delay", 36)
ATTRIB_LOGICALSIZE = AttributeId("logicalsize", 37)
ATTRIB_PHYSICAL = AttributeId("physical", 38)
ATTRIB_PIECE = AttributeId("piece", 39)

# Well-known ElementIds
ELEM_UNKNOWN = ElementId("unknown", 0)

# From address.cc
ELEM_ADDR = ElementId("addr", 11)
ELEM_RANGE = ElementId("range", 12)
ELEM_RANGELIST = ElementId("rangelist", 13)
ELEM_REGISTER = ElementId("register", 14)
ELEM_SEQNUM = ElementId("seqnum", 15)
ELEM_VARNODE = ElementId("varnode", 16)

# From translate.cc
ELEM_OP = ElementId("op", 17)
ELEM_SLEIGH = ElementId("sleigh", 18)
ELEM_SPACE = ElementId("space", 19)
ELEM_SPACEID = ElementId("spaceid", 20)
ELEM_SPACES = ElementId("spaces", 21)
ELEM_SPACE_BASE = ElementId("space_base", 22)
ELEM_SPACE_OTHER = ElementId("space_other", 23)
ELEM_SPACE_OVERLAY = ElementId("space_overlay", 24)
ELEM_SPACE_UNIQUE = ElementId("space_unique", 25)
ELEM_TRUNCATE_SPACE = ElementId("truncate_space", 26)


# =========================================================================
# Decoder (abstract base)
# =========================================================================

class Decoder(ABC):
    """A class for reading structured data from a stream.

    All data is loosely structured as with an XML document.
    """

    def __init__(self, spc_manager: Optional[AddrSpaceManager] = None) -> None:
        self.spcManager: Optional[AddrSpaceManager] = spc_manager

    def getAddrSpaceManager(self) -> Optional[AddrSpaceManager]:
        return self.spcManager

    @abstractmethod
    def ingestStream(self, s: str) -> None: ...

    @abstractmethod
    def peekElement(self) -> int: ...

    @abstractmethod
    def openElement(self, elemId: Optional[ElementId] = None) -> int: ...

    @abstractmethod
    def closeElement(self, id_: int) -> None: ...

    @abstractmethod
    def closeElementSkipping(self, id_: int) -> None: ...

    @abstractmethod
    def getNextAttributeId(self) -> int: ...

    @abstractmethod
    def getIndexedAttributeId(self, attribId: AttributeId) -> int: ...

    @abstractmethod
    def rewindAttributes(self) -> None: ...

    @abstractmethod
    def readBool(self, attribId: Optional[AttributeId] = None) -> bool: ...

    @abstractmethod
    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int: ...

    @abstractmethod
    def readSignedIntegerExpectString(self, expect_or_attribId, expect_str: Optional[str] = None,
                                       expectval: int = 0) -> int: ...

    @abstractmethod
    def readUnsignedInteger(self, attribId: Optional[AttributeId] = None) -> int: ...

    @abstractmethod
    def readString(self, attribId: Optional[AttributeId] = None) -> str: ...

    @abstractmethod
    def readSpace(self, attribId: Optional[AttributeId] = None) -> AddrSpace: ...

    @abstractmethod
    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode: ...

    def skipElement(self) -> None:
        elemId = self.openElement()
        self.closeElementSkipping(elemId)


# =========================================================================
# Encoder (abstract base)
# =========================================================================

class Encoder(ABC):
    """A class for writing structured data to a stream."""

    @abstractmethod
    def openElement(self, elemId: ElementId) -> None: ...

    @abstractmethod
    def closeElement(self, elemId: ElementId) -> None: ...

    @abstractmethod
    def writeBool(self, attribId: AttributeId, val: bool) -> None: ...

    @abstractmethod
    def writeSignedInteger(self, attribId: AttributeId, val: int) -> None: ...

    @abstractmethod
    def writeUnsignedInteger(self, attribId: AttributeId, val: int) -> None: ...

    @abstractmethod
    def writeString(self, attribId: AttributeId, val: str) -> None: ...

    @abstractmethod
    def writeStringIndexed(self, attribId: AttributeId, index: int, val: str) -> None: ...

    @abstractmethod
    def writeSpace(self, attribId: AttributeId, spc: AddrSpace) -> None: ...

    @abstractmethod
    def writeOpcode(self, attribId: AttributeId, opc: OpCode) -> None: ...


# =========================================================================
# XmlDecode – XML-based decoder using ElementTree
# =========================================================================

class XmlDecode(Decoder):
    """An XML-based decoder.

    The underlying transfer encoding is an XML document.
    """

    def __init__(self, spc_manager: Optional[AddrSpaceManager] = None,
                 root: Optional[Element] = None, scope: int = 0) -> None:
        super().__init__(spc_manager)
        self._root: Optional[Element] = root
        self._elStack: list[Element] = []
        self._iterStack: list[list[Element]] = []
        self._childIndexStack: list[int] = []
        self._attributeIndex: int = -1
        self._scope: int = scope
        self._attrKeys: list[str] = []

    def ingestStream(self, s: str) -> None:
        self._root = xml_fromstring(s)

    def _currentElement(self) -> Element:
        return self._elStack[-1]

    def _findMatchingAttribute(self, el: Element, attrib_name: str) -> int:
        keys = list(el.attrib.keys())
        for i, k in enumerate(keys):
            if k == attrib_name:
                return i
        return -1

    def peekElement(self) -> int:
        if not self._elStack:
            if self._root is not None:
                return ElementId.find(self._root.tag, self._scope)
            return 0
        parent = self._currentElement()
        children = list(parent)
        idx = self._childIndexStack[-1]
        if idx >= len(children):
            return 0
        child = children[idx]
        return ElementId.find(child.tag, self._scope)

    def openElement(self, elemId: Optional[ElementId] = None) -> int:
        if not self._elStack:
            el = self._root
        else:
            parent = self._currentElement()
            children = list(parent)
            idx = self._childIndexStack[-1]
            if idx >= len(children):
                from ghidra.core.error import DecoderError
                raise DecoderError("No more child elements")
            el = children[idx]
            self._childIndexStack[-1] = idx + 1

        self._elStack.append(el)
        self._childIndexStack.append(0)
        self._attributeIndex = -1
        self._attrKeys = list(el.attrib.keys())

        found_id = ElementId.find(el.tag, self._scope)
        if elemId is not None and found_id != elemId.id:
            from ghidra.core.error import DecoderError
            raise DecoderError(f"Expected element <{elemId.name}>, got <{el.tag}>")
        return found_id

    def closeElement(self, id_: int) -> None:
        self._elStack.pop()
        self._childIndexStack.pop()
        self._attributeIndex = -1
        if self._elStack:
            self._attrKeys = list(self._elStack[-1].attrib.keys())

    def closeElementSkipping(self, id_: int) -> None:
        self.closeElement(id_)

    def getNextAttributeId(self) -> int:
        el = self._currentElement()
        keys = list(el.attrib.keys())
        self._attributeIndex += 1
        if self._attributeIndex >= len(keys):
            self._attributeIndex = len(keys)
            return 0
        attr_name = keys[self._attributeIndex]
        return AttributeId.find(attr_name, self._scope)

    def getIndexedAttributeId(self, attribId: AttributeId) -> int:
        return 0  # Simplified

    def rewindAttributes(self) -> None:
        self._attributeIndex = -1

    def _getAttributeValue(self, attribId: Optional[AttributeId] = None) -> str:
        el = self._currentElement()
        if attribId is not None:
            val = el.attrib.get(attribId.name)
            if val is None:
                if attribId == ATTRIB_CONTENT:
                    return el.text or ""
                from ghidra.core.error import DecoderError
                raise DecoderError(f"Attribute '{attribId.name}' not found")
            self.rewindAttributes()
            return val
        # Use current attribute index
        keys = list(el.attrib.keys())
        if 0 <= self._attributeIndex < len(keys):
            return el.attrib[keys[self._attributeIndex]]
        from ghidra.core.error import DecoderError
        raise DecoderError("No current attribute to read")

    def readBool(self, attribId: Optional[AttributeId] = None) -> bool:
        val = self._getAttributeValue(attribId)
        return val.lower() in ("true", "1", "yes", "y")

    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        val = self._getAttributeValue(attribId)
        return int(val, 0)

    def readSignedIntegerExpectString(self, expect_or_attribId, expect_str=None, expectval=0):
        if isinstance(expect_or_attribId, AttributeId):
            val = self._getAttributeValue(expect_or_attribId)
            if val == expect_str:
                return expectval
            return int(val, 0)
        else:
            val = self._getAttributeValue()
            if val == expect_or_attribId:
                return expect_str if expect_str is not None else expectval
            return int(val, 0)

    def readUnsignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        val = self._getAttributeValue(attribId)
        return int(val, 0)

    def readString(self, attribId: Optional[AttributeId] = None) -> str:
        return self._getAttributeValue(attribId)

    def readSpace(self, attribId: Optional[AttributeId] = None) -> AddrSpace:
        name = self._getAttributeValue(attribId)
        if self.spcManager is None:
            from ghidra.core.error import DecoderError
            raise DecoderError("No address space manager for readSpace")
        return self.spcManager.getSpaceByName(name)

    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode:
        val = self._getAttributeValue(attribId)
        return get_opcode(val)


# =========================================================================
# XmlEncode – XML-based encoder
# =========================================================================

class XmlEncode(Encoder):
    """An XML-based encoder that writes to a StringIO stream."""

    def __init__(self, stream: Optional[io.StringIO] = None, do_format: bool = True) -> None:
        self._stream: io.StringIO = stream if stream is not None else io.StringIO()
        self._depth: int = 0
        self._tagStatus: int = 2  # 0=tag_start, 1=tag_content, 2=tag_stop
        self._doFormatting: bool = do_format
        self._elemStack: list[str] = []

    def getStream(self) -> io.StringIO:
        return self._stream

    def toString(self) -> str:
        return self._stream.getvalue()

    def _newLine(self) -> None:
        if self._doFormatting:
            self._stream.write("\n")
            self._stream.write("  " * self._depth)

    def openElement(self, elemId: ElementId) -> None:
        if self._tagStatus == 0:
            self._stream.write(">")
        self._newLine()
        self._stream.write(f"<{elemId.name}")
        self._elemStack.append(elemId.name)
        self._depth += 1
        self._tagStatus = 0  # tag_start

    def closeElement(self, elemId: ElementId) -> None:
        self._depth -= 1
        name = self._elemStack.pop()
        if self._tagStatus == 0:
            self._stream.write("/>")
        else:
            self._newLine()
            self._stream.write(f"</{name}>")
        self._tagStatus = 2  # tag_stop

    def writeBool(self, attribId: AttributeId, val: bool) -> None:
        self._stream.write(f' {attribId.name}="{str(val).lower()}"')

    def writeSignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._stream.write(f' {attribId.name}="0x{val & 0xFFFFFFFFFFFFFFFF:x}"')

    def writeUnsignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._stream.write(f' {attribId.name}="0x{val:x}"')

    def writeString(self, attribId: AttributeId, val: str) -> None:
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
                self._tagStatus = 1
            self._stream.write(val)
        else:
            self._stream.write(f' {attribId.name}="{val}"')

    def writeStringIndexed(self, attribId: AttributeId, index: int, val: str) -> None:
        self._stream.write(f' {attribId.name}{index}="{val}"')

    def writeSpace(self, attribId: AttributeId, spc: AddrSpace) -> None:
        self._stream.write(f' {attribId.name}="{spc.getName()}"')

    def writeOpcode(self, attribId: AttributeId, opc: OpCode) -> None:
        self._stream.write(f' {attribId.name}="{get_opname(opc)}"')
