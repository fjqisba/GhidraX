"""
Corresponds to: translate.hh / translate.cc

Classes for disassembly and pcode generation.
Includes the Translate abstract base class, PcodeEmit, and AssemblyEmit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Dict, List

from ghidra.core.error import LowlevelError, UnimplError, BadDataError
from ghidra.core.opcodes import OpCode
from ghidra.core.address import Address
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.float_format import FloatFormat
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace, JoinSpace, OtherSpace,
    IPTR_CONSTANT, IPTR_PROCESSOR, IPTR_INTERNAL, IPTR_JOIN,
)
from ghidra.core.marshal import (
    Encoder, Decoder, ElementId, AttributeId,
    ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_DEFAULTSPACE, ATTRIB_UNIQBASE,
    ELEM_SPACE, ELEM_SPACES, ELEM_SPACE_BASE, ELEM_SPACE_UNIQUE,
    ELEM_SPACE_OTHER, ELEM_SPACE_OVERLAY, ELEM_TRUNCATE_SPACE,
)

if TYPE_CHECKING:
    pass


# =========================================================================
# TruncationTag
# =========================================================================

class TruncationTag:
    """Object for describing how a space should be truncated."""

    def __init__(self) -> None:
        self.spaceName: str = ""
        self.size: int = 0

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_TRUNCATE_SPACE)
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_NAME.id:
                self.spaceName = decoder.readString()
            elif attrib_id == ATTRIB_SIZE.id:
                self.size = decoder.readSignedInteger()
        decoder.closeElement(elem_id)

    def getName(self) -> str:
        return self.spaceName

    def getSize(self) -> int:
        return self.size


# =========================================================================
# PcodeEmit
# =========================================================================

class PcodeEmit(ABC):
    """Abstract class for emitting pcode to an application.

    Translation engines pass back the generated pcode for an
    instruction to the application using this class.
    """

    @abstractmethod
    def dump(self, addr: Address, opc: OpCode,
             outvar: Optional[VarnodeData],
             vars_: List[VarnodeData], isize: int) -> None:
        """The main pcode emit method.

        A single pcode instruction is returned to the application
        via this method.
        """
        ...


# =========================================================================
# AssemblyEmit
# =========================================================================

class AssemblyEmit(ABC):
    """Abstract class for emitting disassembly to an application."""

    @abstractmethod
    def dump(self, addr: Address, mnem: str, body: str) -> None:
        """The main disassembly emitting method."""
        ...


# =========================================================================
# AddressResolver
# =========================================================================

class AddressResolver(ABC):
    """Abstract class for converting native constants to addresses."""

    @abstractmethod
    def resolve(self, val: int, sz: int, point: Address) -> tuple[Address, int]:
        """Resolve a native constant to an address.

        Returns (resolved_address, full_encoding).
        """
        ...


# =========================================================================
# Translate
# =========================================================================

class Translate(AddrSpaceManager):
    """Abstract base for translation engines (disassembler + pcode generator).

    Corresponds to the Translate class in translate.hh.
    Manages address spaces and provides methods for translating
    machine instructions into p-code.
    """

    def __init__(self) -> None:
        super().__init__()
        self._floatformats: Dict[int, FloatFormat] = {}
        self._alignment: int = 0
        self._target_endian: int = 0  # 0=little, 1=big
        self._unique_base: int = 0

    # --- Float format management ---

    def getFloatFormat(self, size: int) -> FloatFormat:
        """Get the floating-point format for a given byte size."""
        fmt = self._floatformats.get(size)
        if fmt is None:
            fmt = FloatFormat(size)
            self._floatformats[size] = fmt
        return fmt

    def setFloatFormat(self, size: int, fmt: FloatFormat) -> None:
        self._floatformats[size] = fmt

    # --- Properties ---

    def getAlignment(self) -> int:
        return self._alignment

    def isBigEndian(self) -> bool:
        return self._target_endian != 0

    def getUniqueBase(self) -> int:
        return self._unique_base

    def setUniqueBase(self, val: int) -> None:
        if val > self._unique_base:
            self._unique_base = val

    # --- Abstract translation methods ---

    @abstractmethod
    def oneInstruction(self, emit: PcodeEmit, addr: Address) -> int:
        """Transform a single machine instruction into pcode.

        Returns the length of the machine instruction in bytes.
        """
        ...

    @abstractmethod
    def printAssembly(self, emit: AssemblyEmit, addr: Address) -> int:
        """Disassemble a single machine instruction.

        Returns the length of the machine instruction in bytes.
        """
        ...

    def getRegisterName(self, base: AddrSpace, off: int, size: int) -> str:
        """Get the name of a register given its location."""
        return ""

    def getRegister(self, nm: str) -> VarnodeData:
        """Get the location of a register by name."""
        raise LowlevelError(f"No register named: {nm}")

    def getAllRegisters(self) -> Dict[str, VarnodeData]:
        """Get all register definitions."""
        return {}

    def getUserOpNames(self) -> List[str]:
        """Get the list of user-defined pcode op names."""
        return []

    def getUniqueStart(self) -> int:
        """Get the starting offset for the unique space."""
        return self._unique_base
