"""
Corresponds to: cast.hh / cast.cc

API and specific strategies for applying type casts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional

from ghidra.types.datatype import (
    Datatype, TypeFactory, MetaType,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT,
    TYPE_PTR, TYPE_PTRREL, TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE,
)

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp


class IntPromotionCode(IntEnum):
    """Types of integer promotion."""
    NO_PROMOTION = -1
    UNKNOWN_PROMOTION = 0
    UNSIGNED_EXTENSION = 1
    SIGNED_EXTENSION = 2
    EITHER_EXTENSION = 3


class CastStrategy(ABC):
    """A strategy for applying type casts.

    Makes four kinds of decisions:
      - Do we need a cast operator for a given assignment
      - Does the given conversion need to be represented as a cast
      - Does the given extension/comparison match integer promotion
      - What data-type is produced by integer arithmetic
    """

    def __init__(self) -> None:
        self.tlst: Optional[TypeFactory] = None
        self.promoteSize: int = 4

    def setTypeFactory(self, t: TypeFactory) -> None:
        self.tlst = t
        self.promoteSize = t.getSizeOfInt()

    @abstractmethod
    def localExtensionType(self, vn: Varnode, op: PcodeOp) -> int:
        ...

    @abstractmethod
    def intPromotionType(self, vn: Varnode) -> int:
        ...

    @abstractmethod
    def checkIntPromotionForCompare(self, op: PcodeOp, slot: int) -> bool:
        ...

    @abstractmethod
    def checkIntPromotionForExtension(self, op: PcodeOp) -> bool:
        ...

    @abstractmethod
    def isExtensionCastImplied(self, op: PcodeOp, readOp: Optional[PcodeOp]) -> bool:
        ...

    @abstractmethod
    def castStandard(self, reqtype: Datatype, curtype: Datatype,
                     care_uint_int: bool, care_ptr_uint: bool) -> Optional[Datatype]:
        ...

    @abstractmethod
    def arithmeticOutputStandard(self, op: PcodeOp) -> Datatype:
        ...

    @abstractmethod
    def isSubpieceCast(self, outtype: Datatype, intype: Datatype, offset: int) -> bool:
        ...

    @abstractmethod
    def isSubpieceCastEndian(self, outtype: Datatype, intype: Datatype,
                              offset: int, isbigend: bool) -> bool:
        ...

    @abstractmethod
    def isSextCast(self, outtype: Datatype, intype: Datatype) -> bool:
        ...

    @abstractmethod
    def isZextCast(self, outtype: Datatype, intype: Datatype) -> bool:
        ...

    def caresAboutCharRepresentation(self, vn: Varnode, op: Optional[PcodeOp]) -> bool:
        return False


class CastStrategyC(CastStrategy):
    """Casting strategies specific to the C language."""

    def localExtensionType(self, vn, op):
        if vn.isConstant():
            tp = vn.getType()
            if tp is not None and tp.getMetatype() == TYPE_INT:
                return int(IntPromotionCode.SIGNED_EXTENSION)
            return int(IntPromotionCode.UNSIGNED_EXTENSION)
        tp = vn.getType()
        if tp is None:
            return int(IntPromotionCode.UNKNOWN_PROMOTION)
        meta = tp.getMetatype()
        if meta == TYPE_INT:
            return int(IntPromotionCode.SIGNED_EXTENSION)
        if meta == TYPE_UINT or meta == TYPE_BOOL:
            return int(IntPromotionCode.UNSIGNED_EXTENSION)
        return int(IntPromotionCode.UNKNOWN_PROMOTION)

    def intPromotionType(self, vn):
        if vn.getSize() >= self.promoteSize:
            return int(IntPromotionCode.NO_PROMOTION)
        if vn.isConstant():
            return self.localExtensionType(vn, None)
        if not vn.isWritten():
            return self.localExtensionType(vn, None)
        return self.localExtensionType(vn, vn.getDef())

    def checkIntPromotionForCompare(self, op, slot):
        vn = op.getIn(slot)
        if vn is None:
            return False
        if vn.getSize() >= self.promoteSize:
            return False
        promoType = self.intPromotionType(vn)
        if promoType == int(IntPromotionCode.NO_PROMOTION):
            return False
        return True

    def checkIntPromotionForExtension(self, op):
        vn = op.getIn(0)
        if vn is None:
            return False
        if vn.getSize() >= self.promoteSize:
            return False
        return True

    def isExtensionCastImplied(self, op, readOp):
        invn = op.getIn(0)
        if invn is None:
            return True
        if invn.getSize() >= self.promoteSize:
            return False
        return True

    def castStandard(self, reqtype, curtype, care_uint_int, care_ptr_uint):
        if reqtype is curtype:
            return None
        reqmeta = reqtype.getMetatype()
        curmeta = curtype.getMetatype()

        if reqtype.getSize() != curtype.getSize():
            return reqtype

        if reqmeta == curmeta:
            return None

        if reqmeta == TYPE_VOID or curmeta == TYPE_VOID:
            return None

        if care_uint_int:
            if (reqmeta == TYPE_INT and curmeta == TYPE_UINT) or \
               (reqmeta == TYPE_UINT and curmeta == TYPE_INT):
                return reqtype

        if care_ptr_uint:
            if reqmeta == TYPE_PTR and curmeta in (TYPE_UINT, TYPE_INT, TYPE_UNKNOWN):
                return reqtype
            if curmeta == TYPE_PTR and reqmeta in (TYPE_UINT, TYPE_INT, TYPE_UNKNOWN):
                return reqtype

        if reqmeta == TYPE_FLOAT and curmeta != TYPE_FLOAT:
            return reqtype
        if curmeta == TYPE_FLOAT and reqmeta != TYPE_FLOAT:
            return reqtype

        if reqmeta == TYPE_BOOL and curmeta != TYPE_BOOL:
            return reqtype
        if curmeta == TYPE_BOOL and reqmeta != TYPE_BOOL:
            return reqtype

        return None

    def arithmeticOutputStandard(self, op):
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getBase(1, TYPE_INT)
        tp = outvn.getType()
        if tp is not None:
            return tp
        return self.tlst.getBase(outvn.getSize(), TYPE_INT)

    def isSubpieceCast(self, outtype, intype, offset):
        if outtype.getMetatype() == TYPE_PTR:
            return True
        if intype.getMetatype() == TYPE_PTR:
            return True
        if outtype.getMetatype() == TYPE_FLOAT or intype.getMetatype() == TYPE_FLOAT:
            return True
        return (outtype.getSize() < intype.getSize())

    def isSubpieceCastEndian(self, outtype, intype, offset, isbigend):
        return self.isSubpieceCast(outtype, intype, offset)

    def isSextCast(self, outtype, intype):
        inmeta = intype.getMetatype()
        if inmeta in (TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_UNKNOWN):
            return True
        return False

    def isZextCast(self, outtype, intype):
        inmeta = intype.getMetatype()
        if inmeta in (TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_UNKNOWN):
            return True
        return False


class CastStrategyJava(CastStrategyC):
    """Casting strategies specific to the Java language."""

    def castStandard(self, reqtype, curtype, care_uint_int, care_ptr_uint):
        if reqtype is curtype:
            return None
        reqmeta = reqtype.getMetatype()
        curmeta = curtype.getMetatype()

        if reqmeta == TYPE_PTR and curmeta == TYPE_PTR:
            return None

        return super().castStandard(reqtype, curtype, care_uint_int, care_ptr_uint)
