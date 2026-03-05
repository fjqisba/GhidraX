"""
Corresponds to: fspec.hh / fspec.cc

Definitions for specifying function prototypes.
Core classes: ParamEntry, ParamListStandard, ProtoModel, FuncProto, FuncCallSpecs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List, Dict

from ghidra.core.address import Address, Range, RangeList
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.error import LowlevelError
from ghidra.types.datatype import (
    Datatype, TypeFactory, MetaType, TypeClass,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_FLOAT, TYPE_PTR, TYPE_CODE,
    TYPECLASS_GENERAL, TYPECLASS_FLOAT,
)

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder


class ParamUnassignedError(LowlevelError):
    """Exception thrown when a prototype can't be modeled properly."""

    def getMessage(self) -> str:
        return str(self)


class EffectRecord:
    """Description of the indirect effect a sub-function has on a memory range."""
    unaffected = 1
    killedbycall = 2
    return_address = 3
    unknown_effect = 4

    def __init__(self, addr=None, size: int = 0, tp: int = 4) -> None:
        self._addr = addr if addr is not None else Address()
        self._size: int = size
        self._type: int = tp

    def getType(self) -> int:
        return self._type

    def getAddress(self) -> Address:
        return self._addr

    def getSize(self) -> int:
        return self._size

    def __eq__(self, other) -> bool:
        if not isinstance(other, EffectRecord):
            return NotImplemented
        return self._addr == other._addr and self._size == other._size and self._type == other._type

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    def setType(self, tp: int) -> None:
        self._type = tp

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    @staticmethod
    def compareByAddress(op1, op2) -> bool:
        return op1._addr < op2._addr


class ParameterPieces:
    """Basic elements of a parameter: address, data-type, properties."""
    isthis = 1
    hiddenretparm = 2
    indirectstorage = 4
    namelock = 8
    typelock = 16
    sizelock = 32

    def __init__(self) -> None:
        self.addr: Address = Address()
        self.type = None  # Datatype
        self.flags: int = 0

    def swapMarkup(self, op) -> None:
        self.type, op.type = op.type, self.type


class PrototypePieces:
    """Raw components of a function prototype (obtained from parsing source code)."""
    def __init__(self) -> None:
        self.model = None  # ProtoModel
        self.name: str = ""
        self.outtype = None  # Datatype
        self.intypes: list = []  # List[Datatype]
        self.innames: list = []  # List[str]
        self.firstVarArgSlot: int = -1


class ParameterBasic:
    """A stand-alone parameter with no backing symbol."""
    def __init__(self, nm: str = "", addr=None, tp=None, fl: int = 0) -> None:
        self._name: str = nm
        self._addr = addr if addr is not None else Address()
        self._type = tp
        self._flags: int = fl

    def getName(self) -> str:
        return self._name

    def getType(self):
        return self._type

    def getAddress(self):
        return self._addr

    def getSize(self) -> int:
        return self._type.getSize() if self._type is not None and hasattr(self._type, 'getSize') else 0

    def isTypeLocked(self) -> bool:
        return (self._flags & ParameterPieces.typelock) != 0

    def isNameLocked(self) -> bool:
        return (self._flags & ParameterPieces.namelock) != 0

    def isSizeTypeLocked(self) -> bool:
        return (self._flags & ParameterPieces.sizelock) != 0

    def isThisPointer(self) -> bool:
        return (self._flags & ParameterPieces.isthis) != 0

    def isIndirectStorage(self) -> bool:
        return (self._flags & ParameterPieces.indirectstorage) != 0

    def isHiddenReturn(self) -> bool:
        return (self._flags & ParameterPieces.hiddenretparm) != 0

    def isNameUndefined(self) -> bool:
        return len(self._name) == 0

    def setTypeLock(self, val: bool) -> None:
        if val:
            self._flags |= ParameterPieces.typelock
        else:
            self._flags &= ~ParameterPieces.typelock

    def setNameLock(self, val: bool) -> None:
        if val:
            self._flags |= ParameterPieces.namelock
        else:
            self._flags &= ~ParameterPieces.namelock

    def setThisPointer(self, val: bool) -> None:
        if val:
            self._flags |= ParameterPieces.isthis
        else:
            self._flags &= ~ParameterPieces.isthis

    def clone(self):
        return ParameterBasic(self._name, self._addr, self._type, self._flags)


class ProtoStore:
    """A collection of parameter descriptions making up a function prototype."""
    def getNumInputs(self) -> int:
        return 0

    def getInput(self, i: int):
        return None

    def getOutput(self):
        return None

    def setInput(self, i: int, nm: str, pieces) -> None:
        pass

    def setOutput(self, piece) -> None:
        pass

    def clearInput(self, i: int) -> None:
        pass

    def clearAllInputs(self) -> None:
        pass

    def clearOutput(self) -> None:
        pass

    def clone(self):
        return ProtoStore()


class ProtoStoreInternal(ProtoStore):
    """Internal storage for parameters without backing symbols."""
    def __init__(self) -> None:
        self._inparam: list = []
        self._outparam = None

    def getNumInputs(self) -> int:
        return len(self._inparam)

    def getInput(self, i: int):
        if 0 <= i < len(self._inparam):
            return self._inparam[i]
        return None

    def getOutput(self):
        return self._outparam

    def setInput(self, i: int, nm: str, pieces) -> None:
        while i >= len(self._inparam):
            self._inparam.append(None)
        addr = pieces.addr if hasattr(pieces, 'addr') else Address()
        tp = pieces.type if hasattr(pieces, 'type') else None
        fl = pieces.flags if hasattr(pieces, 'flags') else 0
        self._inparam[i] = ParameterBasic(nm, addr, tp, fl)

    def setOutput(self, piece) -> None:
        addr = piece.addr if hasattr(piece, 'addr') else Address()
        tp = piece.type if hasattr(piece, 'type') else None
        fl = piece.flags if hasattr(piece, 'flags') else 0
        self._outparam = ParameterBasic("", addr, tp, fl)

    def clearInput(self, i: int) -> None:
        if 0 <= i < len(self._inparam):
            del self._inparam[i]

    def clearAllInputs(self) -> None:
        self._inparam.clear()

    def clearOutput(self) -> None:
        self._outparam = None

    def clone(self):
        c = ProtoStoreInternal()
        for p in self._inparam:
            c._inparam.append(p.clone() if p is not None else None)
        if self._outparam is not None:
            c._outparam = self._outparam.clone()
        return c


class ScoreProtoModel:
    """Class for calculating 'goodness of fit' of parameter trials against a prototype model."""
    def __init__(self, isinput: bool, model, numparam: int) -> None:
        self._isinputscore: bool = isinput
        self._model = model
        self._finalscore: int = -1
        self._mismatch: int = 0
        self._entries: list = []

    def addParameter(self, addr, sz: int) -> None:
        self._entries.append((addr, sz))

    def doScore(self) -> None:
        """Compute the fitness score."""
        self._finalscore = 0
        self._mismatch = 0
        if self._model is None:
            self._finalscore = 500
            return
        for addr, sz in self._entries:
            if self._isinputscore:
                if hasattr(self._model, 'possibleInputParam') and not self._model.possibleInputParam(addr, sz):
                    self._mismatch += 1
                    self._finalscore += 500
            else:
                if hasattr(self._model, 'possibleOutputParam') and not self._model.possibleOutputParam(addr, sz):
                    self._mismatch += 1
                    self._finalscore += 500

    def getScore(self) -> int:
        return self._finalscore

    def getNumMismatch(self) -> int:
        return self._mismatch

    def getModel(self):
        return self._model

    def getEntries(self) -> list:
        return self._entries


class UnknownProtoModel:
    """An unrecognized prototype model that adopts placeholder behavior."""
    def __init__(self, nm: str, placeHolder) -> None:
        self._name = nm
        self._placeholderModel = placeHolder

    def getName(self) -> str:
        return self._name

    def getPlaceholderModel(self):
        return self._placeholderModel

    def isUnknown(self) -> bool:
        return True

    def setName(self, nm: str) -> None:
        self._name = nm

    def encode(self, encoder) -> None:
        pass


class ProtoModelMerged:
    """A prototype model made by merging together other models."""
    def __init__(self, glb=None) -> None:
        self._glb = glb
        self._modellist: list = []

    def numModels(self) -> int:
        return len(self._modellist)

    def getModel(self, i: int):
        return self._modellist[i]

    def foldIn(self, model) -> None:
        self._modellist.append(model)

    def selectModel(self, active) -> Optional[object]:
        """Select the best model given a set of trials."""
        if not self._modellist:
            return None
        best = None
        bestScore = 0x7FFFFFFF
        for model in self._modellist:
            scorer = ScoreProtoModel(True, model, active.getNumTrials() if hasattr(active, 'getNumTrials') else 0)
            for i in range(active.getNumTrials() if hasattr(active, 'getNumTrials') else 0):
                trial = active.getTrial(i) if hasattr(active, 'getTrial') else None
                if trial is not None:
                    scorer.addParameter(trial.getAddress(), trial.getSize())
            scorer.doScore()
            if scorer.getScore() < bestScore:
                bestScore = scorer.getScore()
                best = model
        return best

    def isMerged(self) -> bool:
        return True

    def getGlb(self):
        return self._glb

    def clearModels(self) -> None:
        self._modellist.clear()


# =========================================================================
# ParamEntry
# =========================================================================

class ParamEntry:
    """A contiguous range of memory that can be used to pass parameters."""

    force_left_justify = 1
    reverse_stack = 2
    smallsize_zext = 4
    smallsize_sext = 8
    smallsize_inttype = 0x20
    smallsize_floatext = 0x40
    is_grouped = 0x200
    overlapping = 0x400
    first_storage = 0x800

    def __init__(self, group: int = 0) -> None:
        self.flags: int = 0
        self.type: TypeClass = TypeClass.TYPECLASS_GENERAL
        self.groupSet: List[int] = [group]
        self.spaceid: Optional[AddrSpace] = None
        self.addressbase: int = 0
        self.size: int = 0
        self.minsize: int = 1
        self.alignment: int = 0
        self.numslots: int = 0

    def getGroup(self) -> int:
        return self.groupSet[0]

    def getAllGroups(self) -> List[int]:
        return self.groupSet

    def getSize(self) -> int:
        return self.size

    def getMinSize(self) -> int:
        return self.minsize

    def getAlign(self) -> int:
        return self.alignment

    def getType(self) -> TypeClass:
        return self.type

    def isExclusion(self) -> bool:
        return self.alignment == 0

    def isReverseStack(self) -> bool:
        return (self.flags & ParamEntry.reverse_stack) != 0

    def isGrouped(self) -> bool:
        return (self.flags & ParamEntry.is_grouped) != 0

    def isOverlap(self) -> bool:
        return (self.flags & ParamEntry.overlapping) != 0

    def isFirstInClass(self) -> bool:
        return (self.flags & ParamEntry.first_storage) != 0

    def getSpace(self) -> Optional[AddrSpace]:
        return self.spaceid

    def getBase(self) -> int:
        return self.addressbase

    def containedBy(self, addr: Address, sz: int) -> bool:
        if addr.getSpace() is not self.spaceid:
            return False
        if addr.getOffset() < self.addressbase:
            return False
        return (addr.getOffset() + sz) <= (self.addressbase + self.size)

    def intersects(self, addr: Address, sz: int) -> bool:
        if addr.getSpace() is not self.spaceid:
            return False
        end1 = self.addressbase + self.size
        end2 = addr.getOffset() + sz
        return not (addr.getOffset() >= end1 or self.addressbase >= end2)

    def getNumSlots(self) -> int:
        return self.numslots

    def isLeftJustified(self) -> bool:
        return (self.flags & ParamEntry.force_left_justify) != 0

    def justifiedContain(self, addr: Address, sz: int) -> int:
        if not self.containedBy(addr, sz):
            return -1
        return addr.getOffset() - self.addressbase

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass


# =========================================================================
# ParamList (abstract)
# =========================================================================

class ParamList(ABC):
    """An ordered list of parameter storage locations."""

    @abstractmethod
    def getNumParamEntry(self) -> int: ...

    @abstractmethod
    def getEntry(self, i: int) -> ParamEntry: ...


class ParamListStandard(ParamList):
    """A standard ordered list of parameter entries."""

    def __init__(self) -> None:
        self.entry: List[ParamEntry] = []
        self.spacebase: Optional[AddrSpace] = None
        self.maxdelay: int = 0
        self.pointermax: int = 0
        self.thisbeforeret: bool = False
        self.nonfloatgroup: int = 0

    def getNumParamEntry(self) -> int:
        return len(self.entry)

    def getEntry(self, i: int) -> ParamEntry:
        return self.entry[i]

    def addEntry(self, e: ParamEntry) -> None:
        self.entry.append(e)

    def getSpacebase(self):
        return self.spacebase

    def getMaxDelay(self) -> int:
        return self.maxdelay

    def getPointerMax(self) -> int:
        return self.pointermax

    def possibleParam(self, loc, size: int) -> bool:
        for e in self.entry:
            if e.containedBy(loc, size):
                return True
        return False

    def fillinMap(self, active) -> None:
        pass


# =========================================================================
# ProtoModel
# =========================================================================

class ProtoModel:
    """A prototype model: calling convention description.

    Describes how parameters and return values are passed for a given
    calling convention (e.g. cdecl, stdcall, fastcall, etc.)
    """

    extrapop_unknown = 0x8000

    def __init__(self, name: str = "", glb=None) -> None:
        self.name: str = name
        self.glb = glb  # Architecture
        self.input: Optional[ParamListStandard] = None
        self.output: Optional[ParamListStandard] = None
        self.extrapop: int = 0
        self.stackshift: int = 0
        self.hasThis: bool = False
        self.isConstruct: bool = False
        self.hasUponEntry: bool = False
        self.hasUponReturn: bool = False
        self.defaultLocalRange: RangeList = RangeList()
        self.defaultParamRange: RangeList = RangeList()
        self.unaffected: List[VarnodeData] = []
        self.killedbycall: List[VarnodeData] = []
        self.likelytrash: List[VarnodeData] = []
        self.internalStorage: List[VarnodeData] = []
        self.compatModel: Optional[ProtoModel] = None

    def getName(self) -> str:
        return self.name

    def getArch(self):
        return self.glb

    def getAliasParent(self):
        return self.compatModel

    def getExtraPop(self) -> int:
        return self.extrapop

    def setExtraPop(self, ep: int) -> None:
        self.extrapop = ep

    def getStackshift(self) -> int:
        return self.stackshift

    def hasThisPointer(self) -> bool:
        return self.hasThis

    def isConstructor(self) -> bool:
        return self.isConstruct

    def printInDecl(self) -> bool:
        return getattr(self, '_isPrinted', False)

    def setPrintInDecl(self, val: bool) -> None:
        self._isPrinted = val

    def getInjectUponEntry(self) -> int:
        return getattr(self, '_injectUponEntry', -1)

    def getInjectUponReturn(self) -> int:
        return getattr(self, '_injectUponReturn', -1)

    def isCompatible(self, op2) -> bool:
        if op2 is self:
            return True
        if self.compatModel is not None and self.compatModel is op2:
            return True
        if op2 is not None and op2.compatModel is self:
            return True
        return False

    def hasEffect(self, addr, size: int):
        """Determine side-effect of this model on the given memory range."""
        for eff in getattr(self, '_effectlist', []):
            if hasattr(eff, 'getAddress') and hasattr(eff, 'getSize'):
                if eff.getAddress() == addr and eff.getSize() >= size:
                    return eff.getType() if hasattr(eff, 'getType') else 'unknown'
        return 'unknown'

    def deriveInputMap(self, active) -> None:
        if self.input is not None and hasattr(self.input, 'fillinMap'):
            self.input.fillinMap(active)

    def deriveOutputMap(self, active) -> None:
        if self.output is not None and hasattr(self.output, 'fillinMap'):
            self.output.fillinMap(active)

    def assignParameterStorage(self, proto, res: list, ignoreOutputError: bool = False) -> None:
        pass

    def checkInputJoin(self, hiaddr, hisize: int, loaddr, losize: int) -> bool:
        if self.input is not None and hasattr(self.input, 'checkJoin'):
            return self.input.checkJoin(hiaddr, hisize, loaddr, losize)
        return False

    def checkOutputJoin(self, hiaddr, hisize: int, loaddr, losize: int) -> bool:
        if self.output is not None and hasattr(self.output, 'checkJoin'):
            return self.output.checkJoin(hiaddr, hisize, loaddr, losize)
        return False

    def checkInputSplit(self, loc, size: int, splitpoint: int) -> bool:
        if self.input is not None and hasattr(self.input, 'checkSplit'):
            return self.input.checkSplit(loc, size, splitpoint)
        return False

    def characterizeAsInputParam(self, loc, size: int) -> int:
        if self.input is not None and hasattr(self.input, 'characterizeAsParam'):
            return self.input.characterizeAsParam(loc, size)
        return 0

    def characterizeAsOutput(self, loc, size: int) -> int:
        if self.output is not None and hasattr(self.output, 'characterizeAsParam'):
            return self.output.characterizeAsParam(loc, size)
        return 0

    def possibleInputParam(self, loc, size: int) -> bool:
        if self.input is not None and hasattr(self.input, 'possibleParam'):
            return self.input.possibleParam(loc, size)
        return False

    def possibleOutputParam(self, loc, size: int) -> bool:
        if self.output is not None and hasattr(self.output, 'possibleParam'):
            return self.output.possibleParam(loc, size)
        return False

    def getBiggestContainedInputParam(self, loc, size: int, res) -> bool:
        if self.input is not None and hasattr(self.input, 'getBiggestContainedParam'):
            return self.input.getBiggestContainedParam(loc, size, res)
        return False

    def getBiggestContainedOutput(self, loc, size: int, res) -> bool:
        if self.output is not None and hasattr(self.output, 'getBiggestContainedParam'):
            return self.output.getBiggestContainedParam(loc, size, res)
        return False

    def getSpacebase(self):
        if self.input is not None:
            return self.input.spacebase
        return None

    def isStackGrowsNegative(self) -> bool:
        return getattr(self, '_stackgrowsnegative', True)

    def getLocalRange(self):
        return self.defaultLocalRange

    def getParamRange(self):
        return self.defaultParamRange

    def getMaxInputDelay(self) -> int:
        if self.input is not None:
            return self.input.maxdelay
        return 0

    def getMaxOutputDelay(self) -> int:
        if self.output is not None:
            return self.output.maxdelay
        return 0

    def isAutoKilledByCall(self) -> bool:
        return False

    def isMerged(self) -> bool:
        return False

    def isUnknown(self) -> bool:
        return False

    @staticmethod
    def lookupEffect(efflist: list, addr, size: int) -> int:
        for eff in efflist:
            if hasattr(eff, 'getAddress') and eff.getAddress() == addr:
                if hasattr(eff, 'getSize') and eff.getSize() >= size:
                    return eff.getType() if hasattr(eff, 'getType') else 4
        return 4  # unknown_effect

    def getInput(self) -> Optional[ParamListStandard]:
        return self.input

    def getOutput(self) -> Optional[ParamListStandard]:
        return self.output

    def getUnaffected(self) -> List[VarnodeData]:
        return self.unaffected

    def getKilledByCall(self) -> List[VarnodeData]:
        return self.killedbycall

    def getLikelyTrash(self) -> List[VarnodeData]:
        return self.likelytrash

    def getInternalStorage(self) -> List[VarnodeData]:
        return self.internalStorage

    def numEffects(self) -> int:
        return len(getattr(self, '_effectlist', []))

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    def __repr__(self) -> str:
        return f"ProtoModel({self.name!r})"


# =========================================================================
# ParameterPieces
# =========================================================================

class ParameterPieces:
    """Raw pieces of a function parameter or return value."""

    def __init__(self) -> None:
        self.type: Optional[Datatype] = None
        self.addr: Address = Address()
        self.name: str = ""
        self.flags: int = 0

    def getType(self):
        return self.type

    def getAddress(self) -> Address:
        return self.addr

    def getName(self) -> str:
        return self.name

    def getFlags(self) -> int:
        return self.flags

    def setFlags(self, fl: int) -> None:
        self.flags = fl


class PrototypePieces:
    """Raw pieces of a function prototype."""

    def __init__(self) -> None:
        self.model: Optional[ProtoModel] = None
        self.name: str = ""
        self.intypes: List[Datatype] = []
        self.innames: List[str] = []
        self.outtype: Optional[Datatype] = None
        self.dotdotdot: bool = False
        self.firstVarArgSlot: int = -1

    def getModel(self):
        return self.model

    def getName(self) -> str:
        return self.name

    def getOuttype(self):
        return self.outtype

    def getNumInputs(self) -> int:
        return len(self.intypes)

    def isDotdotdot(self) -> bool:
        return self.dotdotdot


# =========================================================================
# ProtoParameter
# =========================================================================

class ProtoParameter:
    """A single parameter in a function prototype."""

    def __init__(self, name: str = "", tp: Optional[Datatype] = None,
                 addr: Optional[Address] = None, sz: int = 0) -> None:
        self.name: str = name
        self.type: Optional[Datatype] = tp
        self.addr: Address = addr if addr is not None else Address()
        self.size: int = sz
        self.flags: int = 0

    def getName(self) -> str:
        return self.name

    def getType(self) -> Optional[Datatype]:
        return self.type

    def getAddress(self) -> Address:
        return self.addr

    def getSize(self) -> int:
        return self.size

    def isTypeLocked(self) -> bool:
        from ghidra.ir.varnode import Varnode
        return (self.flags & Varnode.typelock) != 0

    def isNameLocked(self) -> bool:
        from ghidra.ir.varnode import Varnode
        return (self.flags & Varnode.namelock) != 0

    def setName(self, nm: str) -> None:
        self.name = nm

    def setType(self, tp) -> None:
        self.type = tp

    def setAddress(self, addr: Address) -> None:
        self.addr = addr

    def setSize(self, sz: int) -> None:
        self.size = sz

    def clone(self):
        p = ProtoParameter(self.name, self.type, self.addr, self.size)
        p.flags = self.flags
        return p


# =========================================================================
# FuncProto
# =========================================================================

class FuncProto:
    """A function prototype: return type + parameters + calling convention.

    Describes the formal interface to a function.
    """

    voidinputlock = 1
    modellock = 2
    is_inline = 4
    no_return = 8
    paramshift_applied = 16
    error_inputparam = 32
    error_outputparam = 64
    custom_storage = 128
    unknown_model = 256
    is_constructor = 0x200
    is_destructor = 0x400
    has_thisptr = 0x800
    is_override = 0x1000

    def __init__(self) -> None:
        self.model: Optional[ProtoModel] = None
        self.store: List[ProtoParameter] = []
        self.outparam: Optional[ProtoParameter] = None
        self.flags: int = 0
        self.extrapop: int = ProtoModel.extrapop_unknown
        self.injectId: int = -1

    def getModel(self) -> Optional[ProtoModel]:
        return self.model

    def setModel(self, m: ProtoModel) -> None:
        self.model = m

    def numParams(self) -> int:
        return len(self.store)

    def getParam(self, i: int) -> ProtoParameter:
        return self.store[i]

    def getOutput(self) -> Optional[ProtoParameter]:
        return self.outparam

    def setOutput(self, p: ProtoParameter) -> None:
        self.outparam = p

    def addParam(self, p: ProtoParameter) -> None:
        self.store.append(p)

    def clearParams(self) -> None:
        self.store.clear()

    def isModelLocked(self) -> bool:
        return (self.flags & FuncProto.modellock) != 0

    def isInputLocked(self) -> bool:
        return (self.flags & FuncProto.voidinputlock) != 0 or len(self.store) > 0

    def isOutputLocked(self) -> bool:
        return self.outparam is not None and self.outparam.isTypeLocked()

    def isInline(self) -> bool:
        return (self.flags & FuncProto.is_inline) != 0

    def isNoReturn(self) -> bool:
        return (self.flags & FuncProto.no_return) != 0

    def isConstructor(self) -> bool:
        return (self.flags & FuncProto.is_constructor) != 0

    def isDestructor(self) -> bool:
        return (self.flags & FuncProto.is_destructor) != 0

    def hasThisPointer(self) -> bool:
        return (self.flags & FuncProto.has_thisptr) != 0

    dotdotdot = 0x2000
    auto_killedbycall = 0x4000

    def isDotdotdot(self) -> bool:
        return (self.flags & FuncProto.dotdotdot) != 0

    def setDotdotdot(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.dotdotdot
        else:
            self.flags &= ~FuncProto.dotdotdot

    def isOverride(self) -> bool:
        return (self.flags & FuncProto.is_override) != 0

    def setOverride(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.is_override
        else:
            self.flags &= ~FuncProto.is_override

    def hasCustomStorage(self) -> bool:
        return (self.flags & FuncProto.custom_storage) != 0

    def getSpacebase(self):
        return self.model.getSpacebase() if self.model else None

    def isStackGrowsNegative(self) -> bool:
        return self.model.isStackGrowsNegative() if self.model else True

    def getLocalRange(self):
        return self.model.getLocalRange() if self.model else None

    def getParamRange(self):
        return self.model.getParamRange() if self.model else None

    def getArch(self):
        return self.model.getArch() if self.model else None

    def characterizeAsInputParam(self, addr, size: int) -> int:
        return self.model.characterizeAsInputParam(addr, size) if self.model else 0

    def characterizeAsOutput(self, addr, size: int) -> int:
        return self.model.characterizeAsOutput(addr, size) if self.model else 0

    def possibleInputParam(self, addr, size: int) -> bool:
        return self.model.possibleInputParam(addr, size) if self.model else False

    def possibleOutputParam(self, addr, size: int) -> bool:
        return self.model.possibleOutputParam(addr, size) if self.model else False

    def getBiggestContainedInputParam(self, loc, size: int, res) -> bool:
        return self.model.getBiggestContainedInputParam(loc, size, res) if self.model else False

    def getBiggestContainedOutput(self, loc, size: int, res) -> bool:
        return self.model.getBiggestContainedOutput(loc, size, res) if self.model else False

    def hasEffect(self, addr, size: int) -> int:
        if self.model is not None:
            return self.model.hasEffect(addr, size)
        return EffectRecord.unknown_effect

    def deriveInputMap(self, active) -> None:
        if self.model is not None:
            self.model.deriveInputMap(active)

    def deriveOutputMap(self, active) -> None:
        if self.model is not None:
            self.model.deriveOutputMap(active)

    def checkInputJoin(self, hiaddr, hisz: int, loaddr, losz: int) -> bool:
        return self.model.checkInputJoin(hiaddr, hisz, loaddr, losz) if self.model else False

    def checkInputSplit(self, loc, size: int, splitpoint: int) -> bool:
        return self.model.checkInputSplit(loc, size, splitpoint) if self.model else False

    def assumedInputExtension(self, addr, size: int, res=None):
        return OpCode.CPUI_COPY

    def assumedOutputExtension(self, addr, size: int, res=None):
        return OpCode.CPUI_COPY

    def unjustifiedInputParam(self, addr, size: int, res=None) -> bool:
        return False

    def getThisPointerStorage(self, dt=None):
        return Address()

    def isCompatible(self, op2) -> bool:
        if self.model is not None and op2.model is not None:
            return self.model.isCompatible(op2.model)
        return False

    def isAutoKilledByCall(self) -> bool:
        if self.model is not None and hasattr(self.model, 'isAutoKilledByCall'):
            return self.model.isAutoKilledByCall()
        return (self.flags & FuncProto.auto_killedbycall) != 0

    def getMaxInputDelay(self) -> int:
        return self.model.getMaxInputDelay() if self.model else 0

    def getMaxOutputDelay(self) -> int:
        return self.model.getMaxOutputDelay() if self.model else 0

    def getPieces(self, pieces) -> None:
        """Get the raw pieces of the prototype."""
        if pieces is not None:
            pieces.model = self.model
            pieces.outtype = self.outparam.getType() if self.outparam else None
            pieces.intypes = [p.getType() for p in self.store if p is not None]
            pieces.innames = [p.getName() for p in self.store if p is not None]

    def setPieces(self, pieces) -> None:
        """Set this prototype based on raw pieces."""
        if pieces is not None:
            if pieces.model is not None:
                self.model = pieces.model
            self.store.clear()
            for i, tp in enumerate(pieces.intypes):
                nm = pieces.innames[i] if i < len(pieces.innames) else ""
                p = ProtoParameter(tp)
                if hasattr(p, '_name'):
                    p._name = nm
                self.store.append(p)
            if pieces.outtype is not None:
                self.outparam = ProtoParameter(pieces.outtype)

    def setScope(self, s, startpoint) -> None:
        """Set a backing symbol Scope for this."""
        pass

    def resolveModel(self, active) -> None:
        """Resolve the prototype model from active trials."""
        pass

    def updateInputTypes(self, data, triallist: list, activeinput) -> None:
        pass

    def updateInputNoTypes(self, data, triallist: list, activeinput) -> None:
        pass

    def updateOutputTypes(self, triallist: list) -> None:
        pass

    def updateOutputNoTypes(self, triallist: list, factory=None) -> None:
        pass

    def updateAllTypes(self, proto) -> None:
        """Update all types from a PrototypePieces."""
        self.setPieces(proto)

    def resolveExtraPop(self) -> None:
        """Resolve the extrapop value."""
        if self.model is not None:
            self.extrapop = self.model.getExtraPop()

    def paramShift(self, shift: int) -> None:
        """Add parameters to the front of the input parameter list."""
        pass

    def setReturnBytesConsumed(self, val: int) -> bool:
        return False

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder, glb=None) -> None:
        pass

    def printRaw(self, funcname: str = "") -> str:
        parts = []
        if self.outparam is not None and self.outparam.getType() is not None:
            parts.append(str(self.outparam.getType()))
        else:
            parts.append("void")
        parts.append(f" {funcname}(")
        for i, p in enumerate(self.store):
            if i > 0:
                parts.append(", ")
            if p.getType() is not None:
                parts.append(str(p.getType()))
            if hasattr(p, 'getName') and p.getName():
                parts.append(f" {p.getName()}")
        parts.append(")")
        return "".join(parts)

    def copyFlowEffects(self, op2) -> None:
        """Copy properties that affect data-flow."""
        if op2 is not None:
            if op2.isInline():
                self.setInline(True)
            if op2.isNoReturn():
                self.setNoReturn(True)
            self.injectId = op2.injectId

    def getExtraPop(self) -> int:
        return self.extrapop

    def setExtraPop(self, val: int) -> None:
        self.extrapop = val

    def setNoReturn(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.no_return
        else:
            self.flags &= ~FuncProto.no_return

    def setInline(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.is_inline
        else:
            self.flags &= ~FuncProto.is_inline

    def getOutputType(self):
        if self.outparam is not None:
            return self.outparam.getType()
        return None

    def getModelName(self):
        return self.model.getName() if self.model else ""

    def isModelUnknown(self):
        return (self.flags & FuncProto.unknown_model) != 0

    def isOverride(self):
        return (self.flags & FuncProto.is_override) != 0

    def printModelInDecl(self):
        return self.model is not None and (self.flags & FuncProto.modellock) != 0

    def getInjectId(self):
        return self.injectId

    def setInjectId(self, val):
        self.injectId = val

    def cancelInjectId(self):
        self.injectId = -1

    def getReturnBytesConsumed(self):
        if self.outparam is not None and self.outparam.getType() is not None:
            return self.outparam.getType().getSize()
        return 0

    def setParamshift(self, val):
        self.paramshift = val if hasattr(self, 'paramshift') else 0

    def isParamshiftApplied(self):
        return (self.flags & FuncProto.paramshift_applied) != 0

    def setParamshiftApplied(self):
        self.flags |= FuncProto.paramshift_applied

    def hasInputErrors(self):
        return (self.flags & FuncProto.error_inputparam) != 0

    def hasOutputErrors(self):
        return (self.flags & FuncProto.error_outputparam) != 0

    def setInputErrors(self, val):
        if val: self.flags |= FuncProto.error_inputparam
        else: self.flags &= ~FuncProto.error_inputparam

    def setOutputErrors(self, val):
        if val: self.flags |= FuncProto.error_outputparam
        else: self.flags &= ~FuncProto.error_outputparam

    def isInputLocked(self):
        return (self.flags & FuncProto.voidinputlock) != 0 or len(self.store) > 0

    def isOutputLocked(self):
        return self.outparam is not None and self.outparam.isTypeLocked()

    def setModelLock(self, val):
        if val: self.flags |= FuncProto.modellock
        else: self.flags &= ~FuncProto.modellock

    def setConstructor(self, val):
        if val: self.flags |= FuncProto.is_constructor
        else: self.flags &= ~FuncProto.is_constructor

    def setDestructor(self, val):
        if val: self.flags |= FuncProto.is_destructor
        else: self.flags &= ~FuncProto.is_destructor

    def setThisPointer(self, val):
        if val: self.flags |= FuncProto.has_thisptr
        else: self.flags &= ~FuncProto.has_thisptr

    def getComparableFlags(self):
        return self.flags & (FuncProto.voidinputlock | FuncProto.modellock | FuncProto.is_inline | FuncProto.no_return | FuncProto.has_thisptr | FuncProto.is_constructor | FuncProto.is_destructor)

    def getMaxInputDelay(self):
        if self.model and self.model.input:
            return self.model.input.maxdelay
        return 0

    def getMaxOutputDelay(self):
        if self.model and self.model.output:
            return self.model.output.maxdelay
        return 0

    def getModelExtraPop(self):
        return self.model.getExtraPop() if self.model else 0

    def clearInput(self):
        self.store.clear()

    def clearUnlockedInput(self):
        self.store = [p for p in self.store if p.isTypeLocked()]

    def clearUnlockedOutput(self):
        if self.outparam and not self.outparam.isTypeLocked():
            self.outparam = None

    def copy(self, other):
        self.model = other.model
        self.store = list(other.store)
        self.outparam = other.outparam
        self.flags = other.flags
        self.extrapop = other.extrapop
        self.injectId = other.injectId

    def setCustomStorage(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.custom_storage
        else:
            self.flags &= ~FuncProto.custom_storage

    def setVoidInputLock(self, val: bool) -> None:
        if val:
            self.flags |= FuncProto.voidinputlock
        else:
            self.flags &= ~FuncProto.voidinputlock

    def getFlags(self) -> int:
        return self.flags

    def __repr__(self) -> str:
        model_name = self.model.getName() if self.model else "?"
        return f"FuncProto(model={model_name}, params={len(self.store)})"


# =========================================================================
# FuncCallSpecs
# =========================================================================

class FuncCallSpecs:
    """Specifications for a particular function call site.

    Holds the prototype information and parameter/return assignments
    for a specific CALL operation within a function body.
    """

    def __init__(self, op=None) -> None:
        self.op = op  # PcodeOp (the CALL op)
        self.fd = None  # Funcdata of the called function (if known)
        self.entryaddress: Address = Address()
        self.name: str = ""
        self.proto: FuncProto = FuncProto()
        self.effective_extrapop: int = ProtoModel.extrapop_unknown
        self.stackoffset: int = 0
        self.paramshift: int = 0
        self.matchCallCount: int = 0
        self.isinputactive: bool = False
        self.isoutputactive: bool = False

    def getOp(self):
        return self.op

    def getEntryAddress(self) -> Address:
        return self.entryaddress

    def setAddress(self, addr: Address) -> None:
        self.entryaddress = addr

    def getName(self) -> str:
        return self.name

    def setName(self, nm: str) -> None:
        self.name = nm

    def getFuncdata(self):
        return self.fd

    def setFuncdata(self, f) -> None:
        self.fd = f

    def getProto(self) -> FuncProto:
        return self.proto

    def numParams(self) -> int:
        return self.proto.numParams()

    def getParam(self, i: int) -> ProtoParameter:
        return self.proto.getParam(i)

    def getEffectiveExtraPop(self) -> int:
        return self.effective_extrapop

    def isInputActive(self) -> bool:
        return self.isinputactive

    def isOutputActive(self) -> bool:
        return self.isoutputactive

    def hasThisPointer(self):
        return self.proto.hasThisPointer()

    def getSymbol(self):
        return getattr(self, '_symbol', None)

    def setSymbol(self, sym):
        self._symbol = sym

    def getStackOffset(self):
        return self.stackoffset

    def setStackOffset(self, val):
        self.stackoffset = val

    def getParamshift(self):
        return self.paramshift

    def setParamshift(self, val):
        self.paramshift = val

    def getMatchCallCount(self):
        return self.matchCallCount

    def setMatchCallCount(self, val):
        self.matchCallCount = val

    def setInputActive(self, val):
        self.isinputactive = val

    def setOutputActive(self, val):
        self.isoutputactive = val

    def isInline(self):
        return self.proto.isInline()

    def isNoReturn(self):
        return self.proto.isNoReturn()

    def getExtraPop(self):
        return self.proto.getExtraPop()

    def setEffectiveExtraPop(self, val):
        self.effective_extrapop = val

    def hasModel(self):
        return self.proto.getModel() is not None

    def getModelName(self):
        return self.proto.getModelName()

    offset_unknown = 0x80000000

    def copyFlowEffects(self, proto) -> None:
        """Copy flow effects (inline, noreturn) from given prototype."""
        if proto is not None:
            if hasattr(proto, 'isInline') and proto.isInline():
                self.proto.setInline(True)
            if hasattr(proto, 'isNoReturn') and proto.isNoReturn():
                self.proto.setNoReturn(True)
            if hasattr(proto, 'getInjectId'):
                self.proto.setInjectId(proto.getInjectId())

    def hasEffect(self, addr, size: int):
        """Determine the effect of the call on the given memory range."""
        if self.proto.model is not None:
            return self.proto.model.hasEffect(addr, size)
        return 'unknown'

    def hasEffectTranslate(self, addr, size: int):
        """Determine effect, translating for stack-based addresses."""
        return self.hasEffect(addr, size)

    def getSpacebaseOffset(self) -> int:
        """Get the offset for stack-based parameters."""
        return self.stackoffset

    def getActiveInput(self):
        """Get the active input ParamActive, or None."""
        return getattr(self, '_activeInput', None)

    def getActiveOutput(self):
        """Get the active output ParamActive, or None."""
        return getattr(self, '_activeOutput', None)

    def isStackOutputLock(self) -> bool:
        return False

    def characterizeAsOutput(self, addr, size: int) -> int:
        """Characterize whether the given range overlaps output storage."""
        if self.proto.model is not None and hasattr(self.proto.model, 'characterizeAsOutput'):
            return self.proto.model.characterizeAsOutput(addr, size)
        return ParamEntry.no_containment if hasattr(ParamEntry, 'no_containment') else 0

    def characterizeAsInputParam(self, addr, size: int) -> int:
        """Characterize whether the given range overlaps input parameter storage."""
        if self.proto.model is not None and hasattr(self.proto.model, 'characterizeAsInputParam'):
            return self.proto.model.characterizeAsInputParam(addr, size)
        return 0

    def getBiggestContainedInputParam(self, addr, size: int, res) -> bool:
        """Pass-back the biggest input parameter contained within the given range."""
        return False

    def getBiggestContainedOutput(self, addr, size: int, res) -> bool:
        """Pass-back the biggest possible output contained within the given range."""
        return False

    def getOutput(self):
        """Get the output parameter."""
        return self.proto.outparam

    def getInjectId(self) -> int:
        return self.proto.getInjectId()

    def setNoReturn(self, val: bool) -> None:
        self.proto.setNoReturn(val)

    def setBadJumpTable(self, val: bool) -> None:
        self._badJumpTable = val

    def setInternal(self, model, rettype) -> None:
        """Set internal calling convention."""
        self.proto.model = model
        if rettype is not None:
            self.proto.outparam = ProtoParameter(rettype)

    def setInputLock(self, val: bool) -> None:
        if val:
            self.proto.flags |= FuncProto.voidinputlock

    def setOutputLock(self, val: bool) -> None:
        pass

    def abortSpacebaseRelative(self, fd) -> None:
        """Abort any spacebase-relative analysis for this call."""
        pass

    def isAutoKilledByCall(self) -> bool:
        if self.proto.model is not None and hasattr(self.proto.model, 'isAutoKilledByCall'):
            return self.proto.model.isAutoKilledByCall()
        return False

    def initActiveInput(self) -> None:
        """Turn on analysis recovering input parameters."""
        self.isinputactive = True
        if not hasattr(self, '_activeInput') or self._activeInput is None:
            from ghidra.fspec.paramactive import ParamActive
            self._activeInput = ParamActive(True)

    def clearActiveInput(self) -> None:
        """Turn off analysis recovering input parameters."""
        self.isinputactive = False

    def initActiveOutput(self) -> None:
        """Turn on analysis recovering the return value."""
        self.isoutputactive = True
        if not hasattr(self, '_activeOutput') or self._activeOutput is None:
            from ghidra.fspec.paramactive import ParamActive
            self._activeOutput = ParamActive(False)

    def clearActiveOutput(self) -> None:
        """Turn off analysis recovering the return value."""
        self.isoutputactive = False

    def isBadJumpTable(self) -> bool:
        return getattr(self, '_badJumpTable', False)

    def setStackOutputLock(self, val: bool) -> None:
        self._isstackoutputlock = val

    def getStackPlaceholderSlot(self) -> int:
        return getattr(self, '_stackPlaceholderSlot', -1)

    def setStackPlaceholderSlot(self, slot: int) -> None:
        self._stackPlaceholderSlot = slot
        if self.isinputactive and hasattr(self, '_activeInput') and self._activeInput is not None:
            self._activeInput.setPlaceholderSlot()

    def clearStackPlaceholderSlot(self) -> None:
        self._stackPlaceholderSlot = -1
        if self.isinputactive and hasattr(self, '_activeInput') and self._activeInput is not None:
            self._activeInput.freePlaceholderSlot()

    def clone(self, newop=None):
        """Clone this FuncCallSpecs given the mirrored p-code CALL."""
        fc = FuncCallSpecs(newop if newop is not None else self.op)
        fc.name = self.name
        fc.entryaddress = self.entryaddress
        fc.fd = self.fd
        fc.proto.copy(self.proto)
        fc.effective_extrapop = self.effective_extrapop
        fc.stackoffset = self.stackoffset
        fc.paramshift = self.paramshift
        fc.matchCallCount = self.matchCallCount
        return fc

    def deindirect(self, data, newfd) -> None:
        """Convert an indirect call to a direct call."""
        if newfd is not None:
            self.fd = newfd
            if hasattr(newfd, 'getName'):
                self.name = newfd.getName()
            if hasattr(newfd, 'getAddress'):
                self.entryaddress = newfd.getAddress()

    def forceSet(self, data, fp) -> None:
        """Force the prototype to match a given FuncProto."""
        self.proto.copy(fp)

    def insertPcode(self, data) -> None:
        """Insert p-code for this call (e.g. inject callfixup)."""
        pass

    def createPlaceholder(self, data, spacebase) -> None:
        """Create a stack-pointer placeholder input for this call."""
        pass

    def resolveSpacebaseRelative(self, data, phvn) -> None:
        """Resolve the spacebase-relative placeholder."""
        if phvn is not None and hasattr(phvn, 'getOffset'):
            self.stackoffset = phvn.getOffset()

    def finalInputCheck(self) -> None:
        """Perform final check on input parameters."""
        pass

    def checkInputTrialUse(self, data, aliascheck=None) -> None:
        """Check which input trials are actually used."""
        pass

    def checkOutputTrialUse(self, data, trialvn: list = None) -> None:
        """Check which output trials are actually used."""
        pass

    def buildInputFromTrials(self, data) -> None:
        """Build input parameters from trial analysis."""
        pass

    def buildOutputFromTrials(self, data, trialvn: list = None) -> None:
        """Build output (return value) from trial analysis."""
        pass

    def collectOutputTrialVarnodes(self, trialvn: list) -> None:
        """Collect Varnodes that could be return values."""
        pass

    def getInputBytesConsumed(self, slot: int) -> int:
        """Get number of bytes consumed by sub-function for given input slot."""
        return 0

    def setInputBytesConsumed(self, slot: int, val: int) -> bool:
        """Set number of bytes consumed by sub-function for given input slot."""
        return False

    def paramshiftModifyStart(self) -> None:
        """Begin parameter shift modification."""
        pass

    def paramshiftModifyStop(self, data) -> bool:
        """End parameter shift modification."""
        return False

    def checkInputJoin(self, slot1: int, ishislot: bool, vn1, vn2) -> bool:
        """Check if two input Varnodes can be joined into a single parameter."""
        return False

    def doInputJoin(self, slot1: int, ishislot: bool) -> None:
        """Join two input trials into a single parameter."""
        pass

    def lateRestriction(self, restrictedProto, newinput: list, newoutput: list) -> bool:
        """Apply a late restriction from a resolved prototype."""
        return False

    @staticmethod
    def compareByEntryAddress(a, b) -> bool:
        """Compare FuncCallSpecs by function entry address."""
        return a.entryaddress < b.entryaddress

    @staticmethod
    def countMatchingCalls(qlst: list) -> None:
        """Count how many calls target the same sub-function."""
        counts = {}
        for fc in qlst:
            key = fc.entryaddress
            counts[key] = counts.get(key, 0) + 1
        for fc in qlst:
            fc.matchCallCount = counts.get(fc.entryaddress, 1)

    @staticmethod
    def findPreexistingWhole(vn1, vn2):
        """Find a pre-existing whole Varnode from two pieces."""
        return None

    @staticmethod
    def getFspecFromConst(addr):
        """Retrieve the FuncCallSpecs from an encoded constant address."""
        return None

    def getProtoModel(self):
        return self.proto.getModel()

    def isInputLocked(self) -> bool:
        return self.proto.isInputLocked()

    def __repr__(self) -> str:
        return f"FuncCallSpecs({self.name!r} @ {self.entryaddress})"
