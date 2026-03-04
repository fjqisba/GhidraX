"""
Corresponds to: inject_sleigh.hh / inject_sleigh.cc / pcodeinject.hh

P-code injection library for call fixups, callother fixups, and executable p-code.
"""

from __future__ import annotations
from typing import Optional, List, Dict
from ghidra.core.address import Address


class InjectPayload:
    """A snippet of p-code that can be injected at various points."""

    CALLFIXUP_TYPE = 1
    CALLOTHERFIXUP_TYPE = 2
    CALLMECHANISM_TYPE = 3
    EXECUTABLEPCODE_TYPE = 4

    def __init__(self, nm: str = "", tp: int = 0) -> None:
        self.name: str = nm
        self.type: int = tp
        self.paramshift: int = 0
        self.dynamic: bool = False
        self.incidentalcopy: bool = False

    def getName(self) -> str:
        return self.name

    def getType(self) -> int:
        return self.type

    def getParamShift(self) -> int:
        return self.paramshift

    def isDynamic(self) -> bool:
        return self.dynamic

    def isIncidentalCopy(self) -> bool:
        return self.incidentalcopy


class InjectContext:
    """Context for a particular p-code injection site."""

    def __init__(self) -> None:
        self.baseaddr: Address = Address()
        self.nextaddr: Address = Address()
        self.calladdr: Address = Address()
        self.inputlist: list = []
        self.output: list = []


class PcodeInjectLibrary:
    """A library of p-code injection payloads.

    Manages call fixups, callother fixups, and executable p-code snippets.
    Each payload is registered by name and assigned a unique id.
    """

    def __init__(self) -> None:
        self._payloads: List[InjectPayload] = []
        self._namemap: Dict[str, int] = {}
        self._callFixupMap: Dict[str, int] = {}
        self._callOtherFixupMap: Dict[str, int] = {}
        self._callMechMap: Dict[str, int] = {}
        self._exePcodeMap: Dict[str, int] = {}

    def registerPayload(self, payload: InjectPayload) -> int:
        idx = len(self._payloads)
        self._payloads.append(payload)
        self._namemap[payload.name] = idx
        if payload.type == InjectPayload.CALLFIXUP_TYPE:
            self._callFixupMap[payload.name] = idx
        elif payload.type == InjectPayload.CALLOTHERFIXUP_TYPE:
            self._callOtherFixupMap[payload.name] = idx
        elif payload.type == InjectPayload.CALLMECHANISM_TYPE:
            self._callMechMap[payload.name] = idx
        elif payload.type == InjectPayload.EXECUTABLEPCODE_TYPE:
            self._exePcodeMap[payload.name] = idx
        return idx

    def getPayload(self, idx: int) -> Optional[InjectPayload]:
        if 0 <= idx < len(self._payloads):
            return self._payloads[idx]
        return None

    def getPayloadByName(self, nm: str) -> Optional[InjectPayload]:
        idx = self._namemap.get(nm)
        if idx is not None:
            return self._payloads[idx]
        return None

    def getPayloadId(self, nm: str) -> int:
        return self._namemap.get(nm, -1)

    def numPayloads(self) -> int:
        return len(self._payloads)

    def getCallFixupId(self, nm: str) -> int:
        return self._callFixupMap.get(nm, -1)

    def getCallOtherFixupId(self, nm: str) -> int:
        return self._callOtherFixupMap.get(nm, -1)

    def getCallMechanismId(self, nm: str) -> int:
        return self._callMechMap.get(nm, -1)

    def hasCallFixup(self, nm: str) -> bool:
        return nm in self._callFixupMap

    def hasCallOtherFixup(self, nm: str) -> bool:
        return nm in self._callOtherFixupMap

    def manualCallFixup(self, useropname: str, outname: str,
                        inname: list, snippet: str) -> int:
        """Manually register a call fixup from a p-code snippet."""
        payload = InjectPayload(useropname, InjectPayload.CALLFIXUP_TYPE)
        return self.registerPayload(payload)

    def manualCallOtherFixup(self, useropname: str, outname: str,
                             inname: list, snippet: str) -> int:
        """Manually register a callother fixup from a p-code snippet."""
        payload = InjectPayload(useropname, InjectPayload.CALLOTHERFIXUP_TYPE)
        return self.registerPayload(payload)
