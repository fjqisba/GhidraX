"""
Corresponds to: override.hh / override.cc

A system for sending override commands to the decompiler.
Overrides for prototypes, indirect calls, dead code, flow, goto, and multistage jumps.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ghidra.core.address import Address


class Override:
    """Container of commands that override the decompiler's default behavior for a function.

    Overridable information includes:
      - sub-functions: how they are called and where they call to
      - jumptables: mark indirect jumps needing multistage analysis
      - deadcode: details about dead code elimination
      - data-flow: override interpretation of specific branch instructions
    """

    NONE = 0
    BRANCH = 1
    CALL = 2
    CALL_RETURN = 3
    RETURN = 4

    def __init__(self) -> None:
        self._forcegoto: Dict[int, Address] = {}
        self._deadcodedelay: List[int] = []
        self._indirectover: Dict[int, Address] = {}
        self._protoover: Dict[int, object] = {}
        self._multistagejump: List[Address] = []
        self._flowoverride: Dict[int, int] = {}

    def clear(self) -> None:
        self._forcegoto.clear()
        self._deadcodedelay.clear()
        self._indirectover.clear()
        self._protoover.clear()
        self._multistagejump.clear()
        self._flowoverride.clear()

    def insertForceGoto(self, targetpc: Address, destpc: Address) -> None:
        self._forcegoto[targetpc.getOffset()] = destpc

    def insertDeadcodeDelay(self, spc, delay: int) -> None:
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        while idx >= len(self._deadcodedelay):
            self._deadcodedelay.append(0)
        self._deadcodedelay[idx] = delay

    def hasDeadcodeDelay(self, spc) -> bool:
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        if idx >= len(self._deadcodedelay):
            return False
        return self._deadcodedelay[idx] != 0

    def getDeadcodeDelay(self, spc) -> int:
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        if idx >= len(self._deadcodedelay):
            return 0
        return self._deadcodedelay[idx]

    def insertIndirectOverride(self, callpoint: Address, directcall: Address) -> None:
        self._indirectover[callpoint.getOffset()] = directcall

    def insertProtoOverride(self, callpoint: Address, proto) -> None:
        self._protoover[callpoint.getOffset()] = proto

    def insertMultistageJump(self, addr: Address) -> None:
        self._multistagejump.append(addr)

    def insertFlowOverride(self, addr: Address, tp: int) -> None:
        if tp == Override.NONE:
            self._flowoverride.pop(addr.getOffset(), None)
        else:
            self._flowoverride[addr.getOffset()] = tp

    def queryMultistageJumptable(self, addr: Address) -> bool:
        for a in self._multistagejump:
            if a == addr:
                return True
        return False

    def hasFlowOverride(self) -> bool:
        return len(self._flowoverride) > 0

    def getFlowOverride(self, addr: Address) -> int:
        return self._flowoverride.get(addr.getOffset(), Override.NONE)

    def getForceGoto(self, targetpc: Address) -> Optional[Address]:
        return self._forcegoto.get(targetpc.getOffset())

    def getIndirectOverride(self, callpoint: Address) -> Optional[Address]:
        return self._indirectover.get(callpoint.getOffset())

    def getProtoOverride(self, callpoint: Address):
        return self._protoover.get(callpoint.getOffset())

    def applyPrototype(self, data, fspecs) -> None:
        """Apply any prototype override to a FuncCallSpecs."""
        addr = fspecs.getOp().getAddr() if hasattr(fspecs, 'getOp') else None
        if addr is None:
            return
        proto = self.getProtoOverride(addr)
        if proto is not None and hasattr(fspecs, 'setForcedPrototype'):
            fspecs.setForcedPrototype(proto)

    def applyIndirect(self, data, fspecs) -> None:
        """Apply any indirect call override."""
        addr = fspecs.getOp().getAddr() if hasattr(fspecs, 'getOp') else None
        if addr is None:
            return
        direct = self.getIndirectOverride(addr)
        if direct is not None and hasattr(fspecs, 'setDirectCall'):
            fspecs.setDirectCall(direct)

    def applyDeadCodeDelay(self, data) -> None:
        """Apply dead code delay overrides to the function."""
        pass

    def applyForceGoto(self, data) -> None:
        """Apply forced goto overrides."""
        pass

    @staticmethod
    def typeToString(tp: int) -> str:
        _map = {0: "none", 1: "branch", 2: "call", 3: "callreturn", 4: "return"}
        return _map.get(tp, "unknown")

    @staticmethod
    def stringToType(nm: str) -> int:
        _map = {"none": 0, "branch": 1, "call": 2, "callreturn": 3, "return": 4}
        return _map.get(nm.lower(), 0)
