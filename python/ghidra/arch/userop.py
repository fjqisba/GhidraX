"""
Corresponds to: userop.hh / userop.cc

User defined p-code operations (CALLOTHER) and UserOpManage registry.
"""

from __future__ import annotations
from typing import Optional, List, Dict


class UserPcodeOp:
    """Base class for user defined p-code operations."""
    annotation_assignment = 1
    no_operator = 2
    display_string = 4
    unspecialized = 1
    injected = 2
    volatile_read = 3
    volatile_write = 4
    BUILTIN_VOLATILE_READ = 1
    BUILTIN_VOLATILE_WRITE = 2

    def __init__(self, nm="", glb=None, tp=1, ind=-1):
        self.name = nm
        self.glb = glb
        self.type = tp
        self.useropindex = ind
        self.flags = 0

    def getName(self): return self.name
    def getIndex(self): return self.useropindex
    def getDisplay(self): return self.flags & 7
    def getOperatorName(self, op=None): return self.name
    def getOutputLocal(self, op=None): return None
    def getInputLocal(self, op=None, slot=0): return None
    def extractAnnotationSize(self, vn, op): return 0
    def setIndex(self, ind: int) -> None: self.useropindex = ind
    def setDisplay(self, flags: int) -> None: self.flags = (self.flags & ~7) | (flags & 7)
    def getType(self) -> int: return self.type
    def encode(self, encoder) -> None: pass
    def decode(self, decoder) -> None: pass


class UnspecializedPcodeOp(UserPcodeOp):
    def __init__(self, nm="", glb=None, ind=-1):
        super().__init__(nm, glb, UserPcodeOp.unspecialized, ind)


class InjectedUserOp(UserPcodeOp):
    def __init__(self, nm="", glb=None, ind=-1, injid=-1):
        super().__init__(nm, glb, UserPcodeOp.injected, ind)
        self.injectid = injid
    def getInjectId(self): return self.injectid


class VolatileReadOp(UserPcodeOp):
    def __init__(self, nm="read_volatile", glb=None):
        super().__init__(nm, glb, UserPcodeOp.volatile_read, UserPcodeOp.BUILTIN_VOLATILE_READ)
        self.flags = UserPcodeOp.no_operator


class VolatileWriteOp(UserPcodeOp):
    def __init__(self, nm="write_volatile", glb=None):
        super().__init__(nm, glb, UserPcodeOp.volatile_write, UserPcodeOp.BUILTIN_VOLATILE_WRITE)
        self.flags = UserPcodeOp.annotation_assignment


class UserOpManage:
    """Registry for user defined p-code ops, indexed by CALLOTHER id."""

    def __init__(self):
        self.glb = None
        self._useroplist: List[Optional[UserPcodeOp]] = []
        self._useropmap: Dict[str, UserPcodeOp] = {}

    def initialize(self, glb) -> None:
        self.glb = glb
        trans = glb.translate if hasattr(glb, 'translate') else None
        if trans is not None and hasattr(trans, 'numUserOps'):
            n = trans.numUserOps()
            self._useroplist = [None] * n
            for i in range(n):
                nm = trans.getUserOpName(i) if hasattr(trans, 'getUserOpName') else f"userop_{i}"
                if nm:
                    op = UnspecializedPcodeOp(nm, glb, i)
                    self._useroplist[i] = op
                    self._useropmap[nm] = op

    def getOp(self, i) -> Optional[UserPcodeOp]:
        if isinstance(i, str):
            return self._useropmap.get(i)
        if isinstance(i, int) and 0 <= i < len(self._useroplist):
            return self._useroplist[i]
        return None

    def registerOp(self, op: UserPcodeOp) -> None:
        idx = op.getIndex()
        if idx >= 0:
            while idx >= len(self._useroplist):
                self._useroplist.append(None)
            self._useroplist[idx] = op
        self._useropmap[op.getName()] = op

    def numOps(self) -> int:
        return len(self._useroplist)

    def getOpByName(self, nm: str) -> Optional[UserPcodeOp]:
        return self._useropmap.get(nm)

    def numUserOps(self) -> int:
        return len(self._useroplist)

    def decodeSegmentOp(self, decoder, glb) -> None:
        """Decode a segment op from a stream."""
        pass

    def decodeJumpAssist(self, decoder, glb) -> None:
        """Decode a jump assist op from a stream."""
        pass

    def decodeCallOtherFixup(self, decoder, glb) -> None:
        """Decode a CALLOTHER fixup from a stream."""
        pass

    def manualCallOtherFixup(self, useropname: str, outname: str,
                              inname: list, snippet: str, glb=None) -> None:
        """Manually define a CALLOTHER fixup."""
        pass


class SegmentOp(UserPcodeOp):
    """A user-op representing a segment calculation."""
    def __init__(self, nm="segment", glb=None, ind=-1):
        super().__init__(nm, glb, 5, ind)  # segment=5
        self.spc = None
        self.injectId: int = -1
        self.baseinsize: int = 0
        self.innerinsize: int = 0

    def getResolve(self):
        return self

    def getSpace(self):
        return self.spc

    def getBaseSize(self) -> int:
        return self.baseinsize

    def getInnerSize(self) -> int:
        return self.innerinsize

    def getInjectId(self) -> int:
        return self.injectId

    def decode(self, decoder) -> None:
        pass

    def getNumVariableTerms(self) -> int:
        return 0


class JumpAssistOp(UserPcodeOp):
    """A user-op for jump-table assist."""
    def __init__(self, nm="", glb=None, ind=-1):
        super().__init__(nm, glb, 6, ind)  # jumpassist=6
        self.index2addr: int = -1
        self.index2case: int = -1
        self.calcsize: int = -1
        self.defaultaddr: int = -1

    def getIndex2Addr(self) -> int:
        return self.index2addr

    def getIndex2Case(self) -> int:
        return self.index2case

    def getCalcSize(self) -> int:
        return self.calcsize

    def getDefaultAddr(self) -> int:
        return self.defaultaddr

    def setIndex2Addr(self, val: int) -> None:
        self.index2addr = val

    def setCalcSize(self, val: int) -> None:
        self.calcsize = val

    def decode(self, decoder) -> None:
        pass


class InternalStringOp(UserPcodeOp):
    """A user-op for internal string operations."""
    def __init__(self, nm="", glb=None, ind=-1):
        super().__init__(nm, glb, 7, ind)  # string_data=7


class DatatypeUserOp(UserPcodeOp):
    """Generic user-op that provides input/output data-types."""
    def __init__(self, nm="", glb=None, ind=-1, outType=None, *inTypes):
        super().__init__(nm, glb, 8, ind)  # datatype=8
        self.outType = outType
        self.inTypes = list(inTypes)

    def getOutputLocal(self, op=None):
        return self.outType

    def getInputLocal(self, op=None, slot=0):
        if slot < len(self.inTypes):
            return self.inTypes[slot]
        return None

    def getInTypes(self) -> list:
        return self.inTypes

    def setOutType(self, t) -> None:
        self.outType = t
