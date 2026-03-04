"""
Corresponds to: sleigh.hh / sleigh.cc

Main SLEIGH engine for instruction decoding and p-code generation.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List, Dict
from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.translate import PcodeEmit, AssemblyEmit
from ghidra.sleigh.sleighbase import SleighBase

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace


class PcodeData:
    """Data for building one p-code instruction."""

    def __init__(self) -> None:
        self.opc: OpCode = OpCode.CPUI_BLANK
        self.outvar: Optional[VarnodeData] = None
        self.invar: List[VarnodeData] = []
        self.isize: int = 0


class RelativeRecord:
    """Describes a relative p-code branch destination."""

    def __init__(self) -> None:
        self.dataptr: Optional[VarnodeData] = None
        self.calling_index: int = 0


class PcodeCacher:
    """Cache for accumulating p-code for a single instruction before emitting."""

    def __init__(self) -> None:
        self._issued: List[PcodeData] = []
        self._label_refs: List[RelativeRecord] = []
        self._labels: List[int] = []
        self._pool: List[VarnodeData] = []

    def allocateVarnodes(self, size: int) -> List[VarnodeData]:
        result = [VarnodeData() for _ in range(size)]
        self._pool.extend(result)
        return result

    def allocateInstruction(self) -> PcodeData:
        pd = PcodeData()
        self._issued.append(pd)
        return pd

    def addLabelRef(self, ptr: VarnodeData) -> None:
        rr = RelativeRecord()
        rr.dataptr = ptr
        rr.calling_index = len(self._issued) - 1
        self._label_refs.append(rr)

    def addLabel(self, id_: int) -> None:
        while len(self._labels) <= id_:
            self._labels.append(0)
        self._labels[id_] = len(self._issued)

    def clear(self) -> None:
        self._issued.clear()
        self._label_refs.clear()
        self._labels.clear()
        self._pool.clear()

    def resolveRelatives(self) -> None:
        """Rewrite branch target Varnodes as relative offsets."""
        for rr in self._label_refs:
            if rr.dataptr is not None:
                label_id = rr.dataptr.offset
                if 0 <= label_id < len(self._labels):
                    target = self._labels[label_id]
                    rr.dataptr.offset = target - rr.calling_index - 1

    def emit(self, addr: Address, emt: PcodeEmit) -> None:
        """Pass the cached p-code data to the emitter."""
        self.resolveRelatives()
        for pd in self._issued:
            emt.dump(addr, pd.opc, pd.outvar, pd.invar, pd.isize)

    def numOps(self) -> int:
        return len(self._issued)


class DisassemblyCache:
    """Cache for previously disassembled instruction info."""

    def __init__(self) -> None:
        self._cache: Dict[int, tuple] = {}  # offset -> (length, context)

    def getLength(self, offset: int) -> int:
        entry = self._cache.get(offset)
        return entry[0] if entry else 0

    def setLength(self, offset: int, length: int) -> None:
        self._cache[offset] = (length, None)

    def clear(self) -> None:
        self._cache.clear()


class Sleigh(SleighBase):
    """The main SLEIGH engine for translating machine instructions into p-code.

    This extends SleighBase with the ability to actually decode instructions
    from a LoadImage and emit p-code via PcodeEmit.
    """

    def __init__(self, ld=None, c_db=None) -> None:
        super().__init__()
        self._loader = ld          # LoadImage
        self._context_db = c_db    # ContextDatabase
        self._cache: PcodeCacher = PcodeCacher()
        self._discache: DisassemblyCache = DisassemblyCache()
        self._buf: bytes = b""
        self._curaddr: Address = Address()

    def setLoader(self, ld) -> None:
        self._loader = ld

    def setContextDatabase(self, cdb) -> None:
        self._context_db = cdb

    def initialize(self, store) -> None:
        """Initialize the SLEIGH engine from a DocumentStorage.

        In the full implementation, this reads the .sla file and builds
        all the decoding tables.
        """
        pass

    def oneInstruction(self, emit: PcodeEmit, addr: Address) -> int:
        """Translate a single machine instruction into p-code.

        Returns the length of the machine instruction in bytes.

        Full implementation would:
        1. Read bytes from LoadImage at addr
        2. Match instruction pattern using decoding tree
        3. Generate p-code from matched constructor's semantic section
        4. Emit p-code via emit.dump()
        """
        # Placeholder - returns 0 (no instruction decoded)
        return 0

    def printAssembly(self, emit: AssemblyEmit, addr: Address) -> int:
        """Disassemble a single machine instruction.

        Returns the length of the machine instruction in bytes.

        Full implementation would:
        1. Read bytes from LoadImage at addr
        2. Match instruction pattern
        3. Generate assembly text from matched constructor's print section
        4. Emit via emit.dump()
        """
        return 0

    def allowContextSet(self, val: bool) -> None:
        """Toggle whether context changes are allowed during translation."""
        pass

    def __repr__(self) -> str:
        init = "initialized" if self.isInitialized() else "uninitialized"
        return f"Sleigh({init})"
