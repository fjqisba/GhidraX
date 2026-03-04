"""
Lifter: bridges sleigh_native C++ P-code output into the Python IR framework.

Converts native PcodeResult objects into Funcdata populated with
Python Varnode/PcodeOp/BlockBasic objects, ready for analysis and PrintC output.
"""

from __future__ import annotations

from typing import Optional, Dict, List, Tuple

from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace, OtherSpace,
    IPTR_PROCESSOR, IPTR_CONSTANT, IPTR_INTERNAL,
)
from ghidra.ir.varnode import Varnode
from ghidra.ir.op import PcodeOp
from ghidra.block.block import BlockBasic
from ghidra.analysis.funcdata import Funcdata


class Lifter:
    """Lifts machine code to Python IR using the native SLEIGH engine.

    Usage:
        lifter = Lifter(sla_path)
        lifter.set_image(base_addr, code_bytes)
        fd = lifter.lift_function("func_name", entry_addr, size)
        # fd is a Funcdata with Varnodes, PcodeOps, BlockBasic populated
    """

    def __init__(self, sla_path: str, context: Optional[Dict[str, int]] = None) -> None:
        from ghidra.sleigh.sleigh_native import SleighNative
        self._native = SleighNative()
        self._native.load_sla(sla_path)
        if context:
            for k, v in context.items():
                self._native.set_context_default(k, v)

        # Build address space manager from native register info
        self._spc_mgr = AddrSpaceManager()
        self._spaces: Dict[str, AddrSpace] = {}
        self._setup_spaces()

    def _setup_spaces(self) -> None:
        """Create Python AddrSpace objects matching the native SLEIGH spaces."""
        cs = ConstantSpace(self._spc_mgr)
        self._spc_mgr._insertSpace(cs)
        self._spc_mgr._constantSpace = cs
        self._spaces["const"] = cs

        code_space_name = self._native.get_default_code_space()

        idx = 1
        for name in [code_space_name, "register", "unique"]:
            if name == "const":
                continue
            if name == "unique":
                spc = UniqueSpace(self._spc_mgr, None, idx)
                self._spc_mgr._insertSpace(spc)
                self._spc_mgr._uniqueSpace = spc
            else:
                tp = IPTR_PROCESSOR
                flags = AddrSpace.hasphysical | AddrSpace.heritaged | AddrSpace.does_deadcode
                spc = AddrSpace(self._spc_mgr, None, tp, name, False, 4, 1, idx, flags, 0, 0)
                self._spc_mgr._insertSpace(spc)
                if name == code_space_name:
                    self._spc_mgr.setDefaultCodeSpace(spc)
                    self._spc_mgr.setDefaultDataSpace(spc)
            self._spaces[name] = spc
            idx += 1

    def _get_space(self, name: str) -> AddrSpace:
        """Get or create a Python AddrSpace by name."""
        if name in self._spaces:
            return self._spaces[name]
        # Create on demand
        idx = len(self._spc_mgr._spaces)
        if name == "unique":
            spc = UniqueSpace(self._spc_mgr, None, idx)
            self._spc_mgr._insertSpace(spc)
            self._spc_mgr._uniqueSpace = spc
        else:
            spc = AddrSpace(self._spc_mgr, None, IPTR_PROCESSOR, name, False, 4, 1, idx,
                            AddrSpace.hasphysical, 0, 0)
            self._spc_mgr._insertSpace(spc)
        self._spaces[name] = spc
        return spc

    def set_image(self, base_addr: int, data: bytes) -> None:
        """Set the binary image to analyze."""
        self._native.set_image(base_addr, data)

    def get_registers(self) -> dict:
        """Get all register definitions from the native engine."""
        return self._native.get_registers()

    def disassemble(self, addr: int):
        """Disassemble a single instruction."""
        return self._native.disassemble(addr)

    def disassemble_range(self, start: int, end: int):
        """Disassemble a range of instructions."""
        return self._native.disassemble_range(start, end)

    def lift_function(self, name: str, entry: int, size: int) -> Funcdata:
        """Lift a function starting at entry for size bytes into a Funcdata.

        This:
        1. Translates each instruction to P-code via native SLEIGH
        2. Creates Python Varnode/PcodeOp objects
        3. Groups ops into basic blocks
        4. Returns a populated Funcdata
        """
        code_spc = self._get_space(self._native.get_default_code_space())
        fd = Funcdata(name, name, None, Address(code_spc, entry), None, size)

        # Lift all instructions in range
        native_results = self._native.pcode_range(entry, entry + size)
        if not native_results:
            return fd

        # Create one basic block for now (simplified - no branch analysis)
        bb = fd.nodeJoinCreateBlock(Address(code_spc, entry))
        bb.setRange(Address(code_spc, entry),
                    Address(code_spc, entry + size - 1))

        # Varnode cache: (space_name, offset, size) -> Varnode
        vn_cache: Dict[Tuple[str, int, int], Varnode] = {}

        def get_or_create_vn(space_name: str, offset: int, sz: int) -> Varnode:
            key = (space_name, offset, sz)
            if key in vn_cache:
                return vn_cache[key]
            spc = self._get_space(space_name)
            vn = fd.newVarnode(sz, Address(spc, offset))
            vn_cache[key] = vn
            return vn

        # Convert each native PcodeResult -> Python PcodeOps
        for insn in native_results:
            for native_op in insn.ops:
                opc = OpCode(native_op.opcode)
                num_in = len(native_op.inputs)
                op = fd.newOp(num_in, Address(code_spc, insn.addr))
                op.setOpcodeEnum(opc)

                # Output
                if native_op.has_output:
                    o = native_op.output
                    out_vn = get_or_create_vn(o.space, o.offset, o.size)
                    fd.opSetOutput(op, out_vn)

                # Inputs
                for i, inp in enumerate(native_op.inputs):
                    in_vn = get_or_create_vn(inp.space, inp.offset, inp.size)
                    fd.opSetInput(op, in_vn, i)

                fd.opInsertEnd(op, bb)

        return fd

    def lift_and_print(self, name: str, entry: int, size: int) -> str:
        """Lift a function and generate C-like output. End-to-end pipeline."""
        import io
        from ghidra.output.prettyprint import EmitMarkup
        from ghidra.output.printc import PrintC
        from ghidra.types.cast import CastStrategyC
        from ghidra.types.datatype import TypeFactory
        from ghidra.fspec.fspec import FuncProto, ProtoModel

        fd = self.lift_function(name, entry, size)

        # Set up minimal prototype
        proto = fd.getFuncProto()
        proto.setModel(ProtoModel("__cdecl"))

        # Generate C output
        stream = io.StringIO()
        emit = EmitMarkup(stream)
        printer = PrintC()
        printer.setEmitter(emit)
        tf = TypeFactory()
        tf.setupCoreTypes()
        cs = CastStrategyC()
        cs.setTypeFactory(tf)
        printer.setCastStrategy(cs)

        printer.docFunction(fd)
        return emit.getOutput()
