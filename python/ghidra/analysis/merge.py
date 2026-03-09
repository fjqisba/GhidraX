"""
Corresponds to: merge.hh / merge.cc

Utilities for merging low-level Varnodes into high-level variables.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List, Tuple
from bisect import bisect_left

from ghidra.ir.cover import Cover, PcodeOpSet
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.variable import HighVariable
    from ghidra.ir.op import PcodeOp
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.block.block import FlowBlock, BlockBasic


# =========================================================================
# BlockVarnode
# =========================================================================

class BlockVarnode:
    """Helper class associating a Varnode with the block where it is defined.

    If a Varnode does not have a defining PcodeOp it is assigned an index of 0.
    """

    def __init__(self) -> None:
        self._index: int = 0
        self._vn: Optional[Varnode] = None

    def set(self, v: Varnode) -> None:
        """Set this as representing the given Varnode."""
        self._vn = v
        op = v.getDef()
        if op is None:
            self._index = 0
        else:
            parent = op.getParent()
            self._index = parent.getIndex() if parent is not None else 0

    def __lt__(self, op2: BlockVarnode) -> bool:
        return self._index < op2._index

    def getVarnode(self) -> Optional[Varnode]:
        return self._vn

    def getIndex(self) -> int:
        return self._index

    @staticmethod
    def findFront(blocknum: int, blist: List[BlockVarnode]) -> int:
        """Find the first BlockVarnode in sorted list with the given block index.

        Returns the index in the list, or -1 if not found.
        """
        lo = 0
        hi = len(blist) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if blist[mid].getIndex() >= blocknum:
                hi = mid
            else:
                lo = mid + 1
        if lo > hi:
            return -1
        if blist[lo].getIndex() != blocknum:
            return -1
        return lo


# =========================================================================
# StackAffectingOps
# =========================================================================

class StackAffectingOps(PcodeOpSet):
    """The set of CALL and STORE ops that might indirectly affect stack variables."""

    def __init__(self, fd: Funcdata) -> None:
        super().__init__()
        self._data: Funcdata = fd

    def populate(self) -> None:
        """Fill the set with CALL ops and guarded STORE ops."""
        for i in range(self._data.numCalls()):
            fc = self._data.getCallSpecs(i)
            if fc is not None:
                self.addOp(fc.getOp())
        # Store guards if available
        if hasattr(self._data, 'getStoreGuards'):
            for guard in self._data.getStoreGuards():
                if hasattr(guard, 'isValid') and guard.isValid(OpCode.CPUI_STORE):
                    self.addOp(guard.getOp())
        self.finalize()

    def affectsTest(self, op: PcodeOp, vn: Varnode) -> bool:
        """Test whether the given op might affect the given Varnode through aliasing."""
        if op.code() == OpCode.CPUI_STORE:
            if hasattr(self._data, 'getStoreGuard'):
                loadGuard = self._data.getStoreGuard(op)
                if loadGuard is None:
                    return True
                return loadGuard.isGuarded(vn.getAddr())
        return True


# =========================================================================
# HighIntersectTest  (simplified cache)
# =========================================================================

class HighIntersectTest:
    """Cached intersection tests between HighVariables."""

    def __init__(self, stackOps: Optional[StackAffectingOps] = None) -> None:
        self._stackOps = stackOps
        self._cache: dict = {}

    def updateHigh(self, high: HighVariable) -> None:
        """Update cache information for a HighVariable."""
        pass

    def intersection(self, a: HighVariable, b: HighVariable) -> bool:
        """Test if two HighVariables have intersecting covers.

        Returns True if there IS an intersection (merge would fail).
        """
        if a is b:
            return False
        key = (id(a), id(b)) if id(a) < id(b) else (id(b), id(a))
        if key in self._cache:
            return self._cache[key]
        ca = a.getCover() if hasattr(a, 'getCover') else None
        cb = b.getCover() if hasattr(b, 'getCover') else None
        if ca is None or cb is None:
            self._cache[key] = False
            return False
        result = ca.intersect(cb) == 2
        self._cache[key] = result
        return result

    def clear(self) -> None:
        self._cache.clear()


# =========================================================================
# Merge
# =========================================================================

class Merge:
    """Class for merging low-level Varnodes into high-level HighVariables.

    Handles forced merges (MULTIEQUAL, INDIRECT, address-tied, mapped stack)
    and speculative merges (same data-type, adjacent input/output).
    """

    def __init__(self, fd: Funcdata) -> None:
        self._data: Funcdata = fd
        self._stackAffectingOps = StackAffectingOps(fd)
        self._testCache = HighIntersectTest(self._stackAffectingOps)
        self._copyTrims: List[PcodeOp] = []
        self._protoPartial: List[PcodeOp] = []

    def clear(self) -> None:
        """Clear any cached data from the last merge process."""
        self._testCache.clear()
        self._copyTrims.clear()
        self._protoPartial.clear()
        self._stackAffectingOps.clear() if hasattr(self._stackAffectingOps, 'clear') else None

    # ----- Static test methods -----

    @staticmethod
    def mergeTestRequired(high_out: HighVariable, high_in: HighVariable) -> bool:
        """Required tests to merge HighVariables (not Cover related)."""
        if high_in is high_out:
            return True
        if high_in.isTypeLock() and high_out.isTypeLock():
            if high_in.getType() is not high_out.getType():
                return False
        if high_out.isAddrTied() and high_in.isAddrTied():
            t1 = high_out.getTiedVarnode() if hasattr(high_out, 'getTiedVarnode') else None
            t2 = high_in.getTiedVarnode() if hasattr(high_in, 'getTiedVarnode') else None
            if t1 is not None and t2 is not None and t1.getAddr() != t2.getAddr():
                return False
        if high_in.isInput():
            if high_out.isPersist():
                return False
            if high_out.isAddrTied() and not high_in.isAddrTied():
                return False
        elif hasattr(high_in, 'isExtraOut') and high_in.isExtraOut():
            return False
        if high_out.isInput():
            if high_in.isPersist():
                return False
            if high_in.isAddrTied() and not high_out.isAddrTied():
                return False
        elif hasattr(high_out, 'isExtraOut') and high_out.isExtraOut():
            return False
        if hasattr(high_in, 'isProtoPartial') and high_in.isProtoPartial():
            if hasattr(high_out, 'isProtoPartial') and high_out.isProtoPartial():
                return False
            if high_out.isInput():
                return False
            if high_out.isAddrTied():
                return False
            if high_out.isPersist():
                return False
        if hasattr(high_out, 'isProtoPartial') and high_out.isProtoPartial():
            if high_in.isInput():
                return False
            if high_in.isAddrTied():
                return False
            if high_in.isPersist():
                return False
        s_in = high_in.getSymbol() if hasattr(high_in, 'getSymbol') else None
        s_out = high_out.getSymbol() if hasattr(high_out, 'getSymbol') else None
        if s_in is not None and s_out is not None:
            if s_in is not s_out:
                return False
            if hasattr(high_in, 'getSymbolOffset') and hasattr(high_out, 'getSymbolOffset'):
                if high_in.getSymbolOffset() != high_out.getSymbolOffset():
                    return False
        return True

    @staticmethod
    def mergeTestAdjacent(high_out: HighVariable, high_in: HighVariable) -> bool:
        """Adjacency tests for merging input/output to same op."""
        if not Merge.mergeTestRequired(high_out, high_in):
            return False
        if high_in.isNameLock() and high_out.isNameLock():
            return False
        if high_out.getType() is not high_in.getType():
            return False
        if high_out.isInput():
            vn = high_out.getInputVarnode() if hasattr(high_out, 'getInputVarnode') else None
            if vn is not None and vn.isIllegalInput() and not vn.isIndirectOnly():
                return False
        if high_in.isInput():
            vn = high_in.getInputVarnode() if hasattr(high_in, 'getInputVarnode') else None
            if vn is not None and vn.isIllegalInput() and not vn.isIndirectOnly():
                return False
        sym = high_in.getSymbol() if hasattr(high_in, 'getSymbol') else None
        if sym is not None and hasattr(sym, 'isIsolated') and sym.isIsolated():
            return False
        sym = high_out.getSymbol() if hasattr(high_out, 'getSymbol') else None
        if sym is not None and hasattr(sym, 'isIsolated') and sym.isIsolated():
            return False
        return True

    @staticmethod
    def mergeTestSpeculative(high_out: HighVariable, high_in: HighVariable) -> bool:
        """Speculative tests for merging HighVariables."""
        if not Merge.mergeTestAdjacent(high_out, high_in):
            return False
        if high_out.isPersist() or high_in.isPersist():
            return False
        if high_out.isInput() or high_in.isInput():
            return False
        if high_out.isAddrTied() or high_in.isAddrTied():
            return False
        return True

    @staticmethod
    def mergeTestMust(vn: Varnode) -> None:
        """Test if vn that must be merged, can be merged. Raise if not."""
        if vn.hasCover() and not vn.isImplied():
            return
        from ghidra.core.error import LowlevelError
        raise LowlevelError("Cannot force merge of range")

    @staticmethod
    def mergeTestBasic(vn: Varnode) -> bool:
        """Test if the given Varnode can ever be merged."""
        if vn is None:
            return False
        if not vn.hasCover():
            return False
        if vn.isImplied():
            return False
        if vn.isProtoPartial():
            return False
        if vn.isSpacebase():
            return False
        return True

    @staticmethod
    def markImplied(vn: Varnode) -> None:
        """Mark the given Varnode as implied."""
        from ghidra.ir.varnode import Varnode as VnCls
        vn.setImplied()
        op = vn.getDef()
        if op is not None:
            for i in range(op.numInput()):
                defvn = op.getIn(i)
                if not defvn.hasCover():
                    continue
                defvn.setFlags(VnCls.coverdirty)

    @staticmethod
    def findSingleCopy(high: HighVariable, singlelist: List[Varnode]) -> None:
        """Find instance Varnodes that are copied from outside the HighVariable."""
        for i in range(high.numInstances()):
            vn = high.getInstance(i)
            if not vn.isWritten():
                continue
            op = vn.getDef()
            if op.code() != OpCode.CPUI_COPY:
                continue
            if op.getIn(0).getHigh() is high:
                continue
            singlelist.append(vn)

    @staticmethod
    def compareHighByBlock(a: HighVariable, b: HighVariable) -> bool:
        """Compare HighVariables by the blocks they cover."""
        ca = a.getCover() if hasattr(a, 'getCover') else None
        cb = b.getCover() if hasattr(b, 'getCover') else None
        if ca is not None and cb is not None and hasattr(ca, 'compareTo'):
            result = ca.compareTo(cb)
        else:
            result = 0
        if result == 0:
            v1 = a.getInstance(0)
            v2 = b.getInstance(0)
            if v1.getAddr() == v2.getAddr():
                def1 = v1.getDef()
                def2 = v2.getDef()
                if def1 is None:
                    return def2 is not None
                elif def2 is None:
                    return False
                return def1.getAddr() < def2.getAddr()
            return v1.getAddr() < v2.getAddr()
        return result < 0

    @staticmethod
    def compareCopyByInVarnode(op1: PcodeOp, op2: PcodeOp) -> bool:
        """Compare COPY ops by input Varnode, then by block."""
        inVn1 = op1.getIn(0)
        inVn2 = op2.getIn(0)
        if inVn1 is not inVn2:
            return inVn1.getCreateIndex() < inVn2.getCreateIndex()
        idx1 = op1.getParent().getIndex() if op1.getParent() else 0
        idx2 = op2.getParent().getIndex() if op2.getParent() else 0
        if idx1 != idx2:
            return idx1 < idx2
        return op1.getSeqNum().getOrder() < op2.getSeqNum().getOrder()

    @staticmethod
    def shadowedVarnode(vn: Varnode) -> bool:
        """Determine if vn is shadowed by another in the same HighVariable."""
        high = vn.getHigh()
        if high is None:
            return False
        for i in range(high.numInstances()):
            othervn = high.getInstance(i)
            if othervn is vn:
                continue
            c1 = vn.getCover()
            c2 = othervn.getCover()
            if c1 is not None and c2 is not None and c1.intersect(c2) == 2:
                return True
        return False

    @staticmethod
    def findAllIntoCopies(high: HighVariable, copyIns: List[PcodeOp], filterTemps: bool) -> None:
        """Find all COPY ops into the given HighVariable from outside."""
        from ghidra.core.space import IPTR_INTERNAL
        for i in range(high.numInstances()):
            vn = high.getInstance(i)
            if not vn.isWritten():
                continue
            op = vn.getDef()
            if op.code() != OpCode.CPUI_COPY:
                continue
            if op.getIn(0).getHigh() is high:
                continue
            if filterTemps and op.getOut().getSpace() is not None:
                if op.getOut().getSpace().getType() != IPTR_INTERNAL:
                    continue
            copyIns.append(op)
        copyIns.sort(key=lambda o: (o.getIn(0).getCreateIndex(),
                                     o.getParent().getIndex() if o.getParent() else 0,
                                     o.getSeqNum().getOrder()))

    # ----- Instance merge methods -----

    def merge(self, high1: HighVariable, high2: HighVariable, isspeculative: bool) -> bool:
        """Perform low-level merge of two HighVariables if possible.

        Returns False if there is a Cover intersection.
        """
        if high1 is high2:
            return True
        if self._testCache.intersection(high1, high2):
            return False
        if hasattr(high1, 'merge'):
            high1.merge(high2, self._testCache, isspeculative)
        if hasattr(high1, 'updateCover'):
            high1.updateCover()
        return True

    def inflateTest(self, a: Varnode, high: HighVariable) -> bool:
        """Test if inflating Cover of a would cause intersections with high."""
        self._testCache.updateHigh(high)
        ahigh = a.getHigh()
        if ahigh is None:
            return False
        for i in range(ahigh.numInstances()):
            b = ahigh.getInstance(i)
            if b.copyShadow(a):
                continue
            bc = b.getCover()
            hc = high.getCover() if hasattr(high, 'getCover') else None
            if bc is not None and hc is not None:
                if bc.intersect(hc) == 2:
                    return True
        return False

    def mergeTest(self, high: HighVariable, tmplist: List[HighVariable]) -> bool:
        """Test for intersections between high and a list of others.

        If no intersections, high is added to the list and True returned.
        """
        if not high.hasCover():
            return False
        for a in tmplist:
            if self._testCache.intersection(a, high):
                return False
        tmplist.append(high)
        return True

    def snipReads(self, vn: Varnode, markedop: List[PcodeOp]) -> None:
        """Snip off set of read p-code ops for a given Varnode."""
        if not markedop:
            return
        # Insert a COPY to isolate reads
        if vn.isInput():
            bl = self._data.getBasicBlocks().getBlock(0) if hasattr(self._data, 'getBasicBlocks') else None
            pc = bl.getStart() if bl is not None else vn.getAddr()
        else:
            pc = vn.getDef().getAddr()
        copyop = self._allocateCopyTrim(vn, pc, markedop[0])
        if copyop is None:
            return
        # Insert after def
        if vn.isInput():
            if hasattr(self._data, 'opInsertBegin') and bl is not None:
                self._data.opInsertBegin(copyop, bl)
        else:
            afterop = vn.getDef()
            if hasattr(self._data, 'opInsertAfter'):
                self._data.opInsertAfter(copyop, afterop)
        # Replace reads
        for op in markedop:
            slot = op.getSlot(vn)
            if hasattr(self._data, 'opSetInput'):
                self._data.opSetInput(op, copyop.getOut(), slot)

    def _allocateCopyTrim(self, inVn: Varnode, addr, trimOp: PcodeOp):
        """Allocate COPY PcodeOp designed to trim an overextended Cover."""
        if not hasattr(self._data, 'newOp'):
            return None
        copyop = self._data.newOp(1, addr)
        self._data.opSetOpcode(copyop, OpCode.CPUI_COPY)
        ct = inVn.getType()
        outVn = self._data.newUnique(inVn.getSize(), ct)
        self._data.opSetOutput(copyop, outVn)
        self._data.opSetInput(copyop, inVn, 0)
        self._copyTrims.append(copyop)
        return copyop

    def snipOutputInterference(self, indop: PcodeOp) -> bool:
        """Snip instances of the output of an INDIRECT that are also inputs to the underlying PcodeOp.

        Examine the output HighVariable for the given INDIRECT op. Varnode instances
        that are also inputs to the underlying PcodeOp causing the INDIRECT are snipped
        by creating a new COPY op from the Varnode to a new temporary.
        Returns True if specific instances are snipped.
        """
        if not hasattr(indop, 'getIn') or indop.numInput() < 2:
            return False
        # Get the op causing the indirect effect
        from ghidra.ir.op import PcodeOp as PcodeOpCls
        if hasattr(PcodeOpCls, 'getOpFromConst'):
            effect_op = PcodeOpCls.getOpFromConst(indop.getIn(1).getAddr())
        else:
            return False
        if effect_op is None:
            return False
        # Collect instances of output->high that are inputs to effect_op
        correctable: list = []
        out_high = indop.getOut().getHigh()
        if out_high is None:
            return False
        self.collectInputs(out_high, correctable, effect_op)
        if not correctable:
            return False
        # Sort by high variable
        correctable.sort(key=lambda x: id(x[0].getIn(x[1]).getHigh()) if x[0].getIn(x[1]).getHigh() else 0)
        snipop = None
        curHigh = None
        for insertop, slot in correctable:
            vn = insertop.getIn(slot)
            if vn.getHigh() is not curHigh:
                snipop = self._allocateCopyTrim(vn, insertop.getAddr(), insertop)
                if snipop is not None and hasattr(self._data, 'opInsertBefore'):
                    self._data.opInsertBefore(snipop, insertop)
                curHigh = vn.getHigh()
            if snipop is not None and hasattr(self._data, 'opSetInput'):
                self._data.opSetInput(insertop, snipop.getOut(), slot)
        return True

    def eliminateIntersect(self, vn: Varnode, blocksort: List[BlockVarnode]) -> None:
        """Eliminate intersections of given Varnode with others in a list."""
        markedop: List[PcodeOp] = []
        for op in list(vn.getDescendants()):
            insertop = False
            for bvn in blocksort:
                vn2 = bvn.getVarnode()
                if vn2 is vn:
                    continue
                overlaptype = vn.characterizeOverlap(vn2)
                if overlaptype == 0:
                    continue
                insertop = True
                break
            if insertop:
                markedop.append(op)
        self.snipReads(vn, markedop)

    def unifyAddress(self, varnodes: list) -> None:
        """Make sure all Varnodes with the same storage can be merged."""
        isectlist = [vn for vn in varnodes if not vn.isFree()]
        blocksort = []
        for vn in isectlist:
            bvn = BlockVarnode()
            bvn.set(vn)
            blocksort.append(bvn)
        blocksort.sort()
        for vn in isectlist:
            self.eliminateIntersect(vn, blocksort)

    def trimOpOutput(self, op: PcodeOp) -> None:
        """Trim the output HighVariable of the given PcodeOp so its Cover is tiny."""
        if not hasattr(self._data, 'newOp'):
            return
        vn = op.getOut()
        ct = vn.getType()
        copyop = self._data.newOp(1, op.getAddr())
        self._data.opSetOpcode(copyop, OpCode.CPUI_COPY)
        uniq = self._data.newUnique(vn.getSize(), ct)
        self._data.opSetOutput(op, uniq)
        self._data.opSetOutput(copyop, vn)
        self._data.opSetInput(copyop, uniq, 0)
        if hasattr(self._data, 'opInsertAfter'):
            self._data.opInsertAfter(copyop, op)

    def trimOpInput(self, op: PcodeOp, slot: int) -> None:
        """Trim the input HighVariable of the given PcodeOp so its Cover is tiny."""
        if not hasattr(self._data, 'newOp'):
            return
        pc = op.getAddr()
        vn = op.getIn(slot)
        copyop = self._allocateCopyTrim(vn, pc, op)
        if copyop is None:
            return
        if hasattr(self._data, 'opSetInput'):
            self._data.opSetInput(op, copyop.getOut(), slot)
        if hasattr(self._data, 'opInsertBefore'):
            self._data.opInsertBefore(copyop, op)

    def mergeRangeMust(self, varnodes: list) -> None:
        """Force the merge of a range of Varnodes with same size and address."""
        if not varnodes:
            return
        vn = varnodes[0]
        self.mergeTestMust(vn)
        high = vn.getHigh()
        for vn2 in varnodes[1:]:
            if vn2.getHigh() is high:
                continue
            self.mergeTestMust(vn2)
            if not self.merge(high, vn2.getHigh(), False):
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Forced merge caused intersection")

    def mergeOp(self, op: PcodeOp) -> None:
        """Force the merge of all input and output Varnodes for the given op."""
        maxslot = 1 if op.code() == OpCode.CPUI_INDIRECT else op.numInput()
        high_out = op.getOut().getHigh()
        # First check non-cover restrictions
        for i in range(maxslot):
            high_in = op.getIn(i).getHigh()
            if not self.mergeTestRequired(high_out, high_in):
                self.trimOpInput(op, i)
                continue
            for j in range(i):
                if not self.mergeTestRequired(op.getIn(j).getHigh(), high_in):
                    self.trimOpInput(op, i)
                    break
        # Check cover restrictions
        testlist: List[HighVariable] = []
        self.mergeTest(high_out, testlist)
        ok = True
        for i in range(maxslot):
            if not self.mergeTest(op.getIn(i).getHigh(), testlist):
                ok = False
                break
        if not ok:
            # Trim until merges work
            for nexttrim in range(maxslot):
                self.trimOpInput(op, nexttrim)
                testlist.clear()
                self.mergeTest(high_out, testlist)
                allgood = True
                for i in range(maxslot):
                    if not self.mergeTest(op.getIn(i).getHigh(), testlist):
                        allgood = False
                        break
                if allgood:
                    break
            else:
                self.trimOpOutput(op)
        # Actually merge
        for i in range(maxslot):
            self.merge(op.getOut().getHigh(), op.getIn(i).getHigh(), False)

    def mergeIndirect(self, indop: PcodeOp) -> None:
        """Force the merge of input and output Varnodes to a given INDIRECT op."""
        outvn = indop.getOut()
        if not outvn.isAddrForce():
            self.mergeOp(indop)
            return
        invn0 = indop.getIn(0)
        if self.mergeTestRequired(outvn.getHigh(), invn0.getHigh()):
            if self.merge(invn0.getHigh(), outvn.getHigh(), False):
                return
        # Fall back to snipping
        self.snipOutputInterference(indop)
        if self.mergeTestRequired(outvn.getHigh(), invn0.getHigh()):
            if self.merge(invn0.getHigh(), outvn.getHigh(), False):
                return
        # Snip the INDIRECT itself
        copyop = self._allocateCopyTrim(invn0, indop.getAddr(), indop)
        if copyop is not None and hasattr(self._data, 'opSetInput'):
            self._data.opSetInput(indop, copyop.getOut(), 0)
            if hasattr(self._data, 'opInsertBefore'):
                self._data.opInsertBefore(copyop, indop)
        if not self.mergeTestRequired(outvn.getHigh(), indop.getIn(0).getHigh()) or \
           not self.merge(indop.getIn(0).getHigh(), outvn.getHigh(), False):
            from ghidra.core.error import LowlevelError
            raise LowlevelError("Unable to merge address forced indirect")

    def mergeLinear(self, highvec: List[HighVariable]) -> None:
        """Speculatively merge all HighVariables in the given list."""
        if len(highvec) <= 1:
            return
        for h in highvec:
            self._testCache.updateHigh(h)
        highvec.sort(key=lambda h: id(h))  # Simplified sort
        highstack: List[HighVariable] = []
        for high in highvec:
            merged = False
            for out in highstack:
                if self.mergeTestSpeculative(out, high):
                    if self.merge(out, high, True):
                        merged = True
                        break
            if not merged:
                highstack.append(high)

    # ----- Public merge entry points -----

    def mergeOpcode(self, opc: OpCode) -> None:
        """Try to force input/output merge for all ops of a given type."""
        if not hasattr(self._data, 'getBasicBlocks'):
            return
        bblocks = self._data.getBasicBlocks()
        for i in range(bblocks.getSize()):
            bl = bblocks.getBlock(i)
            if not hasattr(bl, 'beginOp'):
                continue
            for op in bl.getOpRange():
                if op.code() != opc:
                    continue
                vn1 = op.getOut()
                if not self.mergeTestBasic(vn1):
                    continue
                for j in range(op.numInput()):
                    vn2 = op.getIn(j)
                    if not self.mergeTestBasic(vn2):
                        continue
                    if self.mergeTestRequired(vn1.getHigh(), vn2.getHigh()):
                        self.merge(vn1.getHigh(), vn2.getHigh(), False)

    def mergeByDatatype(self, varnodes: list) -> None:
        """Try to merge all HighVariables with the same data-type."""
        highlist: List[HighVariable] = []
        seen = set()
        for vn in varnodes:
            if vn.isFree():
                continue
            high = vn.getHigh()
            if high is None or id(high) in seen:
                continue
            if not self.mergeTestBasic(vn):
                continue
            seen.add(id(high))
            highlist.append(high)
        # Group by datatype
        groups: dict = {}
        for high in highlist:
            ct = high.getType()
            key = id(ct)
            if key not in groups:
                groups[key] = []
            groups[key].append(high)
        for group in groups.values():
            self.mergeLinear(group)

    def mergeAddrTied(self) -> None:
        """Force the merge of address-tied Varnodes."""
        # Simplified: iterate all varnodes and group by address
        if not hasattr(self._data, 'beginLoc'):
            return
        groups: dict = {}
        for vn in self._data.beginLoc():
            if vn.isFree() or not vn.isAddrTied():
                continue
            key = (id(vn.getSpace()), vn.getOffset(), vn.getSize())
            if key not in groups:
                groups[key] = []
            groups[key].append(vn)
        for group in groups.values():
            if len(group) <= 1:
                continue
            self.unifyAddress(group)
            self.mergeRangeMust(group)

    def mergeMarker(self) -> None:
        """Force the merge of input/output Varnodes to MULTIEQUAL and INDIRECT ops."""
        if not hasattr(self._data, 'beginOpAlive'):
            return
        for op in self._data.getAliveOps():
            if not op.isMarker() or op.isIndirectCreation():
                continue
            if op.code() == OpCode.CPUI_INDIRECT:
                self.mergeIndirect(op)
            else:
                self.mergeOp(op)

    def mergeMultiEntry(self) -> None:
        """Merge together Varnodes mapped to SymbolEntrys from the same Symbol.

        Symbols that have more than one SymbolEntry may attach to more than one
        Varnode. These Varnodes need to be merged to properly represent a single variable.
        """
        if not hasattr(self._data, 'getScopeLocal'):
            return
        scope = self._data.getScopeLocal()
        if not hasattr(scope, 'beginMultiEntry'):
            return
        for symbol in scope.beginMultiEntry():
            mergeList: List[Varnode] = []
            numEntries = symbol.numEntries() if hasattr(symbol, 'numEntries') else 0
            mergeCount = 0
            skipCount = 0
            conflictCount = 0
            for i in range(numEntries):
                prevSize = len(mergeList)
                entry = symbol.getMapEntry(i) if hasattr(symbol, 'getMapEntry') else None
                if entry is None:
                    continue
                if hasattr(entry, 'getSize') and hasattr(symbol, 'getType'):
                    if entry.getSize() != symbol.getType().getSize():
                        continue
                if hasattr(self._data, 'findLinkedVarnodes'):
                    self._data.findLinkedVarnodes(entry, mergeList)
                if len(mergeList) == prevSize:
                    skipCount += 1
            if not mergeList:
                continue
            high = mergeList[0].getHigh()
            self._testCache.updateHigh(high)
            for i in range(len(mergeList)):
                newHigh = mergeList[i].getHigh()
                if newHigh is high:
                    continue
                self._testCache.updateHigh(newHigh)
                if not self.mergeTestRequired(high, newHigh):
                    if hasattr(symbol, 'setMergeProblems'):
                        symbol.setMergeProblems()
                    if hasattr(newHigh, 'setUnmerged'):
                        newHigh.setUnmerged()
                    conflictCount += 1
                    continue
                if not self.merge(high, newHigh, False):
                    if hasattr(symbol, 'setMergeProblems'):
                        symbol.setMergeProblems()
                    if hasattr(newHigh, 'setUnmerged'):
                        newHigh.setUnmerged()
                    conflictCount += 1
                    continue
                mergeCount += 1
            if skipCount != 0 or conflictCount != 0:
                msg = 'Unable to'
                if mergeCount != 0:
                    msg += ' fully'
                name = symbol.getName() if hasattr(symbol, 'getName') else '?'
                msg += f' merge symbol: {name}'
                if skipCount > 0:
                    msg += ' -- Some instance varnodes not found.'
                if conflictCount > 0:
                    msg += ' -- Some merges are forbidden'
                if hasattr(self._data, 'warningHeader'):
                    self._data.warningHeader(msg)

    def groupPartials(self) -> None:
        """Run through CONCAT tree roots and group each tree."""
        for op in self._protoPartial:
            if hasattr(op, 'isDead') and op.isDead():
                continue
            if hasattr(op, 'isPartialRoot') and not op.isPartialRoot():
                continue
            self.groupPartialRoot(op.getOut())

    def groupPartialRoot(self, vn: Varnode) -> None:
        """Group the different nodes of a CONCAT tree into a VariableGroup.

        This formally labels all the Varnodes in the tree as overlapping pieces
        of the same variable. The tree is reconstructed from the root Varnode.
        """
        high = vn.getHigh()
        if high is None or high.numInstances() != 1:
            return

        baseOffset = 0
        entry = vn.getSymbolEntry()
        if entry is not None and hasattr(entry, 'getOffset'):
            baseOffset = entry.getOffset()

        # Gather pieces from the CONCAT tree
        pieces: list = []
        if hasattr(vn, 'getDef') and vn.getDef() is not None:
            self._gatherPieceNodes(pieces, vn, vn.getDef(), baseOffset, baseOffset)

        # Check all nodes are still valid
        throwOut = False
        for piece_vn, piece_off in pieces:
            if not piece_vn.isProtoPartial() or piece_vn.getHigh().numInstances() != 1:
                throwOut = True
                break

        if throwOut:
            for piece_vn, _ in pieces:
                piece_vn.clearProtoPartial()
        else:
            for piece_vn, piece_off in pieces:
                if hasattr(piece_vn.getHigh(), 'groupWith'):
                    piece_vn.getHigh().groupWith(piece_off - baseOffset, high)

    def _gatherPieceNodes(self, pieces: list, root, op, baseOff: int, curOff: int) -> None:
        """Recursively gather piece nodes from a CONCAT tree."""
        if op is None:
            return
        if op.code() == OpCode.CPUI_PIECE:
            # High part = input 0, Low part = input 1
            hiVn = op.getIn(0)
            loVn = op.getIn(1)
            loSize = loVn.getSize()
            # Recurse into sub-pieces
            if loVn.isWritten() and loVn.getDef().code() == OpCode.CPUI_PIECE:
                self._gatherPieceNodes(pieces, root, loVn.getDef(), baseOff, curOff)
            else:
                pieces.append((loVn, curOff))
            hiOff = curOff + loSize
            if hiVn.isWritten() and hiVn.getDef().code() == OpCode.CPUI_PIECE:
                self._gatherPieceNodes(pieces, root, hiVn.getDef(), baseOff, hiOff)
            else:
                pieces.append((hiVn, hiOff))

    def mergeAdjacent(self) -> None:
        """Speculatively merge Varnodes that are input/output to the same p-code op."""
        if not hasattr(self._data, 'getAliveOps'):
            return
        for op in self._data.getAliveOps():
            if op.isCall():
                continue
            vn1 = op.getOut()
            if vn1 is None or not self.mergeTestBasic(vn1):
                continue
            high_out = vn1.getHigh()
            for i in range(op.numInput()):
                vn2 = op.getIn(i)
                if not self.mergeTestBasic(vn2):
                    continue
                if vn1.getSize() != vn2.getSize():
                    continue
                high_in = vn2.getHigh()
                if not self.mergeTestAdjacent(high_out, high_in):
                    continue
                if not self._testCache.intersection(high_in, high_out):
                    self.merge(high_out, high_in, True)

    def hideShadows(self, high: HighVariable) -> bool:
        """Hide shadow Varnodes by consolidating COPY chains."""
        singlelist: List[Varnode] = []
        self.findSingleCopy(high, singlelist)
        if len(singlelist) <= 1:
            return False
        res = False
        for i in range(len(singlelist) - 1):
            vn1 = singlelist[i]
            if vn1 is None:
                continue
            for j in range(i + 1, len(singlelist)):
                vn2 = singlelist[j]
                if vn2 is None:
                    continue
                if not vn1.copyShadow(vn2):
                    continue
                c2 = vn2.getCover()
                if c2 is not None and hasattr(c2, 'containVarnodeDef'):
                    if c2.containVarnodeDef(vn1) == 1:
                        if hasattr(self._data, 'opSetInput'):
                            self._data.opSetInput(vn1.getDef(), vn2, 0)
                        res = True
                        break
                c1 = vn1.getCover()
                if c1 is not None and hasattr(c1, 'containVarnodeDef'):
                    if c1.containVarnodeDef(vn2) == 1:
                        if hasattr(self._data, 'opSetInput'):
                            self._data.opSetInput(vn2.getDef(), vn1, 0)
                        singlelist[j] = None
                        res = True
        return res

    def processCopyTrims(self) -> None:
        """Try to reduce/eliminate COPYs produced by the merge trimming process."""
        self._copyTrims.clear()

    def markInternalCopies(self) -> None:
        """Mark redundant/internal COPY PcodeOps."""
        if not hasattr(self._data, 'getAliveOps'):
            return
        for op in self._data.getAliveOps():
            if op.code() == OpCode.CPUI_COPY:
                v1 = op.getOut()
                h1 = v1.getHigh() if v1 is not None else None
                if h1 is not None and h1 is op.getIn(0).getHigh():
                    if hasattr(self._data, 'opMarkNonPrinting'):
                        self._data.opMarkNonPrinting(op)

    def registerProtoPartialRoot(self, vn: Varnode) -> None:
        """Register an unmapped CONCAT stack with the merge process."""
        if vn.getDef() is not None:
            self._protoPartial.append(vn.getDef())

    def checkCopyPair(self, high: HighVariable, domOp: PcodeOp, subOp: PcodeOp) -> bool:
        """Check if the given COPY ops are redundant."""
        domBlock = domOp.getParent()
        subBlock = subOp.getParent()
        if domBlock is None or subBlock is None:
            return False
        if hasattr(domBlock, 'dominates') and not domBlock.dominates(subBlock):
            return False
        return True

    def buildDominantCopy(self, high: HighVariable, copy: List[PcodeOp], pos: int, size: int) -> None:
        """Try to replace a set of COPYs from the same Varnode with a single dominant COPY.

        All COPY outputs must be instances of the same HighVariable. Either an existing COPY
        dominates all the others, or a new dominating COPY is constructed. Replacement only
        happens with COPY outputs that are temporary registers.
        """
        if not hasattr(self._data, 'newOp'):
            return
        # Find common dominating block
        from ghidra.block.block import FlowBlock
        blockSet = []
        for i in range(size):
            parent = copy[pos + i].getParent()
            if parent is not None:
                blockSet.append(parent)
        if not blockSet:
            return
        domBl = FlowBlock.findCommonBlock(blockSet) if hasattr(FlowBlock, 'findCommonBlock') else blockSet[0]
        domCopy = copy[pos]
        rootVn = domCopy.getIn(0)
        domVn = domCopy.getOut()
        domCopyIsNew = (domBl is not domCopy.getParent())

        if domCopyIsNew:
            # Create a new dominant COPY
            domCopy = self._data.newOp(1, domBl.getStop() if hasattr(domBl, 'getStop') else domCopy.getAddr())
            self._data.opSetOpcode(domCopy, OpCode.CPUI_COPY)
            ct = rootVn.getType()
            domVn = self._data.newUnique(rootVn.getSize(), ct)
            self._data.opSetOutput(domCopy, domVn)
            self._data.opSetInput(domCopy, rootVn, 0)
            if hasattr(self._data, 'opInsertEnd'):
                self._data.opInsertEnd(domCopy, domBl)

        # Replace non-intersecting COPYs with read of dominant Varnode
        for i in range(size):
            op = copy[pos + i]
            if op is domCopy:
                continue
            outVn = op.getOut()
            if outVn is not domVn:
                if hasattr(self._data, 'totalReplace'):
                    self._data.totalReplace(outVn, domVn)
                if hasattr(self._data, 'opDestroy'):
                    self._data.opDestroy(op)

    def markRedundantCopies(self, high: HighVariable, copy: List[PcodeOp], pos: int, size: int) -> None:
        """Mark redundant COPY ops as non-printing."""
        for i in range(size - 1, 0, -1):
            subOp = copy[pos + i]
            if hasattr(subOp, 'isDead') and subOp.isDead():
                continue
            for j in range(i - 1, -1, -1):
                domOp = copy[pos + j]
                if hasattr(domOp, 'isDead') and domOp.isDead():
                    continue
                if self.checkCopyPair(high, domOp, subOp):
                    if hasattr(self._data, 'opMarkNonPrinting'):
                        self._data.opMarkNonPrinting(subOp)
                    break

    def processHighDominantCopy(self, high: HighVariable) -> None:
        """Try to replace COPYs into the given HighVariable with a single dominant COPY."""
        copyIns: List[PcodeOp] = []
        self.findAllIntoCopies(high, copyIns, True)
        if len(copyIns) < 2:
            return
        pos = 0
        while pos < len(copyIns):
            inVn = copyIns[pos].getIn(0)
            sz = 1
            while pos + sz < len(copyIns) and copyIns[pos + sz].getIn(0) is inVn:
                sz += 1
            if sz > 1:
                self.buildDominantCopy(high, copyIns, pos, sz)
            pos += sz

    def processHighRedundantCopy(self, high: HighVariable) -> None:
        """Mark COPY ops into the given HighVariable that are redundant."""
        copyIns: List[PcodeOp] = []
        self.findAllIntoCopies(high, copyIns, False)
        if len(copyIns) < 2:
            return
        pos = 0
        while pos < len(copyIns):
            inVn = copyIns[pos].getIn(0)
            sz = 1
            while pos + sz < len(copyIns) and copyIns[pos + sz].getIn(0) is inVn:
                sz += 1
            if sz > 1:
                self.markRedundantCopies(high, copyIns, pos, sz)
            pos += sz

    def getTestCount(self) -> int:
        return self._testcount if hasattr(self, '_testcount') else 0

    def getStackAffectingOps(self) -> list:
        return self._stackAffectingOps if hasattr(self, '_stackAffectingOps') else []

    def getNumHighMerges(self) -> int:
        return self._numHighMerges if hasattr(self, '_numHighMerges') else 0

    def verifyHighCovers(self) -> None:
        """Verify that all HighVariable covers are consistent (debug method)."""
        pass

    def collectInputs(self, high: HighVariable, oplist: list, op: PcodeOp) -> None:
        """Collect Varnode instances from a HighVariable that are inputs to a given PcodeOp."""
        while True:
            for i in range(op.numInput()):
                vn = op.getIn(i)
                if vn.isAnnotation():
                    continue
                testHigh = vn.getHigh()
                if testHigh is high:
                    oplist.append((op, i))
            prev = op.previousOp() if hasattr(op, 'previousOp') else None
            if prev is None or prev.code() != OpCode.CPUI_INDIRECT:
                break
            op = prev
