"""
Tests for pure Python basic classes: AddrSpace, Address, SeqNum, Varnode.
Verifies correctness against C++ Ghidra decompiler semantics.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import pytest
from ghidra.core.error import LowlevelError
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace, JoinSpace, OtherSpace,
    SpaceType, IPTR_CONSTANT, IPTR_PROCESSOR, IPTR_INTERNAL, IPTR_JOIN,
)
from ghidra.core.address import (
    Address, SeqNum, Range, RangeList,
    calc_mask, sign_extend, zero_extend, byte_swap, popcount,
    mostsigbit_set, leastsigbit_set, count_leading_zeros,
    pcode_left, pcode_right, signbit_negative, uintb_negate,
)
from ghidra.ir.varnode import Varnode, VarnodeBank


# =========================================================================
# AddrSpace tests
# =========================================================================

class TestAddrSpace:
    def test_basic_construction(self):
        spc = AddrSpace(name="ram", size=8, ind=3)
        assert spc.getName() == "ram"
        assert spc.getAddrSize() == 8
        assert spc.getIndex() == 3
        assert spc.getType() == IPTR_PROCESSOR
        assert spc.getWordSize() == 1

    def test_big_endian(self):
        spc_le = AddrSpace(name="ram", size=4, big_end=False)
        spc_be = AddrSpace(name="ram", size=4, big_end=True)
        assert not spc_le.isBigEndian()
        assert spc_be.isBigEndian()

    def test_highest_mask(self):
        spc4 = AddrSpace(name="ram", size=4)
        assert spc4.getHighest() == 0xFFFFFFFF
        spc8 = AddrSpace(name="ram", size=8)
        assert spc8.getHighest() == 0xFFFFFFFFFFFFFFFF
        spc2 = AddrSpace(name="ram", size=2)
        assert spc2.getHighest() == 0xFFFF

    def test_wrap_offset(self):
        spc = AddrSpace(name="ram", size=4)
        assert spc.wrapOffset(0) == 0
        assert spc.wrapOffset(0x100) == 0x100
        assert spc.wrapOffset(0xFFFFFFFF) == 0xFFFFFFFF
        assert spc.wrapOffset(0x100000000) == 0  # wraps
        assert spc.wrapOffset(0x100000001) == 1  # wraps

    def test_constant_space(self):
        cs = ConstantSpace()
        assert cs.getName() == "const"
        assert cs.getType() == IPTR_CONSTANT
        assert cs.getShortcut() == '#'
        assert cs.printRaw(42) == "#0x2a"

    def test_unique_space(self):
        us = UniqueSpace(ind=5)
        assert us.getName() == "unique"
        assert us.getType() == IPTR_INTERNAL
        assert us.getShortcut() == 'u'

    def test_join_space(self):
        js = JoinSpace(ind=6)
        assert js.getName() == "join"
        assert js.getType() == IPTR_JOIN

    def test_other_space(self):
        os_ = OtherSpace()
        assert os_.getName() == "OTHER"
        assert os_.isOtherSpace()


class TestAddrSpaceManager:
    def test_insert_and_lookup(self):
        mgr = AddrSpaceManager()
        cs = ConstantSpace(mgr)
        mgr._insertSpace(cs)
        mgr._constantSpace = cs
        ram = AddrSpace(mgr, name="ram", size=8, ind=2)
        mgr._insertSpace(ram)

        assert mgr.getSpaceByName("const") is cs
        assert mgr.getSpaceByName("ram") is ram
        assert mgr.getSpaceByIndex(0) is cs
        assert mgr.getSpaceByIndex(2) is ram
        assert mgr.getConstantSpace() is cs

    def test_lookup_nonexistent(self):
        mgr = AddrSpaceManager()
        with pytest.raises(LowlevelError):
            mgr.getSpaceByName("nonexistent")


# =========================================================================
# Address tests
# =========================================================================

class TestAddress:
    def setup_method(self):
        self.ram = AddrSpace(name="ram", size=8, ind=1)
        self.reg = AddrSpace(name="register", size=4, ind=2)
        self.cs = ConstantSpace()

    def test_basic_construction(self):
        addr = Address(self.ram, 0x1000)
        assert addr.getSpace() is self.ram
        assert addr.getOffset() == 0x1000
        assert not addr.isInvalid()

    def test_invalid_address(self):
        addr = Address()
        assert addr.isInvalid()
        assert addr.printRaw() == "invalid_addr"

    def test_equality(self):
        a1 = Address(self.ram, 0x1000)
        a2 = Address(self.ram, 0x1000)
        a3 = Address(self.ram, 0x2000)
        a4 = Address(self.reg, 0x1000)
        assert a1 == a2
        assert a1 != a3
        assert a1 != a4

    def test_ordering(self):
        a1 = Address(self.ram, 0x1000)
        a2 = Address(self.ram, 0x2000)
        assert a1 < a2
        assert a1 <= a2
        assert not (a2 < a1)
        assert not (a2 <= a1)

    def test_arithmetic(self):
        a = Address(self.ram, 0x1000)
        b = a + 0x100
        assert b.getOffset() == 0x1100
        assert b.getSpace() is self.ram
        c = a - 0x100
        assert c.getOffset() == 0xF00

    def test_hash(self):
        a1 = Address(self.ram, 0x1000)
        a2 = Address(self.ram, 0x1000)
        s = {a1}
        assert a2 in s

    def test_extremal(self):
        mn = Address.from_extreme(Address.m_minimal)
        mx = Address.from_extreme(Address.m_maximal)
        assert mn < mx
        assert mn.printRaw() == "invalid_addr"
        assert mx.printRaw() == "max_addr"

    def test_is_constant(self):
        a1 = Address(self.cs, 42)
        assert a1.isConstant()
        a2 = Address(self.ram, 42)
        assert not a2.isConstant()

    def test_containedBy(self):
        a = Address(self.ram, 0x100)
        b = Address(self.ram, 0x100)
        assert a.containedBy(4, b, 8)  # [100,103] in [100,107]
        assert not a.containedBy(16, b, 8)  # [100,10F] not in [100,107]

    def test_overlap(self):
        a = Address(self.ram, 0x100)
        b = Address(self.ram, 0x100)
        assert a.overlap(0, b, 4) == 0
        assert a.overlap(2, b, 4) == 2
        assert a.overlap(4, b, 4) == -1  # outside

    def test_isContiguous(self):
        # little-endian: self=HIGH part, loaddr=LOW part
        # lo(LOW) at [100,103], hi(HIGH) at [104,107] → hi.isContiguous(4, lo, 4)
        ram_le = AddrSpace(name="ram", size=8, ind=1, big_end=False)
        lo = Address(ram_le, 0x100)
        hi = Address(ram_le, 0x104)
        assert hi.isContiguous(4, lo, 4)  # lo+losz == hi.offset
        assert not lo.isContiguous(4, hi, 4)  # hi+4 != lo.offset


class TestSeqNum:
    def test_basic(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        pc = Address(ram, 0x401000)
        sq = SeqNum(pc, 5)
        assert sq.getAddr() == pc
        assert sq.getTime() == 5
        assert sq.getOrder() == 0

    def test_equality(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        s1 = SeqNum(Address(ram, 0x1000), 1)
        s2 = SeqNum(Address(ram, 0x1000), 1)
        s3 = SeqNum(Address(ram, 0x1000), 2)
        assert s1 == s2
        assert s1 != s3

    def test_ordering(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        s1 = SeqNum(Address(ram, 0x1000), 1)
        s2 = SeqNum(Address(ram, 0x1000), 2)
        assert s1 < s2


# =========================================================================
# Range / RangeList tests
# =========================================================================

class TestRange:
    def test_basic(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        r = Range(ram, 0x100, 0x1FF)
        assert r.getFirst() == 0x100
        assert r.getLast() == 0x1FF
        assert r.getSpace() is ram

    def test_contains(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        r = Range(ram, 0x100, 0x1FF)
        assert r.contains(Address(ram, 0x100))
        assert r.contains(Address(ram, 0x150))
        assert r.contains(Address(ram, 0x1FF))
        assert not r.contains(Address(ram, 0x200))
        assert not r.contains(Address(ram, 0x0FF))


class TestRangeList:
    def test_insert_and_query(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        rl = RangeList()
        rl.insertRange(ram, 0x100, 0x1FF)
        assert rl.numRanges() == 1
        assert rl.inRange(Address(ram, 0x100), 1)
        assert rl.inRange(Address(ram, 0x150), 1)
        assert not rl.inRange(Address(ram, 0x200), 1)

    def test_merge_overlapping(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        rl = RangeList()
        rl.insertRange(ram, 0x100, 0x1FF)
        rl.insertRange(ram, 0x180, 0x2FF)
        assert rl.numRanges() == 1  # merged
        r = rl.getFirstRange()
        assert r.getFirst() == 0x100
        assert r.getLast() == 0x2FF

    def test_remove(self):
        ram = AddrSpace(name="ram", size=8, ind=1)
        rl = RangeList()
        rl.insertRange(ram, 0x100, 0x3FF)
        rl.removeRange(ram, 0x200, 0x2FF)
        assert rl.numRanges() == 2  # split into two


# =========================================================================
# Utility function tests
# =========================================================================

class TestUtilFunctions:
    def test_calc_mask(self):
        assert calc_mask(1) == 0xFF
        assert calc_mask(2) == 0xFFFF
        assert calc_mask(4) == 0xFFFFFFFF
        assert calc_mask(8) == 0xFFFFFFFFFFFFFFFF
        assert calc_mask(16) == 0xFFFFFFFFFFFFFFFF

    def test_sign_extend(self):
        assert sign_extend(0x80, 7) == -128  # bit 7 set
        assert sign_extend(0x7F, 7) == 0x7F  # bit 7 clear

    def test_zero_extend(self):
        assert zero_extend(0xFF, 7) == 0xFF
        assert zero_extend(0x1FF, 7) == 0xFF

    def test_byte_swap(self):
        assert byte_swap(0x12345678, 4) == 0x78563412
        assert byte_swap(0x1234, 2) == 0x3412

    def test_popcount(self):
        assert popcount(0) == 0
        assert popcount(1) == 1
        assert popcount(0xFF) == 8
        assert popcount(0xFFFFFFFF) == 32

    def test_mostsigbit(self):
        assert mostsigbit_set(0) == -1
        assert mostsigbit_set(1) == 0
        assert mostsigbit_set(0x80) == 7
        assert mostsigbit_set(0x100) == 8

    def test_leastsigbit(self):
        assert leastsigbit_set(0) == -1
        assert leastsigbit_set(1) == 0
        assert leastsigbit_set(0x80) == 7
        assert leastsigbit_set(0x100) == 8

    def test_count_leading_zeros(self):
        assert count_leading_zeros(0) == 64
        assert count_leading_zeros(1) == 63
        assert count_leading_zeros(0x8000000000000000) == 0

    def test_pcode_shift(self):
        assert pcode_left(1, 4) == 16
        assert pcode_left(1, 64) == 0
        assert pcode_right(16, 4) == 1
        assert pcode_right(16, 64) == 0

    def test_signbit_negative(self):
        assert signbit_negative(0x80, 1)
        assert not signbit_negative(0x7F, 1)
        assert signbit_negative(0x80000000, 4)

    def test_uintb_negate(self):
        assert uintb_negate(0, 1) == 0xFF
        assert uintb_negate(0xFF, 1) == 0


# =========================================================================
# Varnode tests
# =========================================================================

class TestVarnode:
    def setup_method(self):
        self.ram = AddrSpace(name="ram", size=8, ind=1)
        self.cs = ConstantSpace()
        self.us = UniqueSpace(ind=3)

    def test_basic_construction(self):
        vn = Varnode(4, Address(self.ram, 0x1000))
        assert vn.getSize() == 4
        assert vn.getOffset() == 0x1000
        assert vn.getSpace() is self.ram
        assert not vn.isConstant()
        assert vn.isFree()

    def test_constant_varnode(self):
        vn = Varnode(4, Address(self.cs, 42))
        assert vn.isConstant()
        assert vn.getOffset() == 42
        assert vn.constantMatch(42)
        assert not vn.constantMatch(43)

    def test_flags(self):
        vn = Varnode(4, Address(self.ram, 0x1000))
        assert not vn.isInput()
        vn.setInput()
        assert vn.isInput()
        assert not vn.isFree()

    def test_mark_flags(self):
        vn = Varnode(4, Address(self.ram, 0x1000))
        assert not vn.isMark()
        vn.setMark()
        assert vn.isMark()
        vn.clearMark()
        assert not vn.isMark()

    def test_type_lock(self):
        vn = Varnode(4, Address(self.ram, 0x1000))
        assert not vn.isTypeLock()
        vn.setFlags(Varnode.typelock)
        assert vn.isTypeLock()

    def test_comparisons(self):
        v1 = Varnode(4, Address(self.ram, 0x1000))
        v2 = Varnode(4, Address(self.ram, 0x2000))
        assert v1 < v2
        v3 = Varnode(4, Address(self.ram, 0x1000))
        assert v1 == v3

    def test_intersects(self):
        v1 = Varnode(4, Address(self.ram, 0x1000))
        v2 = Varnode(4, Address(self.ram, 0x1002))
        v3 = Varnode(4, Address(self.ram, 0x1004))
        assert v1.intersects(v2)
        assert not v1.intersects(v3)

    def test_overlap(self):
        v1 = Varnode(4, Address(self.ram, 0x1000))
        v2 = Varnode(4, Address(self.ram, 0x1002))
        # overlap returns where self falls in op's range
        assert v2.overlap(v1) == 2   # v2 starts at byte 2 of v1
        assert v1.overlap(v2) == -1  # v1 doesn't start within v2's range
        v3 = Varnode(4, Address(self.ram, 0x2000))
        assert v1.overlap(v3) == -1

    def test_printRaw(self):
        vn = Varnode(4, Address(self.ram, 0x1000))
        s = vn.printRaw()
        assert "ram" in s
        assert "0x1000" in s

    def test_constant_printRaw(self):
        vn = Varnode(4, Address(self.cs, 42))
        s = vn.printRaw()
        assert s.startswith("#")


class TestVarnodeBank:
    def setup_method(self):
        self.ram = AddrSpace(name="ram", size=8, ind=1)

    def test_create(self):
        bank = VarnodeBank()
        vn = bank.create(4, Address(self.ram, 0x1000))
        assert bank.size() == 1
        assert vn.getSize() == 4

    def test_destroy(self):
        bank = VarnodeBank()
        vn = bank.create(4, Address(self.ram, 0x1000))
        bank.destroy(vn)
        assert bank.size() == 0

    def test_find_input(self):
        bank = VarnodeBank()
        vn = bank.create(4, Address(self.ram, 0x1000))
        assert bank.findInput(4, Address(self.ram, 0x1000)) is None
        vn.setInput()
        assert bank.findInput(4, Address(self.ram, 0x1000)) is vn

    def test_multiple_varnodes(self):
        bank = VarnodeBank()
        v1 = bank.create(4, Address(self.ram, 0x1000))
        v2 = bank.create(4, Address(self.ram, 0x2000))
        v3 = bank.create(8, Address(self.ram, 0x1000))
        assert bank.size() == 3
        found = bank.findLoc(Address(self.ram, 0x1000), 4)
        assert len(found) == 1
        assert found[0] is v1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
