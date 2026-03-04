"""
ParamTrial and ParamActive classes for parameter recovery.
Corresponds to fspec.hh / fspec.cc.
"""
from __future__ import annotations
from typing import List, Optional
from ghidra.core.address import Address


class ParamTrial:
    """A potential parameter location being evaluated."""
    # Flags
    checked = 0x01
    used = 0x02
    defnouse = 0x04
    active = 0x08
    unref = 0x10
    killedbycall = 0x20
    rem_formed = 0x40
    indcreate_formed = 0x80
    condexe_effect = 0x100
    fix_position = 0x200

    def __init__(self, addr: Address, sz: int, slot: int = -1) -> None:
        self._addr = addr
        self._size = sz
        self._slot = slot
        self._flags = 0
        self._fixedPosition = -1

    def getAddress(self) -> Address:
        return self._addr

    def getSize(self) -> int:
        return self._size

    def getSlot(self) -> int:
        return self._slot

    def setSlot(self, s: int) -> None:
        self._slot = s

    def setAddress(self, addr: Address, sz: int) -> None:
        self._addr = addr
        self._size = sz

    def isChecked(self) -> bool:
        return (self._flags & ParamTrial.checked) != 0

    def isUsed(self) -> bool:
        return (self._flags & ParamTrial.used) != 0

    def isActive(self) -> bool:
        return (self._flags & ParamTrial.active) != 0

    def isUnref(self) -> bool:
        return (self._flags & ParamTrial.unref) != 0

    def isFixedPosition(self) -> bool:
        return (self._flags & ParamTrial.fix_position) != 0

    def markChecked(self) -> None:
        self._flags |= ParamTrial.checked

    def markUsed(self) -> None:
        self._flags |= ParamTrial.used

    ancestor_realistic = 0x200
    ancestor_solid = 0x400

    def getEntry(self):
        """Get the PrototypeModel entry matching this trial."""
        return getattr(self, '_entry', None)

    def setEntry(self, ent, off: int = -1) -> None:
        """Set the model entry for this trial."""
        self._entry = ent
        self._offset = off

    def getOffset(self) -> int:
        """Get the offset associated with this trial."""
        return getattr(self, '_offset', -1)

    def markActive(self) -> None:
        self._flags |= ParamTrial.active | ParamTrial.checked

    def markInactive(self) -> None:
        self._flags &= ~ParamTrial.active
        self._flags |= ParamTrial.checked

    def markNoUse(self) -> None:
        self._flags &= ~(ParamTrial.active | ParamTrial.used)
        self._flags |= ParamTrial.checked | ParamTrial.defnouse

    def markUnref(self) -> None:
        self._flags |= ParamTrial.unref | ParamTrial.checked
        self._slot = -1

    def markKilledByCall(self) -> None:
        self._flags |= ParamTrial.killedbycall

    def isDefinitelyNotUsed(self) -> bool:
        return (self._flags & ParamTrial.defnouse) != 0

    def isKilledByCall(self) -> bool:
        return (self._flags & ParamTrial.killedbycall) != 0

    def setRemFormed(self) -> None:
        self._flags |= ParamTrial.rem_formed

    def isRemFormed(self) -> bool:
        return (self._flags & ParamTrial.rem_formed) != 0

    def setIndCreateFormed(self) -> None:
        self._flags |= ParamTrial.indcreate_formed

    def isIndCreateFormed(self) -> bool:
        return (self._flags & ParamTrial.indcreate_formed) != 0

    def setCondExeEffect(self) -> None:
        self._flags |= ParamTrial.condexe_effect

    def hasCondExeEffect(self) -> bool:
        return (self._flags & ParamTrial.condexe_effect) != 0

    def setAncestorRealistic(self) -> None:
        self._flags |= ParamTrial.ancestor_realistic

    def hasAncestorRealistic(self) -> bool:
        return (self._flags & ParamTrial.ancestor_realistic) != 0

    def setAncestorSolid(self) -> None:
        self._flags |= ParamTrial.ancestor_solid

    def hasAncestorSolid(self) -> bool:
        return (self._flags & ParamTrial.ancestor_solid) != 0

    def slotGroup(self) -> int:
        """Get position of this within its parameter group."""
        entry = self.getEntry()
        if entry is not None and hasattr(entry, 'getSlot'):
            return entry.getSlot(self._addr, self._size - 1)
        return 0

    def splitHi(self, sz: int):
        """Create a trial representing the first part of this."""
        return ParamTrial(self._addr, sz, self._slot)

    def splitLo(self, sz: int):
        """Create a trial representing the last part of this."""
        newaddr = Address(self._addr.getSpace(), self._addr.getOffset() + (self._size - sz))
        return ParamTrial(newaddr, sz, self._slot)

    def setFixedPosition(self, pos: int) -> None:
        self._fixedPosition = pos

    def getFixedPosition(self) -> int:
        return self._fixedPosition

    def testShrink(self, addr: Address, sz: int) -> bool:
        """Test if this trial can be made smaller to the given range."""
        if addr.getSpace() is not self._addr.getSpace():
            return False
        if addr.getOffset() < self._addr.getOffset():
            return False
        if addr.getOffset() + sz > self._addr.getOffset() + self._size:
            return False
        return True

    def __lt__(self, other: ParamTrial) -> bool:
        if self._slot != other._slot:
            return self._slot < other._slot
        return self._addr.getOffset() < other._addr.getOffset()

    @staticmethod
    def fixedPositionCompare(a: ParamTrial, b: ParamTrial) -> bool:
        if a._fixedPosition != b._fixedPosition:
            return a._fixedPosition < b._fixedPosition
        return a < b


class ParamActive:
    """Container for parameter trials during active prototype recovery."""

    def __init__(self, recoversub: bool = False) -> None:
        self._trial: List[ParamTrial] = []
        self._slotbase: int = 1
        self._stackplaceholder: int = -1
        self._numpasses: int = 0
        self._maxpass: int = 0
        self._isfullychecked: bool = False
        self._needsfinalcheck: bool = False
        self._recoversubcall: bool = recoversub
        self._joinReverse: bool = False

    def clear(self) -> None:
        self._trial.clear()
        self._slotbase = 1
        self._stackplaceholder = -1
        self._numpasses = 0
        self._isfullychecked = False
        self._needsfinalcheck = False

    def registerTrial(self, addr: Address, sz: int) -> None:
        slot = self._slotbase
        self._slotbase += 1
        self._trial.append(ParamTrial(addr, sz, slot))

    def getNumTrials(self) -> int:
        return len(self._trial)

    def getTrial(self, i: int) -> ParamTrial:
        return self._trial[i]

    def whichTrial(self, addr: Address, sz: int) -> int:
        for i, t in enumerate(self._trial):
            if t.getAddress() == addr and t.getSize() == sz:
                return i
        return -1

    def needsFinalCheck(self) -> bool:
        return self._needsfinalcheck

    def markNeedsFinalCheck(self) -> None:
        self._needsfinalcheck = True

    def isRecoverSubcall(self) -> bool:
        return self._recoversubcall

    def isFullyChecked(self) -> bool:
        return self._isfullychecked

    def markFullyChecked(self) -> None:
        self._isfullychecked = True

    def isJoinReverse(self) -> bool:
        return self._joinReverse

    def setJoinReverse(self) -> None:
        self._joinReverse = True

    def setPlaceholderSlot(self) -> None:
        self._stackplaceholder = self._slotbase
        self._slotbase += 1

    def freePlaceholderSlot(self) -> None:
        self._stackplaceholder = -1

    def getNumPasses(self) -> int:
        return self._numpasses

    def getMaxPass(self) -> int:
        return self._maxpass

    def setMaxPass(self, val: int) -> None:
        self._maxpass = val

    def finishPass(self) -> None:
        self._numpasses += 1

    def sortTrials(self) -> None:
        self._trial.sort()

    def deleteUnusedTrials(self) -> None:
        self._trial = [t for t in self._trial if t.isUsed()]

    def splitTrial(self, i: int, sz: int) -> None:
        t = self._trial[i]
        addr1 = t.getAddress()
        sz1 = sz
        addr2 = Address(addr1.getSpace(), addr1.getOffset() + sz)
        sz2 = t.getSize() - sz
        t.setAddress(addr1, sz1)
        newtrial = ParamTrial(addr2, sz2, t.getSlot())
        self._trial.insert(i + 1, newtrial)

    def getNumUsed(self) -> int:
        return sum(1 for t in self._trial if t.isUsed())

    def getTrialForInputVarnode(self, slot: int) -> ParamTrial:
        """Get trial corresponding to the given input Varnode slot."""
        adj = 1 if (self._stackplaceholder < 0 or slot < self._stackplaceholder) else 2
        idx = slot - adj
        if 0 <= idx < len(self._trial):
            return self._trial[idx]
        return self._trial[0] if self._trial else None

    def joinTrial(self, slot: int, addr: Address, sz: int) -> None:
        """Join adjacent parameter trials."""
        for i, t in enumerate(self._trial):
            if t.getSlot() == slot:
                t.setAddress(addr, sz)
                # Remove the next trial if it exists
                if i + 1 < len(self._trial):
                    del self._trial[i + 1]
                break

    def sortFixedPosition(self) -> None:
        """Sort trials by fixed position then by normal ordering."""
        self._trial.sort(key=lambda t: (t.getFixedPosition() if t.getFixedPosition() >= 0 else 0x7FFFFFFF, t.getSlot()))

    def testShrink(self, i: int, addr: Address, sz: int) -> bool:
        """Test if the given trial can be shrunk to the given range."""
        if 0 <= i < len(self._trial):
            return self._trial[i].testShrink(addr, sz)
        return False

    def shrink(self, i: int, addr: Address, sz: int) -> None:
        """Shrink the given trial to a new given range."""
        if 0 <= i < len(self._trial):
            self._trial[i].setAddress(addr, sz)

    def __repr__(self) -> str:
        return f"ParamActive(trials={len(self._trial)}, passes={self._numpasses})"
