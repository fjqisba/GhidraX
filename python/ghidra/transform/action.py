"""
Corresponds to: action.hh / action.cc

Action, Rule, ActionGroup, ActionPool, ActionDatabase classes.
The framework for applying transformations on function data-flow.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, List, Dict, Set

from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# ActionGroupList
# =========================================================================

class ActionGroupList:
    """The list of groups defining a root Action."""

    def __init__(self) -> None:
        self.list: Set[str] = set()

    def contains(self, nm: str) -> bool:
        return nm in self.list

    def add(self, nm: str) -> None:
        self.list.add(nm)

    def remove(self, nm: str) -> None:
        self.list.discard(nm)


# =========================================================================
# Action
# =========================================================================

class Action(ABC):
    """Large scale transformations applied to the varnode/op graph.

    The base for objects that make changes to the syntax tree of a Funcdata.
    """

    # ruleflags
    rule_repeatapply = 4
    rule_onceperfunc = 8
    rule_oneactperfunc = 16
    rule_debug = 32
    rule_warnings_on = 64
    rule_warnings_given = 128

    # statusflags
    status_start = 1
    status_breakstarthit = 2
    status_repeat = 4
    status_mid = 8
    status_end = 16
    status_actionbreak = 32

    # breakflags
    break_start = 1
    tmpbreak_start = 2
    break_action = 4
    tmpbreak_action = 8

    def __init__(self, f: int, nm: str, g: str = "") -> None:
        self._lcount: int = 0
        self._count: int = 0
        self._status: int = 0
        self._breakpoint: int = 0
        self._flags: int = f
        self._count_tests: int = 0
        self._count_apply: int = 0
        self._name: str = nm
        self._basegroup: str = g

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._basegroup

    def getStatus(self) -> int:
        return self._status

    def getNumTests(self) -> int:
        return self._count_tests

    def getNumApply(self) -> int:
        return self._count_apply

    def setBreakPoint(self, tp: int, specify: str) -> bool:
        if specify == self._name or specify == "":
            self._breakpoint |= tp
            return True
        return False

    def clearBreakPoints(self) -> None:
        self._breakpoint = 0

    def perform(self, data: Funcdata) -> int:
        """Perform this action (if necessary). Returns 0 for success."""
        if (self._status & Action.status_end) != 0:
            if (self._flags & Action.rule_onceperfunc) != 0:
                return 0
        self._count_tests += 1
        self._lcount = self._count
        result = self.apply(data)
        if self._count != self._lcount:
            self._count_apply += 1
        return result

    @abstractmethod
    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        ...

    def reset(self, data: Funcdata) -> None:
        self._status = Action.status_start
        self._count = 0
        self._lcount = 0

    def resetStats(self) -> None:
        self._count_tests = 0
        self._count_apply = 0

    @abstractmethod
    def apply(self, data: Funcdata) -> int:
        """Apply this action. Return 0 for complete, -1 for partial."""
        ...

    def getSubAction(self, specify: str) -> Optional[Action]:
        if self._name == specify:
            return self
        return None

    def getSubRule(self, specify: str) -> Optional[Rule]:
        return None

    def __repr__(self) -> str:
        return f"Action({self._name!r})"


# =========================================================================
# ActionGroup
# =========================================================================

class ActionGroup(Action):
    """A group of actions applied in sequence."""

    def __init__(self, f: int, nm: str) -> None:
        super().__init__(f, nm, "")
        self._list: List[Action] = []
        self._state_idx: int = 0

    def addAction(self, ac: Action) -> None:
        self._list.append(ac)

    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        grp = ActionGroup(self._flags, self._name)
        for ac in self._list:
            sub = ac.clone(grouplist)
            if sub is not None:
                grp.addAction(sub)
        if len(grp._list) == 0:
            return None
        return grp

    def reset(self, data: Funcdata) -> None:
        super().reset(data)
        self._state_idx = 0
        for ac in self._list:
            ac.reset(data)

    def resetStats(self) -> None:
        super().resetStats()
        for ac in self._list:
            ac.resetStats()

    def apply(self, data: Funcdata) -> int:
        while self._state_idx < len(self._list):
            ac = self._list[self._state_idx]
            res = ac.perform(data)
            if ac._count != ac._lcount:
                self._count += 1
            self._state_idx += 1
            if res < 0:
                return res
        self._status |= Action.status_end
        # Check if repeat is needed
        if (self._flags & Action.rule_repeatapply) != 0 and self._count != self._lcount:
            self._state_idx = 0
            for ac in self._list:
                ac.reset(data)
        return 0

    def clearBreakPoints(self) -> None:
        super().clearBreakPoints()
        for ac in self._list:
            ac.clearBreakPoints()

    def getSubAction(self, specify: str) -> Optional[Action]:
        if self._name == specify:
            return self
        for ac in self._list:
            sub = ac.getSubAction(specify)
            if sub is not None:
                return sub
        return None

    def getSubRule(self, specify: str) -> Optional[Rule]:
        for ac in self._list:
            sub = ac.getSubRule(specify)
            if sub is not None:
                return sub
        return None


# =========================================================================
# ActionRestartGroup
# =========================================================================

class ActionRestartGroup(ActionGroup):
    """Action which checks if restart actions have been generated and restarts."""

    def __init__(self, f: int, nm: str, maxrestarts: int = 3) -> None:
        super().__init__(f, nm)
        self._maxrestarts: int = maxrestarts
        self._curstart: int = 0

    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        grp = ActionRestartGroup(self._flags, self._name, self._maxrestarts)
        for ac in self._list:
            sub = ac.clone(grouplist)
            if sub is not None:
                grp.addAction(sub)
        if len(grp._list) == 0:
            return None
        return grp

    def reset(self, data: Funcdata) -> None:
        super().reset(data)
        self._curstart = 0

    def apply(self, data: Funcdata) -> int:
        res = super().apply(data)
        if res < 0:
            return res
        if data.hasRestartPending() and self._curstart < self._maxrestarts:
            self._curstart += 1
            data.setRestartPending(False)
            self.reset(data)
            return self.apply(data)
        return 0


# =========================================================================
# Rule
# =========================================================================

class Rule(ABC):
    """Class for performing a single transformation on a PcodeOp or Varnode.

    A Rule is handed a specific PcodeOp and determines if it can apply,
    then makes any changes. Rules inform the system of applicable op-codes
    through getOpList().
    """

    type_disable = 1
    rule_debug = 2
    warnings_on = 4
    warnings_given = 8

    def __init__(self, g: str, fl: int, nm: str) -> None:
        self._flags: int = fl
        self._breakpoint: int = 0
        self._name: str = nm
        self._basegroup: str = g
        self._count_tests: int = 0
        self._count_apply: int = 0

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._basegroup

    def getNumTests(self) -> int:
        return self._count_tests

    def getNumApply(self) -> int:
        return self._count_apply

    def isDisabled(self) -> bool:
        return (self._flags & Rule.type_disable) != 0

    def setDisable(self) -> None:
        self._flags |= Rule.type_disable

    def clearDisable(self) -> None:
        self._flags &= ~Rule.type_disable

    def setBreak(self, tp: int) -> None:
        self._breakpoint |= tp

    def clearBreak(self, tp: int) -> None:
        self._breakpoint &= ~tp

    def clearBreakPoints(self) -> None:
        self._breakpoint = 0

    @abstractmethod
    def clone(self, grouplist: ActionGroupList) -> Optional[Rule]:
        ...

    def getOpList(self) -> List[int]:
        """Return list of OpCode values this rule operates on."""
        return []

    def applyOp(self, op, data: Funcdata) -> int:
        """Attempt to apply this Rule. Returns non-zero if applied."""
        return 0

    def reset(self, data: Funcdata) -> None:
        pass

    def resetStats(self) -> None:
        self._count_tests = 0
        self._count_apply = 0

    def __repr__(self) -> str:
        return f"Rule({self._name!r})"


# =========================================================================
# ActionPool
# =========================================================================

class ActionPool(Action):
    """A pool of Rules that apply simultaneously.

    Rules are given an opportunity to apply to every PcodeOp in a function.
    """

    def __init__(self, f: int, nm: str) -> None:
        super().__init__(f, nm, "")
        self._allrules: List[Rule] = []
        self._perop: Dict[int, List[Rule]] = {}

    def addRule(self, rl: Rule) -> None:
        self._allrules.append(rl)
        for opc in rl.getOpList():
            if opc not in self._perop:
                self._perop[opc] = []
            self._perop[opc].append(rl)

    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        pool = ActionPool(self._flags, self._name)
        for rl in self._allrules:
            sub = rl.clone(grouplist)
            if sub is not None:
                pool.addRule(sub)
        if len(pool._allrules) == 0:
            return None
        return pool

    def reset(self, data: Funcdata) -> None:
        super().reset(data)
        for rl in self._allrules:
            rl.reset(data)

    def resetStats(self) -> None:
        super().resetStats()
        for rl in self._allrules:
            rl.resetStats()

    def apply(self, data: Funcdata) -> int:
        """Apply all rules to all alive PcodeOps in the function."""
        changed = True
        iterations = 0
        max_iterations = 100
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            for op in list(data._obank.beginAlive()):
                if op.isDead():
                    continue
                opc = int(op.code())
                rules = self._perop.get(opc, [])
                for rl in rules:
                    if rl.isDisabled():
                        continue
                    rl._count_tests += 1
                    res = rl.applyOp(op, data)
                    if res != 0:
                        rl._count_apply += 1
                        self._count += 1
                        changed = True
                        break  # Restart from beginning after a change
                if changed:
                    break
            if not (self._flags & Action.rule_repeatapply):
                break
        self._status |= Action.status_end
        return 0

    def getSubRule(self, specify: str) -> Optional[Rule]:
        for rl in self._allrules:
            if rl.getName() == specify:
                return rl
        return None


# =========================================================================
# ActionDatabase
# =========================================================================

class ActionDatabase:
    """Database of root Action objects for transforming functions."""

    UNIVERSAL_NAME = "universal"

    def __init__(self) -> None:
        self._currentact: Optional[Action] = None
        self._currentactname: str = ""
        self._groupmap: Dict[str, ActionGroupList] = {}
        self._actionmap: Dict[str, Action] = {}
        self._isDefaultGroups: bool = False

    def getCurrent(self) -> Optional[Action]:
        return self._currentact

    def getCurrentName(self) -> str:
        return self._currentactname

    def registerAction(self, nm: str, act: Action) -> None:
        self._actionmap[nm] = act

    def setCurrent(self, actname: str) -> Optional[Action]:
        self._currentactname = actname
        self._currentact = self._deriveAction("universal", actname)
        return self._currentact

    def _deriveAction(self, baseaction: str, grp: str) -> Optional[Action]:
        """Derive a root Action by cloning from base using a group list."""
        existing = self._actionmap.get(grp)
        if existing is not None:
            return existing
        grouplist = self._groupmap.get(grp)
        if grouplist is None:
            return None
        base = self._actionmap.get(baseaction)
        if base is None:
            return None
        newact = base.clone(grouplist)
        if newact is not None:
            self._actionmap[grp] = newact
        return newact

    def getGroup(self, grp: str) -> Optional[ActionGroupList]:
        return self._groupmap.get(grp)

    def setGroup(self, grp: str, groups: List[str]) -> None:
        gl = ActionGroupList()
        for g in groups:
            gl.add(g)
        self._groupmap[grp] = gl

    def addToGroup(self, grp: str, basegroup: str) -> bool:
        gl = self._groupmap.get(grp)
        if gl is None:
            gl = ActionGroupList()
            self._groupmap[grp] = gl
        gl.add(basegroup)
        return True

    def removeFromGroup(self, grp: str, basegroup: str) -> bool:
        gl = self._groupmap.get(grp)
        if gl is None:
            return False
        gl.remove(basegroup)
        return True

    def resetDefaults(self) -> None:
        self._isDefaultGroups = False

    def __repr__(self) -> str:
        return f"ActionDatabase(current={self._currentactname!r}, actions={len(self._actionmap)})"
