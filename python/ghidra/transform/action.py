"""
Corresponds to: action.hh / action.cc

Action, Rule, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase classes.
The framework for applying transformations on function data-flow.
"""

from __future__ import annotations

import io
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, List, Dict, Set, Tuple

from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.arch.architecture import Architecture
    from ghidra.ir.op import PcodeOp


# =========================================================================
# Helper
# =========================================================================

def next_specifyterm(specify: str) -> Tuple[str, str]:
    """Pull the next token from a ':' separated list of Action and Rule names.

    Returns (token, remain).
    """
    idx = specify.find(':')
    if idx >= 0:
        return specify[:idx], specify[idx + 1:]
    return specify, ""


# =========================================================================
# ActionGroupList
# =========================================================================

class ActionGroupList:
    """The list of groups defining a root Action."""

    def __init__(self) -> None:
        self.list: Set[str] = set()

    def contains(self, nm: str) -> bool:
        """Check if this ActionGroupList contains a given group."""
        return nm in self.list


# =========================================================================
# Action
# =========================================================================

class Action(ABC):
    """Large scale transformations applied to the varnode/op graph.

    The base for objects that make changes to the syntax tree of a Funcdata.
    The action is invoked through the apply(data) method.
    This base class keeps track of basic statistics about how the action is
    being applied.  Derived classes indicate that a change has been applied
    by incrementing the count field.
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

    def __init__(self, f: int, nm: str, g: str) -> None:
        self._flags: int = f
        self._status: int = Action.status_start
        self._breakpoint: int = 0
        self._name: str = nm
        self._basegroup: str = g
        self._count_tests: int = 0
        self._count_apply: int = 0
        self._lcount: int = 0
        self._count: int = 0

    # --- Protected helpers ---

    def issueWarning(self, glb: Architecture) -> None:
        """If enabled, issue a warning that this Action has been applied."""
        if (self._flags & (Action.rule_warnings_on | Action.rule_warnings_given)) == Action.rule_warnings_on:
            self._flags |= Action.rule_warnings_given
            glb.printMessage("WARNING: Applied action " + self._name)

    def checkStartBreak(self) -> bool:
        """Check if there was an active start break point on this action."""
        if (self._breakpoint & (Action.break_start | Action.tmpbreak_start)) != 0:
            self._breakpoint &= ~Action.tmpbreak_start
            return True
        return False

    def checkActionBreak(self) -> bool:
        """Check if there was an active action breakpoint on this Action."""
        if (self._breakpoint & (Action.break_action | Action.tmpbreak_action)) != 0:
            self._breakpoint &= ~Action.tmpbreak_action
            return True
        return False

    def turnOnWarnings(self) -> None:
        """Enable warnings for this Action."""
        self._flags |= Action.rule_warnings_on

    def turnOffWarnings(self) -> None:
        """Disable warnings for this Action."""
        self._flags &= ~Action.rule_warnings_on

    # --- Public interface ---

    def getName(self) -> str:
        """Get the Action's name."""
        return self._name

    def getGroup(self) -> str:
        """Get the Action's group."""
        return self._basegroup

    def getStatus(self) -> int:
        """Get the current status of this Action."""
        return self._status

    def getNumTests(self) -> int:
        """Get the number of times apply() was invoked."""
        return self._count_tests

    def getNumApply(self) -> int:
        """Get the number of times apply() made changes."""
        return self._count_apply

    def turnOnDebug(self, nm: str) -> bool:
        """If this Action matches the given name, enable debugging."""
        if nm == self._name:
            self._flags |= Action.rule_debug
            return True
        return False

    def turnOffDebug(self, nm: str) -> bool:
        """If this Action matches the given name, disable debugging."""
        if nm == self._name:
            self._flags &= ~Action.rule_debug
            return True
        return False

    def printStatistics(self, s: io.StringIO) -> None:
        """Dump statistics to stream."""
        s.write(f"{self._name} Tested={self._count_tests} Applied={self._count_apply}\n")

    def perform(self, data: Funcdata) -> int:
        """Run this Action until completion or a breakpoint occurs.

        Generally the number of changes made by the action is returned,
        but if a breakpoint occurs -1 is returned.
        A successive call to perform() will 'continue' from the break point.
        """
        while True:
            # C++ switch with fall-through: start -> breakstarthit/repeat -> mid
            if self._status == Action.status_start:
                self._count = 0
                if self.checkStartBreak():
                    self._status = Action.status_breakstarthit
                    return -1
                self._count_tests += 1
                # fall through to breakstarthit/repeat
                self._lcount = self._count
                res = self.apply(data)
            elif self._status in (Action.status_breakstarthit, Action.status_repeat):
                self._lcount = self._count
                res = self.apply(data)
            elif self._status == Action.status_mid:
                res = self.apply(data)
            elif self._status == Action.status_end:
                return 0
            elif self._status == Action.status_actionbreak:
                # C++: just break out of switch, skip result checking
                pass
            else:
                break

            # Only check results if we actually called apply()
            if self._status != Action.status_actionbreak:
                if res < 0:
                    self._status = Action.status_mid
                    return res
                elif self._lcount < self._count:
                    self.issueWarning(data.getArch())
                    self._count_apply += 1
                    if self.checkActionBreak():
                        self._status = Action.status_actionbreak
                        return -1

            self._status = Action.status_repeat
            if not (self._lcount < self._count and (self._flags & Action.rule_repeatapply) != 0):
                break

        if (self._flags & (Action.rule_onceperfunc | Action.rule_oneactperfunc)) != 0:
            if self._count > 0 or (self._flags & Action.rule_onceperfunc) != 0:
                self._status = Action.status_end
            else:
                self._status = Action.status_start
        else:
            self._status = Action.status_start

        return self._count

    def setBreakPoint(self, tp: int, specify: str) -> bool:
        """Set a breakpoint on this action."""
        res = self.getSubAction(specify)
        if res is not None:
            res._breakpoint |= tp
            return True
        rule = self.getSubRule(specify)
        if rule is not None:
            rule.setBreak(tp)
            return True
        return False

    def clearBreakPoints(self) -> None:
        """Clear all breakpoints set on this Action."""
        self._breakpoint = 0

    def setWarning(self, val: bool, specify: str) -> bool:
        """Toggle a warning on this action or sub-action/rule."""
        res = self.getSubAction(specify)
        if res is not None:
            if val:
                res.turnOnWarnings()
            else:
                res.turnOffWarnings()
            return True
        rule = self.getSubRule(specify)
        if rule is not None:
            if val:
                rule.turnOnWarnings()
            else:
                rule.turnOffWarnings()
            return True
        return False

    def disableRule(self, specify: str) -> bool:
        """Disable a specific Rule within this Action."""
        rule = self.getSubRule(specify)
        if rule is not None:
            rule.setDisable()
            return True
        return False

    def enableRule(self, specify: str) -> bool:
        """Enable a specific Rule within this Action."""
        rule = self.getSubRule(specify)
        if rule is not None:
            rule.clearDisable()
            return True
        return False

    @abstractmethod
    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        """Clone the Action based on the grouplist."""
        ...

    def reset(self, data: Funcdata) -> None:
        """Reset the Action for a new function."""
        self._status = Action.status_start
        self._flags &= ~Action.rule_warnings_given

    def resetStats(self) -> None:
        """Reset the statistics."""
        self._count_tests = 0
        self._count_apply = 0

    @abstractmethod
    def apply(self, data: Funcdata) -> int:
        """Make a single attempt to apply this Action.

        Return 0 for a complete application, -1 for a partial completion (due to breakpoint).
        """
        ...

    def print(self, s: io.StringIO, num: int, depth: int) -> int:
        """Print a description of this Action to stream."""
        s.write(f"{num:4d}")
        s.write(" repeat " if (self._flags & Action.rule_repeatapply) != 0 else "        ")
        s.write('!' if (self._flags & Action.rule_onceperfunc) != 0 else ' ')
        s.write('S' if (self._breakpoint & (Action.break_start | Action.tmpbreak_start)) != 0 else ' ')
        s.write('A' if (self._breakpoint & (Action.break_action | Action.tmpbreak_action)) != 0 else ' ')
        s.write(' ' * (depth * 5 + 2))
        s.write(self._name)
        return num + 1

    def printState(self, s: io.StringIO) -> None:
        """Print status to stream."""
        s.write(self._name)
        if self._status in (Action.status_repeat, Action.status_breakstarthit, Action.status_start):
            s.write(" start")
        elif self._status == Action.status_mid:
            s.write(':')
        elif self._status == Action.status_end:
            s.write(" end")

    def getSubAction(self, specify: str) -> Optional[Action]:
        """Retrieve a specific sub-action by name."""
        if self._name == specify:
            return self
        return None

    def getSubRule(self, specify: str) -> Optional[Rule]:
        """Retrieve a specific sub-rule by name."""
        return None

    def __repr__(self) -> str:
        return f"Action({self._name!r})"


# =========================================================================
# ActionGroup
# =========================================================================

class ActionGroup(Action):
    """A group of actions (generally) applied in sequence.

    This is a list of Action objects, which are usually applied in sequence.
    But the behavior properties of each individual Action may affect this.
    """

    def __init__(self, f: int, nm: str) -> None:
        super().__init__(f, nm, "")
        self._list: List[Action] = []
        self._state_idx: int = 0

    def addAction(self, ac: Action) -> None:
        """Add an Action to the group."""
        self._list.append(ac)

    def clearBreakPoints(self) -> None:
        for ac in self._list:
            ac.clearBreakPoints()
        super().clearBreakPoints()

    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        res: Optional[ActionGroup] = None
        for ac in self._list:
            sub = ac.clone(grouplist)
            if sub is not None:
                if res is None:
                    res = ActionGroup(self._flags, self._name)
                res.addAction(sub)
        return res

    def reset(self, data: Funcdata) -> None:
        super().reset(data)
        for ac in self._list:
            ac.reset(data)

    def resetStats(self) -> None:
        super().resetStats()
        for ac in self._list:
            ac.resetStats()

    def apply(self, data: Funcdata) -> int:
        if self._status != Action.status_mid:
            self._state_idx = 0
        while self._state_idx < len(self._list):
            ac = self._list[self._state_idx]
            res = ac.perform(data)
            if res > 0:
                self._count += res
                if self.checkActionBreak():
                    self._state_idx += 1
                    return -1
            elif res < 0:
                return -1
            self._state_idx += 1
        return 0

    def print(self, s: io.StringIO, num: int, depth: int) -> int:
        num = super().print(s, num, depth)
        s.write('\n')
        for i, ac in enumerate(self._list):
            num = ac.print(s, num, depth + 1)
            if self._state_idx == i:
                s.write("  <-- ")
            s.write('\n')
        return num

    def printState(self, s: io.StringIO) -> None:
        super().printState(s)
        if self._status == Action.status_mid:
            if 0 <= self._state_idx < len(self._list):
                self._list[self._state_idx].printState(s)

    def getSubAction(self, specify: str) -> Optional[Action]:
        token, remain = next_specifyterm(specify)
        if self._name == token:
            if not remain:
                return self
        else:
            remain = specify

        lastaction: Optional[Action] = None
        matchcount = 0
        for ac in self._list:
            testaction = ac.getSubAction(remain)
            if testaction is not None:
                lastaction = testaction
                matchcount += 1
                if matchcount > 1:
                    return None
        return lastaction

    def getSubRule(self, specify: str) -> Optional[Rule]:
        token, remain = next_specifyterm(specify)
        if self._name == token:
            if not remain:
                return None
        else:
            remain = specify

        lastrule: Optional[Rule] = None
        matchcount = 0
        for ac in self._list:
            testrule = ac.getSubRule(remain)
            if testrule is not None:
                lastrule = testrule
                matchcount += 1
                if matchcount > 1:
                    return None
        return lastrule

    def turnOnDebug(self, nm: str) -> bool:
        if super().turnOnDebug(nm):
            return True
        for ac in self._list:
            if ac.turnOnDebug(nm):
                return True
        return False

    def turnOffDebug(self, nm: str) -> bool:
        if super().turnOffDebug(nm):
            return True
        for ac in self._list:
            if ac.turnOffDebug(nm):
                return True
        return False

    def printStatistics(self, s: io.StringIO) -> None:
        super().printStatistics(s)
        for ac in self._list:
            ac.printStatistics(s)


# =========================================================================
# ActionRestartGroup
# =========================================================================

class ActionRestartGroup(ActionGroup):
    """Action which checks if restart (sub)actions have been generated
    and restarts itself.

    Actions or Rules can request a restart on a Funcdata object by calling
    setRestartPending(True) on it. This action checks for the request then
    resets and reruns the group of Actions as appropriate.
    """

    def __init__(self, f: int, nm: str, maxrestarts: int = 3) -> None:
        super().__init__(f, nm)
        self._maxrestarts: int = maxrestarts
        self._curstart: int = 0

    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        res: Optional[ActionRestartGroup] = None
        for ac in self._list:
            sub = ac.clone(grouplist)
            if sub is not None:
                if res is None:
                    res = ActionRestartGroup(self._flags, self._name, self._maxrestarts)
                res.addAction(sub)
        return res

    def reset(self, data: Funcdata) -> None:
        self._curstart = 0
        super().reset(data)

    def apply(self, data: Funcdata) -> int:
        if self._curstart == -1:
            return 0
        while True:
            res = super().apply(data)
            if res != 0:
                return res
            if not data.hasRestartPending():
                self._curstart = -1
                return 0
            if data.isJumptableRecoveryOn():
                return 0
            self._curstart += 1
            if self._curstart > self._maxrestarts:
                data.warningHeader("Exceeded maximum restarts with more pending")
                self._curstart = -1
                return 0
            data.getArch().clearAnalysis(data)

            for ac in self._list:
                ac.reset(data)
            self._status = Action.status_start


# =========================================================================
# Rule
# =========================================================================

class Rule(ABC):
    """Class for performing a single transformation on a PcodeOp or Varnode.

    A Rule, through its applyOp() method, is handed a specific PcodeOp as a
    potential point to apply. It determines if it can apply at that point, then
    makes any changes. Rules inform the system of what types of PcodeOps they
    can possibly apply to through the getOpList() method. A set of Rules are
    pooled together into a single Action via the ActionPool, which efficiently
    applies each Rule across a whole function.
    """

    # typeflags
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
        """Return the name of this Rule."""
        return self._name

    def getGroup(self) -> str:
        """Return the group this Rule belongs to."""
        return self._basegroup

    def getNumTests(self) -> int:
        """Get number of attempted applications."""
        return self._count_tests

    def getNumApply(self) -> int:
        """Get number of successful applications."""
        return self._count_apply

    def setBreak(self, tp: int) -> None:
        """Set a breakpoint on this Rule."""
        self._breakpoint |= tp

    def clearBreak(self, tp: int) -> None:
        """Clear a breakpoint on this Rule."""
        self._breakpoint &= ~tp

    def clearBreakPoints(self) -> None:
        """Clear all breakpoints on this Rule."""
        self._breakpoint = 0

    def turnOnWarnings(self) -> None:
        """Enable warnings for this Rule."""
        self._flags |= Rule.warnings_on

    def turnOffWarnings(self) -> None:
        """Disable warnings for this Rule."""
        self._flags &= ~Rule.warnings_on

    def isDisabled(self) -> bool:
        """Return True if this Rule is disabled."""
        return (self._flags & Rule.type_disable) != 0

    def setDisable(self) -> None:
        """Disable this Rule (within its pool)."""
        self._flags |= Rule.type_disable

    def clearDisable(self) -> None:
        """Enable this Rule (within its pool)."""
        self._flags &= ~Rule.type_disable

    def checkActionBreak(self) -> bool:
        """Check if an action breakpoint is turned on."""
        if (self._breakpoint & (Action.break_action | Action.tmpbreak_action)) != 0:
            self._breakpoint &= ~Action.tmpbreak_action
            return True
        return False

    def getBreakPoint(self) -> int:
        """Return breakpoint toggles."""
        return self._breakpoint

    def issueWarning(self, glb: Architecture) -> None:
        """If enabled, print a warning that this Rule has been applied."""
        if (self._flags & (Rule.warnings_on | Rule.warnings_given)) == Rule.warnings_on:
            self._flags |= Rule.warnings_given
            glb.printMessage("WARNING: Applied rule " + self._name)

    @abstractmethod
    def clone(self, grouplist: ActionGroupList) -> Optional[Rule]:
        """Clone the Rule. Returns None if not in the grouplist."""
        ...

    def getOpList(self) -> List[int]:
        """List of op codes this rule operates on.

        By default, returns all possible OpCodes.
        """
        return list(range(int(OpCode.CPUI_MAX)))

    def applyOp(self, op: PcodeOp, data: Funcdata) -> int:
        """Attempt to apply this Rule.

        Returns non-zero (1) if the Rule applied, 0 otherwise.
        """
        return 0

    def reset(self, data: Funcdata) -> None:
        """Reset this Rule. Clears per-function state."""
        self._flags &= ~Rule.warnings_given

    def resetStats(self) -> None:
        """Reset Rule statistics."""
        self._count_tests = 0
        self._count_apply = 0

    def printStatistics(self, s: io.StringIO) -> None:
        """Print statistics for this Rule."""
        s.write(f"{self._name} Tested={self._count_tests} Applied={self._count_apply}\n")

    def turnOnDebug(self, nm: str) -> bool:
        """If this Rule has the given name, enable debugging."""
        if nm == self._name:
            self._flags |= Rule.rule_debug
            return True
        return False

    def turnOffDebug(self, nm: str) -> bool:
        """If this Rule has the given name, disable debugging."""
        if nm == self._name:
            self._flags &= ~Rule.rule_debug
            return True
        return False

    def __repr__(self) -> str:
        return f"Rule({self._name!r})"


# =========================================================================
# ActionPool
# =========================================================================

class ActionPool(Action):
    """A pool of Rules that apply simultaneously.

    This class groups together a set of Rules as a formal Action.
    Rules are given an opportunity to apply to every PcodeOp in a function.
    Usually rule_repeatapply is enabled for this action, which causes
    all Rules to apply repeatedly until no Rule can make an additional change.
    """

    CPUI_MAX = int(OpCode.CPUI_MAX)

    def __init__(self, f: int, nm: str) -> None:
        super().__init__(f, nm, "")
        self._allrules: List[Rule] = []
        self._perop: Dict[int, List[Rule]] = {}
        self._op_state_iter = None  # Iterator state for apply
        self._op_state_list: Optional[list] = None
        self._op_state_idx: int = 0
        self._rule_index: int = 0

    def addRule(self, rl: Rule) -> None:
        """Add a Rule to the pool."""
        self._allrules.append(rl)
        oplist = rl.getOpList()
        for opc in oplist:
            if opc not in self._perop:
                self._perop[opc] = []
            self._perop[opc].append(rl)

    def clearBreakPoints(self) -> None:
        for rl in self._allrules:
            rl.clearBreakPoints()
        super().clearBreakPoints()

    def clone(self, grouplist: ActionGroupList) -> Optional[Action]:
        res: Optional[ActionPool] = None
        for rl in self._allrules:
            sub = rl.clone(grouplist)
            if sub is not None:
                if res is None:
                    res = ActionPool(self._flags, self._name)
                res.addRule(sub)
        return res

    def reset(self, data: Funcdata) -> None:
        super().reset(data)
        for rl in self._allrules:
            rl.reset(data)

    def resetStats(self) -> None:
        super().resetStats()
        for rl in self._allrules:
            rl.resetStats()

    def _processOp(self, op: PcodeOp, data: Funcdata) -> int:
        """Apply the next possible Rule to a PcodeOp.

        The PcodeOp iterator is advanced internally.
        Returns 0 if no breakpoint, -1 otherwise.
        """
        if op.isDead():
            self._op_state_idx += 1
            data.opDeadAndGone(op)
            self._rule_index = 0
            return 0

        opc = int(op.code())
        rules = self._perop.get(opc, [])
        while self._rule_index < len(rules):
            rl = rules[self._rule_index]
            self._rule_index += 1
            if rl.isDisabled():
                continue
            rl._count_tests += 1
            res = rl.applyOp(op, data)
            if res > 0:
                rl._count_apply += 1
                self._count += res
                rl.issueWarning(data.getArch())
                if rl.checkActionBreak():
                    return -1
                if op.isDead():
                    break
                new_opc = int(op.code())
                if opc != new_opc:
                    opc = new_opc
                    rules = self._perop.get(opc, [])
                    self._rule_index = 0
            else:
                new_opc = int(op.code())
                if opc != new_opc:
                    data.getArch().printMessage(
                        "ERROR: Rule " + rl.getName() +
                        " changed op without returning result of 1!")
                    opc = new_opc
                    rules = self._perop.get(opc, [])
                    self._rule_index = 0

        self._op_state_idx += 1
        self._rule_index = 0
        return 0

    def apply(self, data: Funcdata) -> int:
        """Apply all rules to all PcodeOps in the function."""
        if self._status != Action.status_mid:
            self._op_state_list = list(data.beginOpAll())
            self._op_state_idx = 0
            self._rule_index = 0

        while self._op_state_idx < len(self._op_state_list):
            op = self._op_state_list[self._op_state_idx]
            if self._processOp(op, data) != 0:
                return -1

        return 0

    def print(self, s: io.StringIO, num: int, depth: int) -> int:
        num = super().print(s, num, depth)
        s.write('\n')
        depth += 1
        for rl in self._allrules:
            s.write(f"{num:4d}")
            s.write('D' if rl.isDisabled() else ' ')
            s.write('A' if (rl.getBreakPoint() & (Action.break_action | Action.tmpbreak_action)) != 0 else ' ')
            s.write(' ' * (depth * 5 + 2))
            s.write(rl.getName())
            s.write('\n')
            num += 1
        return num

    def printState(self, s: io.StringIO) -> None:
        super().printState(s)
        if self._status == Action.status_mid:
            if self._op_state_list and 0 <= self._op_state_idx - 1 < len(self._op_state_list):
                op = self._op_state_list[self._op_state_idx - 1]
                s.write(f" {op.getSeqNum()}")

    def getSubRule(self, specify: str) -> Optional[Rule]:
        token, remain = next_specifyterm(specify)
        if self._name == token:
            if not remain:
                return None
        else:
            remain = specify

        lastrule: Optional[Rule] = None
        matchcount = 0
        for rl in self._allrules:
            if rl.getName() == remain:
                lastrule = rl
                matchcount += 1
                if matchcount > 1:
                    return None
        return lastrule

    def turnOnDebug(self, nm: str) -> bool:
        if super().turnOnDebug(nm):
            return True
        for rl in self._allrules:
            if rl.turnOnDebug(nm):
                return True
        return False

    def turnOffDebug(self, nm: str) -> bool:
        if super().turnOffDebug(nm):
            return True
        for rl in self._allrules:
            if rl.turnOffDebug(nm):
                return True
        return False

    def printStatistics(self, s: io.StringIO) -> None:
        super().printStatistics(s)
        for rl in self._allrules:
            rl.printStatistics(s)


# =========================================================================
# ActionDatabase
# =========================================================================

class ActionDatabase:
    """Database of root Action objects that can be used to transform a function.

    This is a container for Action objects. It also manages root Action objects,
    which encapsulate a complete transformation system that can be applied to
    functions. Root Action objects are derived from a single universal Action
    object that has every possible sub-action within it. A root Action has its
    own name and is derived from the universal via a grouplist, which lists a
    particular subset of Action and Rule groups to use for the root.
    """

    UNIVERSAL_NAME = "universal"

    def __init__(self) -> None:
        self._currentact: Optional[Action] = None
        self._currentactname: str = ""
        self._groupmap: Dict[str, ActionGroupList] = {}
        self._actionmap: Dict[str, Action] = {}
        self._isDefaultGroups: bool = False

    def getCurrent(self) -> Optional[Action]:
        """Get the current root Action."""
        return self._currentact

    def getCurrentName(self) -> str:
        """Get the name of the current root Action."""
        return self._currentactname

    def getGroup(self, grp: str) -> ActionGroupList:
        """Get a specific grouplist by name."""
        gl = self._groupmap.get(grp)
        if gl is None:
            raise RuntimeError("Action group does not exist: " + grp)
        return gl

    def setCurrent(self, actname: str) -> Optional[Action]:
        """Set the current root Action."""
        self._currentactname = actname
        self._currentact = self._deriveAction(ActionDatabase.UNIVERSAL_NAME, actname)
        return self._currentact

    def toggleAction(self, grp: str, basegrp: str, val: bool) -> Optional[Action]:
        """Toggle a group of Actions with a root Action."""
        act = self.getAction(ActionDatabase.UNIVERSAL_NAME)
        if val:
            self.addToGroup(grp, basegrp)
        else:
            self.removeFromGroup(grp, basegrp)
        curgrp = self.getGroup(grp)
        newact = act.clone(curgrp)
        self._registerAction(grp, newact)
        if grp == self._currentactname:
            self._currentact = newact
        return newact

    def setGroup(self, grp: str, groups: List[str]) -> None:
        """Establish a new root Action from a list of group names."""
        gl = ActionGroupList()
        for g in groups:
            if g:
                gl.list.add(g)
        self._groupmap[grp] = gl
        self._isDefaultGroups = False

    def cloneGroup(self, oldname: str, newname: str) -> None:
        """Clone a root Action by copying its grouplist."""
        curgrp = self.getGroup(oldname)
        newgl = ActionGroupList()
        newgl.list = set(curgrp.list)
        self._groupmap[newname] = newgl
        self._isDefaultGroups = False

    def addToGroup(self, grp: str, basegroup: str) -> bool:
        """Add a group to a root Action."""
        self._isDefaultGroups = False
        if grp not in self._groupmap:
            self._groupmap[grp] = ActionGroupList()
        gl = self._groupmap[grp]
        was_new = basegroup not in gl.list
        gl.list.add(basegroup)
        return was_new

    def removeFromGroup(self, grp: str, basegrp: str) -> bool:
        """Remove a group from a root Action."""
        self._isDefaultGroups = False
        if grp not in self._groupmap:
            self._groupmap[grp] = ActionGroupList()
        gl = self._groupmap[grp]
        if basegrp in gl.list:
            gl.list.discard(basegrp)
            return True
        return False

    def universalAction(self, glb: Architecture) -> None:
        """Build the universal action. Override to populate."""
        pass

    def buildDefaultGroups(self) -> None:
        """Set up descriptions of preconfigured root Actions. Override to populate."""
        pass

    def resetDefaults(self) -> None:
        """(Re)set the default configuration."""
        universal_act = self._actionmap.get(ActionDatabase.UNIVERSAL_NAME)
        to_delete = {k: v for k, v in self._actionmap.items() if v is not universal_act}
        for k in to_delete:
            del self._actionmap[k]
        if universal_act is not None:
            self._actionmap[ActionDatabase.UNIVERSAL_NAME] = universal_act
        self.buildDefaultGroups()
        self.setCurrent("decompile")

    def getAction(self, nm: str) -> Action:
        """Look up a root Action by name."""
        act = self._actionmap.get(nm)
        if act is None:
            raise RuntimeError("No registered action: " + nm)
        return act

    def registerAction(self, nm: str, act: Action) -> None:
        """Public registration of a root Action."""
        self._registerAction(nm, act)

    def _registerAction(self, nm: str, act: Optional[Action]) -> None:
        """Internal method for associating a root Action name with its Action object."""
        self._actionmap[nm] = act

    def _deriveAction(self, baseaction: str, grp: str) -> Optional[Action]:
        """Derive a root Action by cloning from base using a group list."""
        existing = self._actionmap.get(grp)
        if existing is not None:
            return existing
        curgrp = self.getGroup(grp)
        act = self.getAction(baseaction)
        newact = act.clone(curgrp)
        self._registerAction(grp, newact)
        return newact

    def __repr__(self) -> str:
        return f"ActionDatabase(current={self._currentactname!r}, actions={len(self._actionmap)})"
