"""
universalAction() pipeline wiring + buildDefaultGroups().
Corresponds to the end of coreaction.cc.
"""
from __future__ import annotations
from ghidra.transform.action import (
    Action, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase,
)
from ghidra.transform.coreaction import *
from ghidra.transform.coreaction2 import *

# Import all available rules
from ghidra.transform.ruleaction import *
from ghidra.transform.ruleaction_batch1a import *
from ghidra.transform.ruleaction_batch1b import *
from ghidra.transform.ruleaction_batch1c import *
from ghidra.transform.ruleaction_batch1d import *
from ghidra.transform.ruleaction_batch1e import *
from ghidra.transform.ruleaction_batch1f import *
from ghidra.transform.ruleaction_batch1g import *
from ghidra.transform.ruleaction_batch1h import *
from ghidra.transform.ruleaction_batch1i import *
from ghidra.transform.ruleaction_batch2a import *
from ghidra.transform.ruleaction_batch2b import *
from ghidra.transform.ruleaction_batch2c import *


def universalAction(allacts: ActionDatabase, conf) -> None:
    """Construct the universal Action containing all possible components.

    Mirrors ActionDatabase::universalAction() in coreaction.cc.
    """
    stackspace = conf.getStackSpace() if conf is not None else None

    act = ActionRestartGroup(Action.rule_onceperfunc, "universal", 1)
    allacts.registerAction("universal", act)

    act.addAction(ActionStart("base"))
    act.addAction(ActionConstbase("base"))
    act.addAction(ActionNormalizeSetup("normalanalysis"))
    act.addAction(ActionDefaultParams("base"))
    act.addAction(ActionExtraPopSetup("base", stackspace))
    act.addAction(ActionPrototypeTypes("protorecovery"))
    act.addAction(ActionFuncLink("protorecovery"))
    act.addAction(ActionFuncLinkOutOnly("noproto"))

    # --- fullloop ---
    actfullloop = ActionGroup(Action.rule_repeatapply, "fullloop")

    # --- mainloop ---
    actmainloop = ActionGroup(Action.rule_repeatapply, "mainloop")
    actmainloop.addAction(ActionUnreachable("base"))
    actmainloop.addAction(ActionVarnodeProps("base"))
    actmainloop.addAction(ActionHeritage("base"))
    actmainloop.addAction(ActionParamDouble("protorecovery"))
    actmainloop.addAction(ActionSegmentize("base"))
    actmainloop.addAction(ActionInternalStorage("base"))
    actmainloop.addAction(ActionForceGoto("blockrecovery"))
    actmainloop.addAction(ActionDirectWrite("protorecovery_a", True))
    actmainloop.addAction(ActionDirectWrite("protorecovery_b", False))
    actmainloop.addAction(ActionActiveParam("protorecovery"))
    actmainloop.addAction(ActionReturnRecovery("protorecovery"))
    actmainloop.addAction(ActionRestrictLocal("localrecovery"))
    actmainloop.addAction(ActionDeadCode("deadcode"))
    actmainloop.addAction(ActionDynamicMapping("dynamic"))
    actmainloop.addAction(ActionRestructureVarnode("localrecovery"))
    actmainloop.addAction(ActionSpacebase("base"))
    actmainloop.addAction(ActionNonzeroMask("analysis"))
    actmainloop.addAction(ActionInferTypes("typerecovery"))

    # --- stackstall (contains oppool1) ---
    actstackstall = ActionGroup(Action.rule_repeatapply, "stackstall")

    actprop = ActionPool(Action.rule_repeatapply, "oppool1")
    actprop.addRule(RuleEarlyRemoval("deadcode"))
    actprop.addRule(RuleTermOrder("analysis"))
    # RuleSelectCse - needs CSE infra
    # RuleCollectTerms - needs TermOrder
    actprop.addRule(RuleSborrow("analysis"))
    actprop.addRule(RuleScarry("analysis"))
    actprop.addRule(RuleIntLessEqual("analysis"))
    actprop.addRule(RuleTrivialArith("analysis"))
    actprop.addRule(RuleTrivialBool("analysis"))
    actprop.addRule(RuleTrivialShift("analysis"))
    actprop.addRule(RuleSignShift("analysis"))
    actprop.addRule(RuleTestSign("analysis"))
    actprop.addRule(RuleIdentityEl("analysis"))
    actprop.addRule(RuleOrMask("analysis"))
    actprop.addRule(RuleAndMask("analysis"))
    actprop.addRule(RuleOrConsume("analysis"))
    actprop.addRule(RuleOrCollapse("analysis"))
    actprop.addRule(RuleAndOrLump("analysis"))
    actprop.addRule(RuleShiftBitops("analysis"))
    actprop.addRule(RuleRightShiftAnd("analysis"))
    actprop.addRule(RuleNotDistribute("analysis"))
    actprop.addRule(RuleHighOrderAnd("analysis"))
    actprop.addRule(RuleAndDistribute("analysis"))
    actprop.addRule(RuleAndCommute("analysis"))
    actprop.addRule(RuleAndPiece("analysis"))
    actprop.addRule(RuleAndZext("analysis"))
    actprop.addRule(RuleAndCompare("analysis"))
    actprop.addRule(RuleDoubleSub("analysis"))
    actprop.addRule(RuleDoubleShift("analysis"))
    actprop.addRule(RuleDoubleArithShift("analysis"))
    actprop.addRule(RuleConcatShift("analysis"))
    actprop.addRule(RuleLeftRight("analysis"))
    actprop.addRule(RuleShiftCompare("analysis"))
    actprop.addRule(RuleShift2Mult("analysis"))
    actprop.addRule(RuleShiftPiece("analysis"))
    # RuleMultiCollapse - needs totalReplace
    # RuleIndirectCollapse - needs getOpFromConst
    actprop.addRule(Rule2Comp2Mult("analysis"))
    actprop.addRule(RuleSub2Add("analysis"))
    actprop.addRule(RuleCarryElim("analysis"))
    actprop.addRule(RuleBxor2NotEqual("analysis"))
    actprop.addRule(RuleLess2Zero("analysis"))
    actprop.addRule(RuleLessEqual2Zero("analysis"))
    actprop.addRule(RuleSLess2Zero("analysis"))
    actprop.addRule(RuleEqual2Zero("analysis"))
    actprop.addRule(RuleEqual2Constant("analysis"))
    # RuleThreeWayCompare - complex
    actprop.addRule(RuleXorCollapse("analysis"))
    actprop.addRule(RuleAddMultCollapse("analysis"))
    actprop.addRule(RuleCollapseConstants("analysis"))
    # RuleTransformCpool - needs cpool
    actprop.addRule(RulePropagateCopy("analysis"))
    actprop.addRule(RuleZextEliminate("analysis"))
    actprop.addRule(RuleSlessToLess("analysis"))
    actprop.addRule(RuleZextSless("analysis"))
    actprop.addRule(RuleBitUndistribute("analysis"))
    actprop.addRule(RuleBooleanUndistribute("analysis"))
    actprop.addRule(RuleBooleanDedup("analysis"))
    actprop.addRule(RuleBoolZext("analysis"))
    actprop.addRule(RuleBooleanNegate("analysis"))
    actprop.addRule(RuleLogic2Bool("analysis"))
    actprop.addRule(RuleSubExtComm("analysis"))
    # RuleSubCommute - complex
    actprop.addRule(RuleConcatCommute("analysis"))
    actprop.addRule(RuleConcatZext("analysis"))
    actprop.addRule(RuleZextCommute("analysis"))
    actprop.addRule(RuleZextShiftZext("analysis"))
    actprop.addRule(RuleShiftAnd("analysis"))
    actprop.addRule(RuleConcatZero("analysis"))
    actprop.addRule(RuleConcatLeftShift("analysis"))
    actprop.addRule(RuleSubZext("analysis"))
    actprop.addRule(RuleSubCancel("analysis"))
    actprop.addRule(RuleShiftSub("analysis"))
    actprop.addRule(RuleHumptyDumpty("analysis"))
    actprop.addRule(RuleDumptyHump("analysis"))
    actprop.addRule(RuleHumptyOr("analysis"))
    actprop.addRule(RuleNegateIdentity("analysis"))
    actprop.addRule(RuleSubNormal("analysis"))
    actprop.addRule(RulePositiveDiv("analysis"))
    # RuleDivTermAdd/2, RuleDivOpt, etc. - need 128-bit
    actprop.addRule(RuleSignForm("analysis"))
    actprop.addRule(RuleSignNearMult("analysis"))
    actprop.addRule(RuleModOpt("analysis"))
    actprop.addRule(RuleCondNegate("analysis"))
    actprop.addRule(RuleBoolNegate("analysis"))
    actprop.addRule(RuleLessEqual("analysis"))
    actprop.addRule(RuleLessNotEqual("analysis"))
    actprop.addRule(RuleLessOne("analysis"))
    actprop.addRule(RuleFloatRange("analysis"))
    actprop.addRule(RulePiece2Zext("analysis"))
    actprop.addRule(RulePiece2Sext("analysis"))
    actprop.addRule(RulePopcountBoolXor("analysis"))
    actprop.addRule(RuleXorSwap("analysis"))
    actprop.addRule(RuleLzcountShiftBool("analysis"))
    actprop.addRule(RuleOrCompare("analysis"))
    actprop.addRule(RuleNegateNegate("analysis"))
    actprop.addRule(RuleFuncPtrEncoding("analysis"))
    actprop.addRule(RuleFloatCast("floatprecision"))
    # Extra CPU-specific rules would be added here

    actstackstall.addAction(actprop)
    actstackstall.addAction(ActionLaneDivide("base"))
    actstackstall.addAction(ActionMultiCse("analysis"))
    actstackstall.addAction(ActionShadowVar("analysis"))
    actstackstall.addAction(ActionDeindirect("deindirect"))
    actstackstall.addAction(ActionStackPtrFlow("stackptrflow", stackspace))
    actmainloop.addAction(actstackstall)

    actmainloop.addAction(ActionRedundBranch("deadcontrolflow"))
    actmainloop.addAction(ActionBlockStructure("blockrecovery"))
    actmainloop.addAction(ActionConstantPtr("typerecovery"))

    # oppool2
    actprop2 = ActionPool(Action.rule_repeatapply, "oppool2")
    # RulePushPtr, RuleStructOffset0, RulePtrArith - need type system
    # RuleLoadVarnode, RuleStoreVarnode - need LOAD/STORE infra
    actmainloop.addAction(actprop2)

    actmainloop.addAction(ActionDeterminedBranch("unreachable"))
    actmainloop.addAction(ActionUnreachable("unreachable"))
    actmainloop.addAction(ActionNodeJoin("nodejoin"))
    actmainloop.addAction(ActionConditionalExe("conditionalexe"))
    actmainloop.addAction(ActionConditionalConst("analysis"))

    actfullloop.addAction(actmainloop)
    actfullloop.addAction(ActionLikelyTrash("protorecovery"))
    actfullloop.addAction(ActionDirectWrite("protorecovery_a", True))
    actfullloop.addAction(ActionDirectWrite("protorecovery_b", False))
    actfullloop.addAction(ActionDeadCode("deadcode"))
    actfullloop.addAction(ActionDoNothing("deadcontrolflow"))
    actfullloop.addAction(ActionSwitchNorm("switchnorm"))
    actfullloop.addAction(ActionReturnSplit("returnsplit"))
    actfullloop.addAction(ActionUnjustifiedParams("protorecovery"))
    actfullloop.addAction(ActionStartTypes("typerecovery"))
    actfullloop.addAction(ActionActiveReturn("protorecovery"))

    act.addAction(actfullloop)
    act.addAction(ActionMappedLocalSync("localrecovery"))
    act.addAction(ActionStartCleanUp("cleanup"))

    # cleanup pool
    actcleanup = ActionPool(Action.rule_repeatapply, "cleanup")
    actcleanup.addRule(RuleMultNegOne("cleanup"))
    # RuleAddUnsigned - needs type system
    actcleanup.addRule(Rule2Comp2Sub("cleanup"))
    # RuleSubRight - needs type system
    # RuleExpandLoad, RulePtrsubCharConstant, etc. - need type system
    act.addAction(actcleanup)

    act.addAction(ActionPreferComplement("blockrecovery"))
    act.addAction(ActionStructureTransform("blockrecovery"))
    act.addAction(ActionNormalizeBranches("normalizebranches"))
    act.addAction(ActionAssignHigh("merge"))
    act.addAction(ActionMergeRequired("merge"))
    act.addAction(ActionMarkExplicit("merge"))
    act.addAction(ActionMarkImplied("merge"))
    act.addAction(ActionMergeMultiEntry("merge"))
    act.addAction(ActionMergeCopy("merge"))
    act.addAction(ActionDominantCopy("merge"))
    act.addAction(ActionDynamicSymbols("dynamic"))
    act.addAction(ActionMarkIndirectOnly("merge"))
    act.addAction(ActionMergeAdjacent("merge"))
    act.addAction(ActionMergeType("merge"))
    act.addAction(ActionHideShadow("merge"))
    act.addAction(ActionCopyMarker("merge"))
    act.addAction(ActionOutputPrototype("localrecovery"))
    act.addAction(ActionInputPrototype("fixateproto"))
    act.addAction(ActionMapGlobals("fixateglobals"))
    act.addAction(ActionDynamicSymbols("dynamic"))
    act.addAction(ActionNameVars("merge"))
    act.addAction(ActionSetCasts("casts"))
    act.addAction(ActionFinalStructure("blockrecovery"))
    act.addAction(ActionPrototypeWarnings("protorecovery"))
    act.addAction(ActionStop("base"))


def buildDefaultGroups(allacts: ActionDatabase) -> None:
    """Set up descriptions of preconfigured root Actions."""
    groups = [
        "base", "protorecovery", "protorecovery_a", "protorecovery_b",
        "deindirect", "localrecovery", "deadcode", "typerecovery",
        "stackptrflow", "blockrecovery", "stackvars", "deadcontrolflow",
        "switchnorm", "cleanup", "merge", "dynamic", "casts", "analysis",
        "fixateproto", "fixateglobals", "segment", "returnsplit",
        "nodejoin", "doubleload", "doubleprecis", "unreachable",
        "subvar", "floatprecision", "conditionalexe", "normalanalysis",
        "normalizebranches", "noproto", "splitcopy", "splitpointer",
        "constsequence",
    ]
    allacts.setGroup("decompile", groups)
