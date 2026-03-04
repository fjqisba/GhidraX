"""
Corresponds to: options.hh / options.cc

Classes for processing architecture configuration options.
ArchOption base class + OptionDatabase dispatcher + all concrete option classes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Dict

from ghidra.core.error import LowlevelError

if TYPE_CHECKING:
    from ghidra.arch.architecture import Architecture


class ArchOption:
    """Base class for options that affect Architecture configuration."""

    def __init__(self) -> None:
        self.name: str = ""

    def getName(self) -> str:
        return self.name

    def apply(self, glb, p1: str = "", p2: str = "", p3: str = "") -> str:
        raise NotImplementedError

    @staticmethod
    def onOrOff(p: str) -> bool:
        p = p.strip().lower()
        if p in ("on", "yes", "true", "1"):
            return True
        if p in ("off", "no", "false", "0"):
            return False
        raise LowlevelError(f"Option must be 'on' or 'off': {p}")


class OptionDatabase:
    """Dispatcher for ArchOption commands."""

    def __init__(self, glb) -> None:
        self._glb = glb
        self._optionmap: Dict[str, ArchOption] = {}
        self._registerDefaults()

    def _registerDefaults(self) -> None:
        for cls in _ALL_OPTIONS:
            opt = cls()
            self._optionmap[opt.name] = opt

    def registerOption(self, option: ArchOption) -> None:
        self._optionmap[option.name] = option

    def set(self, name: str, p1: str = "", p2: str = "", p3: str = "") -> str:
        opt = self._optionmap.get(name)
        if opt is None:
            raise LowlevelError(f"Unknown option: {name}")
        return opt.apply(self._glb, p1, p2, p3)


# ================================================================
# Concrete option classes
# ================================================================

class OptionExtraPop(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "extrapop"

    def apply(self, glb, p1="", p2="", p3=""):
        if p1 == "unknown":
            glb.extra_pop = -1
        else:
            try:
                glb.extra_pop = int(p1)
            except ValueError:
                raise LowlevelError(f"Bad extrapop value: {p1}")
        return "Extra pop set"


class OptionDefaultPrototype(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "defaultprototype"

    def apply(self, glb, p1="", p2="", p3=""):
        model = glb.getModel(p1) if hasattr(glb, 'getModel') else None
        if model is None:
            raise LowlevelError(f"Unknown prototype model: {p1}")
        glb.setDefaultModel(model)
        return f"Default prototype set to {p1}"


class OptionInferConstPtr(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "inferconstptr"

    def apply(self, glb, p1="", p2="", p3=""):
        glb.infer_pointers = ArchOption.onOrOff(p1)
        return f"Infer constant pointers {'on' if glb.infer_pointers else 'off'}"


class OptionForLoops(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "analyzeforloops"

    def apply(self, glb, p1="", p2="", p3=""):
        glb.analyze_for_loops = ArchOption.onOrOff(p1)
        return f"Analyze for loops {'on' if glb.analyze_for_loops else 'off'}"


class OptionNullPrinting(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "nullprinting"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.option_NULL = val
        return f"NULL printing {'on' if val else 'off'}"


class OptionInPlaceOps(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "inplaceops"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.option_inplace_ops = val
        return f"In-place operators {'on' if val else 'off'}"


class OptionConventionPrinting(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "conventionprinting"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.option_convention = val
        return f"Convention printing {'on' if val else 'off'}"


class OptionNoCastPrinting(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "nocastprinting"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.option_nocasts = val
        return f"No-cast printing {'on' if val else 'off'}"


class OptionHideExtensions(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "hideextensions"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1)
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.option_hide_exts = val
        return f"Hide extensions {'on' if val else 'off'}"


class OptionMaxLineWidth(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "maxlinewidth"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1)
        except ValueError:
            raise LowlevelError(f"Bad maxlinewidth value: {p1}")
        if hasattr(glb, 'print_') and glb.print_ is not None:
            emit = glb.print_.getEmitter()
            if emit is not None:
                emit.setMaxLineSize(val)
        return f"Max line width set to {val}"


class OptionIndentIncrement(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "indentincrement"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1)
        except ValueError:
            raise LowlevelError(f"Bad indentincrement value: {p1}")
        if hasattr(glb, 'print_') and glb.print_ is not None:
            emit = glb.print_.getEmitter()
            if emit is not None:
                emit.setIndentIncrement(val)
        return f"Indent increment set to {val}"


class OptionCommentIndent(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentindent"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1)
        except ValueError:
            raise LowlevelError(f"Bad commentindent value: {p1}")
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.setLineCommentIndent(val)
        return f"Comment indent set to {val}"


class OptionCommentStyle(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentstyle"

    def apply(self, glb, p1="", p2="", p3=""):
        if hasattr(glb, 'print_') and glb.print_ is not None:
            if p1 in ("c", "/*"):
                glb.print_.setCommentDelimeter("/* ", " */", False)
            elif p1 in ("cplusplus", "//"):
                glb.print_.setCommentDelimeter("// ", "", True)
            else:
                raise LowlevelError(f"Unknown comment style: {p1}")
        return f"Comment style set to {p1}"


class OptionCommentHeader(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentheader"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.database.comment import Comment
        tp = Comment.encodeCommentType(p1)
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.setHeaderComment(tp)
        return f"Comment header type set to {p1}"


class OptionCommentInstruction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "commentinstruction"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.database.comment import Comment
        tp = Comment.encodeCommentType(p1)
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.setInstructionComment(tp)
        return f"Comment instruction type set to {p1}"


class OptionIntegerFormat(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "integerformat"

    def apply(self, glb, p1="", p2="", p3=""):
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.setIntegerFormat(p1)
        return f"Integer format set to {p1}"


class OptionSetAction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "setaction"

    def apply(self, glb, p1="", p2="", p3=""):
        if hasattr(glb, 'allacts'):
            glb.allacts.setCurrent(p1)
        return f"Current action set to {p1}"


class OptionCurrentAction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "currentaction"

    def apply(self, glb, p1="", p2="", p3=""):
        if hasattr(glb, 'allacts'):
            glb.allacts.setCurrent(p1)
        return f"Current action set to {p1}"


class OptionToggleRule(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "togglerule"

    def apply(self, glb, p1="", p2="", p3=""):
        if hasattr(glb, 'allacts'):
            act = glb.allacts.getCurrent()
            if act is not None and hasattr(act, 'toggleRule'):
                act.toggleRule(p1, p2)
        return f"Rule {p1} toggled"


class OptionAliasBlock(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "aliasblock"

    def apply(self, glb, p1="", p2="", p3=""):
        _map = {"none": 0, "stack": 1, "register": 2, "all": 3}
        val = _map.get(p1.lower(), -1)
        if val < 0:
            raise LowlevelError(f"Unknown alias block level: {p1}")
        glb.alias_block_level = val
        return f"Alias block level set to {p1}"


class OptionMaxInstruction(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "maxinstruction"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1)
        except ValueError:
            raise LowlevelError(f"Bad maxinstruction value: {p1}")
        glb.max_instructions = val
        return f"Max instructions set to {val}"


class OptionNamespaceStrategy(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "namespacestrategy"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.output.printlanguage import PrintLanguage
        _map = {"minimal": PrintLanguage.MINIMAL_NAMESPACES,
                "all": PrintLanguage.ALL_NAMESPACES,
                "none": PrintLanguage.NO_NAMESPACES}
        val = _map.get(p1.lower(), -1)
        if val < 0:
            raise LowlevelError(f"Unknown namespace strategy: {p1}")
        if hasattr(glb, 'print_') and glb.print_ is not None:
            glb.print_.setNamespaceStrategy(val)
        return f"Namespace strategy set to {p1}"


class OptionJumpTableMax(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "jumptablemax"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1)
        except ValueError:
            raise LowlevelError(f"Bad jumptablemax value: {p1}")
        glb.max_jumptable_size = val
        return f"Jump table max set to {val}"


class OptionProtoEval(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "protoeval"

    def apply(self, glb, p1="", p2="", p3=""):
        model = glb.getModel(p1) if hasattr(glb, 'getModel') else None
        if model is not None:
            if p2 == "current":
                glb.evalfp_current = model
            elif p2 == "called":
                glb.evalfp_called = model
            else:
                glb.evalfp_current = model
                glb.evalfp_called = model
        return f"Prototype evaluation set to {p1}"


class OptionSetLanguage(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "setlanguage"

    def apply(self, glb, p1="", p2="", p3=""):
        if hasattr(glb, 'setPrintLanguage'):
            glb.setPrintLanguage(p1)
        return f"Language set to {p1}"


class OptionSplitDatatypes(ArchOption):
    option_struct = 1
    option_array = 2
    option_pointer = 4

    def __init__(self):
        super().__init__()
        self.name = "splitdatatype"

    def apply(self, glb, p1="", p2="", p3=""):
        _map = {"struct": 1, "array": 2, "pointer": 4}
        bit = _map.get(p1.lower(), 0)
        val = ArchOption.onOrOff(p2) if p2 else True
        if val:
            glb.split_datatype_config |= bit
        else:
            glb.split_datatype_config &= ~bit
        return f"Split datatype {p1} {'on' if val else 'off'}"


class OptionNanIgnore(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "nanignore"

    def apply(self, glb, p1="", p2="", p3=""):
        p1l = p1.lower()
        if p1l == "all":
            glb.nan_ignore_all = True
            glb.nan_ignore_compare = True
        elif p1l == "compare":
            glb.nan_ignore_compare = True
        elif p1l == "none":
            glb.nan_ignore_all = False
            glb.nan_ignore_compare = False
        return f"NaN ignore set to {p1}"


class OptionWarning(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "warning"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Warning option: {p1}"


class OptionReadOnly(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "readonly"

    def apply(self, glb, p1="", p2="", p3=""):
        val = ArchOption.onOrOff(p1) if p1 else True
        glb.readonlypropagate = val
        return f"Read-only propagation {'on' if val else 'off'}"


class OptionInline(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "inline"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Inline: {p1}"


class OptionNoReturn(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "noreturn"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Noreturn: {p1}"


class OptionIgnoreUnimplemented(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "ignoreunimplemented"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Ignore unimplemented set"


class OptionErrorUnimplemented(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "errorunimplemented"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Error on unimplemented set"


class OptionErrorReinterpreted(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "errorreinterpreted"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Error on reinterpreted set"


class OptionErrorTooManyInstructions(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "errortoomanyinstructions"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Error on too many instructions set"


class OptionAllowContextSet(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "allowcontextset"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Allow context set"


class OptionJumpLoad(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "jumpload"

    def apply(self, glb, p1="", p2="", p3=""):
        return f"Jump load: {p1}"


class OptionBraceFormat(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "braceformat"

    def apply(self, glb, p1="", p2="", p3=""):
        from ghidra.output.prettyprint import Emit
        _map = {"same": Emit.same_line, "next": Emit.next_line, "skip": Emit.skip_line}
        style = _map.get(p2.lower(), Emit.same_line) if p2 else Emit.same_line
        if hasattr(glb, 'print_') and glb.print_ is not None:
            pc = glb.print_
            target = p1.lower()
            if target == "function":
                pc.option_brace_func = style if hasattr(pc, 'option_brace_func') else None
            elif target == "ifelse":
                pc.option_brace_ifelse = style if hasattr(pc, 'option_brace_ifelse') else None
            elif target == "loop":
                pc.option_brace_loop = style if hasattr(pc, 'option_brace_loop') else None
            elif target == "switch":
                pc.option_brace_switch = style if hasattr(pc, 'option_brace_switch') else None
        return f"Brace format for {p1} set to {p2}"


class OptionStructAlign(ArchOption):
    def __init__(self):
        super().__init__()
        self.name = "structalign"

    def apply(self, glb, p1="", p2="", p3=""):
        try:
            val = int(p1)
        except ValueError:
            raise LowlevelError(f"Bad structalign value: {p1}")
        if hasattr(glb, 'types') and glb.types is not None:
            glb.types.setStructAlign(val) if hasattr(glb.types, 'setStructAlign') else None
        return f"Struct alignment set to {val}"


# Registry of all option classes
_ALL_OPTIONS = [
    OptionExtraPop, OptionDefaultPrototype, OptionInferConstPtr, OptionForLoops,
    OptionNullPrinting, OptionInPlaceOps, OptionConventionPrinting, OptionNoCastPrinting,
    OptionHideExtensions, OptionMaxLineWidth, OptionIndentIncrement,
    OptionCommentIndent, OptionCommentStyle, OptionCommentHeader, OptionCommentInstruction,
    OptionIntegerFormat, OptionSetAction, OptionCurrentAction, OptionToggleRule,
    OptionAliasBlock, OptionMaxInstruction, OptionNamespaceStrategy,
    OptionJumpTableMax, OptionProtoEval, OptionSetLanguage, OptionSplitDatatypes,
    OptionNanIgnore, OptionWarning, OptionReadOnly, OptionInline, OptionNoReturn,
    OptionIgnoreUnimplemented, OptionErrorUnimplemented, OptionErrorReinterpreted,
    OptionErrorTooManyInstructions, OptionAllowContextSet, OptionJumpLoad,
    OptionBraceFormat, OptionStructAlign,
]
