"""
Corresponds to: printlanguage.hh / printlanguage.cc

Base class API for emitting a high-level language.
Includes the RPN (Reverse Polish Notation) stack for expression emission.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List

from ghidra.core.error import LowlevelError
from ghidra.output.prettyprint import Emit, EmitMarkup, SyntaxHighlight

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.block.block import FlowBlock
    from ghidra.types.datatype import Datatype
    from ghidra.types.cast import CastStrategy
    from ghidra.database.database import Scope


OPEN_PAREN = "("
CLOSE_PAREN = ")"


class OpToken:
    """A token representing an operator in the high-level language.

    Knows how to print itself and other syntax information like
    precedence level and associativity, desired spacing,
    and how the operator groups its input expressions.
    """

    binary = 0
    unary_prefix = 1
    postsurround = 2
    presurround = 3
    space = 4
    hiddenfunction = 5

    class TokenType(IntEnum):
        binary = 0
        unary_prefix = 1
        postsurround = 2
        presurround = 3
        space = 4
        hiddenfunction = 5

    def __init__(self, p1: str = "", p2: str = "", stage: int = 0,
                 prec: int = 0, assoc: bool = False, tp: int = 0,
                 spacing: int = 1, bump: int = 0) -> None:
        self.print1: str = p1
        self.print2: str = p2
        self.stage: int = stage
        self.precedence: int = prec
        self.associative: bool = assoc
        self.type: int = tp
        self.spacing: int = spacing
        self.bump: int = bump
        self.negate: Optional[OpToken] = None


class ReversePolish:
    """An entry on the reverse polish notation (RPN) stack."""
    __slots__ = ('tok', 'visited', 'paren', 'op', 'id', 'id2')

    def __init__(self) -> None:
        self.tok: Optional[OpToken] = None
        self.visited: int = 0
        self.paren: bool = False
        self.op = None  # PcodeOp
        self.id: int = 0
        self.id2: int = 0


class NodePending:
    """A pending data-flow node waiting to be placed on the RPN stack."""
    __slots__ = ('vn', 'op', 'vnmod')

    def __init__(self, vn, op, m: int) -> None:
        self.vn = vn    # Varnode
        self.op = op    # PcodeOp
        self.vnmod: int = m


class Atom:
    """A single non-operator token emitted by the decompiler.

    Plays the role of variable tokens on the RPN stack with the operator tokens.
    An Atom can be a variable, data-type name, function name, structure field, etc.
    """

    def __init__(self, name: str, tp: int, hl: int,
                 op=None, second=None, offset: int = 0) -> None:
        self.name: str = name
        self.type: int = tp       # tagtype
        self.highlight: int = hl  # SyntaxHighlight
        self.op = op              # PcodeOp
        self.ptr_second = second  # Varnode | Funcdata | Datatype | int
        self.offset: int = offset


# tagtype constants
syntax = 0
vartoken = 1
functoken = 2
optoken = 3
typetoken = 4
fieldtoken = 5
casetoken = 6
blanktoken = 7


class PrintLanguage(ABC):
    """The base class API for emitting a high-level language.

    Responsible for converting a function's transformed data-flow graph
    into the final stream of tokens of a high-level source code language.

    Implements the RPN (Reverse Polish Notation) stack for expression emission:
    operators and variables are pushed onto the stack and ultimately emitted
    in the correct order with proper parenthesization.
    """

    # Printing modifiers
    force_hex = 1
    force_dec = 2
    bestfit = 4
    force_scinote = 8
    force_pointer = 0x10
    print_load_value = 0x20
    print_store_value = 0x40
    no_branch = 0x80
    only_branch = 0x100
    comma_separate = 0x200
    flat = 0x400
    falsebranch = 0x800
    nofallthru = 0x1000
    negatetoken = 0x2000
    hide_thisparam = 0x4000
    pending_brace = 0x8000

    class Modifiers(IntEnum):
        force_hex = 1
        force_dec = 2
        bestfit = 4
        force_scinote = 8
        force_pointer = 0x10
        print_load_value = 0x20
        print_store_value = 0x40
        no_branch = 0x80
        only_branch = 0x100
        comma_separate = 0x200
        flat = 0x400
        nofallthru = 0x800

    # Namespace strategies
    MINIMAL_NAMESPACES = 0
    NO_NAMESPACES = 1
    ALL_NAMESPACES = 2

    def __init__(self, glb=None, nm: str = "") -> None:
        self._glb = glb  # Architecture
        self._name: str = nm
        self._emit: Optional[Emit] = None
        self._castStrategy: Optional[CastStrategy] = None
        self._modstack: List[int] = []
        self._scopestack: list = []
        self._curscope = None  # Scope
        self._mods: int = 0
        self._head_comment_type: int = 0
        self._line_comment_type: int = 0
        self._instr_comment_type: int = 0
        self._line_commentindent: int = 20
        self._commentstart: str = "// "
        self._commentend: str = ""
        self._namespc_strategy: int = PrintLanguage.MINIMAL_NAMESPACES
        # RPN stack
        self._revpol: List[ReversePolish] = []
        self._nodepend: List[NodePending] = []
        self._pending: int = 0

    # --- Basic accessors ---

    def getName(self) -> str:
        return self._name

    def getEmitter(self) -> Optional[Emit]:
        return self._emit

    def setEmitter(self, emit: Emit) -> None:
        self._emit = emit

    def getCastStrategy(self):
        return self._castStrategy

    def setCastStrategy(self, cs) -> None:
        self._castStrategy = cs

    # --- Modifier stack ---

    def isSet(self, m: int) -> bool:
        return (self._mods & m) != 0

    def pushMod(self) -> None:
        self._modstack.append(self._mods)

    def popMod(self) -> None:
        self._mods = self._modstack.pop()

    def setMod(self, m: int) -> None:
        self._mods |= m

    def unsetMod(self, m: int) -> None:
        self._mods &= ~m

    def clearMod(self, m: int) -> None:
        self._mods &= ~m

    # --- Scope stack ---

    def pushScope(self, sc) -> None:
        self._scopestack.append(sc)
        self._curscope = sc

    def popScope(self) -> None:
        self._scopestack.pop()
        if self._scopestack:
            self._curscope = self._scopestack[-1]
        else:
            self._curscope = None

    # --- Comment configuration ---

    def setCommentDelimeter(self, start: str, stop: str, usecommentfill: bool) -> None:
        self._commentstart = start
        self._commentend = stop

    def setLineCommentIndent(self, val: int) -> None:
        self._line_commentindent = val

    def setInstructionComment(self, val: int) -> None:
        self._instr_comment_type = val

    def getInstructionComment(self) -> int:
        return self._instr_comment_type

    def setHeaderComment(self, val: int) -> None:
        self._head_comment_type = val

    def getHeaderComment(self) -> int:
        return self._head_comment_type

    def setNamespaceStrategy(self, strat: int) -> None:
        self._namespc_strategy = strat

    # ================================================================
    # RPN Stack Operations
    # ================================================================

    def pushOp(self, tok: OpToken, op) -> None:
        """Push an operator token onto the RPN stack.

        This generally will recursively push an entire expression,
        up to Varnode objects marked as explicit, and will decide
        token order and parenthesis placement.
        """
        if self._pending < len(self._nodepend):
            self.recurse()

        if not self._revpol:
            paren = False
            id_ = self._emit.openGroup()
        else:
            self.emitOp(self._revpol[-1])
            paren = self.parentheses(tok)
            if paren:
                id_ = self._emit.openParen(OPEN_PAREN)
            else:
                id_ = self._emit.openGroup()

        entry = ReversePolish()
        entry.tok = tok
        entry.visited = 0
        entry.paren = paren
        entry.op = op
        entry.id = id_
        self._revpol.append(entry)

    def pushAtom(self, atom: Atom) -> None:
        """Push a variable token onto the RPN stack.

        This may trigger some amount of the RPN stack to get emitted,
        depending on what was pushed previously.
        """
        if self._pending < len(self._nodepend):
            self.recurse()

        if not self._revpol:
            self.emitAtom(atom)
        else:
            self.emitOp(self._revpol[-1])
            self.emitAtom(atom)
            while self._revpol:
                self._revpol[-1].visited += 1
                if self._revpol[-1].visited == self._revpol[-1].tok.stage:
                    self.emitOp(self._revpol[-1])
                    if self._revpol[-1].paren:
                        self._emit.closeParen(CLOSE_PAREN, self._revpol[-1].id)
                    else:
                        self._emit.closeGroup(self._revpol[-1].id)
                    self._revpol.pop()
                else:
                    break

    def pushVn(self, vn, op, m: int) -> None:
        """Push an expression rooted at a Varnode onto the RPN stack.

        When calling this method multiple times to push Varnode inputs for a
        single p-code op, the inputs must be pushed in reverse order.
        """
        self._nodepend.append(NodePending(vn, op, m))

    def pushVnExplicit(self, vn, op) -> None:
        """Push an explicit variable onto the RPN stack.

        Decides how the Varnode should be emitted (symbol, constant, etc.)
        and pushes the resulting leaf Atom.
        """
        if hasattr(vn, 'isAnnotation') and vn.isAnnotation():
            self.pushAnnotation(vn, op)
            return
        if vn.isConstant():
            ct = vn.getHighTypeReadFacing(op) if hasattr(vn, 'getHighTypeReadFacing') else vn.getType()
            self.pushConstant(vn.getOffset(), ct, vartoken, vn, op)
            return
        self.pushSymbolDetail(vn, op, True)

    def pushSymbolDetail(self, vn, op, isRead: bool) -> None:
        """Push symbol name with adornments matching given Varnode.

        We know the Varnode matches part of a single Symbol.
        Push tokens that represent the Varnode, which may require
        extracting subfields or casting.
        """
        high = vn.getHigh()
        if high is None:
            self.pushUnnamedLocation(vn.getAddr(), vn, op)
            return
        sym = high.getSymbol() if hasattr(high, 'getSymbol') else None
        if sym is None:
            rep = high.getNameRepresentative()
            if rep is not None:
                self.pushUnnamedLocation(rep.getAddr(), vn, op)
            else:
                self.pushUnnamedLocation(vn.getAddr(), vn, op)
        else:
            symboloff = high.getSymbolOffset() if hasattr(high, 'getSymbolOffset') else -1
            if symboloff == -1:
                self.pushSymbol(sym, vn, op)
                return
            tp = sym.getType() if hasattr(sym, 'getType') else None
            if tp is not None and symboloff + vn.getSize() <= tp.getSize():
                inslot = op.getSlot(vn) if (isRead and hasattr(op, 'getSlot')) else -1
                self.pushPartialSymbol(sym, symboloff, vn.getSize(), vn, op, inslot, isRead)
            else:
                self.pushMismatchSymbol(sym, symboloff, vn.getSize(), vn, op)

    # ================================================================
    # Parenthesization
    # ================================================================

    def parentheses(self, op2: OpToken) -> bool:
        """Determine if the given token should be emitted in its own parenthetic expression."""
        top = self._revpol[-1]
        topToken = top.tok
        stage = top.visited

        if topToken.type == OpToken.space or topToken.type == OpToken.binary:
            if topToken.precedence > op2.precedence:
                return True
            if topToken.precedence < op2.precedence:
                return False
            if topToken.associative and (topToken is op2):
                return False
            if op2.type == OpToken.postsurround and stage == 0:
                return False
            return True
        elif topToken.type == OpToken.unary_prefix:
            if topToken.precedence > op2.precedence:
                return True
            if topToken.precedence < op2.precedence:
                return False
            if op2.type == OpToken.unary_prefix or op2.type == OpToken.presurround:
                return False
            return True
        elif topToken.type == OpToken.postsurround:
            if stage == 1:
                return False
            if topToken.precedence > op2.precedence:
                return True
            if topToken.precedence < op2.precedence:
                return False
            if op2.type == OpToken.postsurround or op2.type == OpToken.binary:
                return False
            return True
        elif topToken.type == OpToken.presurround:
            if stage == 0:
                return False
            if topToken.precedence > op2.precedence:
                return True
            if topToken.precedence < op2.precedence:
                return False
            if op2.type == OpToken.unary_prefix or op2.type == OpToken.presurround:
                return False
            return True
        elif topToken.type == OpToken.hiddenfunction:
            if stage == 0 and len(self._revpol) > 1:
                prevToken = self._revpol[-2].tok
                if prevToken.type != OpToken.binary and prevToken.type != OpToken.unary_prefix:
                    return False
                if prevToken.precedence < op2.precedence:
                    return False
            return True

        return True

    # ================================================================
    # Emit helpers
    # ================================================================

    def emitOp(self, entry: ReversePolish) -> None:
        """Send an operator token from the RPN to the emitter."""
        tok = entry.tok
        if tok.type == OpToken.binary:
            if entry.visited != 1:
                return
            self._emit.spaces(tok.spacing, tok.bump)
            self._emit.tagOp(tok.print1, SyntaxHighlight.no_color, entry.op)
            self._emit.spaces(tok.spacing, tok.bump)
        elif tok.type == OpToken.unary_prefix:
            if entry.visited != 0:
                return
            self._emit.tagOp(tok.print1, SyntaxHighlight.no_color, entry.op)
            self._emit.spaces(tok.spacing, tok.bump)
        elif tok.type == OpToken.postsurround:
            if entry.visited == 0:
                return
            if entry.visited == 1:
                self._emit.spaces(tok.spacing, tok.bump)
                entry.id2 = self._emit.openParen(tok.print1)
                self._emit.spaces(0, tok.bump)
            else:
                self._emit.closeParen(tok.print2, entry.id2)
        elif tok.type == OpToken.presurround:
            if entry.visited == 2:
                return
            if entry.visited == 0:
                entry.id2 = self._emit.openParen(tok.print1)
            else:
                self._emit.closeParen(tok.print2, entry.id2)
                self._emit.spaces(tok.spacing, tok.bump)
        elif tok.type == OpToken.space:
            if entry.visited != 1:
                return
            self._emit.spaces(tok.spacing, tok.bump)
        elif tok.type == OpToken.hiddenfunction:
            return

    def emitAtom(self, atom: Atom) -> None:
        """Send a variable token from the RPN to the emitter."""
        if atom.type == syntax:
            self._emit.print(atom.name, atom.highlight)
        elif atom.type == vartoken:
            self._emit.tagVariable(atom.name, atom.highlight, atom.ptr_second, atom.op)
        elif atom.type == functoken:
            self._emit.tagFuncName(atom.name, atom.highlight, atom.ptr_second, atom.op)
        elif atom.type == optoken:
            self._emit.tagOp(atom.name, atom.highlight, atom.op)
        elif atom.type == typetoken:
            self._emit.tagType(atom.name, atom.highlight, atom.ptr_second)
        elif atom.type == fieldtoken:
            self._emit.tagField(atom.name, atom.highlight, atom.ptr_second, atom.offset, atom.op)
        elif atom.type == casetoken:
            pass
        elif atom.type == blanktoken:
            pass

    # ================================================================
    # Recurse
    # ================================================================

    def recurse(self) -> None:
        """Emit from the RPN stack as much as possible.

        Any complete sub-expressions still on the RPN will get emitted.
        """
        modsave = self._mods
        lastPending = self._pending
        self._pending = len(self._nodepend)

        while lastPending < self._pending:
            nd = self._nodepend.pop()
            self._pending -= 1
            vn = nd.vn
            op = nd.op
            self._mods = nd.vnmod

            if hasattr(vn, 'isImplied') and vn.isImplied():
                if hasattr(vn, 'hasImpliedField') and vn.hasImpliedField():
                    self.pushImpliedField(vn, op)
                else:
                    defOp = vn.getDef()
                    if defOp is not None:
                        opc = defOp.getOpcode()
                        if hasattr(opc, 'push'):
                            opc.push(self, defOp, op)
                        else:
                            self.pushVnExplicit(vn, op)
                    else:
                        self.pushVnExplicit(vn, op)
            else:
                self.pushVnExplicit(vn, op)

            self._pending = len(self._nodepend)

        self._mods = modsave

    # ================================================================
    # Standard operator push helpers
    # ================================================================

    def opBinary(self, tok: OpToken, op) -> None:
        """Push a binary operator onto the RPN stack.

        Both of its input expressions are also pushed.
        """
        if self.isSet(PrintLanguage.negatetoken):
            if tok.negate is not None:
                tok = tok.negate
            else:
                raise LowlevelError("Could not find fliptoken")
            self.unsetMod(PrintLanguage.negatetoken)

        self.pushOp(tok, op)
        # implied vn's pushed on in reverse order for efficiency
        self.pushVn(op.getIn(1), op, self._mods)
        self.pushVn(op.getIn(0), op, self._mods)

    def opUnary(self, tok: OpToken, op) -> None:
        """Push a unary operator onto the RPN stack.

        Its input expression is also pushed.
        """
        self.pushOp(tok, op)
        self.pushVn(op.getIn(0), op, self._mods)

    # ================================================================
    # Utility methods
    # ================================================================

    @staticmethod
    def mostNaturalBase(val: int) -> int:
        """Determine the most natural base for an integer."""
        if val == 0:
            return 10

        # Count 0's and 9's in decimal
        countdec = 0
        tmp = val
        setdig = tmp % 10
        if setdig == 0 or setdig == 9:
            countdec += 1
            tmp //= 10
            while tmp != 0:
                dig = tmp % 10
                if dig == setdig:
                    countdec += 1
                else:
                    break
                tmp //= 10

        if countdec == 0:
            return 16
        if countdec == 1:
            if tmp > 1 or setdig == 9:
                return 16
        elif countdec == 2:
            if tmp > 10:
                return 16
        elif countdec <= 4:
            if tmp > 100:
                return 16
        else:
            if tmp > 1000:
                return 16

        # Count 0's and f's in hex
        counthex = 0
        tmp = val
        setdig = tmp & 0xF
        if setdig == 0 or setdig == 0xF:
            counthex += 1
            tmp >>= 4
            while tmp != 0:
                dig = tmp & 0xF
                if dig == setdig:
                    counthex += 1
                else:
                    break
                tmp >>= 4

        return 10 if countdec > counthex else 16

    @staticmethod
    def unicodeNeedsEscape(codepoint: int) -> bool:
        """Determine if the given codepoint needs to be escaped."""
        if codepoint < 0x20:
            return True
        if codepoint < 0x7F:
            if codepoint in (92, ord('"'), ord("'")):
                return True
            return False
        if codepoint < 0x100:
            return codepoint <= 0xa0
        if codepoint >= 0x2fa20:
            return True
        if codepoint < 0x2000:
            if 0x180b <= codepoint <= 0x180e:
                return True
            if codepoint == 0x61c or codepoint == 0x1680:
                return True
            return False
        if codepoint < 0x3000:
            if codepoint < 0x2010:
                return True
            if 0x2028 <= codepoint <= 0x202f:
                return True
            if codepoint in (0x205f, 0x2060):
                return True
            if 0x2066 <= codepoint <= 0x206f:
                return True
            return False
        if codepoint < 0xe000:
            if codepoint == 0x3000:
                return True
            if codepoint >= 0xd7fc:
                return True
            return False
        if codepoint < 0xf900:
            return True
        if 0xfe00 <= codepoint <= 0xfe0f:
            return True
        if codepoint == 0xfeff:
            return True
        if 0xfff0 <= codepoint <= 0xffff:
            if codepoint in (0xfffc, 0xfffd):
                return False
            return True
        return False

    # ================================================================
    # Clear / Reset
    # ================================================================

    def clear(self) -> None:
        """Clear the RPN stack and the low-level emitter."""
        if self._emit is not None:
            self._emit.parenlevel = 0
            self._emit.indentlevel = 0
        if self._modstack:
            self._mods = self._modstack[0]
            self._modstack.clear()
        self._scopestack.clear()
        self._curscope = None
        self._revpol.clear()
        self._pending = 0
        self._nodepend.clear()

    def resetDefaultsInternal(self) -> None:
        self._mods = 0
        self._line_commentindent = 20
        self._namespc_strategy = PrintLanguage.MINIMAL_NAMESPACES

    def getPending(self) -> int:
        return self._pending

    def setFlat(self, val: bool) -> None:
        if val:
            self._mods |= PrintLanguage.flat
        else:
            self._mods &= ~PrintLanguage.flat

    def escapeCharacterData(self, buf: bytes, charsize: int = 1, bigend: bool = False) -> str:
        """Escape a byte buffer as unicode character data for string emission."""
        result = []
        i = 0
        while i < len(buf):
            if charsize == 1:
                cp = buf[i]
                i += 1
            elif charsize == 2:
                if i + 1 >= len(buf):
                    break
                if bigend:
                    cp = (buf[i] << 8) | buf[i + 1]
                else:
                    cp = buf[i] | (buf[i + 1] << 8)
                i += 2
            elif charsize == 4:
                if i + 3 >= len(buf):
                    break
                if bigend:
                    cp = (buf[i] << 24) | (buf[i+1] << 16) | (buf[i+2] << 8) | buf[i+3]
                else:
                    cp = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
                i += 4
            else:
                cp = buf[i]
                i += 1
            if cp == 0:
                return ''.join(result)
            if self.unicodeNeedsEscape(cp):
                _esc = {0: '\\0', 7: '\\a', 8: '\\b', 9: '\\t', 10: '\\n',
                        11: '\\v', 12: '\\f', 13: '\\r', 92: '\\\\', 34: '\\"', 39: "\\'"}
                e = _esc.get(cp)
                if e:
                    result.append(e)
                elif cp < 256:
                    result.append(f'\\x{cp:02x}')
                elif cp < 65536:
                    result.append(f'\\x{cp:04x}')
                else:
                    result.append(f'\\x{cp:08x}')
            else:
                result.append(chr(cp) if cp < 0x110000 else f'\\x{cp:08x}')
        return ''.join(result)

    def setPackedOutput(self, val: bool) -> None:
        if self._emit is not None and hasattr(self._emit, 'setPackedOutput'):
            self._emit.setPackedOutput(val)

    def setIntegerFormat(self, nm: str) -> None:
        if nm.startswith("hex"):
            mod = PrintLanguage.force_hex
        elif nm.startswith("dec"):
            mod = PrintLanguage.force_dec
        elif nm.startswith("best"):
            mod = 0
        else:
            raise LowlevelError("Unknown integer format option: " + nm)
        self._mods &= ~(PrintLanguage.force_hex | PrintLanguage.force_dec)
        self._mods |= mod

    @staticmethod
    def unnamedField(off: int, size: int) -> str:
        return f"_{off}_{size}_"

    # --- Main entry points ---

    @abstractmethod
    def docFunction(self, fd) -> None:
        """Emit a complete function (declaration + body)."""
        ...

    @abstractmethod
    def docAllGlobals(self) -> None:
        """Emit all global variable declarations."""
        ...

    @abstractmethod
    def docTypeDefinitions(self, typegrp=None) -> None:
        """Emit all type definitions."""
        ...

    # --- Abstract push/emit methods to be implemented by subclasses ---

    @abstractmethod
    def pushConstant(self, val: int, ct, tag: int, vn, op) -> None: ...

    @abstractmethod
    def pushSymbol(self, sym, vn, op) -> None: ...

    @abstractmethod
    def pushUnnamedLocation(self, addr, vn, op) -> None: ...

    @abstractmethod
    def pushPartialSymbol(self, sym, off: int, sz: int, vn, op, slot: int, allowCast: bool) -> None: ...

    @abstractmethod
    def pushMismatchSymbol(self, sym, off: int, sz: int, vn, op) -> None: ...

    @abstractmethod
    def pushImpliedField(self, vn, op) -> None: ...

    @abstractmethod
    def pushAnnotation(self, vn, op) -> None: ...

    @abstractmethod
    def emitExpression(self, op) -> None:
        """Emit an expression rooted at the given PcodeOp."""
        ...

    @abstractmethod
    def emitVarDecl(self, sym) -> None:
        """Emit a variable declaration."""
        ...

    @abstractmethod
    def emitStatement(self, op) -> None:
        """Emit a single statement."""
        ...

    @abstractmethod
    def pushType(self, ct) -> None:
        """Push a data-type name onto the RPN expression stack."""
        ...

    def pushEquate(self, val: int, sz: int, sym, vn, op) -> bool:
        """Push a constant marked up by an EquateSymbol onto the RPN stack."""
        return False

    @abstractmethod
    def emitFunctionDeclaration(self, fd) -> None:
        """Emit a function declaration."""
        ...

    @abstractmethod
    def emitScopeVarDecls(self, symScope, cat: int) -> bool:
        """Emit all the variable declarations for a given scope."""
        ...

    @abstractmethod
    def emitVarDeclStatement(self, sym) -> None:
        """Emit a variable declaration statement."""
        ...

    def emitLineComment(self, indent: int, comm) -> None:
        """Emit a comment line."""
        if self._emit is not None:
            self._emit.tagLine(indent)
            txt = comm.getText() if hasattr(comm, 'getText') else str(comm)
            self._emit.tagComment(txt, SyntaxHighlight.comment_color, 0)

    @abstractmethod
    def checkPrintNegation(self, vn) -> bool:
        """Check whether a given boolean Varnode can be printed in negated form."""
        ...

    @abstractmethod
    def docSingleGlobal(self, sym) -> None:
        """Emit the declaration for a single (global) Symbol."""
        ...

    @abstractmethod
    def opConstructor(self, op, withNew: bool) -> None:
        """Emit an operator constructing an object."""
        ...

    @abstractmethod
    def setCommentStyle(self, nm: str) -> None:
        """Set the way comments are displayed."""
        ...

    @abstractmethod
    def initializeFromArchitecture(self) -> None:
        """Initialize architecture specific aspects of printer."""
        ...

    # ================================================================
    # Abstract opXxx methods (implemented by PrintC)
    # ================================================================

    @abstractmethod
    def opCopy(self, op) -> None: ...
    @abstractmethod
    def opLoad(self, op) -> None: ...
    @abstractmethod
    def opStore(self, op) -> None: ...
    @abstractmethod
    def opBranch(self, op) -> None: ...
    @abstractmethod
    def opCbranch(self, op) -> None: ...
    @abstractmethod
    def opBranchind(self, op) -> None: ...
    @abstractmethod
    def opCall(self, op) -> None: ...
    @abstractmethod
    def opCallind(self, op) -> None: ...
    @abstractmethod
    def opCallother(self, op) -> None: ...
    @abstractmethod
    def opReturn(self, op) -> None: ...
    @abstractmethod
    def opIntEqual(self, op) -> None: ...
    @abstractmethod
    def opIntNotEqual(self, op) -> None: ...
    @abstractmethod
    def opIntSless(self, op) -> None: ...
    @abstractmethod
    def opIntSlessEqual(self, op) -> None: ...
    @abstractmethod
    def opIntLess(self, op) -> None: ...
    @abstractmethod
    def opIntLessEqual(self, op) -> None: ...
    @abstractmethod
    def opIntZext(self, op, readOp=None) -> None: ...
    @abstractmethod
    def opIntSext(self, op, readOp=None) -> None: ...
    @abstractmethod
    def opIntAdd(self, op) -> None: ...
    @abstractmethod
    def opIntSub(self, op) -> None: ...
    @abstractmethod
    def opIntCarry(self, op) -> None: ...
    @abstractmethod
    def opIntScarry(self, op) -> None: ...
    @abstractmethod
    def opIntSborrow(self, op) -> None: ...
    @abstractmethod
    def opInt2Comp(self, op) -> None: ...
    @abstractmethod
    def opIntNegate(self, op) -> None: ...
    @abstractmethod
    def opIntXor(self, op) -> None: ...
    @abstractmethod
    def opIntAnd(self, op) -> None: ...
    @abstractmethod
    def opIntOr(self, op) -> None: ...
    @abstractmethod
    def opIntLeft(self, op) -> None: ...
    @abstractmethod
    def opIntRight(self, op) -> None: ...
    @abstractmethod
    def opIntSright(self, op) -> None: ...
    @abstractmethod
    def opIntMult(self, op) -> None: ...
    @abstractmethod
    def opIntDiv(self, op) -> None: ...
    @abstractmethod
    def opIntSdiv(self, op) -> None: ...
    @abstractmethod
    def opIntRem(self, op) -> None: ...
    @abstractmethod
    def opIntSrem(self, op) -> None: ...
    @abstractmethod
    def opBoolNegate(self, op) -> None: ...
    @abstractmethod
    def opBoolXor(self, op) -> None: ...
    @abstractmethod
    def opBoolAnd(self, op) -> None: ...
    @abstractmethod
    def opBoolOr(self, op) -> None: ...
    @abstractmethod
    def opFloatEqual(self, op) -> None: ...
    @abstractmethod
    def opFloatNotEqual(self, op) -> None: ...
    @abstractmethod
    def opFloatLess(self, op) -> None: ...
    @abstractmethod
    def opFloatLessEqual(self, op) -> None: ...
    @abstractmethod
    def opFloatNan(self, op) -> None: ...
    @abstractmethod
    def opFloatAdd(self, op) -> None: ...
    @abstractmethod
    def opFloatDiv(self, op) -> None: ...
    @abstractmethod
    def opFloatMult(self, op) -> None: ...
    @abstractmethod
    def opFloatSub(self, op) -> None: ...
    @abstractmethod
    def opFloatNeg(self, op) -> None: ...
    @abstractmethod
    def opFloatAbs(self, op) -> None: ...
    @abstractmethod
    def opFloatSqrt(self, op) -> None: ...
    @abstractmethod
    def opFloatInt2Float(self, op) -> None: ...
    @abstractmethod
    def opFloatFloat2Float(self, op) -> None: ...
    @abstractmethod
    def opFloatTrunc(self, op) -> None: ...
    @abstractmethod
    def opFloatCeil(self, op) -> None: ...
    @abstractmethod
    def opFloatFloor(self, op) -> None: ...
    @abstractmethod
    def opFloatRound(self, op) -> None: ...
    @abstractmethod
    def opMultiequal(self, op) -> None: ...
    @abstractmethod
    def opIndirect(self, op) -> None: ...
    @abstractmethod
    def opPiece(self, op) -> None: ...
    @abstractmethod
    def opSubpiece(self, op) -> None: ...
    @abstractmethod
    def opCast(self, op) -> None: ...
    @abstractmethod
    def opPtradd(self, op) -> None: ...
    @abstractmethod
    def opPtrsub(self, op) -> None: ...
    @abstractmethod
    def opSegmentOp(self, op) -> None: ...
    @abstractmethod
    def opCpoolRefOp(self, op) -> None: ...
    @abstractmethod
    def opNewOp(self, op) -> None: ...
    @abstractmethod
    def opInsertOp(self, op) -> None: ...
    @abstractmethod
    def opExtractOp(self, op) -> None: ...
    @abstractmethod
    def opPopcountOp(self, op) -> None: ...
    @abstractmethod
    def opLzcountOp(self, op) -> None: ...

    # Abstract block emission methods
    @abstractmethod
    def emitBlockBasic(self, bb) -> None: ...
    @abstractmethod
    def emitBlockGraph(self, bl) -> None: ...
    @abstractmethod
    def emitBlockCopy(self, bl) -> None: ...
    @abstractmethod
    def emitBlockGoto(self, bl) -> None: ...
    @abstractmethod
    def emitBlockLs(self, bl) -> None: ...
    @abstractmethod
    def emitBlockCondition(self, bl) -> None: ...
    @abstractmethod
    def emitBlockIf(self, bl) -> None: ...
    @abstractmethod
    def emitBlockWhileDo(self, bl) -> None: ...
    @abstractmethod
    def emitBlockDoWhile(self, bl) -> None: ...
    @abstractmethod
    def emitBlockInfLoop(self, bl) -> None: ...
    @abstractmethod
    def emitBlockSwitch(self, bl) -> None: ...

    def adjustTypeOperators(self) -> None:
        """Set basic data-type information for p-code operators."""
        pass

    def getArch(self):
        """Get the owning Architecture."""
        return self._glb

    def getOutputStream(self):
        """Get the output stream being emitted to."""
        if self._emit is not None:
            return self._emit.getOutputStream()
        return None

    def setOutputStream(self, t) -> None:
        """Set the output stream to emit to."""
        if self._emit is not None:
            self._emit.setOutputStream(t)

    def setMaxLineSize(self, mls: int) -> None:
        """Set the maximum number of characters per line."""
        if self._emit is not None:
            self._emit.setMaxLineSize(mls)

    def setIndentIncrement(self, inc: int) -> None:
        """Set the number of characters to indent per level of code nesting."""
        if self._emit is not None:
            self._emit.setIndentIncrement(inc)

    def emitsMarkup(self) -> bool:
        """Does the low-level emitter emit markup?"""
        if self._emit is not None:
            return self._emit.emitsMarkup()
        return False

    def setMarkup(self, val: bool) -> None:
        """Turn on/off mark-up in emitted output."""
        if self._emit is not None:
            self._emit.setMarkup(val)

    @staticmethod
    def formatBinary(val: int) -> str:
        """Print a number in binary form."""
        if val == 0:
            return '0b0'
        bits = []
        while val > 0:
            bits.append('1' if (val & 1) else '0')
            val >>= 1
        bits.reverse()
        return '0b' + ''.join(bits)

    def resetDefaults(self) -> None:
        if self._emit is not None:
            self._emit.resetDefaults()
        self.resetDefaultsInternal()

    def __repr__(self) -> str:
        return f"PrintLanguage({self._name!r})"
