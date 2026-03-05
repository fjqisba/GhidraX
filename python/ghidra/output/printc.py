"""
Corresponds to: printc.hh / printc.cc

C language code emitter. Converts decompiled data-flow into C source code.
Uses the RPN (Reverse Polish Notation) stack from PrintLanguage for proper
operator precedence, parenthesization, and expression emission.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List
import io

from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask
from ghidra.output.prettyprint import Emit, EmitMarkup, SyntaxHighlight
from ghidra.output.printlanguage import (
    PrintLanguage, OpToken, Atom, ReversePolish,
    OPEN_PAREN, CLOSE_PAREN,
    syntax, vartoken, functoken, optoken, typetoken, fieldtoken, casetoken, blanktoken,
)
from ghidra.types.cast import CastStrategyC

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.types.datatype import Datatype


# =========================================================================
# OpToken definitions — faithful port from printc.cc
# stage = number of inputs consumed before the operator is fully emitted
# OpToken(print1, print2, stage, precedence, associative, type, spacing, bump)
# =========================================================================

def _tok(p1, p2, stage, prec, assoc, tp, spacing=1, bump=0):
    return OpToken(p1, p2, stage, prec, assoc, tp, spacing, bump)

_B = OpToken.binary
_U = OpToken.unary_prefix
_PS = OpToken.postsurround
_PR = OpToken.presurround
_SP = OpToken.space
_HF = OpToken.hiddenfunction


class PrintC(PrintLanguage):
    """The C-language token emitter.

    Implements all opXxx handlers using the RPN stack from PrintLanguage.
    Faithfully ports the C++ PrintC class from Ghidra.
    """

    # --- Static OpToken instances (matching printc.cc) ---
    hidden         = _tok("",   "",  1, 70, False, _HF, 0, 0)
    scope          = _tok("::", "",  2, 70, True,  _B,  0, 0)
    object_member  = _tok(".",  "",  2, 66, True,  _B,  0, 0)
    pointer_member = _tok("->", "",  2, 66, True,  _B,  0, 0)
    subscript      = _tok("[",  "]", 2, 66, False, _PS, 0, 0)
    function_call  = _tok("(",  ")", 2, 66, False, _PS, 0, 10)
    bitwise_not    = _tok("~",  "",  1, 62, False, _U,  0, 0)
    boolean_not    = _tok("!",  "",  1, 62, False, _U,  0, 0)
    unary_minus    = _tok("-",  "",  1, 62, False, _U,  0, 0)
    unary_plus     = _tok("+",  "",  1, 62, False, _U,  0, 0)
    addressof      = _tok("&",  "",  1, 62, False, _U,  0, 0)
    dereference    = _tok("*",  "",  1, 62, False, _U,  0, 0)
    typecast       = _tok("(",  ")", 2, 62, False, _PR, 0, 0)
    multiply       = _tok("*",  "",  2, 54, True,  _B,  1, 0)
    divide         = _tok("/",  "",  2, 54, False, _B,  1, 0)
    modulo         = _tok("%",  "",  2, 54, False, _B,  1, 0)
    binary_plus    = _tok("+",  "",  2, 50, True,  _B,  1, 0)
    binary_minus   = _tok("-",  "",  2, 50, False, _B,  1, 0)
    shift_left     = _tok("<<", "",  2, 46, False, _B,  1, 0)
    shift_right    = _tok(">>", "",  2, 46, False, _B,  1, 0)
    shift_sright   = _tok(">>", "",  2, 46, False, _B,  1, 0)
    less_than      = _tok("<",  "",  2, 42, False, _B,  1, 0)
    less_equal     = _tok("<=", "",  2, 42, False, _B,  1, 0)
    greater_than   = _tok(">",  "",  2, 42, False, _B,  1, 0)
    greater_equal  = _tok(">=", "",  2, 42, False, _B,  1, 0)
    equal          = _tok("==", "",  2, 38, False, _B,  1, 0)
    not_equal      = _tok("!=", "",  2, 38, False, _B,  1, 0)
    bitwise_and    = _tok("&",  "",  2, 34, True,  _B,  1, 0)
    bitwise_xor    = _tok("^",  "",  2, 30, True,  _B,  1, 0)
    bitwise_or     = _tok("|",  "",  2, 26, True,  _B,  1, 0)
    boolean_and    = _tok("&&", "",  2, 22, False, _B,  1, 0)
    boolean_xor    = _tok("^^", "",  2, 20, False, _B,  1, 0)
    boolean_or     = _tok("||", "",  2, 18, False, _B,  1, 0)
    assignment     = _tok("=",  "",  2, 14, False, _B,  1, 5)
    comma          = _tok(",",  "",  2,  2, True,  _B,  0, 0)
    new_op         = _tok("",   "",  2, 62, False, _SP, 1, 0)
    type_instanceOf = _tok("instanceof", "", 2, 26, False, _B, 1, 0)
    # In-place operators
    multequal  = _tok("*=",  "", 2, 14, False, _B, 1, 5)
    divequal   = _tok("/=",  "", 2, 14, False, _B, 1, 5)
    remequal   = _tok("%=",  "", 2, 14, False, _B, 1, 5)
    plusequal   = _tok("+=",  "", 2, 14, False, _B, 1, 5)
    minusequal  = _tok("-=",  "", 2, 14, False, _B, 1, 5)
    leftequal   = _tok("<<=", "", 2, 14, False, _B, 1, 5)
    rightequal  = _tok(">>=", "", 2, 14, False, _B, 1, 5)
    andequal    = _tok("&=",  "", 2, 14, False, _B, 1, 5)
    orequal     = _tok("|=",  "", 2, 14, False, _B, 1, 5)
    xorequal    = _tok("^=",  "", 2, 14, False, _B, 1, 5)
    # Type expression tokens
    type_expr_space   = _tok("", "", 2, 10, False, _SP, 1, 0)
    type_expr_nospace = _tok("", "", 2, 10, False, _SP, 0, 0)
    ptr_expr   = _tok("*", "",  1, 62, False, _U, 0, 0)
    array_expr = _tok("[", "]", 2, 66, False, _PS, 1, 0)
    enum_cat   = _tok("|", "",  2, 26, True,  _B, 0, 0)

    # --- String constants ---
    EMPTY_STRING = ""
    OPEN_CURLY = "{"
    CLOSE_CURLY = "}"
    SEMICOLON = ";"
    COLON = ":"
    EQUALSIGN = "="
    COMMA = ","
    DOTDOTDOT = "..."
    KEYWORD_VOID = "void"
    KEYWORD_TRUE = "true"
    KEYWORD_FALSE = "false"
    KEYWORD_IF = "if"
    KEYWORD_ELSE = "else"
    KEYWORD_DO = "do"
    KEYWORD_WHILE = "while"
    KEYWORD_FOR = "for"
    KEYWORD_GOTO = "goto"
    KEYWORD_BREAK = "break"
    KEYWORD_CONTINUE = "continue"
    KEYWORD_CASE = "case"
    KEYWORD_SWITCH = "switch"
    KEYWORD_DEFAULT = "default"
    KEYWORD_RETURN = "return"
    KEYWORD_NEW = "new"

    def __init__(self, glb=None, nm: str = "c-language") -> None:
        super().__init__(glb, nm)
        self._castStrategy = CastStrategyC()
        self.option_NULL: bool = False
        self.option_inplace_ops: bool = False
        self.option_convention: bool = True
        self.option_nocasts: bool = False
        self.option_unplaced: bool = False
        self.option_hide_exts: bool = True
        self.nullToken: str = "NULL"
        self.sizeSuffix: str = "L"
        # Set up negate (flip) tokens
        PrintC.less_than.negate = PrintC.greater_equal
        PrintC.less_equal.negate = PrintC.greater_than
        PrintC.greater_than.negate = PrintC.less_equal
        PrintC.greater_equal.negate = PrintC.less_than
        PrintC.equal.negate = PrintC.not_equal
        PrintC.not_equal.negate = PrintC.equal
        self.resetDefaultsPrintC()

    def resetDefaultsPrintC(self):
        """Reset C-specific options to defaults."""
        self.option_convention = True
        self.option_hide_exts = True
        self.option_inplace_ops = False
        self.option_nocasts = False
        self.option_NULL = False
        self.option_unplaced = False
        self.setCStyleComments()

    def resetDefaults(self):
        super().resetDefaults()
        self.resetDefaultsPrintC()

    # ================================================================
    # Push methods for constants and symbols
    # ================================================================

    def pushConstant(self, val, ct, tag, vn, op):
        """Push a constant value onto the RPN stack based on its data-type."""
        from ghidra.types.datatype import (
            MetaType, TYPE_UINT, TYPE_INT, TYPE_UNKNOWN, TYPE_BOOL,
            TYPE_VOID, TYPE_PTR, TYPE_PTRREL, TYPE_FLOAT, TYPE_CODE,
        )
        if ct is None:
            self.push_integer(val, 4, False, tag, vn, op)
            return
        meta = ct.getMetatype()
        if meta == TYPE_UINT:
            if hasattr(ct, 'isCharPrint') and ct.isCharPrint():
                self.pushCharConstant(val, ct, tag, vn, op)
            elif hasattr(ct, 'isEnumType') and ct.isEnumType():
                self.pushEnumConstant(val, ct, tag, vn, op)
            else:
                self.push_integer(val, ct.getSize(), False, tag, vn, op)
        elif meta == TYPE_INT:
            if hasattr(ct, 'isCharPrint') and ct.isCharPrint():
                self.pushCharConstant(val, ct, tag, vn, op)
            elif hasattr(ct, 'isEnumType') and ct.isEnumType():
                self.pushEnumConstant(val, ct, tag, vn, op)
            else:
                self.push_integer(val, ct.getSize(), True, tag, vn, op)
        elif meta == TYPE_UNKNOWN:
            self.push_integer(val, ct.getSize(), False, tag, vn, op)
        elif meta == TYPE_BOOL:
            self.pushBoolConstant(val, ct, tag, vn, op)
        elif meta == TYPE_FLOAT:
            self.push_float(val, ct.getSize(), tag, vn, op)
        elif meta == TYPE_VOID:
            self.push_integer(val, 1, False, tag, vn, op)
        elif meta in (TYPE_PTR, TYPE_PTRREL):
            if self.option_NULL and val == 0:
                self.pushAtom(Atom(self.nullToken, vartoken,
                                   SyntaxHighlight.var_color, op, vn))
                return
            subtype = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
            if subtype is not None:
                if hasattr(subtype, 'isCharPrint') and subtype.isCharPrint():
                    if self.pushPtrCharConstant(val, ct, vn, op):
                        return
                elif subtype.getMetatype() == TYPE_CODE if hasattr(subtype, 'getMetatype') else False:
                    if self.pushPtrCodeConstant(val, ct, vn, op):
                        return
            if not self.option_nocasts:
                self.pushOp(PrintC.typecast, op)
                self.pushType(ct)
            self.pushMod()
            if not self.isSet(PrintLanguage.force_dec):
                self.setMod(PrintLanguage.force_hex)
            self.push_integer(val, ct.getSize(), False, tag, vn, op)
            self.popMod()
        else:
            # Default: cast + hex
            if not self.option_nocasts:
                self.pushOp(PrintC.typecast, op)
                self.pushType(ct)
            self.pushMod()
            if not self.isSet(PrintLanguage.force_dec):
                self.setMod(PrintLanguage.force_hex)
            self.push_integer(val, ct.getSize(), False, tag, vn, op)
            self.popMod()

    def push_integer(self, val, sz, sign, tag, vn, op):
        """Push an integer constant as a formatted string token."""
        print_negsign = False
        if sign:
            mask = calc_mask(sz)
            flip = val ^ mask
            if flip < val:
                print_negsign = True
                val = flip + 1

        # Decide format
        if self._mods & PrintLanguage.force_hex:
            use_hex = True
        elif val <= 10 or (self._mods & PrintLanguage.force_dec):
            use_hex = False
        else:
            use_hex = (PrintLanguage.mostNaturalBase(val) == 16)

        s = ""
        if print_negsign:
            s += "-"
        if use_hex:
            s += f"0x{val:x}"
        else:
            s += str(val)

        self.pushAtom(Atom(s, tag, SyntaxHighlight.const_color, op, vn))

    def push_float(self, val, sz, tag, vn, op):
        """Push a floating-point constant."""
        token = f"FLOAT_{val:#x}"
        if self._glb is not None and hasattr(self._glb, 'translate') and self._glb.translate is not None:
            fmt = self._glb.translate.getFloatFormat(sz) if hasattr(self._glb.translate, 'getFloatFormat') else None
            if fmt is not None:
                try:
                    hostval, fc = fmt.getHostFloat(val)
                    token = str(hostval)
                    if '.' not in token and 'e' not in token and 'E' not in token:
                        token += ".0"
                except Exception:
                    pass
        self.pushAtom(Atom(token, tag, SyntaxHighlight.const_color, op, vn))

    def pushBoolConstant(self, val, ct, tag, vn, op):
        """Push a boolean constant (true/false)."""
        if val != 0:
            self.pushAtom(Atom(self.KEYWORD_TRUE, tag, SyntaxHighlight.const_color, op, vn))
        else:
            self.pushAtom(Atom(self.KEYWORD_FALSE, tag, SyntaxHighlight.const_color, op, vn))

    def pushCharConstant(self, val, ct, tag, vn, op):
        """Push a character constant like 'A' or '\\n'."""
        import io as _io
        s = _io.StringIO()
        sz = ct.getSize() if ct is not None else 1
        if sz > 1:
            s.write("L")
        s.write("'")
        if val == 0: s.write("\\0")
        elif val == 7: s.write("\\a")
        elif val == 8: s.write("\\b")
        elif val == 9: s.write("\\t")
        elif val == 10: s.write("\\n")
        elif val == 11: s.write("\\v")
        elif val == 12: s.write("\\f")
        elif val == 13: s.write("\\r")
        elif val == 92: s.write("\\\\")
        elif val == 39: s.write("\\'")
        elif val == 34: s.write('\\"')
        elif 0x20 <= val < 0x7F: s.write(chr(val))
        else: s.write(f"\\x{val:02x}")
        s.write("'")
        self.pushAtom(Atom(s.getvalue(), tag, SyntaxHighlight.const_color, op, vn))

    def printUnicode(self, s, onechar):
        """Print a unicode character, using escape sequences where needed."""
        if PrintLanguage.unicodeNeedsEscape(onechar):
            _esc = {0: "\\0", 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n",
                    11: "\\v", 12: "\\f", 13: "\\r", 92: "\\\\", 34: '\\"', 39: "\\'"}
            esc = _esc.get(onechar)
            if esc:
                s.write(esc)
            else:
                self.printCharHexEscape(s, onechar)
        else:
            if onechar < 0x80:
                s.write(chr(onechar))
            elif onechar < 0x800:
                s.write(chr(0xC0 | (onechar >> 6)))
                s.write(chr(0x80 | (onechar & 0x3F)))
            else:
                s.write(chr(onechar))

    @staticmethod
    def printCharHexEscape(s, val):
        """Print a character as a hex escape sequence."""
        if val < 256:
            s.write(f"\\x{val:02x}")
        elif val < 65536:
            s.write(f"\\x{val:04x}")
        else:
            s.write(f"\\x{val:08x}")

    def pushEnumConstant(self, val, ct, tag, vn, op):
        """Push an enumeration constant by name if possible."""
        if ct is not None and hasattr(ct, 'getMatches'):
            names = ct.getMatches(val)
            if names:
                self.pushAtom(Atom(names[0], tag, SyntaxHighlight.const_color, op, vn))
                return
        if ct is not None and hasattr(ct, 'getName'):
            # Try direct name lookup
            nm = None
            if hasattr(ct, 'beginEnum'):
                for k, v in ct.beginEnum():
                    if k == val:
                        nm = v
                        break
            if nm is not None:
                self.pushAtom(Atom(nm, tag, SyntaxHighlight.const_color, op, vn))
                return
        # Fallback to integer
        sign = ct.getMetatype() == 14 if ct is not None else False  # TYPE_INT = 14
        self.push_integer(val, ct.getSize() if ct else 4, sign, tag, vn, op)

    def pushPtrCharConstant(self, val, ct, vn, op) -> bool:
        """Try to push a quoted string for a char* constant. Returns True if successful."""
        if val == 0:
            return False
        if self._glb is None:
            return False
        # Try to read string data from the load image
        spc = self._glb.getDefaultDataSpace() if hasattr(self._glb, 'getDefaultDataSpace') else None
        if spc is None:
            return False
        from ghidra.core.address import Address
        stringaddr = Address(spc, val)
        # Check if address is in a read-only region
        loader = self._glb.loader if hasattr(self._glb, 'loader') else None
        if loader is None:
            return False
        try:
            data = loader.loadFill(stringaddr, 256) if hasattr(loader, 'loadFill') else None
            if data is None:
                return False
            # Build the string — look for null terminator
            chars = []
            for b in data:
                if b == 0:
                    break
                if 0x20 <= b < 0x7F:
                    if b == ord('\\'):
                        chars.append('\\\\')
                    elif b == ord('"'):
                        chars.append('\\"')
                    else:
                        chars.append(chr(b))
                else:
                    chars.append(f'\\x{b:02x}')
            if not chars:
                return False
            s = '"' + ''.join(chars) + '"'
            self.pushAtom(Atom(s, vartoken, SyntaxHighlight.const_color, op, vn))
            return True
        except Exception:
            return False

    def pushPtrCodeConstant(self, val, ct, vn, op) -> bool:
        """Try to push a function name for a code pointer constant. Returns True if successful."""
        if self._glb is None:
            return False
        spc = self._glb.getDefaultCodeSpace() if hasattr(self._glb, 'getDefaultCodeSpace') else None
        if spc is None:
            return False
        # Look up function at the pointed-to address
        symboltab = self._glb.symboltab if hasattr(self._glb, 'symboltab') else None
        if symboltab is None:
            return False
        from ghidra.core.address import Address
        addr = Address(spc, val)
        globalScope = symboltab.getGlobalScope() if hasattr(symboltab, 'getGlobalScope') else None
        if globalScope is None:
            return False
        fd = globalScope.queryFunction(addr) if hasattr(globalScope, 'queryFunction') else None
        if fd is not None:
            nm = fd.getDisplayName() if hasattr(fd, 'getDisplayName') else str(fd)
            self.pushAtom(Atom(nm, functoken, SyntaxHighlight.funcname_color, op, fd))
            return True
        return False

    def pushEquate(self, val, sz, sym, vn, op) -> bool:
        """Try to push an equate symbol substitution. Returns True if successful."""
        if sym is None:
            return False
        baseval = sym.getValue() if hasattr(sym, 'getValue') else None
        if baseval is None:
            return False
        mask = calc_mask(sz)
        modval = baseval & mask
        if modval == val:
            self.pushSymbol(sym, vn, op)
            return True
        # Check negation ~
        modval = (~baseval) & mask
        if modval == val:
            self.pushOp(PrintC.bitwise_not, None)
            self.pushSymbol(sym, vn, op)
            return True
        # Check twos complement -
        modval = (-baseval) & mask
        if modval == val:
            self.pushOp(PrintC.unary_minus, None)
            self.pushSymbol(sym, vn, op)
            return True
        # Check +1
        modval = (baseval + 1) & mask
        if modval == val:
            self.pushOp(PrintC.binary_plus, None)
            self.pushSymbol(sym, vn, op)
            self.push_integer(1, sz, False, syntax, None, None)
            return True
        # Check -1
        modval = (baseval - 1) & mask
        if modval == val:
            self.pushOp(PrintC.binary_minus, None)
            self.pushSymbol(sym, vn, op)
            self.push_integer(1, sz, False, syntax, None, None)
            return True
        return False

    def pushType(self, ct):
        """Push a data-type onto the RPN stack (as if for a cast)."""
        self.pushTypeStart(ct, True)
        self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))
        self.pushTypeEnd(ct)

    def pushTypeStart(self, ct, noident):
        """Push the start of a type declaration with pointer/array adornments."""
        from ghidra.types.datatype import TYPE_PTR, TYPE_ARRAY, TYPE_CODE
        if ct is None:
            self.pushOp(PrintC.type_expr_space, None)
            self.pushAtom(Atom("void", typetoken, SyntaxHighlight.type_color, None, ct))
            return
        # Build the type stack: walk through ptr/array/code to find base type
        typestack = []
        cur = ct
        while True:
            typestack.append(cur)
            nm = cur.getName() if hasattr(cur, 'getName') else ""
            if nm:
                break
            meta = cur.getMetatype()
            if meta == TYPE_PTR and hasattr(cur, 'getPtrTo'):
                cur = cur.getPtrTo()
            elif meta == TYPE_ARRAY and hasattr(cur, 'getBase'):
                cur = cur.getBase()
            elif meta == TYPE_CODE and hasattr(cur, 'getPrototype'):
                proto = cur.getPrototype()
                if proto is not None and hasattr(proto, 'getOutputType'):
                    cur = proto.getOutputType()
                else:
                    break
            else:
                break
        # The base type is at the end of the stack
        base = typestack[-1]
        nm = base.getName() if hasattr(base, 'getName') else ""
        if not nm:
            nm = self.genericTypeName(base)
        tok = PrintC.type_expr_nospace if (noident and len(typestack) == 1) else PrintC.type_expr_space
        dispnm = base.getDisplayName() if hasattr(base, 'getDisplayName') else nm
        self.pushOp(tok, None)
        self.pushAtom(Atom(dispnm, typetoken, SyntaxHighlight.type_color, None, base))
        # Push adornments in reverse (ptr_expr for pointers, array_expr for arrays)
        for i in range(len(typestack) - 2, -1, -1):
            adorn = typestack[i]
            meta = adorn.getMetatype()
            if meta == TYPE_PTR:
                self.pushOp(PrintC.ptr_expr, None)
            elif meta == TYPE_ARRAY:
                self.pushOp(PrintC.array_expr, None)
            elif meta == TYPE_CODE:
                self.pushOp(PrintC.function_call, None)

    def pushTypeEnd(self, ct):
        """Push the tail end of a type declaration (array sizes, function params)."""
        from ghidra.types.datatype import TYPE_PTR, TYPE_ARRAY, TYPE_CODE
        if ct is None:
            return
        # Walk the same type stack and push tail tokens
        cur = ct
        while True:
            nm = cur.getName() if hasattr(cur, 'getName') else ""
            if nm:
                break
            meta = cur.getMetatype()
            if meta == TYPE_PTR and hasattr(cur, 'getPtrTo'):
                cur = cur.getPtrTo()
            elif meta == TYPE_ARRAY and hasattr(cur, 'getBase'):
                # Push array size
                nelems = cur.numElements() if hasattr(cur, 'numElements') else 0
                self.pushMod()
                self.setMod(PrintLanguage.force_dec)
                self.push_integer(nelems, 4, False, syntax, None, None)
                self.popMod()
                cur = cur.getBase()
            elif meta == TYPE_CODE and hasattr(cur, 'getPrototype'):
                proto = cur.getPrototype()
                if proto is not None:
                    self.pushPrototypeInputs_rpn(proto)
                    if hasattr(proto, 'getOutputType'):
                        cur = proto.getOutputType()
                    else:
                        break
                else:
                    self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))
                    break
            else:
                break

    def pushPrototypeInputs_rpn(self, proto):
        """Push prototype input parameters onto the RPN stack for type declarations."""
        sz = proto.numParams()
        if sz == 0 and not (hasattr(proto, 'isDotdotdot') and proto.isDotdotdot()):
            self.pushAtom(Atom(self.KEYWORD_VOID, syntax, SyntaxHighlight.keyword_color))
        else:
            for i in range(sz - 1):
                self.pushOp(PrintC.comma, None)
            for i in range(sz):
                param = proto.getParam(i)
                ptype = param.getType() if hasattr(param, 'getType') else None
                self.pushTypeStart(ptype, True)
                self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))
                self.pushTypeEnd(ptype)
            if hasattr(proto, 'isDotdotdot') and proto.isDotdotdot():
                if sz != 0:
                    self.pushAtom(Atom(self.DOTDOTDOT, syntax, SyntaxHighlight.no_color))
                else:
                    self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))

    def pushSymbolScope(self, sym):
        """Push namespace scope resolution operators for a symbol."""
        if self._namespc_strategy == PrintLanguage.NO_NAMESPACES:
            return
        if sym is None or not hasattr(sym, 'getScope'):
            return
        scope = sym.getScope() if hasattr(sym, 'getScope') else None
        if scope is None or scope is self._curscope:
            return
        if self._namespc_strategy == PrintLanguage.MINIMAL_NAMESPACES:
            depth = sym.getResolutionDepth(self._curscope) if hasattr(sym, 'getResolutionDepth') else 0
        elif self._namespc_strategy == PrintLanguage.ALL_NAMESPACES:
            depth = sym.getResolutionDepth(None) if hasattr(sym, 'getResolutionDepth') else 0
        else:
            depth = 0
        if depth > 0:
            scopeList = []
            point = scope
            for _ in range(depth):
                if point is None:
                    break
                scopeList.append(point)
                point = point.getParent() if hasattr(point, 'getParent') else None
                self.pushOp(PrintC.scope, None)
            for sc in reversed(scopeList):
                dnm = sc.getDisplayName() if hasattr(sc, 'getDisplayName') else sc.getName() if hasattr(sc, 'getName') else ""
                self.pushAtom(Atom(dnm, syntax, SyntaxHighlight.global_color, None, None))

    def emitSymbolScope(self, sym):
        """Emit namespace scope tokens for a symbol directly."""
        if self._namespc_strategy == PrintLanguage.NO_NAMESPACES:
            return
        if sym is None or not hasattr(sym, 'getScope'):
            return
        scope = sym.getScope() if hasattr(sym, 'getScope') else None
        if scope is None or scope is self._curscope:
            return
        if self._namespc_strategy == PrintLanguage.MINIMAL_NAMESPACES:
            depth = sym.getResolutionDepth(self._curscope) if hasattr(sym, 'getResolutionDepth') else 0
        else:
            depth = sym.getResolutionDepth(None) if hasattr(sym, 'getResolutionDepth') else 0
        if depth > 0:
            scopeList = []
            point = scope
            for _ in range(depth):
                if point is None:
                    break
                scopeList.append(point)
                point = point.getParent() if hasattr(point, 'getParent') else None
            for sc in reversed(scopeList):
                dnm = sc.getDisplayName() if hasattr(sc, 'getDisplayName') else sc.getName() if hasattr(sc, 'getName') else ""
                self._emit.print(dnm, SyntaxHighlight.global_color)
                self._emit.print(PrintC.scope.print1, SyntaxHighlight.no_color)

    def pushSymbol(self, sym, vn, op):
        """Push a Symbol name onto the RPN stack with scope resolution."""
        if sym is None:
            self.pushAtom(Atom("UNKNOWN", vartoken, SyntaxHighlight.var_color, op, vn))
            return
        # Determine highlight color
        tokenColor = SyntaxHighlight.var_color
        if hasattr(sym, 'isVolatile') and sym.isVolatile():
            tokenColor = SyntaxHighlight.special_color
        elif hasattr(sym, 'getScope') and hasattr(sym.getScope(), 'isGlobal') and sym.getScope().isGlobal():
            tokenColor = SyntaxHighlight.global_color
        elif hasattr(sym, 'getCategory'):
            cat = sym.getCategory()
            if cat == 0:  # function_parameter
                tokenColor = SyntaxHighlight.param_color
        self.pushSymbolScope(sym)
        nm = sym.getDisplayName() if hasattr(sym, 'getDisplayName') else (
            sym.getName() if hasattr(sym, 'getName') else str(sym))
        self.pushAtom(Atom(nm, vartoken, tokenColor, op, vn))

    def pushUnnamedLocation(self, addr, vn, op):
        """Push an unnamed location (address-based name)."""
        if addr is None:
            self.pushAtom(Atom("UNNAMED", vartoken, SyntaxHighlight.var_color, op, vn))
            return
        spc = addr.getSpace()
        if spc is not None and spc.getName() == "register":
            off = addr.getOffset()
            sz = vn.getSize() if vn is not None else 4
            name = self._getRegisterName(off, sz)
            self.pushAtom(Atom(name, vartoken, SyntaxHighlight.var_color, op, vn))
        elif spc is not None and spc.getName() == "unique":
            name = f"tmp_{addr.getOffset():x}"
            self.pushAtom(Atom(name, vartoken, SyntaxHighlight.var_color, op, vn))
        else:
            sn = spc.getName() if spc is not None else "mem"
            name = f"{sn}{addr.getOffset():x}"
            self.pushAtom(Atom(name, vartoken, SyntaxHighlight.var_color, op, vn))

    def _getRegisterName(self, off, sz):
        """Get x86 register name from offset and size."""
        if self._glb is not None and hasattr(self._glb, 'translate') and self._glb.translate is not None:
            nm = self._glb.translate.getRegisterName(None, off, sz) if hasattr(self._glb.translate, 'getRegisterName') else ""
            if nm:
                return nm
        _x86_regs = {
            (0x0,4): "EAX", (0x4,4): "ECX", (0x8,4): "EDX", (0xC,4): "EBX",
            (0x10,4): "ESP", (0x14,4): "EBP", (0x18,4): "ESI", (0x1C,4): "EDI",
            (0x0,1): "AL", (0x1,1): "AH", (0x4,1): "CL", (0x8,1): "DL",
            (0x0,2): "AX", (0x4,2): "CX", (0x8,2): "DX", (0xC,2): "BX",
            (0x200,1): "CF", (0x206,1): "ZF", (0x207,1): "SF", (0x20B,1): "OF",
        }
        return _x86_regs.get((off, sz), f"reg_{off:x}")

    def pushPartialSymbol(self, sym, off, sz, vn, op, slot, allowCast):
        """Push a partial symbol reference with field traversal.

        Navigate struct/union fields bottom-up to emit proper a.b.c syntax.
        """
        from ghidra.types.datatype import TYPE_STRUCT, TYPE_UNION, TYPE_ARRAY
        if sym is None:
            if vn is not None:
                self.pushUnnamedLocation(vn.getAddr(), vn, op)
            return
        ct = sym.getType() if hasattr(sym, 'getType') else None
        if ct is None or off == 0:
            self.pushSymbol(sym, vn, op)
            return
        # Walk the type to find the field at the given offset
        fields = []  # list of (token, fieldname)
        curtype = ct
        curoff = off
        while curtype is not None and curoff > 0:
            meta = curtype.getMetatype()
            if meta == TYPE_STRUCT and hasattr(curtype, 'findTruncation'):
                newoff = [0]
                fld = curtype.findTruncation(curoff, sz, op, slot, newoff)
                if fld is not None and hasattr(fld, 'name'):
                    fields.append((PrintC.object_member, fld.name, curtype))
                    curoff = newoff[0] if isinstance(newoff, list) else newoff
                    curtype = fld.type if hasattr(fld, 'type') else None
                else:
                    fields.append((PrintC.object_member, f"_{curoff}_{sz}_", curtype))
                    break
            elif meta == TYPE_ARRAY and hasattr(curtype, 'getSubEntry'):
                arrayof = curtype.getSubEntry(curoff, sz)
                if arrayof is not None:
                    fields.append((PrintC.subscript, str(curoff), curtype))
                    curtype = arrayof
                    curoff = 0
                else:
                    break
            else:
                break
        # Push operators in reverse for correct RPN order
        for tok, fname, parent in reversed(fields):
            self.pushOp(tok, op)
        self.pushSymbol(sym, vn, op)
        for tok, fname, parent in fields:
            self.pushAtom(Atom(fname, fieldtoken, SyntaxHighlight.no_color, op, parent))

    def pushMismatchSymbol(self, sym, off, sz, vn, op):
        """Push a mismatched symbol."""
        if off == 0 and sym is not None:
            nm = sym.getDisplayName() if hasattr(sym, 'getDisplayName') else str(sym)
            self.pushAtom(Atom("_" + nm, vartoken, SyntaxHighlight.var_color, op, vn))
        else:
            if vn is not None:
                self.pushUnnamedLocation(vn.getAddr(), vn, op)
            else:
                self.pushAtom(Atom("MISMATCH", vartoken, SyntaxHighlight.var_color, op, vn))

    def printCharacterConstant(self, s, val, charsize):
        """Print a character constant with optional wide-char prefix."""
        if charsize > 1:
            self.doEmitWideCharPrefix(s, charsize)
        s.write("'")
        self.printUnicode(s, val)
        s.write("'")

    def doEmitWideCharPrefix(self, s, charsize):
        """Emit wide character prefix based on character size."""
        if charsize == 2:
            s.write("u")
        elif charsize == 4:
            s.write("U")
        else:
            s.write("L")

    @staticmethod
    def getHiddenThisSlot(op, fc):
        """Get the slot of the hidden 'this' parameter, or -1 if none."""
        if fc is None:
            return -1
        if not (hasattr(fc, 'hasThisPointer') and fc.hasThisPointer()):
            return -1
        return 1  # slot 1 is typically the hidden this

    def pushAnnotation(self, vn, op):
        """Push an annotation varnode."""
        spc = vn.getSpace() if hasattr(vn, 'getSpace') else None
        if spc is not None:
            off = vn.getOffset()
            sz = vn.getSize()
            name = self._getRegisterName(off, sz)
            self.pushAtom(Atom(name, vartoken, SyntaxHighlight.special_color, op, vn))
        else:
            self.pushAtom(Atom("annotation", vartoken, SyntaxHighlight.special_color, op, vn))

    def genericFunctionName(self, addr):
        return f"func_{addr.getOffset():x}" if addr is not None else "func_unknown"

    def genericTypeName(self, ct):
        from ghidra.types.datatype import TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_FLOAT
        if ct is None:
            return "BADTYPE"
        meta = ct.getMetatype()
        if meta == TYPE_INT:
            return f"unkint{ct.getSize()}"
        elif meta == TYPE_UINT:
            return f"unkuint{ct.getSize()}"
        elif meta == TYPE_UNKNOWN:
            return f"unkbyte{ct.getSize()}"
        elif meta == TYPE_FLOAT:
            return f"unkfloat{ct.getSize()}"
        return "BADTYPE"

    # ================================================================
    # Op handlers — called via TypeOp.push() or directly
    # ================================================================

    def opFunc(self, op):
        """Push a functional expression: NAME(arg1, arg2, ...)"""
        self.pushOp(PrintC.function_call, op)
        nm = op.getOpName() if hasattr(op, 'getOpName') else "FUNC"
        self.pushAtom(Atom(nm, optoken, SyntaxHighlight.no_color, op))
        if op.numInput() > 0:
            for i in range(op.numInput() - 1):
                self.pushOp(PrintC.comma, op)
            for i in range(op.numInput() - 1, -1, -1):
                self.pushVn(op.getIn(i), op, self._mods)
        else:
            self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))

    def opTypeCast(self, op):
        """Push a type-cast expression: (type)expr"""
        outvn = op.getOut()
        if outvn is not None and not self.option_nocasts:
            dt = outvn.getHighTypeDefFacing() if hasattr(outvn, 'getHighTypeDefFacing') else outvn.getType()
            self.pushOp(PrintC.typecast, op)
            self.pushType(dt)
        self.pushVn(op.getIn(0), op, self._mods)

    def opHiddenFunc(self, op):
        """Push a hidden functional op (forces parentheses if needed)."""
        self.pushOp(PrintC.hidden, op)
        self.pushVn(op.getIn(0), op, self._mods)

    def checkAddressOfCast(self, op) -> bool:
        """Check if a CAST can be rendered as '&' (address-of array).

        The output must be ptr-to-array, input must be ptr-to-element,
        and the input must represent a symbol with array type.
        """
        from ghidra.types.datatype import TYPE_PTR, TYPE_ARRAY
        outvn = op.getOut()
        invn = op.getIn(0)
        if outvn is None or invn is None:
            return False
        dt0 = outvn.getHighTypeDefFacing() if hasattr(outvn, 'getHighTypeDefFacing') else outvn.getType()
        dt1 = invn.getHighTypeReadFacing(op) if hasattr(invn, 'getHighTypeReadFacing') else invn.getType()
        if dt0 is None or dt1 is None:
            return False
        if dt0.getMetatype() != TYPE_PTR or dt1.getMetatype() != TYPE_PTR:
            return False
        base0 = dt0.getPtrTo() if hasattr(dt0, 'getPtrTo') else None
        base1 = dt1.getPtrTo() if hasattr(dt1, 'getPtrTo') else None
        if base0 is None or base1 is None:
            return False
        if base0.getMetatype() != TYPE_ARRAY:
            return False
        arrayBase = base0.getBase() if hasattr(base0, 'getBase') else None
        if arrayBase is None:
            return False
        if arrayBase is not base1:
            return False
        return True

    def checkArrayDeref(self, vn) -> bool:
        """Check if a LOAD/STORE can use array [] or field . syntax instead of *."""
        if not hasattr(vn, 'isImplied') or not vn.isImplied():
            return False
        if not hasattr(vn, 'isWritten') or not vn.isWritten():
            return False
        defop = vn.getDef()
        if defop is None:
            return False
        opc = defop.code()
        if opc == OpCode.CPUI_SEGMENTOP:
            seg_vn = defop.getIn(2)
            if not hasattr(seg_vn, 'isImplied') or not seg_vn.isImplied():
                return False
            if not hasattr(seg_vn, 'isWritten') or not seg_vn.isWritten():
                return False
            defop = seg_vn.getDef()
            if defop is None:
                return False
            opc = defop.code()
        return opc == OpCode.CPUI_PTRSUB or opc == OpCode.CPUI_PTRADD

    def pushImpliedField(self, vn, op):
        """Push field access for a varnode with an implied field."""
        from ghidra.types.datatype import TYPE_STRUCT, TYPE_UNION
        defOp = vn.getDef()
        if defOp is None:
            self.pushVnExplicit(vn, op)
            return
        ct = vn.getHighTypeDefFacing() if hasattr(vn, 'getHighTypeDefFacing') else vn.getType()
        if ct is None:
            self.pushVnExplicit(vn, op)
            return
        meta = ct.getMetatype()
        if meta == TYPE_STRUCT or meta == TYPE_UNION:
            fieldOff = vn.getImpliedField() if hasattr(vn, 'getImpliedField') else -1
            if fieldOff >= 0 and hasattr(ct, 'findTruncation'):
                newoff = [0]
                fld = ct.findTruncation(fieldOff, vn.getSize(), defOp, -1, newoff)
                if fld is not None and hasattr(fld, 'name'):
                    self.pushOp(PrintC.object_member, defOp)
                    opc = defOp.getOpcode()
                    if hasattr(opc, 'push'):
                        opc.push(self, defOp, op)
                    else:
                        self.pushVnExplicit(vn, op)
                    self.pushAtom(Atom(fld.name, fieldtoken, SyntaxHighlight.no_color, defOp, ct))
                    return
        # Fallback
        opc = defOp.getOpcode()
        if hasattr(opc, 'push'):
            opc.push(self, defOp, op)
        else:
            self.pushVnExplicit(vn, op)

    def opCopy(self, op):
        self.pushVn(op.getIn(0), op, self._mods)

    def opLoad(self, op):
        usearray = self.checkArrayDeref(op.getIn(1))
        m = self._mods
        if usearray and not self.isSet(PrintLanguage.force_pointer):
            m |= PrintLanguage.print_load_value
        else:
            self.pushOp(PrintC.dereference, op)
        self.pushVn(op.getIn(1), op, m)

    def opStore(self, op):
        m = self._mods
        self.pushOp(PrintC.assignment, op)
        usearray = self.checkArrayDeref(op.getIn(1))
        if usearray and not self.isSet(PrintLanguage.force_pointer):
            m |= PrintLanguage.print_store_value
        else:
            self.pushOp(PrintC.dereference, op)
        self.pushVn(op.getIn(2), op, self._mods)
        self.pushVn(op.getIn(1), op, m)

    def opBranch(self, op):
        if self.isSet(PrintLanguage.flat):
            self._emit.tagOp(self.KEYWORD_GOTO, SyntaxHighlight.keyword_color, op)
            self._emit.spaces(1)
            self.pushVn(op.getIn(0), op, self._mods)

    def opCbranch(self, op):
        yesif = self.isSet(PrintLanguage.flat)
        yesparen = not self.isSet(PrintLanguage.comma_separate)
        booleanflip = op.isBooleanFlip() if hasattr(op, 'isBooleanFlip') else False
        m = self._mods

        if yesif:
            self._emit.tagOp(self.KEYWORD_IF, SyntaxHighlight.keyword_color, op)
            self._emit.spaces(1)
            if hasattr(op, 'isFallthruTrue') and op.isFallthruTrue():
                booleanflip = not booleanflip
                m |= PrintLanguage.falsebranch

        if yesparen:
            id_ = self._emit.openParen(OPEN_PAREN)
        else:
            id_ = self._emit.openGroup()

        if booleanflip:
            if self.checkPrintNegation(op.getIn(1)):
                m |= PrintLanguage.negatetoken
                booleanflip = False
        if booleanflip:
            self.pushOp(PrintC.boolean_not, op)
        self.pushVn(op.getIn(1), op, m)
        self.recurse()

        if yesparen:
            self._emit.closeParen(CLOSE_PAREN, id_)
        else:
            self._emit.closeGroup(id_)

        if yesif:
            self._emit.spaces(1)
            self._emit.print(self.KEYWORD_GOTO, SyntaxHighlight.keyword_color)
            self._emit.spaces(1)
            self.pushVn(op.getIn(0), op, self._mods)

    def opBranchind(self, op):
        self._emit.tagOp(self.KEYWORD_SWITCH, SyntaxHighlight.keyword_color, op)
        id_ = self._emit.openParen(OPEN_PAREN)
        self.pushVn(op.getIn(0), op, self._mods)
        self.recurse()
        self._emit.closeParen(CLOSE_PAREN, id_)

    def opCall(self, op):
        self.pushOp(PrintC.function_call, op)
        callpoint = op.getIn(0)
        nm = "func_unknown"
        fd_target = None
        fc_sym = None
        # Try to resolve function name from callspecs
        parent = op.getParent() if hasattr(op, 'getParent') else None
        funcdata = parent.getFuncdata() if (parent is not None and hasattr(parent, 'getFuncdata')) else None
        if funcdata is not None and hasattr(funcdata, 'getCallSpecs'):
            fc = funcdata.getCallSpecs(op)
            if fc is not None:
                fcnm = fc.getName() if hasattr(fc, 'getName') else ""
                if fcnm:
                    nm = fcnm
                else:
                    nm = self.genericFunctionName(fc.getEntryAddress() if hasattr(fc, 'getEntryAddress') else None)
                fd_target = fc.getFuncdata() if hasattr(fc, 'getFuncdata') else None
                fc_sym = fc.getSymbol() if hasattr(fc, 'getSymbol') else None
        elif hasattr(callpoint, 'getSpace') and callpoint.getSpace() is not None:
            from ghidra.core.space import IPTR_FSPEC
            if callpoint.getSpace().getType() == IPTR_FSPEC:
                addr = callpoint.getAddr()
                nm = self.genericFunctionName(addr)
        # Push namespace scope for the function symbol
        if fc_sym is not None:
            self.pushSymbolScope(fc_sym)
        self.pushAtom(Atom(nm, functoken, SyntaxHighlight.funcname_color, op, fd_target))
        # Check for hidden this parameter
        skip = -1
        if fc is not None:
            skip = self.getHiddenThisSlot(op, fc)
            if skip >= 0 and not self.isSet(PrintLanguage.hide_thisparam):
                skip = -1
        count = op.numInput() - 1
        if skip >= 0:
            count -= 1
        if count > 0:
            for i in range(count - 1):
                self.pushOp(PrintC.comma, op)
            for i in range(op.numInput() - 1, 0, -1):
                if i == skip:
                    continue
                self.pushVn(op.getIn(i), op, self._mods)
        else:
            self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))

    def opCallind(self, op):
        self.pushOp(PrintC.function_call, op)
        self.pushOp(PrintC.dereference, op)
        # Look up callspecs for hidden this parameter
        skip = -1
        parent = op.getParent() if hasattr(op, 'getParent') else None
        funcdata = parent.getFuncdata() if (parent is not None and hasattr(parent, 'getFuncdata')) else None
        if funcdata is not None and hasattr(funcdata, 'getCallSpecs'):
            fc = funcdata.getCallSpecs(op)
            if fc is not None and hasattr(fc, 'hasThisPointer') and fc.hasThisPointer():
                if self.isSet(PrintLanguage.hide_thisparam):
                    skip = 1  # Skip first parameter (this)
        count = op.numInput() - 1
        if skip >= 0:
            count -= 1
        if count > 1:
            self.pushVn(op.getIn(0), op, self._mods)
            for i in range(count - 1):
                self.pushOp(PrintC.comma, op)
            for i in range(op.numInput() - 1, 0, -1):
                if i == skip:
                    continue
                self.pushVn(op.getIn(i), op, self._mods)
        elif count == 1:
            if skip == 1:
                self.pushVn(op.getIn(2), op, self._mods)
            else:
                self.pushVn(op.getIn(1), op, self._mods)
            self.pushVn(op.getIn(0), op, self._mods)
        else:
            self.pushVn(op.getIn(0), op, self._mods)
            self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))

    def opCallother(self, op):
        """Emit CALLOTHER with display mode awareness."""
        useropIdx = op.getIn(0).getOffset() if op.numInput() > 0 else -1
        display = 0
        if self._glb is not None and hasattr(self._glb, 'userops'):
            userop = self._glb.userops.getOp(int(useropIdx))
            if userop is not None:
                display = userop.getDisplay()
        if display == 0:
            self.opFunc(op)
        elif display == 1:  # annotation_assignment: in1 = in2
            if op.numInput() >= 3:
                self.pushOp(PrintC.assignment, op)
                self.pushVn(op.getIn(2), op, self._mods)
                self.pushVn(op.getIn(1), op, self._mods)
            else:
                self.opFunc(op)
        elif display == 2:  # no_operator: just emit first input as expression
            if op.numInput() >= 2:
                self.pushVn(op.getIn(1), op, self._mods)
            else:
                self.opFunc(op)
        elif display == 4:  # display_string: emit string from StringManager
            if self._glb is not None and hasattr(self._glb, 'stringManager') and self._glb.stringManager is not None:
                addr = op.getAddr() if hasattr(op, 'getAddr') else None
                if addr is not None:
                    sdata = self._glb.stringManager.getString(addr) if hasattr(self._glb.stringManager, 'getString') else None
                    if sdata is not None:
                        self.pushAtom(Atom(sdata, vartoken, SyntaxHighlight.const_color, op, op.getOut()))
                        return
            self.opFunc(op)
        else:
            self.opFunc(op)

    def opConstructor(self, op, withNew=False):
        """Emit constructor call, optionally with 'new' keyword."""
        outvn = op.getOut()
        dt = None
        if outvn is not None:
            dt = outvn.getHighTypeDefFacing() if hasattr(outvn, 'getHighTypeDefFacing') else outvn.getType()
        if dt is None:
            self.opFunc(op)
            return
        from ghidra.types.datatype import TYPE_PTR
        if dt.getMetatype() == TYPE_PTR and hasattr(dt, 'getPtrTo'):
            dt = dt.getPtrTo()
        nm = dt.getDisplayName() if hasattr(dt, 'getDisplayName') else dt.getName() if hasattr(dt, 'getName') else "TYPE"
        if withNew:
            self.pushOp(PrintC.new_op, op)
            self.pushAtom(Atom(self.KEYWORD_NEW, optoken, SyntaxHighlight.keyword_color, op))
        self.pushOp(PrintC.function_call, op)
        self.pushAtom(Atom(nm, typetoken, SyntaxHighlight.type_color, op, dt))
        count = op.numInput()
        if count > 0:
            for i in range(count - 1):
                self.pushOp(PrintC.comma, op)
            for i in range(count - 1, -1, -1):
                self.pushVn(op.getIn(i), op, self._mods)
        else:
            self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))

    def opNewOp(self, op):
        """Emit NEW operator with optional array size."""
        outvn = op.getOut()
        vn0 = op.getIn(0)
        if op.numInput() == 2:
            vn1 = op.getIn(1)
            if not vn0.isConstant():
                # Array allocation: new Type[size]
                self.pushOp(PrintC.new_op, op)
                self.pushAtom(Atom(self.KEYWORD_NEW, optoken, SyntaxHighlight.keyword_color, op, outvn))
                nm = "<type>"
                if outvn is not None:
                    dt = outvn.getType() if hasattr(outvn, 'getType') else None
                    if dt is not None and hasattr(dt, 'getMetatype'):
                        from ghidra.types.datatype import TYPE_PTR
                        while dt.getMetatype() == TYPE_PTR and hasattr(dt, 'getPtrTo'):
                            dt = dt.getPtrTo()
                        nm = dt.getDisplayName() if hasattr(dt, 'getDisplayName') else dt.getName()
                self.pushOp(PrintC.subscript, op)
                self.pushAtom(Atom(nm, optoken, SyntaxHighlight.type_color, op))
                self.pushVn(vn1, op, self._mods)
                return
        # Default: new(size)
        self.pushOp(PrintC.function_call, op)
        self.pushAtom(Atom(self.KEYWORD_NEW, optoken, SyntaxHighlight.keyword_color, op, outvn))
        self.pushVn(vn0, op, self._mods)

    def opReturn(self, op):
        haltType = op.getHaltType() if hasattr(op, 'getHaltType') else 0
        if haltType == 0:
            # Normal return
            self._emit.tagOp(self.KEYWORD_RETURN, SyntaxHighlight.keyword_color, op)
            if op.numInput() > 1:
                self._emit.spaces(1)
                self.pushVn(op.getIn(1), op, self._mods)
        else:
            # Halt variants
            _halt_names = {1: "halt", 2: "halt", 3: "halt_baddata",
                           4: "halt_unimplemented", 5: "halt_missing"}
            nm = _halt_names.get(haltType, "halt")
            self.pushOp(PrintC.function_call, op)
            self.pushAtom(Atom(nm, optoken, SyntaxHighlight.funcname_color, op))
            self.pushAtom(Atom(self.EMPTY_STRING, blanktoken, SyntaxHighlight.no_color))

    def opIntEqual(self, op):       self.opBinary(PrintC.equal, op)
    def opIntNotEqual(self, op):    self.opBinary(PrintC.not_equal, op)
    def opIntSless(self, op):       self.opBinary(PrintC.less_than, op)
    def opIntSlessEqual(self, op):  self.opBinary(PrintC.less_equal, op)
    def opIntLess(self, op):        self.opBinary(PrintC.less_than, op)
    def opIntLessEqual(self, op):   self.opBinary(PrintC.less_equal, op)
    def opIntZext(self, op, readOp=None):
        cs = self._castStrategy
        if cs is not None and hasattr(cs, 'isZextCast'):
            outtype = op.getOut().getHighTypeDefFacing() if hasattr(op.getOut(), 'getHighTypeDefFacing') else op.getOut().getType() if op.getOut() else None
            intype = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else op.getIn(0).getType() if op.getIn(0) else None
            if outtype and intype and cs.isZextCast(outtype, intype):
                if self.option_hide_exts and hasattr(cs, 'isExtensionCastImplied') and cs.isExtensionCastImplied(op, readOp):
                    self.opHiddenFunc(op)
                else:
                    self.opTypeCast(op)
                return
        self.opFunc(op)

    def opIntSext(self, op, readOp=None):
        cs = self._castStrategy
        if cs is not None and hasattr(cs, 'isSextCast'):
            outtype = op.getOut().getHighTypeDefFacing() if hasattr(op.getOut(), 'getHighTypeDefFacing') else op.getOut().getType() if op.getOut() else None
            intype = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else op.getIn(0).getType() if op.getIn(0) else None
            if outtype and intype and cs.isSextCast(outtype, intype):
                if self.option_hide_exts and hasattr(cs, 'isExtensionCastImplied') and cs.isExtensionCastImplied(op, readOp):
                    self.opHiddenFunc(op)
                else:
                    self.opTypeCast(op)
                return
        self.opFunc(op)
    def opIntAdd(self, op):         self.opBinary(PrintC.binary_plus, op)
    def opIntSub(self, op):         self.opBinary(PrintC.binary_minus, op)
    def opIntCarry(self, op):       self.opFunc(op)
    def opIntScarry(self, op):      self.opFunc(op)
    def opIntSborrow(self, op):     self.opFunc(op)
    def opInt2Comp(self, op):       self.opUnary(PrintC.unary_minus, op)
    def opIntNegate(self, op):      self.opUnary(PrintC.bitwise_not, op)
    def opIntXor(self, op):         self.opBinary(PrintC.bitwise_xor, op)
    def opIntAnd(self, op):         self.opBinary(PrintC.bitwise_and, op)
    def opIntOr(self, op):          self.opBinary(PrintC.bitwise_or, op)
    def opIntLeft(self, op):        self.opBinary(PrintC.shift_left, op)
    def opIntRight(self, op):       self.opBinary(PrintC.shift_right, op)
    def opIntSright(self, op):      self.opBinary(PrintC.shift_sright, op)
    def opIntMult(self, op):        self.opBinary(PrintC.multiply, op)
    def opIntDiv(self, op):         self.opBinary(PrintC.divide, op)
    def opIntSdiv(self, op):        self.opBinary(PrintC.divide, op)
    def opIntRem(self, op):         self.opBinary(PrintC.modulo, op)
    def opIntSrem(self, op):        self.opBinary(PrintC.modulo, op)

    def opBoolNegate(self, op):
        if self.isSet(PrintLanguage.negatetoken):
            self.unsetMod(PrintLanguage.negatetoken)
            self.pushVn(op.getIn(0), op, self._mods)
        elif self.checkPrintNegation(op.getIn(0)):
            self.pushVn(op.getIn(0), op, self._mods | PrintLanguage.negatetoken)
        else:
            self.opUnary(PrintC.boolean_not, op)

    def opBoolXor(self, op):        self.opBinary(PrintC.boolean_xor, op)
    def opBoolAnd(self, op):        self.opBinary(PrintC.boolean_and, op)
    def opBoolOr(self, op):         self.opBinary(PrintC.boolean_or, op)

    def opFloatEqual(self, op):         self.opBinary(PrintC.equal, op)
    def opFloatNotEqual(self, op):      self.opBinary(PrintC.not_equal, op)
    def opFloatLess(self, op):          self.opBinary(PrintC.less_than, op)
    def opFloatLessEqual(self, op):     self.opBinary(PrintC.less_equal, op)
    def opFloatNan(self, op):           self.opFunc(op)
    def opFloatAdd(self, op):           self.opBinary(PrintC.binary_plus, op)
    def opFloatDiv(self, op):           self.opBinary(PrintC.divide, op)
    def opFloatMult(self, op):          self.opBinary(PrintC.multiply, op)
    def opFloatSub(self, op):           self.opBinary(PrintC.binary_minus, op)
    def opFloatNeg(self, op):           self.opUnary(PrintC.unary_minus, op)
    def opFloatAbs(self, op):           self.opFunc(op)
    def opFloatSqrt(self, op):          self.opFunc(op)
    def opFloatInt2Float(self, op):
        """Emit INT2FLOAT: absorb preceding ZEXT if present."""
        vn0 = op.getIn(0)
        # Check if input is from a ZEXT that can be absorbed
        if hasattr(vn0, 'isWritten') and vn0.isWritten():
            defop = vn0.getDef()
            if defop is not None and defop.code() == OpCode.CPUI_INT_ZEXT:
                # Absorb the ZEXT — use its input directly
                vn0 = defop.getIn(0)
        outvn = op.getOut()
        dt = outvn.getHighTypeDefFacing() if (outvn and hasattr(outvn, 'getHighTypeDefFacing')) else (outvn.getType() if outvn else None)
        if not self.option_nocasts and dt is not None:
            self.pushOp(PrintC.typecast, op)
            self.pushType(dt)
        self.pushVn(vn0, op, self._mods)
    def opFloatFloat2Float(self, op):   self.opTypeCast(op)
    def opFloatTrunc(self, op):         self.opTypeCast(op)
    def opFloatCeil(self, op):          self.opFunc(op)
    def opFloatFloor(self, op):         self.opFunc(op)
    def opFloatRound(self, op):         self.opFunc(op)

    def opMultiequal(self, op):   pass
    def opIndirect(self, op):     pass
    def opPiece(self, op):        self.opFunc(op)
    def opSubpiece(self, op):
        """Emit SUBPIECE: field extraction or type cast."""
        if hasattr(op, 'doesSpecialPrinting') and op.doesSpecialPrinting():
            vn = op.getIn(0)
            ct = vn.getHighTypeReadFacing(op) if hasattr(vn, 'getHighTypeReadFacing') else vn.getType()
            if ct is not None and hasattr(ct, 'isPieceStructured') and ct.isPieceStructured():
                from ghidra.types.datatype import TYPE_STRUCT
                byteOff = op.getIn(1).getOffset()
                if not self._glb.translate.isBigEndian() if (self._glb and hasattr(self._glb, 'translate') and self._glb.translate) else True:
                    pass  # little endian: byteOff is direct
                else:
                    byteOff = vn.getSize() - op.getOut().getSize() - byteOff
                if ct.getMetatype() == TYPE_STRUCT and hasattr(ct, 'findTruncation'):
                    newoff = [0]
                    fld = ct.findTruncation(int(byteOff), op.getOut().getSize(), op, 1, newoff)
                    if fld is not None and hasattr(fld, 'name'):
                        self.pushOp(PrintC.object_member, op)
                        self.pushVn(vn, op, self._mods)
                        self.pushAtom(Atom(fld.name, fieldtoken, SyntaxHighlight.no_color, ct, fld.ident if hasattr(fld, 'ident') else 0, op))
                        return
        self.opTypeCast(op)
    def opCast(self, op):         self.opTypeCast(op)
    def opPtradd(self, op):
        """Emit PTRADD: array subscript [] or pointer addition."""
        printval = self.isSet(PrintLanguage.print_load_value | PrintLanguage.print_store_value)
        m = self._mods & ~(PrintLanguage.print_load_value | PrintLanguage.print_store_value)
        if printval:
            self.pushOp(PrintC.subscript, op)
        else:
            self.pushOp(PrintC.binary_plus, op)
        self.pushVn(op.getIn(1), op, m)
        self.pushVn(op.getIn(0), op, m)
    def opPtrsub(self, op):
        """Emit PTRSUB: struct/union field access via -> or . syntax."""
        from ghidra.types.datatype import TYPE_PTR, TYPE_STRUCT, TYPE_UNION, TYPE_SPACEBASE, TYPE_ARRAY
        in0 = op.getIn(0)
        in1const = op.getIn(1).getOffset()
        ptype = in0.getHighTypeReadFacing(op) if hasattr(in0, 'getHighTypeReadFacing') else in0.getType()
        if ptype is None or ptype.getMetatype() != TYPE_PTR:
            self.opFunc(op)
            return
        ct = ptype.getPtrTo() if hasattr(ptype, 'getPtrTo') else None
        if ct is None:
            self.opFunc(op)
            return
        m = self._mods & ~(PrintLanguage.print_load_value | PrintLanguage.print_store_value)
        valueon = (self._mods & (PrintLanguage.print_load_value | PrintLanguage.print_store_value)) != 0
        meta = ct.getMetatype()
        if meta == TYPE_STRUCT or meta == TYPE_UNION:
            fieldname = f"field_0x{int(in1const):x}"
            if hasattr(ct, 'findTruncation'):
                newoff = [0]
                fld = ct.findTruncation(int(in1const), 0, op, 0, newoff)
                if fld is not None and hasattr(fld, 'name'):
                    fieldname = fld.name
            if not valueon:
                # Check if we can skip addressof for array output types
                outvn = op.getOut()
                if outvn is not None and self.checkAddressOfCast(op):
                    self.pushOp(PrintC.pointer_member, op)
                else:
                    self.pushOp(PrintC.addressof, op)
                    self.pushOp(PrintC.pointer_member, op)
                self.pushVn(in0, op, m)
                self.pushAtom(Atom(fieldname, fieldtoken, SyntaxHighlight.no_color, op, ct))
            else:
                self.pushOp(PrintC.pointer_member, op)
                self.pushVn(in0, op, m)
                self.pushAtom(Atom(fieldname, fieldtoken, SyntaxHighlight.no_color, op, ct))
        elif meta == TYPE_SPACEBASE:
            if not valueon:
                self.pushOp(PrintC.addressof, op)
            high = op.getIn(1).getHigh() if hasattr(op.getIn(1), 'getHigh') else None
            sym = high.getSymbol() if (high is not None and hasattr(high, 'getSymbol')) else None
            if sym is not None:
                self.pushSymbol(sym, None, op)
            else:
                self.pushUnnamedLocation(op.getIn(1).getAddr() if hasattr(op.getIn(1), 'getAddr') else None, None, op)
        elif meta == TYPE_ARRAY:
            if valueon:
                # Array with load/store value: use subscript syntax arr[0]
                self.pushOp(PrintC.subscript, op)
                self.pushVn(in0, op, m)
                self.push_integer(int(in1const), ct.getSize(), False, syntax, None, None)
            else:
                self.pushOp(PrintC.dereference, op)
                self.pushVn(in0, op, m)
        else:
            self.opFunc(op)
    def opSegmentOp(self, op):    self.pushVn(op.getIn(2), op, self._mods)
    def opCpoolRefOp(self, op):
        """Emit CPOOLREF: constant pool reference with record dispatch."""
        outvn = op.getOut()
        vn0 = op.getIn(0)
        if self._glb is None or not hasattr(self._glb, 'cpool') or self._glb.cpool is None:
            self.opFunc(op)
            return
        refs = []
        for i in range(1, op.numInput()):
            refs.append(op.getIn(i).getOffset())
        rec = self._glb.cpool.getRecord(refs) if hasattr(self._glb.cpool, 'getRecord') else None
        if rec is None:
            self.pushAtom(Atom("UNKNOWNREF", syntax, SyntaxHighlight.const_color, op, outvn))
            return
        tag = rec.getTag() if hasattr(rec, 'getTag') else 0
        token = rec.getToken() if hasattr(rec, 'getToken') else "CPOOLREF"
        if tag == 0:  # string_literal
            self.pushAtom(Atom(token, vartoken, SyntaxHighlight.const_color, op, outvn))
        elif tag == 1:  # class_reference
            self.pushAtom(Atom(token, vartoken, SyntaxHighlight.type_color, op, outvn))
        elif tag == 2:  # pointer_method
            self.pushOp(PrintC.pointer_member, op)
            self.pushVn(vn0, op, self._mods)
            self.pushAtom(Atom(token, syntax, SyntaxHighlight.funcname_color, op, outvn))
        elif tag == 3:  # pointer_field
            self.pushOp(PrintC.pointer_member, op)
            self.pushVn(vn0, op, self._mods)
            self.pushAtom(Atom(token, fieldtoken, SyntaxHighlight.no_color, op, outvn))
        elif tag == 4:  # array_length
            self.pushOp(PrintC.object_member, op)
            self.pushVn(vn0, op, self._mods)
            self.pushAtom(Atom(token, syntax, SyntaxHighlight.var_color, op, outvn))
        elif tag == 5:  # instanceof
            self.pushOp(PrintC.type_instanceOf, op)
            self.pushVn(vn0, op, self._mods)
            self.pushAtom(Atom(token, typetoken, SyntaxHighlight.type_color, op, outvn))
        elif tag == 6:  # check_cast
            self.pushOp(PrintC.typecast, op)
            self.pushAtom(Atom(token, typetoken, SyntaxHighlight.type_color, op, outvn))
            self.pushVn(vn0, op, self._mods)
        else:
            # Default fallback
            if vn0.isConstant():
                self.pushAtom(Atom(token, vartoken, SyntaxHighlight.var_color, op, outvn))
            else:
                self.pushOp(PrintC.pointer_member, op)
                self.pushVn(vn0, op, self._mods)
                self.pushAtom(Atom(token, syntax, SyntaxHighlight.var_color, op, outvn))
    def opInsertOp(self, op):
        if hasattr(op, 'doesSpecialPrinting') and op.doesSpecialPrinting():
            outvn = op.getOut()
            ct = outvn.getHighTypeDefFacing() if (outvn and hasattr(outvn, 'getHighTypeDefFacing')) else (outvn.getType() if outvn else None)
            if ct is not None and hasattr(ct, 'isPieceStructured') and ct.isPieceStructured():
                from ghidra.types.datatype import TYPE_STRUCT
                if ct.getMetatype() == TYPE_STRUCT:
                    self.opFunc(op)
                    return
        self.opFunc(op)

    def opExtractOp(self, op):
        if hasattr(op, 'doesSpecialPrinting') and op.doesSpecialPrinting():
            outvn = op.getOut()
            ct = op.getIn(0).getHighTypeReadFacing(op) if (hasattr(op.getIn(0), 'getHighTypeReadFacing')) else (op.getIn(0).getType() if op.getIn(0) else None)
            if ct is not None and hasattr(ct, 'isPieceStructured') and ct.isPieceStructured():
                from ghidra.types.datatype import TYPE_STRUCT
                byteOff = op.getIn(1).getOffset()
                if ct.getMetatype() == TYPE_STRUCT and hasattr(ct, 'findTruncation'):
                    newoff = [0]
                    fld = ct.findTruncation(int(byteOff), outvn.getSize() if outvn else 0, op, 1, newoff)
                    if fld is not None and hasattr(fld, 'name'):
                        self.pushOp(PrintC.object_member, op)
                        self.pushVn(op.getIn(0), op, self._mods)
                        self.pushAtom(Atom(fld.name, fieldtoken, SyntaxHighlight.no_color, op, ct))
                        return
        self.opFunc(op)
    def opPopcountOp(self, op):   self.opFunc(op)
    def opLzcountOp(self, op):    self.opFunc(op)

    def checkPrintNegation(self, vn):
        """Check if a boolean Varnode can be printed in negated form."""
        if not hasattr(vn, 'isImplied') or not vn.isImplied():
            return False
        if not hasattr(vn, 'isWritten') or not vn.isWritten():
            return False
        defOp = vn.getDef()
        if defOp is None:
            return False
        opc = defOp.code()
        from ghidra.core.opcodes import get_booleanflip, OpCode as OC
        comp, reorder = get_booleanflip(opc)
        return comp != OC.CPUI_MAX

    # ================================================================
    # Expression / Statement emission
    # ================================================================

    def emitExpression(self, op):
        """Emit a full expression for a PcodeOp."""
        outvn = op.getOut()
        if outvn is not None:
            if self.option_inplace_ops and self.emitInplaceOp(op):
                return
            # Check for constructor syntax (doesSpecialPrinting on output-less ops)
            if hasattr(op, 'doesSpecialPrinting') and op.doesSpecialPrinting() and outvn is None:
                pass  # handled below
            else:
                self.pushOp(PrintC.assignment, op)
                self.pushSymbolDetail(outvn, op, False)
        elif hasattr(op, 'doesSpecialPrinting') and op.doesSpecialPrinting():
            # Constructor syntax: out = new Type(args)
            if op.numInput() >= 2:
                invn1 = op.getIn(1)
                if hasattr(invn1, 'isWritten') and invn1.isWritten():
                    newop = invn1.getDef()
                    if newop is not None:
                        newout = newop.getOut()
                        if newout is not None:
                            self.pushOp(PrintC.assignment, newop)
                            self.pushSymbolDetail(newout, newop, False)
                            self.opConstructor(op, True)
                            self.recurse()
                            return
        # Let the opcode handler push the RHS
        opc = op.getOpcode() if hasattr(op, 'getOpcode') else None
        if opc is not None and hasattr(opc, 'push'):
            opc.push(self, op, None)
        else:
            self._fallbackOpPush(op)
        self.recurse()

    def _fallbackOpPush(self, op):
        """Fallback: push op using opcode dispatch table."""
        opc = op.code()
        handler = self._getOpHandler(opc)
        if handler is not None:
            handler(op)
        else:
            self.opFunc(op)

    def _getOpHandler(self, opc):
        """Get the handler method for a given opcode."""
        _dispatch = {
            OpCode.CPUI_COPY: self.opCopy,
            OpCode.CPUI_LOAD: self.opLoad,
            OpCode.CPUI_STORE: self.opStore,
            OpCode.CPUI_BRANCH: self.opBranch,
            OpCode.CPUI_CBRANCH: self.opCbranch,
            OpCode.CPUI_BRANCHIND: self.opBranchind,
            OpCode.CPUI_CALL: self.opCall,
            OpCode.CPUI_CALLIND: self.opCallind,
            OpCode.CPUI_CALLOTHER: self.opCallother,
            OpCode.CPUI_RETURN: self.opReturn,
            OpCode.CPUI_INT_EQUAL: self.opIntEqual,
            OpCode.CPUI_INT_NOTEQUAL: self.opIntNotEqual,
            OpCode.CPUI_INT_SLESS: self.opIntSless,
            OpCode.CPUI_INT_SLESSEQUAL: self.opIntSlessEqual,
            OpCode.CPUI_INT_LESS: self.opIntLess,
            OpCode.CPUI_INT_LESSEQUAL: self.opIntLessEqual,
            OpCode.CPUI_INT_ZEXT: self.opIntZext,
            OpCode.CPUI_INT_SEXT: self.opIntSext,
            OpCode.CPUI_INT_ADD: self.opIntAdd,
            OpCode.CPUI_INT_SUB: self.opIntSub,
            OpCode.CPUI_INT_CARRY: self.opIntCarry,
            OpCode.CPUI_INT_SCARRY: self.opIntScarry,
            OpCode.CPUI_INT_SBORROW: self.opIntSborrow,
            OpCode.CPUI_INT_2COMP: self.opInt2Comp,
            OpCode.CPUI_INT_NEGATE: self.opIntNegate,
            OpCode.CPUI_INT_XOR: self.opIntXor,
            OpCode.CPUI_INT_AND: self.opIntAnd,
            OpCode.CPUI_INT_OR: self.opIntOr,
            OpCode.CPUI_INT_LEFT: self.opIntLeft,
            OpCode.CPUI_INT_RIGHT: self.opIntRight,
            OpCode.CPUI_INT_SRIGHT: self.opIntSright,
            OpCode.CPUI_INT_MULT: self.opIntMult,
            OpCode.CPUI_INT_DIV: self.opIntDiv,
            OpCode.CPUI_INT_SDIV: self.opIntSdiv,
            OpCode.CPUI_INT_REM: self.opIntRem,
            OpCode.CPUI_INT_SREM: self.opIntSrem,
            OpCode.CPUI_BOOL_NEGATE: self.opBoolNegate,
            OpCode.CPUI_BOOL_XOR: self.opBoolXor,
            OpCode.CPUI_BOOL_AND: self.opBoolAnd,
            OpCode.CPUI_BOOL_OR: self.opBoolOr,
            OpCode.CPUI_FLOAT_EQUAL: self.opFloatEqual,
            OpCode.CPUI_FLOAT_NOTEQUAL: self.opFloatNotEqual,
            OpCode.CPUI_FLOAT_LESS: self.opFloatLess,
            OpCode.CPUI_FLOAT_LESSEQUAL: self.opFloatLessEqual,
            OpCode.CPUI_FLOAT_NAN: self.opFloatNan,
            OpCode.CPUI_FLOAT_ADD: self.opFloatAdd,
            OpCode.CPUI_FLOAT_DIV: self.opFloatDiv,
            OpCode.CPUI_FLOAT_MULT: self.opFloatMult,
            OpCode.CPUI_FLOAT_SUB: self.opFloatSub,
            OpCode.CPUI_FLOAT_NEG: self.opFloatNeg,
            OpCode.CPUI_FLOAT_ABS: self.opFloatAbs,
            OpCode.CPUI_FLOAT_SQRT: self.opFloatSqrt,
            OpCode.CPUI_FLOAT_INT2FLOAT: self.opFloatInt2Float,
            OpCode.CPUI_FLOAT_FLOAT2FLOAT: self.opFloatFloat2Float,
            OpCode.CPUI_FLOAT_TRUNC: self.opFloatTrunc,
            OpCode.CPUI_FLOAT_CEIL: self.opFloatCeil,
            OpCode.CPUI_FLOAT_FLOOR: self.opFloatFloor,
            OpCode.CPUI_FLOAT_ROUND: self.opFloatRound,
            OpCode.CPUI_MULTIEQUAL: self.opMultiequal,
            OpCode.CPUI_INDIRECT: self.opIndirect,
            OpCode.CPUI_PIECE: self.opPiece,
            OpCode.CPUI_SUBPIECE: self.opSubpiece,
            OpCode.CPUI_CAST: self.opCast,
            OpCode.CPUI_PTRADD: self.opPtradd,
            OpCode.CPUI_PTRSUB: self.opPtrsub,
            OpCode.CPUI_POPCOUNT: self.opPopcountOp,
            OpCode.CPUI_LZCOUNT: self.opLzcountOp,
        }
        return _dispatch.get(int(opc))

    def emitInplaceOp(self, op):
        """Try to emit an in-place operator (+=, etc). Returns True if emitted."""
        _inplace = {
            OpCode.CPUI_INT_MULT: PrintC.multequal,
            OpCode.CPUI_INT_DIV: PrintC.divequal,
            OpCode.CPUI_INT_SDIV: PrintC.divequal,
            OpCode.CPUI_INT_REM: PrintC.remequal,
            OpCode.CPUI_INT_SREM: PrintC.remequal,
            OpCode.CPUI_INT_ADD: PrintC.plusequal,
            OpCode.CPUI_INT_SUB: PrintC.minusequal,
            OpCode.CPUI_INT_LEFT: PrintC.leftequal,
            OpCode.CPUI_INT_RIGHT: PrintC.rightequal,
            OpCode.CPUI_INT_SRIGHT: PrintC.rightequal,
            OpCode.CPUI_INT_AND: PrintC.andequal,
            OpCode.CPUI_INT_OR: PrintC.orequal,
            OpCode.CPUI_INT_XOR: PrintC.xorequal,
        }
        tok = _inplace.get(int(op.code()))
        if tok is None:
            return False
        vn = op.getIn(0)
        outvn = op.getOut()
        if outvn is None or vn is None:
            return False
        # Check if output and input[0] refer to the same high variable
        if outvn.getHigh() is not vn.getHigh():
            return False
        self.pushOp(tok, op)
        self.pushVnExplicit(vn, op)
        self.pushVn(op.getIn(1), op, self._mods)
        self.recurse()
        return True

    def emitStatement(self, op):
        """Emit a single statement terminated by semicolon."""
        if self._emit is None:
            return
        self.emitCommentGroup(op)
        id_ = self._emit.beginStatement(op)
        self.emitExpression(op)
        self._emit.endStatement(id_)
        if not self.isSet(PrintLanguage.comma_separate):
            self._emit.print(self.SEMICOLON)

    def emitVarDecl(self, sym):
        """Emit a variable declaration."""
        if self._emit is None or sym is None:
            return
        id_ = self._emit.beginVarDecl(sym)
        tp = sym.getType() if hasattr(sym, 'getType') else None
        if tp is not None:
            self.pushTypeStart(tp, False)
            self.pushSymbol(sym, None, None)
            self.pushTypeEnd(tp)
            self.recurse()
        else:
            nm = sym.getDisplayName() if hasattr(sym, 'getDisplayName') else (
                sym.getName() if hasattr(sym, 'getName') else str(sym))
            self._emit.tagVariable(nm, SyntaxHighlight.var_color, None, None)
        self._emit.endVarDecl(id_)

    def emitScopeVarDecls(self, symScope, cat: int) -> bool:
        """Emit all the variable declarations for a given scope."""
        if self._emit is None or symScope is None:
            return False
        emitted = False
        if hasattr(symScope, 'getSymbolList'):
            for sym in symScope.getSymbolList():
                if cat >= 0 and hasattr(sym, 'getCategory') and sym.getCategory() != cat:
                    continue
                self.emitVarDeclStatement(sym)
                emitted = True
        return emitted

    def emitVarDeclStatement(self, sym):
        """Emit a variable declaration as a full statement."""
        if self._emit is None:
            return
        self._emit.tagLine()
        self.emitVarDecl(sym)
        self._emit.print(self.SEMICOLON)

    # ================================================================
    # Block emission
    # ================================================================

    def emitBlockBasic(self, bb):
        """Emit statements in a basic block."""
        if self._emit is None:
            return
        # Set up comment block list
        if hasattr(self, '_commsorter'):
            self._commsorter.setupBlockList(bb)
        # Emit label for flat prints
        self.emitLabelStatement(bb)

        if self.isSet(PrintLanguage.only_branch):
            lastop = bb.lastOp() if hasattr(bb, 'lastOp') else None
            if lastop is not None and hasattr(lastop, 'isBranch') and lastop.isBranch():
                self.emitExpression(lastop)
            return

        separator = False
        ops = bb.getOpList() if hasattr(bb, 'getOpList') else []
        for inst in ops:
            if inst.notPrinted():
                continue
            if hasattr(inst, 'isBranch') and inst.isBranch():
                if self.isSet(PrintLanguage.no_branch):
                    continue
                opc = inst.code()
                if opc == OpCode.CPUI_BRANCH:
                    continue
            outvn = inst.getOut()
            if outvn is not None and hasattr(outvn, 'isImplied') and outvn.isImplied():
                continue
            if separator:
                if self.isSet(PrintLanguage.comma_separate):
                    self._emit.print(self.COMMA)
                    self._emit.spaces(1)
                else:
                    self._emit.tagLine()
            else:
                if not self.isSet(PrintLanguage.comma_separate):
                    self._emit.tagLine()
            self.emitStatement(inst)
            separator = True
        # Flat mode: print goto if no fallthru
        if self.isSet(PrintLanguage.flat) and self.isSet(PrintLanguage.nofallthru):
            lastop = bb.lastOp() if hasattr(bb, 'lastOp') else None
            if lastop is not None:
                self._emit.tagLine()
                id_ = self._emit.beginStatement(lastop)
                self._emit.print(self.KEYWORD_GOTO, SyntaxHighlight.keyword_color)
                self._emit.spaces(1)
                if bb.sizeOut() >= 1:
                    self.emitLabel(bb.getOut(0))
                self._emit.print(self.SEMICOLON)
                self._emit.endStatement(id_)
        self.emitCommentGroup(None)

    def emitBlockGraph(self, bl):
        """Emit an unspecified list of blocks."""
        if self._emit is None:
            return
        blocks = bl.getList() if hasattr(bl, 'getList') else []
        if not blocks and hasattr(bl, 'getSize'):
            blocks = [bl.getBlock(i) for i in range(bl.getSize())]
        for sub in blocks:
            id_ = self._emit.beginBlock(sub)
            sub.emit(self)
            self._emit.endBlock(id_)

    def emitBlockCopy(self, bl):
        """Emit a copy block with label."""
        self.emitAnyLabelStatement(bl)
        ref = bl.subBlock(0) if hasattr(bl, 'subBlock') else None
        if ref is not None:
            ref.emit(self)

    def emitGotoStatement(self, bl, exp_bl, gotype):
        """Emit a goto/break/continue statement."""
        from ghidra.block.block import FlowBlock
        lastop = bl.lastOp() if hasattr(bl, 'lastOp') else None
        id_ = self._emit.beginStatement(lastop)
        if gotype == FlowBlock.f_break_goto:
            self._emit.print(self.KEYWORD_BREAK, SyntaxHighlight.keyword_color)
        elif gotype == FlowBlock.f_continue_goto:
            self._emit.print(self.KEYWORD_CONTINUE, SyntaxHighlight.keyword_color)
        else:
            self._emit.print(self.KEYWORD_GOTO, SyntaxHighlight.keyword_color)
            self._emit.spaces(1)
            if exp_bl is not None:
                self.emitLabel(exp_bl)
        self._emit.print(self.SEMICOLON)
        self._emit.endStatement(id_)

    def emitLabel(self, bl):
        """Emit a label for a control-flow block."""
        leaf = bl.getFrontLeaf() if hasattr(bl, 'getFrontLeaf') else bl
        if leaf is None:
            return
        addr = leaf.getEntryAddr() if hasattr(leaf, 'getEntryAddr') else leaf.getStart()
        spc = addr.getSpace() if not addr.isInvalid() else None
        off = addr.getOffset() if not addr.isInvalid() else 0
        if hasattr(leaf, 'isJoined') and leaf.isJoined():
            prefix = "joined_"
        elif hasattr(leaf, 'isDuplicated') and leaf.isDuplicated():
            prefix = "dup_"
        else:
            prefix = "code_"
        label = f"{prefix}{off:x}"
        self._emit.tagLabel(label, SyntaxHighlight.no_color, spc, off)

    def emitLabelStatement(self, bl):
        """Emit a label statement if the block is a jump target."""
        if self.isSet(PrintLanguage.only_branch):
            return
        if self.isSet(PrintLanguage.flat):
            if not (hasattr(bl, 'isJumpTarget') and bl.isJumpTarget()):
                return
        else:
            if not (hasattr(bl, 'isUnstructuredTarget') and bl.isUnstructuredTarget()):
                return
            from ghidra.block.block import FlowBlock
            if bl.getType() != FlowBlock.BlockType.t_copy:
                return
        self._emit.tagLine(0)
        self.emitLabel(bl)
        self._emit.print(self.COLON)

    def emitAnyLabelStatement(self, bl):
        """Emit label for any block type by finding entry leaf."""
        if hasattr(bl, 'isLabelBumpUp') and bl.isLabelBumpUp():
            return
        leaf = bl.getFrontLeaf() if hasattr(bl, 'getFrontLeaf') else None
        if leaf is None:
            return
        self.emitLabelStatement(leaf)

    def emitBlockGoto(self, bl):
        """Emit a goto block."""
        self.pushMod()
        self.setMod(PrintLanguage.no_branch)
        sub = bl.getBlock(0)
        sub.emit(self)
        self.popMod()
        if hasattr(bl, 'gotoPrints') and bl.gotoPrints():
            self._emit.tagLine()
            target = bl.getGotoTarget() if hasattr(bl, 'getGotoTarget') else None
            gotype = bl.getGotoType() if hasattr(bl, 'getGotoType') else 1
            self.emitGotoStatement(sub, target, gotype)

    def emitBlockLs(self, bl):
        """Emit a sequence of blocks with proper no_branch/nofallthru handling."""
        if self.isSet(PrintLanguage.only_branch):
            sub = bl.getBlock(bl.getSize() - 1)
            sub.emit(self)
            return
        sz = bl.getSize()
        if sz == 0:
            return
        i = 0
        sub = bl.getBlock(i)
        id1 = self._emit.beginBlock(sub)
        i += 1
        if i == sz:
            sub.emit(self)
            self._emit.endBlock(id1)
            return
        self.pushMod()
        if not self.isSet(PrintLanguage.flat):
            self.setMod(PrintLanguage.no_branch)
        if i < sz and bl.getBlock(i) is not sub.nextInFlow():
            self.pushMod()
            self.setMod(PrintLanguage.nofallthru)
            sub.emit(self)
            self.popMod()
        else:
            sub.emit(self)
        self._emit.endBlock(id1)
        while i < sz - 1:
            sub = bl.getBlock(i)
            i += 1
            id2 = self._emit.beginBlock(sub)
            if i < sz and bl.getBlock(i) is not sub.nextInFlow():
                self.pushMod()
                self.setMod(PrintLanguage.nofallthru)
                sub.emit(self)
                self.popMod()
            else:
                sub.emit(self)
            self._emit.endBlock(id2)
        self.popMod()
        sub = bl.getBlock(sz - 1)
        id3 = self._emit.beginBlock(sub)
        sub.emit(self)
        self._emit.endBlock(id3)

    def emitBlockCondition(self, bl):
        """Emit a condition block (&&, ||) using RPN-style operator emission."""
        if self.isSet(PrintLanguage.no_branch):
            id_ = self._emit.beginBlock(bl.getBlock(0))
            bl.getBlock(0).emit(self)
            self._emit.endBlock(id_)
            return
        if self.isSet(PrintLanguage.only_branch) or self.isSet(PrintLanguage.comma_separate):
            id_ = self._emit.openParen(OPEN_PAREN)
            bl.getBlock(0).emit(self)
            self.pushMod()
            self.unsetMod(PrintLanguage.only_branch)
            self.setMod(PrintLanguage.comma_separate)
            # Use RPN-style emission for the operator
            pol = ReversePolish()
            pol.op = None
            pol.visited = 1
            opc = bl.getOpcode() if hasattr(bl, 'getOpcode') else None
            if opc == OpCode.CPUI_BOOL_AND:
                pol.tok = PrintC.boolean_and
            else:
                pol.tok = PrintC.boolean_or
            self.emitOp(pol)
            id2 = self._emit.openParen(OPEN_PAREN)
            bl.getBlock(1).emit(self)
            self._emit.closeParen(CLOSE_PAREN, id2)
            self.popMod()
            self._emit.closeParen(CLOSE_PAREN, id_)

    def emitBlockIf(self, bl):
        """Emit an if/else construct with else-if chain merging."""
        from ghidra.block.block import FlowBlock

        isPendingBrace = self.isSet(PrintLanguage.pending_brace)

        self.pushMod()
        self.unsetMod(PrintLanguage.no_branch | PrintLanguage.only_branch | PrintLanguage.pending_brace)

        # Emit condition block body (no branch)
        self.pushMod()
        self.setMod(PrintLanguage.no_branch)
        condBlock = bl.getBlock(0)
        condBlock.emit(self)
        self.popMod()
        self.emitCommentBlockTree(condBlock)

        # For else-if: if pending_brace was set, emit on same line instead of new line
        if isPendingBrace:
            self._emit.spaces(1)
        else:
            self._emit.tagLine()

        op = condBlock.lastOp() if hasattr(condBlock, 'lastOp') else None
        self._emit.tagOp(self.KEYWORD_IF, SyntaxHighlight.keyword_color, op)
        self._emit.spaces(1)

        # Emit the branch condition
        self.pushMod()
        self.setMod(PrintLanguage.only_branch)
        condBlock.emit(self)
        self.popMod()

        # Check for goto target (simplified if-goto)
        gotoTarget = bl.getGotoTarget() if hasattr(bl, 'getGotoTarget') else None
        if gotoTarget is not None:
            self._emit.spaces(1)
            gotoType = bl.getGotoType() if hasattr(bl, 'getGotoType') else FlowBlock.f_goto_goto
            self.emitGotoStatement(condBlock, gotoTarget, gotoType)
        else:
            # Emit true block with braces
            self.setMod(PrintLanguage.no_branch)
            self._emit.spaces(1)
            self._emit.print(self.OPEN_CURLY)
            indent_id = self._emit.indentlevel
            self._emit.indentlevel += self._emit.indentincrement
            id1 = self._emit.beginBlock(bl.getBlock(1))
            bl.getBlock(1).emit(self)
            self._emit.endBlock(id1)
            self._emit.indentlevel = indent_id
            self._emit.tagLine()
            self._emit.print(self.CLOSE_CURLY)

            # Emit else block if present
            if bl.getSize() == 3:
                self._emit.spaces(1)
                self._emit.print(self.KEYWORD_ELSE, SyntaxHighlight.keyword_color)
                elseBlock = bl.getBlock(2)
                # Check for else-if merging
                if elseBlock.getType() == FlowBlock.BlockType.t_if:
                    # Emit as "else if" — set pending_brace so next emitBlockIf merges
                    self.setMod(PrintLanguage.pending_brace)
                    id2 = self._emit.beginBlock(elseBlock)
                    elseBlock.emit(self)
                    self._emit.endBlock(id2)
                else:
                    self._emit.spaces(1)
                    self._emit.print(self.OPEN_CURLY)
                    self._emit.indentlevel += self._emit.indentincrement
                    id2 = self._emit.beginBlock(elseBlock)
                    elseBlock.emit(self)
                    self._emit.endBlock(id2)
                    self._emit.indentlevel = indent_id
                    self._emit.tagLine()
                    self._emit.print(self.CLOSE_CURLY)

        self.popMod()

    def emitForLoop(self, bl):
        """Emit block as a for loop: for(init; cond; iter) { body }"""
        self.pushMod()
        self.unsetMod(PrintLanguage.no_branch | PrintLanguage.only_branch)
        self.emitAnyLabelStatement(bl)
        condBlock = bl.getBlock(0)
        op = condBlock.lastOp() if hasattr(condBlock, 'lastOp') else None
        self._emit.tagLine()
        self._emit.tagOp(self.KEYWORD_FOR, SyntaxHighlight.keyword_color, op)
        self._emit.spaces(1)
        id1 = self._emit.openParen(OPEN_PAREN)
        self.pushMod()
        self.setMod(PrintLanguage.comma_separate)
        # Emit initializer
        initOp = bl.getInitializeOp() if hasattr(bl, 'getInitializeOp') else None
        if initOp is not None:
            id3 = self._emit.beginStatement(initOp)
            self.emitExpression(initOp)
            self._emit.endStatement(id3)
        self._emit.print(self.SEMICOLON)
        self._emit.spaces(1)
        # Emit condition
        condBlock.emit(self)
        self._emit.print(self.SEMICOLON)
        self._emit.spaces(1)
        # Emit iterator
        iterOp = bl.getIterateOp() if hasattr(bl, 'getIterateOp') else None
        if iterOp is not None:
            id4 = self._emit.beginStatement(iterOp)
            self.emitExpression(iterOp)
            self._emit.endStatement(id4)
        self.popMod()
        self._emit.closeParen(CLOSE_PAREN, id1)
        # Body
        self._emit.spaces(1)
        self._emit.print(self.OPEN_CURLY)
        indent_id = self._emit.indentlevel
        self._emit.indentlevel += self._emit.indentincrement
        self.setMod(PrintLanguage.no_branch)
        id2 = self._emit.beginBlock(bl.getBlock(1))
        bl.getBlock(1).emit(self)
        self._emit.endBlock(id2)
        self._emit.indentlevel = indent_id
        self._emit.tagLine()
        self._emit.print(self.CLOSE_CURLY)
        self.popMod()

    def emitBlockWhileDo(self, bl):
        """Emit a while loop (or for loop if iterator op exists)."""
        if hasattr(bl, 'getIterateOp') and bl.getIterateOp() is not None:
            self.emitForLoop(bl)
            return
        self.pushMod()
        self.unsetMod(PrintLanguage.no_branch | PrintLanguage.only_branch)

        self.emitAnyLabelStatement(bl)
        condBlock = bl.getBlock(0)
        op = condBlock.lastOp() if hasattr(condBlock, 'lastOp') else None

        hasOverflow = hasattr(bl, 'hasOverflowSyntax') and bl.hasOverflowSyntax()

        if hasOverflow:
            # while(true) { body; if(cond) break; }
            self._emit.tagLine()
            self._emit.tagOp(self.KEYWORD_WHILE, SyntaxHighlight.keyword_color, op)
            id1 = self._emit.openParen(OPEN_PAREN)
            self._emit.spaces(1)
            self._emit.print(self.KEYWORD_TRUE, SyntaxHighlight.const_color)
            self._emit.spaces(1)
            self._emit.closeParen(CLOSE_PAREN, id1)
            self._emit.spaces(1)
            self._emit.print(self.OPEN_CURLY)
            indent_id = self._emit.indentlevel
            self._emit.indentlevel += self._emit.indentincrement
            # Emit condition body (no branch)
            self.pushMod()
            self.setMod(PrintLanguage.no_branch)
            condBlock.emit(self)
            self.popMod()
            # Emit "if (cond) break;"
            self._emit.tagLine()
            self._emit.tagOp(self.KEYWORD_IF, SyntaxHighlight.keyword_color, op)
            self._emit.spaces(1)
            self.pushMod()
            self.setMod(PrintLanguage.only_branch)
            condBlock.emit(self)
            self.popMod()
            self._emit.spaces(1)
            from ghidra.block.block import FlowBlock
            self.emitGotoStatement(condBlock, None, FlowBlock.f_break_goto)
        else:
            # Normal: while(condition) { body }
            self.emitCommentBlockTree(condBlock)
            self._emit.tagLine()
            self._emit.tagOp(self.KEYWORD_WHILE, SyntaxHighlight.keyword_color, op)
            self._emit.spaces(1)
            id1 = self._emit.openParen(OPEN_PAREN)
            self.pushMod()
            self.setMod(PrintLanguage.comma_separate)
            condBlock.emit(self)
            self.popMod()
            self._emit.closeParen(CLOSE_PAREN, id1)
            self._emit.spaces(1)
            self._emit.print(self.OPEN_CURLY)
            indent_id = self._emit.indentlevel
            self._emit.indentlevel += self._emit.indentincrement

        self.setMod(PrintLanguage.no_branch)
        id2 = self._emit.beginBlock(bl.getBlock(1))
        bl.getBlock(1).emit(self)
        self._emit.endBlock(id2)

        self._emit.indentlevel = indent_id
        self._emit.tagLine()
        self._emit.print(self.CLOSE_CURLY)
        self.popMod()

    def emitBlockDoWhile(self, bl):
        """Emit a do-while loop."""
        self.pushMod()
        self.unsetMod(PrintLanguage.no_branch | PrintLanguage.only_branch)
        self.emitAnyLabelStatement(bl)
        self._emit.tagLine()
        self._emit.print(self.KEYWORD_DO, SyntaxHighlight.keyword_color)
        self._emit.spaces(1)
        self._emit.print(self.OPEN_CURLY)
        indent_id = self._emit.indentlevel
        self._emit.indentlevel += self._emit.indentincrement

        self.pushMod()
        self.setMod(PrintLanguage.no_branch)
        id2 = self._emit.beginBlock(bl.getBlock(0))
        bl.getBlock(0).emit(self)
        self._emit.endBlock(id2)
        self.popMod()

        self._emit.indentlevel = indent_id
        self._emit.tagLine()
        self._emit.print(self.CLOSE_CURLY)
        self._emit.spaces(1)

        op = bl.getBlock(0).lastOp() if hasattr(bl.getBlock(0), 'lastOp') else None
        self._emit.tagOp(self.KEYWORD_WHILE, SyntaxHighlight.keyword_color, op)
        self._emit.spaces(1)

        self.setMod(PrintLanguage.only_branch)
        bl.getBlock(0).emit(self)
        self._emit.print(self.SEMICOLON)
        self.popMod()

    def emitBlockInfLoop(self, bl):
        """Emit an infinite loop."""
        self.pushMod()
        self.unsetMod(PrintLanguage.no_branch | PrintLanguage.only_branch)
        self.emitAnyLabelStatement(bl)
        self._emit.tagLine()
        self._emit.print(self.KEYWORD_DO, SyntaxHighlight.keyword_color)
        self._emit.spaces(1)
        self._emit.print(self.OPEN_CURLY)
        indent_id = self._emit.indentlevel
        self._emit.indentlevel += self._emit.indentincrement

        id1 = self._emit.beginBlock(bl.getBlock(0))
        bl.getBlock(0).emit(self)
        self._emit.endBlock(id1)

        self._emit.indentlevel = indent_id
        self._emit.tagLine()
        self._emit.print(self.CLOSE_CURLY)
        self._emit.spaces(1)

        op = bl.getBlock(0).lastOp() if hasattr(bl.getBlock(0), 'lastOp') else None
        self._emit.tagOp(self.KEYWORD_WHILE, SyntaxHighlight.keyword_color, op)
        id2 = self._emit.openParen(OPEN_PAREN)
        self._emit.spaces(1)
        self._emit.print(self.KEYWORD_TRUE, SyntaxHighlight.const_color)
        self._emit.spaces(1)
        self._emit.closeParen(CLOSE_PAREN, id2)
        self._emit.print(self.SEMICOLON)
        self.popMod()

    def emitSwitchCase(self, casenum, switchbl):
        """Emit case labels for a specific case block."""
        op = None
        casebl = switchbl.getCaseBlock(casenum) if hasattr(switchbl, 'getCaseBlock') else None
        if casebl is not None and hasattr(casebl, 'firstOp'):
            op = casebl.firstOp()
        isDefault = switchbl.isDefaultCase(casenum) if hasattr(switchbl, 'isDefaultCase') else False
        if isDefault:
            val = switchbl.getLabel(casenum, 0) if hasattr(switchbl, 'getLabel') else 0
            self._emit.tagLine()
            self._emit.tagCaseLabel(self.KEYWORD_DEFAULT, SyntaxHighlight.keyword_color, op, val)
            self._emit.print(self.COLON)
        else:
            nlabels = switchbl.getNumLabels(casenum) if hasattr(switchbl, 'getNumLabels') else 1
            ct = switchbl.getSwitchType() if hasattr(switchbl, 'getSwitchType') else None
            for j in range(nlabels):
                val = switchbl.getLabel(casenum, j) if hasattr(switchbl, 'getLabel') else casenum
                self._emit.tagLine()
                self._emit.print(self.KEYWORD_CASE, SyntaxHighlight.keyword_color)
                self._emit.spaces(1)
                if ct is not None:
                    self.pushConstant(val, ct, casetoken, None, op)
                    self.recurse()
                else:
                    self._emit.print(str(val), SyntaxHighlight.const_color)
                self._emit.print(self.COLON)

    def emitBlockSwitch(self, bl):
        """Emit a switch block."""
        self.pushMod()
        self.unsetMod(PrintLanguage.no_branch | PrintLanguage.only_branch)
        self.emitAnyLabelStatement(bl)

        # Emit switch header
        self.pushMod()
        self.setMod(PrintLanguage.no_branch)
        switchBlock = bl.getSwitchBlock() if hasattr(bl, 'getSwitchBlock') else bl.getBlock(0)
        switchBlock.emit(self)
        self.popMod()
        self.emitCommentBlockTree(switchBlock)

        self._emit.tagLine()
        self.pushMod()
        self.setMod(PrintLanguage.only_branch | PrintLanguage.comma_separate)
        switchBlock.emit(self)
        self.popMod()

        self._emit.spaces(1)
        self._emit.print(self.OPEN_CURLY)
        indent_id = self._emit.indentlevel

        ncases = bl.getNumCaseBlocks() if hasattr(bl, 'getNumCaseBlocks') else bl.getSize() - 1
        for i in range(ncases):
            self.emitSwitchCase(i, bl)
            gotype = bl.getGotoType(i) if hasattr(bl, 'getGotoType') else 0
            self._emit.indentlevel = indent_id + self._emit.indentincrement
            if gotype != 0:
                self._emit.tagLine()
                casebl = bl.getCaseBlock(i) if hasattr(bl, 'getCaseBlock') else bl.getBlock(i + 1)
                self.emitGotoStatement(bl.getBlock(0), casebl, gotype)
            else:
                casebl = bl.getCaseBlock(i) if hasattr(bl, 'getCaseBlock') else bl.getBlock(i + 1)
                id2 = self._emit.beginBlock(casebl)
                casebl.emit(self)
                isExit = bl.isExit(i) if hasattr(bl, 'isExit') else False
                if isExit and i != ncases - 1:
                    self._emit.tagLine()
                    from ghidra.block.block import FlowBlock
                    self.emitGotoStatement(casebl, None, FlowBlock.f_break_goto)
                self._emit.endBlock(id2)
            self._emit.indentlevel = indent_id

        self._emit.tagLine()
        self._emit.print(self.CLOSE_CURLY)
        self.popMod()

    def _emitBlockDispatch(self, bl):
        """Dispatch block emission by type."""
        from ghidra.block.block import (
            FlowBlock, BlockBasic, BlockGraph, BlockCopy, BlockGoto,
            BlockIf, BlockWhileDo, BlockDoWhile, BlockInfLoop,
            BlockSwitch, BlockList, BlockCondition,
        )
        if isinstance(bl, BlockBasic):
            self.emitBlockBasic(bl)
        elif isinstance(bl, BlockCopy):
            self.emitBlockCopy(bl)
        elif isinstance(bl, BlockList):
            self.emitBlockLs(bl)
        elif isinstance(bl, BlockIf):
            self.emitBlockIf(bl)
        elif isinstance(bl, BlockWhileDo):
            self.emitBlockWhileDo(bl)
        elif isinstance(bl, BlockDoWhile):
            self.emitBlockDoWhile(bl)
        elif isinstance(bl, BlockInfLoop):
            self.emitBlockInfLoop(bl)
        elif isinstance(bl, BlockSwitch):
            self.emitBlockSwitch(bl)
        elif isinstance(bl, BlockCondition):
            self.emitBlockCondition(bl)
        elif isinstance(bl, BlockGoto):
            self.emitBlockGoto(bl)
        elif isinstance(bl, BlockGraph):
            self.emitBlockGraph(bl)
        else:
            # Unknown block type, try to emit as graph
            if hasattr(bl, 'getSize'):
                for i in range(bl.getSize()):
                    self._emitBlockDispatch(bl.getBlock(i))

    # ================================================================
    # Top-level document emission
    # ================================================================

    def docFunction(self, fd):
        """Emit a complete function declaration and body."""
        if self._emit is None:
            return
        try:
            # Set up comment sorter
            from ghidra.database.comment import CommentSorter
            if not hasattr(self, '_commsorter'):
                self._commsorter = CommentSorter()
            glb = self._glb
            if glb is not None and hasattr(glb, 'commentdb') and glb.commentdb is not None:
                ctype = self._instr_comment_type | self._head_comment_type
                self._commsorter.setupFunctionList(ctype, fd, glb.commentdb,
                                                    getattr(self, 'option_unplaced', False))

            id1 = self._emit.beginFunction(fd)

            # Emit header comments
            self.emitCommentFuncHeader(fd)

            self._emit.tagLine()
            self.emitFunctionDeclaration(fd)
            self._emit.tagLine()
            self._emit.print(self.OPEN_CURLY)
            self._emit.indentlevel += self._emit.indentincrement

            self.emitLocalVarDecls(fd)

            sblocks = fd.getStructure()
            if self.isSet(PrintLanguage.flat):
                self.emitBlockGraph(fd.getBasicBlocks())
            elif sblocks.getSize() == 0:
                self.emitBlockGraph(fd.getBasicBlocks())
            else:
                self.emitBlockGraph(sblocks)

            # Pop scope that was pushed in emitFunctionDeclaration
            self.popScope()

            self._emit.indentlevel -= self._emit.indentincrement
            self._emit.tagLine()
            self._emit.print(self.CLOSE_CURLY)
            self._emit.tagLine()
            self._emit.endFunction(id1)
        except Exception:
            self.clear()
            raise

    def emitCommentFuncHeader(self, fd):
        """Emit function header comments."""
        if not hasattr(self, '_commsorter'):
            return
        from ghidra.database.comment import CommentSorter
        self._commsorter.setupHeader(CommentSorter.header_basic)
        hascomment = False
        while self._commsorter.hasNext():
            comm = self._commsorter.getNext()
            if comm.isEmitted():
                continue
            if (self._head_comment_type & comm.getType()) == 0:
                continue
            self.emitLineComment(-1, comm)
            hascomment = True
        if hascomment:
            self._emit.tagLine()

    def emitCommentGroup(self, inst):
        """Emit comments associated with a statement."""
        if not hasattr(self, '_commsorter'):
            return
        self._commsorter.setupOpList(inst)
        while self._commsorter.hasNext():
            comm = self._commsorter.getNext()
            if comm.isEmitted():
                continue
            if (self._instr_comment_type & comm.getType()) == 0:
                continue
            self.emitLineComment(-1, comm)

    def emitLineComment(self, indent, comm):
        """Emit a single comment line."""
        if self._emit is None:
            return
        text = comm.getText()
        addr = comm.getAddr()
        spc = addr.getSpace() if not addr.isInvalid() else None
        off = addr.getOffset() if not addr.isInvalid() else 0
        if indent < 0:
            indent = self._line_commentindent
        self._emit.tagLine(indent)
        self._emit.tagComment(self._commentstart, SyntaxHighlight.comment_color, spc, off)
        self._emit.tagComment(text, SyntaxHighlight.comment_color, spc, off)
        if self._commentend:
            self._emit.tagComment(self._commentend, SyntaxHighlight.comment_color, spc, off)
        comm.setEmitted(True)

    def emitFunctionDeclaration(self, fd):
        """Emit a function prototype with scope and convention."""
        proto = fd.getFuncProto()
        id_ = self._emit.beginFuncProto()

        # Return type via emitPrototypeOutput
        self.emitPrototypeOutput(proto, fd)
        self._emit.spaces(1)

        # Calling convention
        if self.option_convention and hasattr(proto, 'printModelInDecl'):
            if proto.printModelInDecl():
                modelName = proto.getModelName() if hasattr(proto, 'getModelName') else ""
                if modelName:
                    hl = SyntaxHighlight.error_color if (hasattr(proto, 'isModelUnknown') and proto.isModelUnknown()) else SyntaxHighlight.keyword_color
                    self._emit.print(modelName, hl)
                    self._emit.spaces(1)

        # Function name with scope
        id1 = self._emit.openGroup()
        self._emit.tagFuncName(fd.getDisplayName(),
                               SyntaxHighlight.funcname_color, fd, None)

        # Parameters
        self._emit.spaces(PrintC.function_call.spacing, PrintC.function_call.bump)
        id2 = self._emit.openParen(OPEN_PAREN)
        self._emit.spaces(0, PrintC.function_call.bump)

        # Push scope for parameter resolution
        localScope = fd.getLocalScope() if hasattr(fd, 'getLocalScope') else None
        if localScope is not None:
            self.pushScope(localScope)
        self.emitPrototypeInputs(proto)
        self._emit.closeParen(CLOSE_PAREN, id2)
        self._emit.closeGroup(id1)

        self._emit.endFuncProto(id_)

    def emitPrototypeInputs(self, proto):
        """Emit the parameter list of a function prototype with names."""
        nparams = proto.numParams()
        if nparams == 0 and not (hasattr(proto, 'isDotdotdot') and proto.isDotdotdot()):
            self._emit.print(self.KEYWORD_VOID, SyntaxHighlight.keyword_color)
            return
        for i in range(nparams):
            if i > 0:
                self._emit.print(self.COMMA)
                self._emit.spaces(1)
            param = proto.getParam(i)
            if param.getType() is not None:
                self.pushTypeStart(param.getType(), False)
                nm = param.getName() if hasattr(param, 'getName') else f"param_{i}"
                self.pushAtom(Atom(nm, vartoken, SyntaxHighlight.param_color))
                self.pushTypeEnd(param.getType())
                self.recurse()
            else:
                nm = param.getName() if hasattr(param, 'getName') else f"param_{i}"
                self._emit.tagVariable(nm, SyntaxHighlight.param_color, None, None)
        if hasattr(proto, 'isDotdotdot') and proto.isDotdotdot():
            if nparams > 0:
                self._emit.print(self.COMMA)
                self._emit.spaces(1)
            self._emit.print(self.DOTDOTDOT, SyntaxHighlight.no_color)

    def emitLocalVarDecls(self, fd):
        """Emit local variable declarations for a function.

        Iterates over all HighVariables in the function and emits
        declarations for those that have names and are not parameters.
        """
        if self._emit is None:
            return
        notempty = False
        # Iterate over all varnodes to find named high variables
        seen_highs = set()
        vbank = fd.getVarnodeBank() if hasattr(fd, 'getVarnodeBank') else None
        if vbank is not None and hasattr(vbank, 'allVarnodes'):
            for vn in vbank.allVarnodes():
                high = vn.getHigh()
                if high is None:
                    continue
                hid = id(high)
                if hid in seen_highs:
                    continue
                seen_highs.add(hid)
                sym = high.getSymbol() if hasattr(high, 'getSymbol') else None
                if sym is None:
                    continue
                # Skip parameters (they're in the prototype)
                if hasattr(sym, 'getCategory'):
                    cat = sym.getCategory()
                    if cat == 0:  # function_parameter
                        continue
                nm = sym.getName() if hasattr(sym, 'getName') else ""
                if not nm:
                    continue
                self.emitVarDeclStatement(sym)
                notempty = True
        if notempty:
            self._emit.tagLine()

    def docSingleGlobal(self, sym):
        """Emit declaration for a single global symbol."""
        if self._emit is None:
            return
        id_ = self._emit.beginDocument()
        self.emitVarDeclStatement(sym)
        self._emit.tagLine()
        self._emit.endDocument(id_)

    def emitCommentBlockTree(self, bl):
        """Emit comments within a control-flow subtree."""
        if bl is None or not hasattr(self, '_commsorter'):
            return
        from ghidra.block.block import FlowBlock
        btype = bl.getType()
        if btype == FlowBlock.BlockType.t_copy:
            sub = bl.subBlock(0) if hasattr(bl, 'subBlock') else None
            if sub is not None:
                bl = sub
                btype = bl.getType()
        if btype == FlowBlock.BlockType.t_plain:
            return
        if btype != FlowBlock.BlockType.t_basic:
            if hasattr(bl, 'getSize'):
                for i in range(bl.getSize()):
                    sub = bl.subBlock(i) if hasattr(bl, 'subBlock') else (bl.getBlock(i) if hasattr(bl, 'getBlock') else None)
                    if sub is not None:
                        self.emitCommentBlockTree(sub)
            return
        self._commsorter.setupBlockList(bl)
        self.emitCommentGroup(None)

    def setCommentStyle(self, nm):
        """Set comment style: 'c' for /* */ or 'cplusplus' for //."""
        if nm in ("c", "/*"):
            self.setCStyleComments()
        elif nm in ("cplusplus", "//"):
            self.setCPlusPlusStyleComments()

    def setCStyleComments(self):
        self.setCommentDelimeter("/* ", " */", False)

    def setCPlusPlusStyleComments(self):
        self.setCommentDelimeter("// ", "", True)

    def initializeFromArchitecture(self):
        """Initialize architecture-specific aspects of the printer."""
        if self._castStrategy is not None and self._glb is not None:
            if hasattr(self._glb, 'types') and self._glb.types is not None:
                self._castStrategy.setTypeFactory(self._glb.types)
        if self._glb is not None and hasattr(self._glb, 'types') and self._glb.types is not None:
            tf = self._glb.types
            sizeOfLong = tf.getSizeOfLong() if hasattr(tf, 'getSizeOfLong') else 4
            sizeOfInt = tf.getSizeOfInt() if hasattr(tf, 'getSizeOfInt') else 4
            if sizeOfLong == sizeOfInt:
                self.sizeSuffix = "LL"
            else:
                self.sizeSuffix = "L"

    def adjustTypeOperators(self):
        """Set type operators for C language (vs Java)."""
        PrintC.scope.print1 = "::"
        PrintC.shift_right.print1 = ">>"

    def emitPrototypeOutput(self, proto, fd=None):
        """Emit the output data-type of a function prototype."""
        outtype = proto.getOutputType() if hasattr(proto, 'getOutputType') else None
        vn = None
        if fd is not None and outtype is not None:
            from ghidra.types.datatype import TYPE_VOID
            if outtype.getMetatype() != TYPE_VOID:
                retop = fd.getFirstReturnOp() if hasattr(fd, 'getFirstReturnOp') else None
                if retop is not None and retop.numInput() >= 2:
                    vn = retop.getIn(1)
        id_ = self._emit.beginReturnType(vn)
        if outtype is not None:
            self.pushType(outtype)
            self.recurse()
        else:
            self._emit.tagType("void", SyntaxHighlight.type_color, None)
        self._emit.endReturnType(id_)

    def docAllGlobals(self):
        """Emit all global variable declarations."""
        if self._emit is None or self._glb is None:
            return
        id_ = self._emit.beginDocument()
        symboltab = self._glb.symboltab if hasattr(self._glb, 'symboltab') else None
        if symboltab is not None:
            globalScope = symboltab.getGlobalScope() if hasattr(symboltab, 'getGlobalScope') else None
            if globalScope is not None:
                self._emitGlobalVarDeclsRecursive(globalScope)
        self._emit.tagLine()
        self._emit.endDocument(id_)

    def _emitGlobalVarDeclsRecursive(self, scope):
        """Emit variable declarations for all symbols in scope and children."""
        if scope is None:
            return
        if hasattr(scope, 'getSymbols'):
            for sym in scope.getSymbols():
                nm = sym.getName() if hasattr(sym, 'getName') else ""
                if not nm:
                    continue
                self.emitVarDeclStatement(sym)

    def docTypeDefinitions(self, typegrp=None):
        """Emit struct and enum type definitions."""
        if self._emit is None:
            return
        if typegrp is None and self._glb is not None:
            typegrp = self._glb.types
        if typegrp is None:
            return
        if hasattr(typegrp, 'dependentOrder'):
            deporder = typegrp.dependentOrder()
            for ct in deporder:
                if hasattr(ct, 'isCoreType') and ct.isCoreType():
                    continue
                self.emitTypeDefinition(ct)
        elif hasattr(typegrp, 'allTypes'):
            for ct in typegrp.allTypes():
                if hasattr(ct, 'isCoreType') and ct.isCoreType():
                    continue
                self.emitTypeDefinition(ct)

    def emitTypeDefinition(self, ct):
        """Emit a single struct or enum type definition."""
        if ct is None:
            return
        from ghidra.types.datatype import TYPE_STRUCT
        meta = ct.getMetatype()
        if meta == TYPE_STRUCT:
            self.emitStructDefinition(ct)
        elif hasattr(ct, 'isEnumType') and ct.isEnumType():
            self.emitEnumDefinition(ct)

    def emitStructDefinition(self, ct):
        """Emit a struct type definition: typedef struct { ... } Name;"""
        if ct is None or self._emit is None:
            return
        nm = ct.getName() if hasattr(ct, 'getName') else ""
        if not nm:
            return
        self._emit.tagLine()
        self._emit.print("typedef struct", SyntaxHighlight.keyword_color)
        self._emit.spaces(1)
        self._emit.print(self.OPEN_CURLY)
        self._emit.indentlevel += self._emit.indentincrement
        if hasattr(ct, 'beginField') and hasattr(ct, 'endField'):
            first = True
            for fld in ct.beginField():
                if not first:
                    self._emit.print(self.COMMA)
                self._emit.tagLine()
                self.pushTypeStart(fld.type if hasattr(fld, 'type') else None, False)
                fnm = fld.name if hasattr(fld, 'name') else "field"
                self.pushAtom(Atom(fnm, syntax, SyntaxHighlight.var_color))
                self.pushTypeEnd(fld.type if hasattr(fld, 'type') else None)
                self.recurse()
                first = False
        self._emit.indentlevel -= self._emit.indentincrement
        self._emit.tagLine()
        self._emit.print(self.CLOSE_CURLY)
        self._emit.spaces(1)
        dispnm = ct.getDisplayName() if hasattr(ct, 'getDisplayName') else nm
        self._emit.print(dispnm)
        self._emit.print(self.SEMICOLON)

    def emitBlockDispatch(self, bl) -> None:
        pass

    def emitBlockCopy(self, bl) -> None:
        if bl is not None and hasattr(bl, 'getRef'):
            ref = bl.getRef()
            if ref is not None and hasattr(ref, 'emit'):
                ref.emit(self)

    def emitBlockInfLoop(self, bl) -> None:
        if self._emit is None:
            return
        self._emit.tagLine()
        self._emit.print("while", SyntaxHighlight.keyword_color)
        self._emit.print("(true)")
        self._emit.spaces(1)
        self._emit.print("{")
        if bl is not None and hasattr(bl, 'getBlock'):
            body = bl.getBlock(0)
            if body is not None and hasattr(body, 'emit'):
                body.emit(self)
        self._emit.tagLine()
        self._emit.print("}")

    def emitBlockDoWhile(self, bl) -> None:
        if self._emit is None:
            return
        self._emit.tagLine()
        self._emit.print("do", SyntaxHighlight.keyword_color)
        self._emit.spaces(1)
        self._emit.print("{")
        if bl is not None and hasattr(bl, 'getBlock'):
            body = bl.getBlock(0)
            if body is not None and hasattr(body, 'emit'):
                body.emit(self)
        self._emit.tagLine()
        self._emit.print("}")
        self._emit.spaces(1)
        self._emit.print("while", SyntaxHighlight.keyword_color)
        self._emit.print("(...)")
        self._emit.print(";")

    def emitBlockCondition(self, bl) -> None:
        if bl is not None and hasattr(bl, 'getBlock'):
            b0 = bl.getBlock(0)
            if b0 is not None and hasattr(b0, 'emit'):
                b0.emit(self)

    def emitBlockSwitch(self, bl) -> None:
        if self._emit is None:
            return
        self._emit.tagLine()
        self._emit.print("switch", SyntaxHighlight.keyword_color)
        self._emit.print("(...)")
        self._emit.spaces(1)
        self._emit.print("{")
        self._emit.print("}")

    def emitBlockLs(self, bl) -> None:
        if bl is None:
            return
        for i in range(bl.getSize()):
            sub = bl.getBlock(i)
            if sub is not None and hasattr(sub, 'emit'):
                sub.emit(self)

    def emitBlockIf(self, bl) -> None:
        if self._emit is None:
            return
        self._emit.tagLine()
        self._emit.print("if", SyntaxHighlight.keyword_color)
        self._emit.print("(...)")
        self._emit.spaces(1)
        self._emit.print("{")
        self._emit.print("}")

    def emitBlockGoto(self, bl) -> None:
        if self._emit is None:
            return
        if bl is not None and hasattr(bl, 'getBlock'):
            body = bl.getBlock(0)
            if body is not None and hasattr(body, 'emit'):
                body.emit(self)
        if bl is not None and hasattr(bl, 'gotoPrints') and bl.gotoPrints():
            self._emit.tagLine()
            self._emit.print("goto", SyntaxHighlight.keyword_color)
            self._emit.print(";")

    def emitBlockWhileDo(self, bl) -> None:
        if self._emit is None:
            return
        self._emit.tagLine()
        self._emit.print("while", SyntaxHighlight.keyword_color)
        self._emit.print("(...)")
        self._emit.spaces(1)
        self._emit.print("{")
        self._emit.print("}")

    def opHiddenFunc(self, op) -> None:
        pass

    def getHeaderComment(self, fd) -> str:
        return ""

    def getDefaultCast(self):
        return self._castStrategy

    def adjustTypeOperators(self) -> None:
        pass

    def setMarkup(self, markup) -> None:
        self._markup = markup

    def opUnimplemented(self, op) -> None:
        self.pushOp(self.function_call, op)
        self.pushAtom(Atom("UNIMPLEMENTED", functoken, SyntaxHighlight.funcname_color, op))

    def opPieceMerge(self, op) -> None:
        self.pushOp(self.function_call, op)
        self.pushAtom(Atom("CONCAT", functoken, SyntaxHighlight.funcname_color, op))

    def opLzcount(self, op) -> None:
        self.pushOp(self.function_call, op)
        self.pushAtom(Atom("LZCOUNT", functoken, SyntaxHighlight.funcname_color, op))
        in0 = op.getIn(0)
        self.pushVn(in0, op, self._mods)

    def opPopcount(self, op) -> None:
        self.pushOp(self.function_call, op)
        self.pushAtom(Atom("POPCOUNT", functoken, SyntaxHighlight.funcname_color, op))
        in0 = op.getIn(0)
        self.pushVn(in0, op, self._mods)

    def opCpoolRef(self, op) -> None:
        self.pushOp(self.function_call, op)
        self.pushAtom(Atom("CPOOL", functoken, SyntaxHighlight.funcname_color, op))

    def opNew(self, op) -> None:
        self.pushOp(self.function_call, op)
        self.pushAtom(Atom("new", functoken, SyntaxHighlight.keyword_color, op))

    def emitTypeNameToken(self, ct, op=None) -> None:
        if self._emit is None or ct is None:
            return
        nm = ct.getDisplayName() if hasattr(ct, 'getDisplayName') else str(ct)
        self._emit.print(nm, SyntaxHighlight.type_color)

    def emitPrototypeReturnType(self, proto) -> None:
        if proto is None or self._emit is None:
            return
        outtype = proto.getOutputType() if hasattr(proto, 'getOutputType') else None
        if outtype is not None:
            self.emitTypeNameToken(outtype)
            self._emit.spaces(1)

    def emitCommentLine(self, text: str) -> None:
        if self._emit is None:
            return
        self._emit.tagLine()
        self._emit.print("// ", SyntaxHighlight.comment_color)
        self._emit.print(text, SyntaxHighlight.comment_color)

    def checkForLabelOverride(self, op) -> bool:
        return False

    def isSetToken(self) -> bool:
        return len(self._nodepend) > 0 if hasattr(self, '_nodepend') else False

    def opExtractOp(self, op) -> None:
        self.pushOp(self.function_call, op)
        self.pushAtom(Atom("EXTRACT", functoken, SyntaxHighlight.funcname_color, op))

    def emitGlobalVarDeclsAsComments(self, fd) -> None:
        pass

    def emitEnumDefinition(self, ct):
        """Emit an enum type definition: typedef enum { ... } Name;"""
        if ct is None or self._emit is None:
            return
        nm = ct.getName() if hasattr(ct, 'getName') else ""
        if not nm:
            return
        self._emit.tagLine()
        self._emit.print("typedef enum", SyntaxHighlight.keyword_color)
        self._emit.spaces(1)
        self._emit.print(self.OPEN_CURLY)
        self._emit.indentlevel += self._emit.indentincrement
        if hasattr(ct, 'beginEnum'):
            self.pushMod()
            sign = False
            if hasattr(ct, 'getMetatype'):
                from ghidra.types.datatype import TYPE_INT
                sign = (ct.getMetatype() == TYPE_INT)
            for val, name in ct.beginEnum():
                self._emit.tagLine()
                self._emit.print(name, SyntaxHighlight.const_color)
                self._emit.spaces(1)
                self._emit.print(self.EQUALSIGN, SyntaxHighlight.no_color)
                self._emit.spaces(1)
                self.push_integer(val, ct.getSize(), sign, syntax, None, None)
                self.recurse()
                self._emit.print(self.SEMICOLON)
            self.popMod()
        self._emit.indentlevel -= self._emit.indentincrement
        self._emit.tagLine()
        self._emit.print(self.CLOSE_CURLY)
        self._emit.spaces(1)
        dispnm = ct.getDisplayName() if hasattr(ct, 'getDisplayName') else nm
        self._emit.print(dispnm)
        self._emit.print(self.SEMICOLON)
