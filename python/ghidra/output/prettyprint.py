"""
Corresponds to: prettyprint.hh / prettyprint.cc

Routines for emitting high-level (C) language syntax in a well formatted way.
Core classes: Emit, EmitMarkup, EmitPrettyPrint.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List
import io

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.block.block import FlowBlock
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.database.database import Symbol
    from ghidra.types.datatype import Datatype


class SyntaxHighlight(IntEnum):
    """Possible types of syntax highlighting."""
    keyword_color = 0
    comment_color = 1
    type_color = 2
    funcname_color = 3
    var_color = 4
    const_color = 5
    param_color = 6
    global_color = 7
    no_color = 8
    error_color = 9
    special_color = 10


class Emit(ABC):
    """Interface for emitting the Decompiler's formal output: source code.

    Implements markup and pretty printing.
    """

    def __init__(self) -> None:
        self.indentlevel: int = 0
        self.parenlevel: int = 0
        self.indentincrement: int = 2

    def resetDefaults(self) -> None:
        self.indentincrement = 2

    def getIndentIncrement(self) -> int:
        return self.indentincrement

    def setIndentIncrement(self, val: int) -> None:
        self.indentincrement = val

    # --- Document structure ---

    @abstractmethod
    def beginDocument(self) -> int: ...

    @abstractmethod
    def endDocument(self, id_: int) -> None: ...

    @abstractmethod
    def beginFunction(self, fd) -> int: ...

    @abstractmethod
    def endFunction(self, id_: int) -> None: ...

    @abstractmethod
    def beginBlock(self, bl) -> int: ...

    @abstractmethod
    def endBlock(self, id_: int) -> None: ...

    @abstractmethod
    def beginReturnType(self, vn) -> int: ...

    @abstractmethod
    def endReturnType(self, id_: int) -> None: ...

    @abstractmethod
    def beginVarDecl(self, sym) -> int: ...

    @abstractmethod
    def endVarDecl(self, id_: int) -> None: ...

    @abstractmethod
    def beginStatement(self, op) -> int: ...

    @abstractmethod
    def endStatement(self, id_: int) -> None: ...

    @abstractmethod
    def beginFuncProto(self) -> int: ...

    @abstractmethod
    def endFuncProto(self, id_: int) -> None: ...

    # --- Grouping ---

    @abstractmethod
    def openParen(self, paren: str, id_: int = 0) -> int: ...

    @abstractmethod
    def closeParen(self, paren: str, id_: int = 0) -> None: ...

    @abstractmethod
    def openGroup(self) -> int: ...

    @abstractmethod
    def closeGroup(self, id_: int) -> None: ...

    # --- Token emission ---

    @abstractmethod
    def tagVariable(self, name: str, hl: SyntaxHighlight, vn, op) -> None: ...

    @abstractmethod
    def tagOp(self, name: str, hl: SyntaxHighlight, op) -> None: ...

    @abstractmethod
    def tagFuncName(self, name: str, hl: SyntaxHighlight, fd, op) -> None: ...

    @abstractmethod
    def tagType(self, name: str, hl: SyntaxHighlight, ct) -> None: ...

    @abstractmethod
    def tagField(self, name: str, hl: SyntaxHighlight, ct, off: int, op) -> None: ...

    @abstractmethod
    def tagComment(self, name: str, hl: SyntaxHighlight, spc, off: int) -> None: ...

    @abstractmethod
    def tagLabel(self, name: str, hl: SyntaxHighlight, spc, off: int) -> None: ...

    @abstractmethod
    def tagCaseLabel(self, name: str, hl: SyntaxHighlight, op, value: int) -> None: ...

    @abstractmethod
    def print(self, data: str, hl: SyntaxHighlight = SyntaxHighlight.no_color) -> None: ...

    @abstractmethod
    def spaces(self, num: int, bump: int = 0) -> int: ...

    @abstractmethod
    def tagLine(self, indent: int = -1) -> int: ...

    # --- Indent / Comment / Brace helpers ---

    def startIndent(self) -> int:
        self.indentlevel += self.indentincrement
        return 0

    def stopIndent(self, id_: int) -> None:
        self.indentlevel -= self.indentincrement

    def startComment(self) -> int:
        return 0

    def stopComment(self, id_: int) -> None:
        pass

    def flush(self) -> None:
        pass

    def clear(self) -> None:
        self.parenlevel = 0
        self.indentlevel = 0

    def setMaxLineSize(self, mls: int) -> None:
        pass

    def getMaxLineSize(self) -> int:
        return -1

    def setCommentFill(self, fill: str) -> None:
        pass

    def openBraceIndent(self, brace: str, style: int = 0) -> int:
        """Emit an opening brace and add an indent level."""
        if style == 0:  # same_line
            self.spaces(1)
            self.print(brace)
        elif style == 1:  # next_line
            self.tagLine()
            self.print(brace)
        else:  # skip_line
            self.tagLine()
            self.tagLine()
            self.print(brace)
        return self.startIndent()

    def openBrace(self, brace: str, style: int = 0) -> None:
        """Emit an opening brace without changing indent."""
        if style == 0:
            self.spaces(1)
            self.print(brace)
        else:
            self.tagLine()
            self.print(brace)

    def closeBraceIndent(self, brace: str, id_: int) -> None:
        """Emit a closing brace and remove an indent level."""
        self.stopIndent(id_)
        self.tagLine()
        self.print(brace)

    # Brace style constants
    same_line = 0
    next_line = 1
    skip_line = 2


class EmitMarkup(Emit):
    """A simple markup emitter that writes to a stream without pretty printing."""

    def __init__(self, stream: Optional[io.StringIO] = None) -> None:
        super().__init__()
        self._stream: io.StringIO = stream if stream is not None else io.StringIO()
        self._id_counter: int = 0

    def _nextId(self) -> int:
        self._id_counter += 1
        return self._id_counter

    def getOutput(self) -> str:
        return self._stream.getvalue()

    def beginDocument(self) -> int:
        return self._nextId()

    def endDocument(self, id_) -> None:
        pass

    def beginFunction(self, fd) -> int:
        return self._nextId()

    def endFunction(self, id_) -> None:
        self._stream.write("\n")

    def beginBlock(self, bl) -> int:
        return self._nextId()

    def endBlock(self, id_) -> None:
        pass

    def beginReturnType(self, vn) -> int:
        return self._nextId()

    def endReturnType(self, id_) -> None:
        pass

    def beginVarDecl(self, sym) -> int:
        return self._nextId()

    def endVarDecl(self, id_) -> None:
        pass

    def beginStatement(self, op) -> int:
        return self._nextId()

    def endStatement(self, id_) -> None:
        self._stream.write("\n")

    def beginFuncProto(self) -> int:
        return self._nextId()

    def endFuncProto(self, id_) -> None:
        pass

    def openParen(self, paren="(", id_=0) -> int:
        self._stream.write(paren)
        self.parenlevel += 1
        return self._nextId()

    def closeParen(self, paren=")", id_=0) -> None:
        self._stream.write(paren)
        self.parenlevel -= 1

    def openGroup(self) -> int:
        return self._nextId()

    def closeGroup(self, id_) -> None:
        pass

    def tagVariable(self, name, hl, vn, op) -> None:
        self._stream.write(name)

    def tagOp(self, name, hl, op) -> None:
        self._stream.write(name)

    def tagFuncName(self, name, hl, fd, op) -> None:
        self._stream.write(name)

    def tagType(self, name, hl, ct) -> None:
        self._stream.write(name)

    def tagField(self, name, hl, ct, off, op) -> None:
        self._stream.write(name)

    def tagComment(self, name, hl, spc, off) -> None:
        self._stream.write(name)

    def tagLabel(self, name, hl, spc, off) -> None:
        self._stream.write(name)

    def tagCaseLabel(self, name, hl, op, value) -> None:
        self._stream.write(name)

    def print(self, data, hl=SyntaxHighlight.no_color) -> None:
        self._stream.write(data)

    def spaces(self, num, bump=0) -> int:
        self._stream.write(" " * num)
        return num

    def tagLine(self, indent=-1) -> int:
        self._stream.write("\n")
        if indent >= 0:
            self._stream.write(" " * indent)
        else:
            self._stream.write(" " * self.indentlevel)
        return self.indentlevel

    def emitsMarkup(self) -> bool:
        return False


class EmitPrettyPrint(Emit):
    """A pretty printer based on the Oppen algorithm.

    Buffers tokens and inserts line breaks to enforce a maximum line size
    while minimizing breaks in important groups. Wraps a low-level emitter
    (EmitMarkup or EmitNoMarkup) for final output.

    Corresponds to: EmitPrettyPrint in prettyprint.hh/cc
    """

    # Internal token types for the buffer
    TOK_STRING = 0    # Actual content
    TOK_BREAK = 1     # Potential line break (whitespace)
    TOK_BEGIN = 2     # Begin a group
    TOK_END = 3       # End a group
    TOK_LINE = 4      # Forced line break
    TOK_INDENT = 5    # Start indent
    TOK_UNINDENT = 6  # Stop indent

    _INFINITY = 999999

    def __init__(self, lowlevel: Optional[Emit] = None) -> None:
        super().__init__()
        if lowlevel is None:
            lowlevel = EmitMarkup()
        self._low: Emit = lowlevel
        self._maxlinesize: int = 100
        self._spaceremain: int = self._maxlinesize
        self._needbreak: bool = False
        self._commentmode: bool = False
        self._commentfill: str = ""
        # Token buffer: list of (type, data_dict)
        self._tokbuf: list = []
        self._scanstack: list = []  # indices of open groups/breaks
        self._leftotal: int = 0
        self._rightotal: int = 0
        self._id_counter: int = 0

    def _nextId(self) -> int:
        self._id_counter += 1
        return self._id_counter

    def _emitToken(self, tok: dict) -> None:
        """Process and emit a single buffered token."""
        tt = tok['type']
        if tt == self.TOK_STRING:
            self._printString(tok.get('data', ''), tok.get('hl', SyntaxHighlight.no_color),
                              tok.get('tag', 'print'), tok)
            self._spaceremain -= tok.get('size', 0)
        elif tt == self.TOK_BREAK:
            num = tok.get('num', 1)
            bump = tok.get('bump', 0)
            if tok.get('totalsize', 0) > self._spaceremain:
                # Break here
                self._spaceremain = tok.get('indent', self.indentlevel) - bump
                self._low.tagLine()
            else:
                self._low.spaces(num)
                self._spaceremain -= num
        elif tt == self.TOK_LINE:
            indent = tok.get('indent_override', -1)
            if indent >= 0:
                self._low.tagLine(indent)
                self._spaceremain = self._maxlinesize - indent
            else:
                self._low.tagLine()
                self._spaceremain = self._maxlinesize - self.indentlevel
        elif tt == self.TOK_BEGIN:
            pass
        elif tt == self.TOK_END:
            pass
        elif tt == self.TOK_INDENT:
            self.indentlevel += self.indentincrement
        elif tt == self.TOK_UNINDENT:
            self.indentlevel -= self.indentincrement

    def _printString(self, data: str, hl: int, tag: str, tok: dict) -> None:
        """Emit a string token to the low-level emitter."""
        if tag == 'variable':
            self._low.tagVariable(data, hl, tok.get('vn'), tok.get('op'))
        elif tag == 'op':
            self._low.tagOp(data, hl, tok.get('op'))
        elif tag == 'funcname':
            self._low.tagFuncName(data, hl, tok.get('fd'), tok.get('op'))
        elif tag == 'type':
            self._low.tagType(data, hl, tok.get('ct'))
        elif tag == 'field':
            self._low.tagField(data, hl, tok.get('ct'), tok.get('off', 0), tok.get('op'))
        elif tag == 'comment':
            self._low.tagComment(data, hl, tok.get('spc'), tok.get('off', 0))
        elif tag == 'label':
            self._low.tagLabel(data, hl, tok.get('spc'), tok.get('off', 0))
        elif tag == 'caselabel':
            self._low.tagCaseLabel(data, hl, tok.get('op'), tok.get('value', 0))
        elif tag == 'openparen':
            self._low.openParen(data, tok.get('id', 0))
        elif tag == 'closeparen':
            self._low.closeParen(data, tok.get('id', 0))
        else:
            self._low.print(data, hl)

    def _flush_buffer(self) -> None:
        """Flush all buffered tokens."""
        for tok in self._tokbuf:
            self._emitToken(tok)
        self._tokbuf.clear()
        self._scanstack.clear()

    # ================================================================
    # Emit interface implementation — for now, pass-through with line tracking
    # A simplified pretty printer that tracks line width and breaks when needed.
    # ================================================================

    def beginDocument(self) -> int:
        return self._low.beginDocument()

    def endDocument(self, id_) -> None:
        self._low.endDocument(id_)

    def beginFunction(self, fd) -> int:
        return self._low.beginFunction(fd)

    def endFunction(self, id_) -> None:
        self._low.endFunction(id_)

    def beginBlock(self, bl) -> int:
        return self._low.beginBlock(bl)

    def endBlock(self, id_) -> None:
        self._low.endBlock(id_)

    def beginReturnType(self, vn) -> int:
        return self._low.beginReturnType(vn)

    def endReturnType(self, id_) -> None:
        self._low.endReturnType(id_)

    def beginVarDecl(self, sym) -> int:
        return self._low.beginVarDecl(sym)

    def endVarDecl(self, id_) -> None:
        self._low.endVarDecl(id_)

    def beginStatement(self, op) -> int:
        return self._low.beginStatement(op)

    def endStatement(self, id_) -> None:
        self._low.endStatement(id_)

    def beginFuncProto(self) -> int:
        return self._low.beginFuncProto()

    def endFuncProto(self, id_) -> None:
        self._low.endFuncProto(id_)

    def tagVariable(self, name, hl, vn, op) -> None:
        self._low.tagVariable(name, hl, vn, op)
        self._spaceremain -= len(name)

    def tagOp(self, name, hl, op) -> None:
        self._low.tagOp(name, hl, op)
        self._spaceremain -= len(name)

    def tagFuncName(self, name, hl, fd, op) -> None:
        self._low.tagFuncName(name, hl, fd, op)
        self._spaceremain -= len(name)

    def tagType(self, name, hl, ct) -> None:
        self._low.tagType(name, hl, ct)
        self._spaceremain -= len(name)

    def tagField(self, name, hl, ct, off, op) -> None:
        self._low.tagField(name, hl, ct, off, op)
        self._spaceremain -= len(name)

    def tagComment(self, name, hl, spc, off) -> None:
        self._low.tagComment(name, hl, spc, off)

    def tagLabel(self, name, hl, spc, off) -> None:
        self._low.tagLabel(name, hl, spc, off)

    def tagCaseLabel(self, name, hl, op, value) -> None:
        self._low.tagCaseLabel(name, hl, op, value)

    def print(self, data, hl=SyntaxHighlight.no_color) -> None:
        self._low.print(data, hl)
        self._spaceremain -= len(data)

    def openParen(self, paren="(", id_=0) -> int:
        r = self._low.openParen(paren, id_)
        self.parenlevel += 1
        self._spaceremain -= len(paren)
        return r

    def closeParen(self, paren=")", id_=0) -> None:
        self._low.closeParen(paren, id_)
        self.parenlevel -= 1
        self._spaceremain -= len(paren)

    def openGroup(self) -> int:
        return self._low.openGroup()

    def closeGroup(self, id_) -> None:
        self._low.closeGroup(id_)

    def spaces(self, num, bump=0) -> int:
        if self._spaceremain < num and num > 0:
            # Force a line break
            self._low.tagLine()
            self._spaceremain = self._maxlinesize - self.indentlevel - bump
            return 0
        self._low.spaces(num, bump)
        self._spaceremain -= num
        return num

    def tagLine(self, indent=-1) -> int:
        self._low.tagLine(indent)
        if indent >= 0:
            self._spaceremain = self._maxlinesize - indent
        else:
            self._spaceremain = self._maxlinesize - self.indentlevel
        return self.indentlevel

    def clear(self) -> None:
        super().clear()
        self._low.clear()
        self._spaceremain = self._maxlinesize
        self._tokbuf.clear()
        self._scanstack.clear()

    def flush(self) -> None:
        self._flush_buffer()
        self._low.flush()

    def setMaxLineSize(self, val: int) -> None:
        self._maxlinesize = val
        self._spaceremain = val

    def getMaxLineSize(self) -> int:
        return self._maxlinesize

    def setCommentFill(self, fill: str) -> None:
        self._commentfill = fill

    def emitsMarkup(self) -> bool:
        return self._low.emitsMarkup() if hasattr(self._low, 'emitsMarkup') else False

    def resetDefaults(self) -> None:
        super().resetDefaults()
        self.setMaxLineSize(100)

    def getOutput(self) -> str:
        """Get the accumulated output (delegates to low-level emitter)."""
        if hasattr(self._low, 'getOutput'):
            return self._low.getOutput()
        return ""
