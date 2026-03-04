"""
Corresponds to: comment.hh / comment.cc

A database interface for high-level language comments.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Optional, List, Dict, Tuple

from ghidra.core.address import Address


class Comment:
    """A comment attached to a specific function and code address."""

    class CommentType(IntEnum):
        user1 = 1
        user2 = 2
        user3 = 4
        header = 8
        warning = 16
        warningheader = 32

    def __init__(self, tp: int = 0, funcaddr: Optional[Address] = None,
                 addr: Optional[Address] = None, uniq: int = 0, text: str = "") -> None:
        self.type: int = tp
        self.uniq: int = uniq
        self.funcaddr: Address = funcaddr if funcaddr is not None else Address()
        self.addr: Address = addr if addr is not None else Address()
        self.text: str = text
        self.emitted: bool = False

    def setEmitted(self, val: bool) -> None:
        self.emitted = val

    def isEmitted(self) -> bool:
        return self.emitted

    def getType(self) -> int:
        return self.type

    def getFuncAddr(self) -> Address:
        return self.funcaddr

    def getAddr(self) -> Address:
        return self.addr

    def getUniq(self) -> int:
        return self.uniq

    def getText(self) -> str:
        return self.text

    @staticmethod
    def encodeCommentType(name: str) -> int:
        _map = {"user1": 1, "user2": 2, "user3": 4, "header": 8,
                "warning": 16, "warningheader": 32}
        return _map.get(name, 0)

    @staticmethod
    def decodeCommentType(val: int) -> str:
        parts = []
        if val & 1: parts.append("user1")
        if val & 2: parts.append("user2")
        if val & 4: parts.append("user3")
        if val & 8: parts.append("header")
        if val & 16: parts.append("warning")
        if val & 32: parts.append("warningheader")
        return "|".join(parts) if parts else "none"


class CommentDatabase(ABC):
    """An interface to a container of comments."""

    @abstractmethod
    def clear(self) -> None: ...

    @abstractmethod
    def clearType(self, fad: Address, tp: int) -> None: ...

    @abstractmethod
    def addComment(self, tp: int, fad: Address, ad: Address, txt: str) -> None: ...

    @abstractmethod
    def addCommentNoDuplicate(self, tp: int, fad: Address, ad: Address, txt: str) -> bool: ...

    @abstractmethod
    def getComments(self, fad: Address) -> List[Comment]: ...


class CommentDatabaseInternal(CommentDatabase):
    """In-memory implementation of CommentDatabase."""

    def __init__(self) -> None:
        self._comments: Dict[Tuple[int, int], List[Comment]] = {}
        self._uniq_counter: int = 0

    def _key(self, fad: Address) -> Tuple[int, int]:
        spc = fad.getSpace()
        return (spc.getIndex() if spc else -1, fad.getOffset())

    def clear(self) -> None:
        self._comments.clear()
        self._uniq_counter = 0

    def clearType(self, fad: Address, tp: int) -> None:
        key = self._key(fad)
        lst = self._comments.get(key)
        if lst:
            self._comments[key] = [c for c in lst if (c.type & tp) == 0]

    def addComment(self, tp: int, fad: Address, ad: Address, txt: str) -> None:
        key = self._key(fad)
        if key not in self._comments:
            self._comments[key] = []
        self._comments[key].append(Comment(tp, fad, ad, self._uniq_counter, txt))
        self._uniq_counter += 1

    def addCommentNoDuplicate(self, tp: int, fad: Address, ad: Address, txt: str) -> bool:
        key = self._key(fad)
        lst = self._comments.get(key, [])
        for c in lst:
            if c.addr == ad and c.text == txt:
                return False
        self.addComment(tp, fad, ad, txt)
        return True

    def getComments(self, fad: Address) -> List[Comment]:
        return self._comments.get(self._key(fad), [])

    def beginComment(self, fad: Address):
        return iter(self.getComments(fad))

    def endComment(self, fad: Address):
        return None


class CommentSorter:
    """Sort comments into and within basic blocks for display.

    Corresponds to CommentSorter in comment.hh/cc.
    """

    header_basic = 0
    header_unplaced = 1

    def __init__(self) -> None:
        self._commmap: Dict[Tuple[int, int, int], Comment] = {}
        self._sorted_keys: List[Tuple[int, int, int]] = []
        self._start_idx: int = 0
        self._stop_idx: int = 0
        self._opstop_idx: int = 0
        self._displayUnplaced: bool = False

    def setupFunctionList(self, tp: int, fd, db, displayUnplaced: bool = False) -> None:
        """Collect all comments for a function and sort by block position."""
        self._commmap.clear()
        self._displayUnplaced = displayUnplaced
        if fd is None or db is None:
            self._sorted_keys = []
            return
        funcaddr = fd.getAddress() if hasattr(fd, 'getAddress') else None
        if funcaddr is None:
            self._sorted_keys = []
            return
        comments = db.getComments(funcaddr)
        pos = 0
        for comm in comments:
            if (comm.getType() & tp) == 0:
                continue
            comm.setEmitted(False)
            blockidx = -1
            order = 0
            caddr = comm.getAddr()
            # Try to find the basic block containing this address
            if hasattr(fd, 'getBasicBlocks'):
                bblocks = fd.getBasicBlocks()
                if hasattr(bblocks, 'getSize'):
                    for i in range(bblocks.getSize()):
                        bl = bblocks.getBlock(i)
                        if hasattr(bl, 'getStart') and hasattr(bl, 'getStop'):
                            start = bl.getStart()
                            stop = bl.getStop()
                            if not caddr.isInvalid() and not start.isInvalid():
                                if start <= caddr and (stop.isInvalid() or caddr <= stop):
                                    blockidx = i
                                    order = caddr.getOffset() - start.getOffset()
                                    break
            if blockidx < 0:
                # Header or unplaced
                ctype = comm.getType()
                if ctype & (Comment.CommentType.header | Comment.CommentType.warningheader):
                    blockidx = -1
                    order = CommentSorter.header_basic
                elif displayUnplaced:
                    blockidx = -1
                    order = CommentSorter.header_unplaced
                else:
                    continue
            key = (blockidx, order, pos)
            self._commmap[key] = comm
            pos += 1
        self._sorted_keys = sorted(self._commmap.keys())
        self._start_idx = 0
        self._stop_idx = len(self._sorted_keys)
        self._opstop_idx = len(self._sorted_keys)

    def setupBlockList(self, bl) -> None:
        """Prepare to walk comments from a single basic block."""
        if bl is None:
            self._start_idx = self._stop_idx = self._opstop_idx = 0
            return
        blockidx = bl.getIndex() if hasattr(bl, 'getIndex') else -1
        # Find range in sorted keys for this block
        self._start_idx = 0
        self._stop_idx = 0
        for i, k in enumerate(self._sorted_keys):
            if k[0] == blockidx:
                if self._start_idx == self._stop_idx:
                    self._start_idx = i
                self._stop_idx = i + 1
        self._opstop_idx = self._stop_idx

    def setupOpList(self, op) -> None:
        """Establish a p-code landmark within the current set of comments."""
        if op is None:
            self._opstop_idx = self._stop_idx
            return
        # Find comments up to this op's address
        opaddr = op.getAddr() if hasattr(op, 'getAddr') else None
        if opaddr is None:
            self._opstop_idx = self._stop_idx
            return
        self._opstop_idx = self._start_idx
        for i in range(self._start_idx, self._stop_idx):
            k = self._sorted_keys[i]
            comm = self._commmap[k]
            if comm.getAddr() <= opaddr:
                self._opstop_idx = i + 1
            else:
                break

    def setupHeader(self, headerType: int) -> None:
        """Prepare to walk comments in the header."""
        self._start_idx = 0
        self._stop_idx = 0
        for i, k in enumerate(self._sorted_keys):
            if k[0] == -1 and k[1] == headerType:
                if self._start_idx == self._stop_idx:
                    self._start_idx = i
                self._stop_idx = i + 1
        self._opstop_idx = self._stop_idx

    def hasNext(self) -> bool:
        return self._start_idx < self._opstop_idx

    def getNext(self) -> Comment:
        k = self._sorted_keys[self._start_idx]
        self._start_idx += 1
        return self._commmap[k]
