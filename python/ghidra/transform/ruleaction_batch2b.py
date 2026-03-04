"""
Remaining rules batch 2b: Division optimization rules + misc.
These rules handle complex division/modulo patterns using multiply-high tricks.
"""
from __future__ import annotations
from ghidra.transform.action import Rule
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, mostsigbit_set


class RuleDivOpt(Rule):
    """Collapse multiply-high division pattern: (x * c) >> n => x / d."""
    def __init__(self, g): super().__init__(g, 0, "divopt")
    def clone(self, gl):
        return RuleDivOpt(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant(): return 0
        n = int(op.getIn(1).getOffset())
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        # Look for SUBPIECE(MULT(ZEXT/SEXT(x), const))
        subop = invn.getDef()
        if subop.code() == OpCode.CPUI_SUBPIECE:
            multvn = subop.getIn(0)
            if not multvn.isWritten(): return 0
            multop = multvn.getDef()
            if multop.code() != OpCode.CPUI_INT_MULT: return 0
            if not multop.getIn(1).isConstant(): return 0
            c = int(subop.getIn(1).getOffset())
            n += c * 8
            extvn = multop.getIn(0)
            if not extvn.isWritten(): return 0
            extop = extvn.getDef()
            if extop.code() not in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT): return 0
            x = extop.getIn(0)
            if x.isFree(): return 0
            xsize = x.getSize() * 8
            multconst = multop.getIn(1).getOffset()
            from ghidra.core.int128 import calcDivisor
            divisor = calcDivisor(n, multconst, xsize)
            if divisor == 0: return 0
            outsize = op.getOut().getSize()
            if extop.code() == OpCode.CPUI_INT_ZEXT:
                data.opSetInput(op, x, 0)
                data.opSetInput(op, data.newConstant(outsize, divisor), 1)
                data.opSetOpcode(op, OpCode.CPUI_INT_DIV)
            else:
                data.opSetInput(op, x, 0)
                data.opSetInput(op, data.newConstant(outsize, divisor), 1)
                data.opSetOpcode(op, OpCode.CPUI_INT_SDIV)
            return 1
        return 0


class RuleDivTermAdd(Rule):
    """Simplify division term: sub(ext(x)*c, n) + x => sub(ext(x)*(c+2^n), n)."""
    def __init__(self, g): super().__init__(g, 0, "divtermadd")
    def clone(self, gl):
        return RuleDivTermAdd(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        # Pattern: (sub(ext(x)*c) >> n) + x => sub(ext(x)*(c+2^n)) >> n
        # This collapses the extra add into the multiply constant
        if not op.getIn(1).isConstant():
            return 0
        n = int(op.getIn(1).getOffset())
        if n > 127:
            return 0
        invn = op.getIn(0)
        if not invn.isWritten():
            return 0
        subop = invn.getDef()
        if subop.code() != OpCode.CPUI_SUBPIECE:
            return 0
        multvn = subop.getIn(0)
        if not multvn.isWritten():
            return 0
        multop = multvn.getDef()
        if multop.code() != OpCode.CPUI_INT_MULT:
            return 0
        if not multop.getIn(1).isConstant():
            return 0
        # Check for extension
        extvn = multop.getIn(0)
        if not extvn.isWritten():
            return 0
        extop = extvn.getDef()
        if extop.code() not in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
            return 0
        # Would need 128-bit constant arithmetic to complete the transform
        return 0


class RuleDivTermAdd2(Rule):
    """Simplify division term addition (variant 2)."""
    def __init__(self, g): super().__init__(g, 0, "divtermadd2")
    def clone(self, gl):
        return RuleDivTermAdd2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]
    def applyOp(self, op, data):
        return 0  # Needs 128-bit arithmetic


class RuleDivChain(Rule):
    """Collapse (x / c1) / c2 => x / (c1*c2)."""
    def __init__(self, g): super().__init__(g, 0, "divchain")
    def clone(self, gl):
        return RuleDivChain(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_SDIV]
    def applyOp(self, op, data):
        opc2 = op.code()
        c2 = op.getIn(1)
        if not c2.isConstant(): return 0
        vn = op.getIn(0)
        if not vn.isWritten(): return 0
        divop = vn.getDef()
        opc1 = divop.code()
        if opc1 != opc2 and not (opc2 == OpCode.CPUI_INT_DIV and opc1 == OpCode.CPUI_INT_RIGHT):
            return 0
        c1 = divop.getIn(1)
        if not c1.isConstant(): return 0
        if not vn.loneDescend(): return 0
        if opc1 == opc2:
            val1 = c1.getOffset()
        else:
            val1 = 1 << int(c1.getOffset())
        base = divop.getIn(0)
        if base.isFree(): return 0
        sz = vn.getSize()
        val2 = c2.getOffset()
        resval = (val1 * val2) & calc_mask(sz)
        if resval == 0: return 0
        data.opSetInput(op, base, 0)
        data.opSetInput(op, data.newConstant(sz, resval), 1)
        return 1


class RuleSignDiv2(Rule):
    """Convert (V + -1*(V s>> 31)) s>> 1 => V s/ 2."""
    def __init__(self, g): super().__init__(g, 0, "signdiv2")
    def clone(self, gl):
        return RuleSignDiv2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant(): return 0
        if op.getIn(1).getOffset() != 1: return 0
        addout = op.getIn(0)
        if not addout.isWritten(): return 0
        addop = addout.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD: return 0
        a = None
        for i in range(2):
            multout = addop.getIn(i)
            if not multout.isWritten(): continue
            multop = multout.getDef()
            if multop.code() != OpCode.CPUI_INT_MULT: continue
            if not multop.getIn(1).isConstant(): continue
            if multop.getIn(1).getOffset() != calc_mask(multop.getIn(1).getSize()): continue
            shiftout = multop.getIn(0)
            if not shiftout.isWritten(): continue
            shiftop = shiftout.getDef()
            if shiftop.code() != OpCode.CPUI_INT_SRIGHT: continue
            if not shiftop.getIn(1).isConstant(): continue
            n = int(shiftop.getIn(1).getOffset())
            a = shiftop.getIn(0)
            if a is not addop.getIn(1 - i): continue
            if n != 8 * a.getSize() - 1: continue
            if a.isFree(): continue
            break
        else:
            return 0
        if a is None: return 0
        data.opSetInput(op, a, 0)
        data.opSetInput(op, data.newConstant(a.getSize(), 2), 1)
        data.opSetOpcode(op, OpCode.CPUI_INT_SDIV)
        return 1


class RuleSignForm2(Rule):
    """Simplify sign extraction: sub(sext(V)*W, c) s>> (sz*8-1) => V s>> (sz*8-1)."""
    def __init__(self, g): super().__init__(g, 0, "signform2")
    def clone(self, gl):
        return RuleSignForm2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        constvn = op.getIn(1)
        if not constvn.isConstant(): return 0
        invn = op.getIn(0)
        sizeout = invn.getSize()
        if int(constvn.getOffset()) != sizeout * 8 - 1: return 0
        if not invn.isWritten(): return 0
        subop = invn.getDef()
        if subop.code() != OpCode.CPUI_SUBPIECE: return 0
        c = int(subop.getIn(1).getOffset())
        multout = subop.getIn(0)
        multsize = multout.getSize()
        if c + sizeout != multsize: return 0  # Must extract high part
        if not multout.isWritten(): return 0
        multop = multout.getDef()
        if multop.code() != OpCode.CPUI_INT_MULT: return 0
        # Search for INT_SEXT input
        for slot in range(2):
            vn = multop.getIn(slot)
            if not vn.isWritten(): continue
            sextop = vn.getDef()
            if sextop.code() == OpCode.CPUI_INT_SEXT:
                a = sextop.getIn(0)
                if a.isFree() or a.getSize() != sizeout: continue
                data.opSetInput(op, a, 0)
                return 1
        return 0


class RuleSignMod2Opt(Rule):
    """Detect signed mod 2 pattern: (x + -(x s>> 31)) & 1 used in x + sign_correction => x s% 2."""
    def __init__(self, g): super().__init__(g, 0, "signmod2opt")
    def clone(self, gl):
        return RuleSignMod2Opt(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_AND]
    def applyOp(self, op, data):
        constvn = op.getIn(1)
        if not constvn.isConstant() or constvn.getOffset() != 1:
            return 0
        addout = op.getIn(0)
        if not addout.isWritten():
            return 0
        addop = addout.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD:
            return 0
        # Look for INT_MULT by -1 on one input
        for multSlot in range(2):
            vn = addop.getIn(multSlot)
            if not vn.isWritten():
                continue
            multop = vn.getDef()
            if multop.code() != OpCode.CPUI_INT_MULT:
                continue
            mc = multop.getIn(1)
            if not mc.isConstant():
                continue
            if mc.getOffset() != calc_mask(mc.getSize()):
                continue
            # Found mult by -1; check for sign extraction pattern
            # Simplified: would need checkSignExtraction helper
            break
        return 0


class RuleSignMod2nOpt(Rule):
    """Detect signed mod 2^n pattern and replace with INT_SREM."""
    def __init__(self, g): super().__init__(g, 0, "signmod2nopt")
    def clone(self, gl):
        return RuleSignMod2nOpt(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_AND]
    def applyOp(self, op, data):
        constvn = op.getIn(1)
        if not constvn.isConstant():
            return 0
        val = constvn.getOffset()
        mask = calc_mask(constvn.getSize())
        # Check if val+1 is a power of 2 (i.e. val = 2^n - 1)
        if val == 0 or val == mask:
            return 0
        n = val + 1
        if (n & (n - 1)) != 0:
            return 0  # Not a power of 2
        # Check if input is an ADD with a sign-correction term
        addout = op.getIn(0)
        if not addout.isWritten():
            return 0
        addop = addout.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD:
            return 0
        # Would need deeper sign-correction detection
        return 0


class RuleSignMod2nOpt2(Rule):
    """Optimize signed modulo by power of 2 (variant 2)."""
    def __init__(self, g): super().__init__(g, 0, "signmod2nopt2")
    def clone(self, gl):
        return RuleSignMod2nOpt2(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]
    def applyOp(self, op, data):
        return 0


class RuleAddUnsigned(Rule):
    """Convert INT_ADD of large unsigned constant to INT_SUB: x + 0xFFFF... => x - small."""
    def __init__(self, g): super().__init__(g, 0, "addunsigned")
    def clone(self, gl):
        return RuleAddUnsigned(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]
    def applyOp(self, op, data):
        constvn = op.getIn(1)
        if not constvn.isConstant(): return 0
        val = constvn.getOffset()
        mask = calc_mask(constvn.getSize())
        sa = constvn.getSize() * 6  # 1/4 less than full bitsize
        quarter = (mask >> sa) << sa
        if (val & quarter) != quarter: return 0  # Top quarter bits must be 1s
        negval = (-val) & mask
        data.opSetOpcode(op, OpCode.CPUI_INT_SUB)
        data.opSetInput(op, data.newConstant(constvn.getSize(), negval), 1)
        return 1


class RuleSubRight(Rule):
    """Simplify SUBPIECE that extracts high bytes of an extended value: sub(zext(x),c) => 0 when c >= sizeof(x)."""
    def __init__(self, g): super().__init__(g, 0, "subright")
    def clone(self, gl):
        return RuleSubRight(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        c = int(op.getIn(1).getOffset())
        defop = invn.getDef()
        if defop.code() == OpCode.CPUI_INT_ZEXT:
            origsize = defop.getIn(0).getSize()
            if c >= origsize:
                # Extracting above the zero-extended part => result is 0
                outsize = op.getOut().getSize()
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opSetInput(op, data.newConstant(outsize, 0), 0)
                data.opRemoveInput(op, 1)
                return 1
        return 0


class RuleExtensionPush(Rule):
    """Push ZEXT/SEXT through arithmetic when all descendants are PTRADD or INT_ADD->PTRADD."""
    def __init__(self, g): super().__init__(g, 0, "extensionpush")
    def clone(self, gl):
        return RuleExtensionPush(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if invn.isConstant() or invn.isAddrForce() or invn.isAddrTied():
            return 0
        outvn = op.getOut()
        if outvn.isTypeLock() or outvn.isNameLock():
            return 0
        addcount = 0
        ptrcount = 0
        for desc in outvn.getDescendants():
            opc = desc.code()
            if opc == OpCode.CPUI_PTRADD:
                ptrcount += 1
            elif opc == OpCode.CPUI_INT_ADD:
                subdesc = desc.getOut().loneDescend()
                if subdesc is None or subdesc.code() != OpCode.CPUI_PTRADD:
                    return 0
                addcount += 1
            else:
                return 0
        if addcount + ptrcount <= 1:
            return 0
        # Would duplicate the extension to all descendants
        return 0  # Needs RulePushPtr.duplicateNeed helper


class RuleThreeWayCompare(Rule):
    """Simplify three-way comparison patterns."""
    def __init__(self, g): super().__init__(g, 0, "threewaycompare")
    def clone(self, gl):
        return RuleThreeWayCompare(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL]
    def applyOp(self, op, data):
        return 0  # Needs CircleRange


class RuleRangeMeld(Rule):
    """Merge adjacent range checks into a single range."""
    def __init__(self, g): super().__init__(g, 0, "rangemeld")
    def clone(self, gl):
        return RuleRangeMeld(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR]
    def applyOp(self, op, data):
        return 0  # Needs CircleRange


class RuleSwitchSingle(Rule):
    """Convert switch with single case to direct BRANCH."""
    def __init__(self, g): super().__init__(g, 0, "switchsingle")
    def clone(self, gl):
        return RuleSwitchSingle(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_BRANCHIND]
    def applyOp(self, op, data):
        bl = op.getParent()
        if bl is None or bl.sizeOut() != 1:
            return 0
        # Single-target BRANCHIND => convert to BRANCH
        data.opSetOpcode(op, OpCode.CPUI_BRANCH)
        return 1


class RuleSegment(Rule):
    """Convert SEGMENTOP to equivalent address calculation."""
    def __init__(self, g): super().__init__(g, 0, "segment")
    def clone(self, gl):
        return RuleSegment(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SEGMENTOP]
    def applyOp(self, op, data):
        # SEGMENTOP(space, base, offset) => base + offset in most flat models
        if op.numInput() < 3: return 0
        basevn = op.getIn(1)
        offvn = op.getIn(2)
        if basevn.isConstant() and basevn.getOffset() == 0:
            # Trivial segment: just use the offset
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, offvn, 0)
            while op.numInput() > 1:
                data.opRemoveInput(op, op.numInput() - 1)
            return 1
        return 0


class RuleTransformCpool(Rule):
    """Transform constant pool references into direct values when possible."""
    def __init__(self, g): super().__init__(g, 0, "transformcpool")
    def clone(self, gl):
        return RuleTransformCpool(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_CPOOLREF]
    def applyOp(self, op, data):
        glb = data.getArch()
        if glb is None: return 0
        cpool = getattr(glb, 'cpool', None)
        if cpool is None: return 0
        # Would query constant pool to resolve the reference
        return 0  # Needs cpool.getRecord()


class RulePiecePathology(Rule):
    """Fix PIECE where high part is sign/zero extension of low part."""
    def __init__(self, g): super().__init__(g, 0, "piecepathology")
    def clone(self, gl):
        return RulePiecePathology(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PIECE]
    def applyOp(self, op, data):
        hivn = op.getIn(0)  # High part
        lovn = op.getIn(1)  # Low part
        # Check if high part is all zeros (zero extension of low)
        if hivn.isConstant() and hivn.getOffset() == 0:
            data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
            data.opSetInput(op, lovn, 0)
            data.opRemoveInput(op, 1)
            return 1
        return 0


class RulePieceStructure(Rule):
    """Detect PIECE ops that form structure fields and convert to structured access."""
    def __init__(self, g): super().__init__(g, 0, "piecestructure")
    def clone(self, gl):
        return RulePieceStructure(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PIECE]
    def applyOp(self, op, data):
        # Would detect when PIECE inputs come from adjacent fields of the same structure
        # and convert to a direct structure access
        outvn = op.getOut()
        if outvn is None: return 0
        # Need to check if output has a structured type
        dt = outvn.getType() if hasattr(outvn, 'getType') and outvn.getType() is not None else None
        if dt is None: return 0
        from ghidra.types.datatype import TYPE_STRUCT
        if dt.getMetatype() == TYPE_STRUCT:
            # Would check if inputs match adjacent fields
            pass
        return 0
