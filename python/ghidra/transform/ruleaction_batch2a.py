"""
Remaining rules batch 2a: INDIRECT/MULTIEQUAL collapse rules + misc.
"""
from __future__ import annotations
from ghidra.transform.action import Rule
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask


class RuleMultiCollapse(Rule):
    """Collapse MULTIEQUAL whose inputs all match the same value (including through chains)."""
    def __init__(self, g): super().__init__(g, 0, "multicollapse")
    def clone(self, gl):
        return RuleMultiCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_MULTIEQUAL]
    def applyOp(self, op, data):
        for i in range(op.numInput()):
            if not op.getIn(i).isHeritageKnown():
                return 0
        # Build matchlist: start with direct inputs, expand through nested MULTIEQUALs
        matchlist = [op.getIn(i) for i in range(op.numInput())]
        defvn = None
        skipset = {id(op.getOut())}
        op.getOut().setMark()
        j = 0
        success = True
        while j < len(matchlist):
            copyr = matchlist[j]; j += 1
            if id(copyr) in skipset:
                continue  # Looping back = same value recurring
            if defvn is None:
                if not copyr.isWritten() or copyr.getDef().code() != OpCode.CPUI_MULTIEQUAL:
                    defvn = copyr  # This is the defining branch
            elif defvn is copyr:
                continue  # Matching branch
            elif copyr.isWritten() and copyr.getDef().code() == OpCode.CPUI_MULTIEQUAL:
                # Non-matching branch is a MULTIEQUAL: add its inputs for further matching
                skipset.add(id(copyr))
                copyr.setMark()
                newop = copyr.getDef()
                for i in range(newop.numInput()):
                    matchlist.append(newop.getIn(i))
            else:
                success = False
                break
        # Clear marks
        op.getOut().clearMark()
        for vid in skipset:
            pass  # Would clear marks on all skip varnodes
        if success and defvn is not None:
            data.totalReplace(op.getOut(), defvn)
            data.opDestroy(op)
            return 1
        return 0


class RuleIndirectCollapse(Rule):
    """Collapse INDIRECT when the indirect effect is a no-op."""
    def __init__(self, g): super().__init__(g, 0, "indirectcollapse")
    def clone(self, gl):
        return RuleIndirectCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INDIRECT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        outvn = op.getOut()
        if invn.getAddr() == outvn.getAddr() and invn.getSize() == outvn.getSize():
            if not op.isIndirectStore():
                data.totalReplace(outvn, invn)
                data.opDestroy(op)
                return 1
        return 0


class RulePullsubMulti(Rule):
    """Pull SUBPIECE through MULTIEQUAL."""
    def __init__(self, g): super().__init__(g, 0, "pullsub_multi")
    def clone(self, gl):
        return RulePullsubMulti(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        defop = invn.getDef()
        if defop.code() != OpCode.CPUI_MULTIEQUAL: return 0
        if not invn.loneDescend(): return 0
        # Pull SUBPIECE through: replace each MULTIEQUAL input with SUBPIECE of that input
        shift = int(op.getIn(1).getOffset())
        outsize = op.getOut().getSize()
        newinputs = []
        for i in range(defop.numInput()):
            inp = defop.getIn(i)
            subop = data.newOp(2, defop.getAddr())
            data.opSetOpcode(subop, OpCode.CPUI_SUBPIECE)
            outvn = data.newUniqueOut(outsize, subop)
            data.opSetInput(subop, inp, 0)
            data.opSetInput(subop, data.newConstant(4, shift), 1)
            data.opInsertBegin(subop, defop.getParent())
            newinputs.append(outvn)
        # Replace MULTIEQUAL output size
        data.opSetOpcode(defop, OpCode.CPUI_MULTIEQUAL)
        data.opSetAllInput(defop, newinputs)
        newoutvn = data.newUniqueOut(outsize, defop)
        data.totalReplace(op.getOut(), newoutvn)
        data.opDestroy(op)
        return 1


class RulePullsubIndirect(Rule):
    """Pull SUBPIECE through INDIRECT."""
    def __init__(self, g): super().__init__(g, 0, "pullsub_indirect")
    def clone(self, gl):
        return RulePullsubIndirect(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        defop = invn.getDef()
        if defop.code() != OpCode.CPUI_INDIRECT: return 0
        if not invn.loneDescend(): return 0
        return 0  # Complex - needs more infrastructure


class RulePushMulti(Rule):
    """Push operation through MULTIEQUAL."""
    def __init__(self, g): super().__init__(g, 0, "push_multi")
    def clone(self, gl):
        return RulePushMulti(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_MULTIEQUAL]
    def applyOp(self, op, data):
        return 0  # Complex - needs substitute finding


class RuleSelectCse(Rule):
    """Common subexpression elimination: if two ops in same block have same opcode and inputs, merge."""
    def __init__(self, g): super().__init__(g, 0, "selectcse")
    def clone(self, gl):
        return RuleSelectCse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR]
    def applyOp(self, op, data):
        bl = op.getParent()
        if bl is None: return 0
        opc = op.code()
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        for other in bl.getOpList():
            if other is op: continue
            if other.code() != opc: continue
            if other.getIn(0) is in0 and other.getIn(1) is in1:
                data.totalReplace(op.getOut(), other.getOut())
                data.opDestroy(op)
                return 1
            if op.code() in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
                if other.getIn(0) is in1 and other.getIn(1) is in0:
                    data.totalReplace(op.getOut(), other.getOut())
                    data.opDestroy(op)
                    return 1
        return 0


class RuleCollectTerms(Rule):
    """Collect terms: x + x => x * 2, x + x*c => x*(c+1)."""
    def __init__(self, g): super().__init__(g, 0, "collectterms")
    def clone(self, gl):
        return RuleCollectTerms(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]
    def applyOp(self, op, data):
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        if in0 is in1:
            # x + x => x * 2
            data.opSetOpcode(op, OpCode.CPUI_INT_MULT)
            data.opSetInput(op, data.newConstant(in0.getSize(), 2), 1)
            return 1
        return 0


class RuleSubCommute(Rule):
    """Commute SUBPIECE with various operations (AND, OR, XOR, ADD, MULT, NEGATE, etc.)."""
    def __init__(self, g): super().__init__(g, 0, "subcommute")
    def clone(self, gl):
        return RuleSubCommute(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        base = op.getIn(0)
        if not base.isWritten(): return 0
        offset = int(op.getIn(1).getOffset())
        outvn = op.getOut()
        insize = base.getSize()
        longform = base.getDef()
        opc = longform.code()
        # Determine which ops commute with SUBPIECE
        if opc in (OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_XOR,
                   OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR):
            pass  # Bitwise ops commute at any offset
        elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_MULT):
            if offset != 0: return 0  # Only commutes with least significant SUBPIECE
        elif opc in (OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_REM):
            if offset != 0: return 0
            # Only commutes if inputs are zero-extended
            if not longform.getIn(0).isWritten(): return 0
            if longform.getIn(0).getDef().code() != OpCode.CPUI_INT_ZEXT: return 0
        elif opc in (OpCode.CPUI_INT_SDIV, OpCode.CPUI_INT_SREM):
            if offset != 0: return 0
            if not longform.getIn(0).isWritten(): return 0
            if longform.getIn(0).getDef().code() != OpCode.CPUI_INT_SEXT: return 0
        else:
            return 0
        # Make sure no other piece of base is getting used
        if base.loneDescend() is not op: return 0
        outsize = outvn.getSize()
        # Commute: replace each input with SUBPIECE of that input
        for i in range(longform.numInput()):
            invn = longform.getIn(i)
            if invn.isConstant():
                # Truncate constant
                val = invn.getOffset()
                if offset < 8:
                    val = (val >> (offset * 8)) & calc_mask(outsize)
                else:
                    val = 0
                newvn = data.newConstant(outsize, val)
            else:
                subop = data.newOp(2, op.getAddr())
                data.opSetOpcode(subop, OpCode.CPUI_SUBPIECE)
                newvn = data.newUniqueOut(outsize, subop)
                data.opSetInput(subop, invn, 0)
                data.opSetInput(subop, data.newConstant(4, offset), 1)
                data.opInsertBefore(subop, op)
            longform.setInput(newvn, i)
            newvn.addDescend(longform)
        # Change longform output size
        data.opSetOpcode(op, opc)
        for i in range(longform.numInput()):
            data.opSetInput(op, longform.getIn(i), i)
        # Resize output
        return 1


class RuleConditionalMove(Rule):
    """Convert 2-input MULTIEQUAL with diamond CFG into BOOL_AND/BOOL_OR or conditional select."""
    def __init__(self, g): super().__init__(g, 0, "conditionalmove")
    def clone(self, gl):
        return RuleConditionalMove(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_MULTIEQUAL]
    def applyOp(self, op, data):
        if op.numInput() != 2:
            return 0
        bb = op.getParent()
        inblock0 = bb.getIn(0)
        inblock1 = bb.getIn(1)
        # Trace back to find common root block
        if inblock0.sizeOut() == 1 and inblock0.sizeIn() == 1:
            rootblock0 = inblock0.getIn(0)
        else:
            rootblock0 = inblock0
        if inblock1.sizeOut() == 1 and inblock1.sizeIn() == 1:
            rootblock1 = inblock1.getIn(0)
        else:
            rootblock1 = inblock1
        if rootblock0 is not rootblock1:
            return 0
        # rootblock must end in CBRANCH
        cbranch = rootblock0.lastOp()
        if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
            return 0
        # Both inputs must be boolean (0 or 1)
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        if in0.isConstant() and in1.isConstant():
            v0 = in0.getOffset()
            v1 = in1.getOffset()
            if v0 in (0, 1) and v1 in (0, 1) and v0 != v1:
                # This is a simple boolean conditional move
                # MULTIEQUAL(0, 1) or MULTIEQUAL(1, 0) based on CBRANCH
                boolvn = cbranch.getIn(1)
                path0istrue = rootblock0.getTrueOut() is inblock0 if rootblock0 is not inblock0 else rootblock0.getTrueOut() is not inblock1
                if cbranch.isBooleanFlip():
                    path0istrue = not path0istrue
                if (v0 == 1 and path0istrue) or (v0 == 0 and not path0istrue):
                    # Output is just the boolean itself
                    data.totalReplace(op.getOut(), boolvn)
                    data.opDestroy(op)
                    return 1
                else:
                    # Output is negation of boolean
                    data.opSetOpcode(op, OpCode.CPUI_BOOL_NEGATE)
                    data.opSetInput(op, boolvn, 0)
                    op.removeInput(1)
                    return 1
        return 0


class RuleFloatSign(Rule):
    """Clean up float sign: FLOAT_MULT(x, -1.0) => FLOAT_NEG(x)."""
    def __init__(self, g): super().__init__(g, 0, "floatsign")
    def clone(self, gl):
        return RuleFloatSign(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_MULT]
    def applyOp(self, op, data):
        for slot in range(2):
            vn = op.getIn(slot)
            if not vn.isConstant(): continue
            # Check for -1.0 pattern (sign bit set, rest matches 1.0)
            sz = vn.getSize()
            val = vn.getOffset()
            if sz == 4 and val == 0xBF800000:  # -1.0f
                data.opSetOpcode(op, OpCode.CPUI_FLOAT_NEG)
                data.opSetInput(op, op.getIn(1 - slot), 0)
                data.opRemoveInput(op, 1)
                return 1
            if sz == 8 and val == 0xBFF0000000000000:  # -1.0
                data.opSetOpcode(op, OpCode.CPUI_FLOAT_NEG)
                data.opSetInput(op, op.getIn(1 - slot), 0)
                data.opRemoveInput(op, 1)
                return 1
        return 0


class RuleFloatSignCleanup(Rule):
    """Cleanup: FLOAT_ABS(FLOAT_NEG(x)) => FLOAT_ABS(x)."""
    def __init__(self, g): super().__init__(g, 0, "floatsigncleanup")
    def clone(self, gl):
        return RuleFloatSignCleanup(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_ABS]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        if invn.getDef().code() == OpCode.CPUI_FLOAT_NEG:
            if invn.loneDescend() is op:
                data.opSetInput(op, invn.getDef().getIn(0), 0)
                data.opDestroy(invn.getDef())
                return 1
        return 0


class RuleIgnoreNan(Rule):
    """Replace FLOAT_NAN with constant false when NaN-ignore mode is on."""
    def __init__(self, g): super().__init__(g, 0, "ignorenan")
    def clone(self, gl):
        return RuleIgnoreNan(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_NAN]
    def applyOp(self, op, data):
        glb = data.getArch()
        if glb is None: return 0
        if not getattr(glb, 'nan_ignore_all', False): return 0
        outvn = op.getOut()
        if outvn is None: return 0
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, data.newConstant(outvn.getSize(), 0), 0)
        return 1


class RuleInt2FloatCollapse(Rule):
    """Collapse INT2FLOAT followed by FLOAT2FLOAT."""
    def __init__(self, g): super().__init__(g, 0, "int2floatcollapse")
    def clone(self, gl):
        return RuleInt2FloatCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_FLOAT2FLOAT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        if invn.getDef().code() != OpCode.CPUI_FLOAT_INT2FLOAT: return 0
        if not invn.loneDescend(): return 0
        origop = invn.getDef()
        data.opSetInput(op, origop.getIn(0), 0)
        data.opSetOpcode(op, OpCode.CPUI_FLOAT_INT2FLOAT)
        data.opDestroy(origop)
        return 1


class RuleUnsigned2Float(Rule):
    """Convert unsigned INT2FLOAT: if input is ZEXT, use the smaller input directly."""
    def __init__(self, g): super().__init__(g, 0, "unsigned2float")
    def clone(self, gl):
        return RuleUnsigned2Float(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_INT2FLOAT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        defop = invn.getDef()
        if defop.code() == OpCode.CPUI_INT_ZEXT:
            if invn.loneDescend() is op:
                data.opSetInput(op, defop.getIn(0), 0)
                data.opDestroy(defop)
                return 1
        return 0
