"""
Non-zero mask calculation. Corresponds to PcodeOp::getNZMaskLocal() in op.cc.
"""
from ghidra.core.opcodes import OpCode
from ghidra.core.address import (
    calc_mask, pcode_left, pcode_right, sign_extend,
    coveringmask, leastsigbit_set, mostsigbit_set, popcount,
)


def getNZMaskLocal(op, cliploop=True):
    out = op.getOut()
    if out is None: return 0
    size = out.getSize()
    fm = calc_mask(size)
    opc = op.code()
    bools = (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
             OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL,
             OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
             OpCode.CPUI_INT_CARRY, OpCode.CPUI_INT_SCARRY,
             OpCode.CPUI_INT_SBORROW, OpCode.CPUI_BOOL_NEGATE,
             OpCode.CPUI_BOOL_XOR, OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,
             OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL,
             OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL,
             OpCode.CPUI_FLOAT_NAN)
    if opc in bools:
        return 1
    if opc in (OpCode.CPUI_COPY, OpCode.CPUI_INT_ZEXT):
        return op.getIn(0).getNZMask()
    if opc == OpCode.CPUI_INT_SEXT:
        return sign_extend(op.getIn(0).getNZMask(), op.getIn(0).getSize(), size) & fm
    if opc in (OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR):
        r = op.getIn(0).getNZMask()
        return r | op.getIn(1).getNZMask() if r != fm else fm
    if opc == OpCode.CPUI_INT_AND:
        r = op.getIn(0).getNZMask()
        return r & op.getIn(1).getNZMask() if r != 0 else 0
    if opc == OpCode.CPUI_INT_LEFT:
        if not op.getIn(1).isConstant(): return fm
        sa = int(op.getIn(1).getOffset())
        return pcode_left(op.getIn(0).getNZMask(), sa) & fm
    if opc == OpCode.CPUI_INT_RIGHT:
        if not op.getIn(1).isConstant(): return fm
        sa = int(op.getIn(1).getOffset())
        return pcode_right(op.getIn(0).getNZMask(), sa)
    if opc == OpCode.CPUI_INT_SRIGHT:
        if not op.getIn(1).isConstant() or size > 8: return fm
        sa = int(op.getIn(1).getOffset())
        r = op.getIn(0).getNZMask()
        if (r & (fm ^ (fm >> 1))) == 0:
            return pcode_right(r, sa)
        return pcode_right(r, sa) | ((fm >> sa) ^ fm)
    if opc == OpCode.CPUI_SUBPIECE:
        r = op.getIn(0).getNZMask()
        s = int(op.getIn(1).getOffset())
        return (r >> (8 * s)) & fm if s < 8 else 0
    if opc == OpCode.CPUI_PIECE:
        sa = op.getIn(1).getSize()
        hi = op.getIn(0).getNZMask()
        r = (hi << (8 * sa)) if sa < 8 else 0
        return (r | op.getIn(1).getNZMask()) & fm
    if opc == OpCode.CPUI_INT_ADD:
        r = op.getIn(0).getNZMask()
        if r != fm:
            r |= op.getIn(1).getNZMask()
            r |= (r << 1)
            r &= fm
        return r
    if opc == OpCode.CPUI_INT_MULT:
        if size > 8: return fm
        v1 = op.getIn(0).getNZMask()
        v2 = op.getIn(1).getNZMask()
        s1 = mostsigbit_set(v1); s2 = mostsigbit_set(v2)
        if s1 == -1 or s2 == -1: return 0
        l1 = leastsigbit_set(v1); l2 = leastsigbit_set(v2)
        sa = l1 + l2
        if sa >= 8 * size: return 0
        t1 = s1 - l1 + 1; t2 = s2 - l2 + 1
        total = t1 + t2 - (1 if t1 == 1 or t2 == 1 else 0)
        r = fm
        if total < 8 * size: r >>= (8 * size - total)
        return (r << sa) & fm
    if opc == OpCode.CPUI_INT_NEGATE:
        return fm
    if opc == OpCode.CPUI_MULTIEQUAL:
        if op.numInput() == 0: return fm
        r = 0
        for i in range(op.numInput()):
            r |= op.getIn(i).getNZMask()
        return r
    if opc == OpCode.CPUI_INDIRECT:
        return fm
    if opc == OpCode.CPUI_POPCOUNT:
        s = popcount(op.getIn(0).getNZMask())
        return coveringmask(s) & fm
    if opc == OpCode.CPUI_LZCOUNT:
        return coveringmask(op.getIn(0).getSize() * 8) & fm
    return fm


def calcNZMask(data):
    """Calculate non-zero mask for all Varnodes in the function."""
    for op in list(data._obank.beginAlive()):
        for i in range(op.numInput()):
            vn = op.getIn(i)
            if not vn.isWritten():
                if vn.isConstant():
                    vn._nzm = vn.getOffset()
                else:
                    vn._nzm = calc_mask(vn.getSize())
        out = op.getOut()
        if out is not None:
            out._nzm = getNZMaskLocal(op, True)
