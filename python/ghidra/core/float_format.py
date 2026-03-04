"""
Corresponds to: float.hh / float.cc

Support for decoding different floating-point formats.
Uses Python's native float (IEEE 754 double) for host representation.
"""

from __future__ import annotations

import math
import struct
from enum import IntEnum

from ghidra.core.address import calc_mask


class FloatClass(IntEnum):
    """The various classes of floating-point encodings."""
    normalized = 0
    infinity = 1
    zero = 2
    nan = 3
    denormalized = 4


class FloatFormat:
    """Encoding information for a single floating-point format.

    Supports manipulation of a single floating-point encoding following
    the IEEE 754 standard.
    """

    def __init__(self, sz: int) -> None:
        self.size: int = sz
        self.signbit_pos: int = 0
        self.frac_pos: int = 0
        self.frac_size: int = 0
        self.exp_pos: int = 0
        self.exp_size: int = 0
        self.bias: int = 0
        self.maxexponent: int = 0
        self.jbitimplied: bool = True
        self.decimalMinPrecision: int = 0
        self.decimalMaxPrecision: int = 0

        # Set up default IEEE 754 parameters based on size
        if sz == 4:
            self.signbit_pos = 31
            self.exp_pos = 23
            self.exp_size = 8
            self.frac_pos = 0
            self.frac_size = 23
            self.bias = 127
            self.jbitimplied = True
        elif sz == 8:
            self.signbit_pos = 63
            self.exp_pos = 52
            self.exp_size = 11
            self.frac_pos = 0
            self.frac_size = 52
            self.bias = 1023
            self.jbitimplied = True
        elif sz == 2:  # half precision
            self.signbit_pos = 15
            self.exp_pos = 10
            self.exp_size = 5
            self.frac_pos = 0
            self.frac_size = 10
            self.bias = 15
            self.jbitimplied = True
        elif sz == 16:  # quad precision (simplified)
            self.signbit_pos = 127
            self.exp_pos = 112
            self.exp_size = 15
            self.frac_pos = 0
            self.frac_size = 112
            self.bias = 16383
            self.jbitimplied = True
        else:
            # Default to 8-byte format
            self.signbit_pos = 63
            self.exp_pos = 52
            self.exp_size = 11
            self.frac_pos = 0
            self.frac_size = 52
            self.bias = 1023
            self.jbitimplied = True

        self.maxexponent = (1 << self.exp_size) - 1
        self._calcPrecision()

    def _calcPrecision(self) -> None:
        """Calculate the decimal precision of this format."""
        import math
        bits = self.frac_size
        if self.jbitimplied:
            bits += 1
        self.decimalMinPrecision = int(math.floor(bits * math.log10(2)))
        self.decimalMaxPrecision = int(math.ceil((bits + 1) * math.log10(2))) + 1

    def getSize(self) -> int:
        return self.size

    # --- Extraction helpers ---

    def extractFractionalCode(self, x: int) -> int:
        mask = (1 << self.frac_size) - 1
        return (x >> self.frac_pos) & mask

    def extractSign(self, x: int) -> bool:
        return ((x >> self.signbit_pos) & 1) != 0

    def extractExponentCode(self, x: int) -> int:
        mask = (1 << self.exp_size) - 1
        return (x >> self.exp_pos) & mask

    def _setFractionalCode(self, x: int, code: int) -> int:
        mask = (1 << self.frac_size) - 1
        x &= ~(mask << self.frac_pos)
        x |= (code & mask) << self.frac_pos
        return x

    def _setSign(self, x: int, sign: bool) -> int:
        if sign:
            x |= (1 << self.signbit_pos)
        else:
            x &= ~(1 << self.signbit_pos)
        return x

    def _setExponentCode(self, x: int, code: int) -> int:
        mask = (1 << self.exp_size) - 1
        x &= ~(mask << self.exp_pos)
        x |= (code & mask) << self.exp_pos
        return x

    # --- Conversion to/from host float ---

    def getHostFloat(self, encoding: int) -> tuple[float, FloatClass]:
        """Convert an encoding into host's double.

        Returns (float_value, float_class).
        """
        sgn = self.extractSign(encoding)
        exp_code = self.extractExponentCode(encoding)
        frac = self.extractFractionalCode(encoding)

        if exp_code == 0:
            if frac == 0:
                val = -0.0 if sgn else 0.0
                return val, FloatClass.zero
            # Denormalized
            exp_val = 1 - self.bias
            val = frac / (1 << self.frac_size)
            val = val * (2.0 ** exp_val)
            if sgn:
                val = -val
            return val, FloatClass.denormalized
        elif exp_code == self.maxexponent:
            if frac == 0:
                val = float('-inf') if sgn else float('inf')
                return val, FloatClass.infinity
            val = float('nan')
            return val, FloatClass.nan

        # Normalized
        exp_val = exp_code - self.bias
        if self.jbitimplied:
            signif = (1 << self.frac_size) | frac
        else:
            signif = frac
        val = signif / (1 << self.frac_size)
        val = val * (2.0 ** exp_val)
        if sgn:
            val = -val
        return val, FloatClass.normalized

    def getEncoding(self, host: float) -> int:
        """Convert host's double into this encoding."""
        if self.size == 8:
            return struct.unpack('<Q', struct.pack('<d', host))[0]
        if self.size == 4:
            return struct.unpack('<I', struct.pack('<f', host))[0]
        # General case: use host double, then re-encode
        if math.isnan(host):
            return self._getNaNEncoding(False)
        if math.isinf(host):
            return self._getInfinityEncoding(host < 0)
        if host == 0.0:
            return self._getZeroEncoding(math.copysign(1.0, host) < 0)

        sgn = host < 0
        host = abs(host)
        exp_val = int(math.floor(math.log2(host)))
        frac = host / (2.0 ** exp_val) - 1.0
        frac_code = int(round(frac * (1 << self.frac_size)))
        exp_code = exp_val + self.bias

        if exp_code <= 0:
            return self._getZeroEncoding(sgn)
        if exp_code >= self.maxexponent:
            return self._getInfinityEncoding(sgn)

        result = 0
        result = self._setFractionalCode(result, frac_code)
        result = self._setExponentCode(result, exp_code)
        result = self._setSign(result, sgn)
        return result

    def _getZeroEncoding(self, sgn: bool) -> int:
        return self._setSign(0, sgn)

    def _getInfinityEncoding(self, sgn: bool) -> int:
        result = self._setExponentCode(0, self.maxexponent)
        return self._setSign(result, sgn)

    def _getNaNEncoding(self, sgn: bool) -> int:
        result = self._setExponentCode(0, self.maxexponent)
        result = self._setFractionalCode(result, 1)
        return self._setSign(result, sgn)

    # --- P-code floating-point operations ---

    def _toHost(self, a: int) -> float:
        val, _ = self.getHostFloat(a)
        return val

    def _fromHost(self, val: float) -> int:
        return self.getEncoding(val)

    def opEqual(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) == self._toHost(b) else 0

    def opNotEqual(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) != self._toHost(b) else 0

    def opLess(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) < self._toHost(b) else 0

    def opLessEqual(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) <= self._toHost(b) else 0

    def opNan(self, a: int) -> int:
        return 1 if math.isnan(self._toHost(a)) else 0

    def opAdd(self, a: int, b: int) -> int:
        return self._fromHost(self._toHost(a) + self._toHost(b))

    def opDiv(self, a: int, b: int) -> int:
        bv = self._toHost(b)
        if bv == 0.0:
            return self._getInfinityEncoding(self._toHost(a) < 0)
        return self._fromHost(self._toHost(a) / bv)

    def opMult(self, a: int, b: int) -> int:
        return self._fromHost(self._toHost(a) * self._toHost(b))

    def opSub(self, a: int, b: int) -> int:
        return self._fromHost(self._toHost(a) - self._toHost(b))

    def opNeg(self, a: int) -> int:
        return self._fromHost(-self._toHost(a))

    def opAbs(self, a: int) -> int:
        return self._fromHost(abs(self._toHost(a)))

    def opSqrt(self, a: int) -> int:
        return self._fromHost(math.sqrt(self._toHost(a)))

    def opTrunc(self, a: int, sizeout: int) -> int:
        val = self._toHost(a)
        ival = int(math.trunc(val))
        mask = calc_mask(sizeout)
        return ival & mask

    def opCeil(self, a: int) -> int:
        return self._fromHost(math.ceil(self._toHost(a)))

    def opFloor(self, a: int) -> int:
        return self._fromHost(math.floor(self._toHost(a)))

    def opRound(self, a: int) -> int:
        return self._fromHost(round(self._toHost(a)))

    def opInt2Float(self, a: int, sizein: int) -> int:
        mask = calc_mask(sizein)
        a &= mask
        # Treat as signed
        if a >= (1 << (sizein * 8 - 1)):
            a -= (1 << (sizein * 8))
        return self._fromHost(float(a))

    def opFloat2Float(self, a: int, outformat: FloatFormat) -> int:
        val = self._toHost(a)
        return outformat.getEncoding(val)

    def printDecimal(self, host: float, forcesci: bool = False) -> str:
        if forcesci:
            return f"{host:.{self.decimalMaxPrecision}e}"
        return f"{host:.{self.decimalMaxPrecision}g}"
