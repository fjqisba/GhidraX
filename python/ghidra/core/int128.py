"""
128-bit integer arithmetic helpers for division optimization rules.
Corresponds to the 128-bit operations in ruleaction.cc (set_u128, leftshift128, add128, etc.)
"""


def set_u128(val: int) -> int:
    """Create a 128-bit unsigned value."""
    return val & ((1 << 128) - 1)


def leftshift128(val: int, sa: int) -> int:
    """Left-shift a 128-bit value."""
    return (val << sa) & ((1 << 128) - 1)


def rightshift128(val: int, sa: int) -> int:
    """Right-shift a 128-bit value."""
    return val >> sa


def add128(a: int, b: int) -> int:
    """Add two 128-bit values."""
    return (a + b) & ((1 << 128) - 1)


def mult128(a: int, b: int) -> int:
    """Multiply two values, result up to 128 bits."""
    return (a * b) & ((1 << 128) - 1)


def mult64to128(a: int, b: int) -> int:
    """Multiply two 64-bit values, returning full 128-bit result."""
    return (a & 0xFFFFFFFFFFFFFFFF) * (b & 0xFFFFFFFFFFFFFFFF)


def div128by64(dividend: int, divisor: int) -> tuple:
    """Divide 128-bit by 64-bit, returning (quotient, remainder)."""
    if divisor == 0:
        return (0, 0)
    q = dividend // divisor
    r = dividend % divisor
    return (q & ((1 << 128) - 1), r & 0xFFFFFFFFFFFFFFFF)


def calcDivisor(n: int, y: int, xsize: int) -> int:
    """Calculate the actual divisor from multiply-high constant and shift.
    
    Given a multiply-high division pattern: (x * y) >> n
    The actual divisor d satisfies: y ≈ 2^n / d
    So d ≈ 2^n / y (rounded).
    """
    if y == 0:
        return 0
    power = 1 << n
    d = (power + y - 1) // y  # Ceiling division
    # Verify: d * y should be close to 2^n
    product = d * y
    if abs(product - power) <= d:
        return d
    return 0
