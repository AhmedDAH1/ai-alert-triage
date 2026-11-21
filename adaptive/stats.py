"""Small-sample statistics."""

import math


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centre - half), min(1.0, centre + half))


def fmt(k: int, n: int) -> str:
    if not n:
        return "-"
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({_pct(k / n)}, CI {_pct(lo, '')}–{_pct(hi)})"


def _pct(x: float, sign: str = "%") -> str:
    """Whole percent, with one decimal below 10% so a small upper bound doesn't read as 0."""
    v = 100 * x
    return f"{v:.1f}{sign}" if 0 < v < 10 else f"{v:.0f}{sign}"
