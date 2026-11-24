"""Small-sample statistics used in the thesis (Python standard library only).

clopper_pearson   exact binomial 95% interval for precision and recall
mcnemar_exact     exact McNemar test on paired detections (same seeds)
mann_whitney      Mann-Whitney U with an exact permutation p-value (small n)
cohen_kappa       agreement between two raters (binary labels)
median_iqr        median and interquartile range
"""
import itertools
import math
import statistics


def _binom_cdf(k, n, p):
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))


def clopper_pearson(k, n, alpha=0.05):
    """Exact two-sided (1-alpha) interval for k successes in n trials."""
    if n == 0:
        return (None, None)

    # lower bound: P(X >= k | p) = alpha/2  (increasing in p)
    if k == 0:
        lower = 0.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            if 1 - _binom_cdf(k - 1, n, mid) < alpha / 2:
                lo = mid
            else:
                hi = mid
        lower = (lo + hi) / 2
    # upper bound: P(X <= k | p) = alpha/2  (decreasing in p)
    if k == n:
        upper = 1.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            if _binom_cdf(k, n, mid) > alpha / 2:
                lo = mid
            else:
                hi = mid
        upper = (lo + hi) / 2
    return (round(lower, 4), round(upper, 4))


def mcnemar_exact(b, c):
    """b = seeds detected only by A, c = seeds detected only by B.
    Returns (two-sided p, one-sided p for A > B)."""
    n = b + c
    if n == 0:
        return 1.0, 1.0
    tail = sum(math.comb(n, i) for i in range(0, min(b, c) + 1)) / 2 ** n
    two_sided = min(1.0, 2 * tail)
    one_sided = sum(math.comb(n, i) for i in range(b, n + 1)) / 2 ** n  # P(X >= b)
    return round(two_sided, 6), round(one_sided, 6)


def _ranks(values):
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = r
        i = j + 1
    return ranks


def mann_whitney(x, y, exact_limit=300000):
    """Two-sided Mann-Whitney U test. Exact permutation p-value when the number
    of splits is small enough, otherwise the normal approximation."""
    nx, ny = len(x), len(y)
    if nx == 0 or ny == 0:
        return None, None, None
    ranks = _ranks(list(x) + list(y))
    rx = sum(ranks[:nx])
    u = rx - nx * (nx + 1) / 2
    mean_u = nx * ny / 2
    if math.comb(nx + ny, nx) <= exact_limit:
        obs = abs(u - mean_u)
        count = total = 0
        for combo in itertools.combinations(range(nx + ny), nx):
            uu = sum(ranks[i] for i in combo) - nx * (nx + 1) / 2
            total += 1
            if abs(uu - mean_u) >= obs - 1e-9:
                count += 1
        return u, round(count / total, 6), "exact"
    sd = math.sqrt(nx * ny * (nx + ny + 1) / 12)
    z = (abs(u - mean_u) - 0.5) / sd
    p = 2 * (1 - 0.5 * (1 + math.erf(z / math.sqrt(2))))
    return u, round(p, 6), "normal"


def cohen_kappa(a, b):
    """Cohen's kappa for two equal-length lists of categorical labels."""
    if not a or len(a) != len(b):
        return None
    n = len(a)
    cats = sorted(set(a) | set(b))
    po = sum(1 for i in range(n) if a[i] == b[i]) / n
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    return 1.0 if pe == 1 else round((po - pe) / (1 - pe), 4)


def median_iqr(values):
    values = sorted(values)
    if not values:
        return None, None, None
    if len(values) < 2:
        return values[0], values[0], values[0]
    q1, q2, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return round(statistics.median(values), 2), round(q1, 2), round(q3, 2)
