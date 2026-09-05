import math
import random


def pass_at_k(successes: int, n: int, k: int) -> float:
    return 1.0 - math.comb(n - successes, k) / math.comb(n, k)


def pass_hat_k(successes: int, n: int, k: int) -> float:
    if successes < k:
        return 0.0
    return math.comb(successes, k) / math.comb(n, k)


def mcnemar(b: int, c: int) -> tuple[float, float]:
    if b + c == 0:
        return 0.0, 1.0
    if b + c < 25:
        m = min(b, c)
        p = 0.0
        for i in range(m + 1):
            p += math.comb(b + c, i) * 0.5 ** (b + c)
        return float(min(b, c)), min(1.0, 2.0 * p)
    stat = (abs(b - c) - 1) ** 2 / (b + c)
    p = math.erfc(math.sqrt(stat / 2.0))
    return stat, p


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - h) / d), min(1.0, (c + h) / d)


def paired_bootstrap(paired: list[tuple[float, float]], n_resamples: int = 10000,
                     seed: int = 0) -> tuple[float, float, float]:
    rng = random.Random(seed)
    n = len(paired)
    deltas = [e - d for d, e in paired]
    mean_delta = sum(deltas) / n
    means = []
    for _ in range(n_resamples):
        s = sum(deltas[rng.randrange(n)] for _ in range(n))
        means.append(s / n)
    means.sort()
    lo = means[int(0.025 * n_resamples)]
    hi = means[int(0.975 * n_resamples)]
    return mean_delta, lo, hi


def demo() -> None:
    assert pass_at_k(0, 5, 2) == 0.0
    assert pass_at_k(5, 5, 2) == 1.0
    assert abs(pass_at_k(2, 5, 2) - (1 - math.comb(3, 2) / math.comb(5, 2))) < 1e-12
    assert pass_hat_k(2, 5, 2) == math.comb(2, 2) / math.comb(5, 2)
    assert pass_hat_k(1, 5, 2) == 0.0
    assert mcnemar(0, 0) == (0.0, 1.0)
    stat, p = mcnemar(10, 0)
    assert abs(p - 2 * 0.5 ** 10) < 1e-12
    _, lo, hi = paired_bootstrap([(0.0, 1.0)] * 20, n_resamples=1000, seed=1)
    assert lo == 1.0 and hi == 1.0
    lo, hi = wilson(88, 100)
    assert lo < 0.88 < hi and 0.79 < lo < 0.82 and 0.93 < hi < 0.95
    assert wilson(0, 0) == (0.0, 1.0)
    a = paired_bootstrap([(0.1, 0.4), (0.2, 0.3)], seed=7)
    b = paired_bootstrap([(0.1, 0.4), (0.2, 0.3)], seed=7)
    assert a == b
    print("ok")


if __name__ == "__main__":
    demo()
