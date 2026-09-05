from eval.metrics.stats import mcnemar, paired_bootstrap, pass_hat_k, pass_at_k


def test_mcnemar_matches_exact_binomial():
    stat, p = mcnemar(10, 3)

    assert stat == 3.0
    assert abs(p - 756 / 8192) < 1e-12


def test_mcnemar_normal_approx_large():
    stat, p = mcnemar(30, 10)

    import math
    assert abs(stat - 9.025) < 1e-12
    assert abs(p - math.erfc(math.sqrt(9.025 / 2.0))) < 1e-12


def test_paired_bootstrap_ci_on_constant_delta():
    mean, lo, hi = paired_bootstrap([(0.25, 0.75)] * 40, n_resamples=500, seed=3)
    assert abs(mean - 0.5) < 1e-12
    assert lo == 0.5 and hi == 0.5


def test_paired_bootstrap_deterministic():
    paired = [(0.1, 0.4), (0.3, 0.2), (0.5, 0.9)]
    assert paired_bootstrap(paired, n_resamples=2000, seed=11) == \
        paired_bootstrap(paired, n_resamples=2000, seed=11)


def test_pass_hat_k_known_case():

    assert pass_hat_k(3, 5, 2) == 0.3
    assert pass_hat_k(1, 5, 2) == 0.0


def test_pass_at_k_known_case():

    assert pass_at_k(2, 5, 2) == 0.7
    assert pass_at_k(5, 5, 2) == 1.0
