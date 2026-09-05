import inspect

from eval.graders import GRADERS

DIMENSIONS = {"security_spoofing", "injection", "overblock",
              "utility", "coordination", "containment"}


def test_every_dimension_registered():
    assert set(GRADERS) == DIMENSIONS


def test_each_grader_is_single_arg_callable():
    for dim, fn in GRADERS.items():
        assert callable(fn), f"{dim} not callable"
        params = list(inspect.signature(fn).parameters.values())
        positional = [p for p in params
                      if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
                      and p.default is p.empty]
        assert len(positional) == 1, f"{dim} takes {len(positional)} required args, not 1"
