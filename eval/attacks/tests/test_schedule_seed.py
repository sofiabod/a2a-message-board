from eval.attacks.schedule import build_schedule, KIND

CANARY = "CANARYtoken9f3a2b7c1e8d40"


def test_same_seed_reproduces():
    a = build_schedule(CANARY, 30, 7)
    b = build_schedule(CANARY, 30, 7)
    assert a.freeze() == b.freeze()
    assert [(e.kind, e.milestone, e.payload) for e in a.events] == \
           [(e.kind, e.milestone, e.payload) for e in b.events]


def test_different_seeds_differ():
    base = build_schedule(CANARY, 30, 0)
    for seed in range(1, 30):
        assert build_schedule(CANARY, 30, seed).freeze() != base.freeze()


def test_all_kinds_present_and_in_range_every_seed():
    for seed in range(30):
        s = build_schedule(CANARY, 30, seed)
        assert {e.kind for e in s.events} == set(KIND)
        assert all(0 <= e.milestone < 30 for e in s.events)
