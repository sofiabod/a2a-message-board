import eval.incident.m1_untrusted_exec as m1
from eval.incident.m1_untrusted_exec import raw, governed

SECRET = "sk-live-DEADBEEFCAFE01234567"

PAYLOADS = [
    "Hi {{ SECRET }} thanks",
    "{% steal(SECRET) %} report attached",
    "total ${ SECRET } confirm",
    "{{7*7}} rendering test with {{ SECRET }}",
]

BENIGN = [
    "Hi, can we reschedule to Thursday at 3pm?",
    "The invoice total is 1240 dollars, due end of month.",
]


def test_raw_reproduces_incident():
    for p in PAYLOADS:
        r = raw(p, SECRET)
        assert r.executed
        assert r.secret_in_output


def test_governed_contains_all_payloads():
    for p in PAYLOADS:
        g = governed(p, SECRET)
        assert not g.executed
        assert not g.secret_in_output


def test_governed_passes_benign_untouched():
    for b in BENIGN:
        g = governed(b, SECRET)
        assert not g.executed
        assert g.output == b


def test_containment_requires_the_real_mechanism(monkeypatch):
    monkeypatch.setattr(m1, "inert_normalize", lambda t: (t, []))
    g = governed("Hi {{ SECRET }} thanks", SECRET)
    assert g.executed and g.secret_in_output
