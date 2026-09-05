import hashlib
import hmac
import json


def _canonical_body(card: dict) -> str:
    body = {k: v for k, v in card.items() if k not in ("case_id", "card_index", "signature")}
    return json.dumps(body, sort_keys=True, ensure_ascii=True)


def card_fingerprint(card: dict) -> str:
    return hashlib.sha256(_canonical_body(card).encode()).hexdigest()


def _identity(card: dict) -> str:
    url = card.get("url", "")
    d = url.split("://", 1)[-1]
    return d.rsplit("@", 1)[-1]


def sign_card(card: dict, key: bytes) -> str:
    return hmac.new(key, _canonical_body(card).encode(), hashlib.sha256).hexdigest()


def build_registry(genuine_card: dict, key: bytes) -> dict:
    ident = _identity(genuine_card)
    return {ident: {"key": key, "expected_body": _canonical_body(genuine_card)}}


def verify_card(card: dict, registry: dict) -> bool:
    entry = registry.get(_identity(card))
    if entry is None:
        return False
    sig = card.get("signature")
    if sig is None:
        return False
    return hmac.compare_digest(sig, sign_card(card, entry["key"]))


def demo():
    import os

    root = "tests/fixtures/as"
    case = "as_001"
    benign = json.load(open(os.path.join(root, case, "benign.json")))
    key = b"registered-genuine-key"
    registry = build_registry(benign, key)

    signed_benign = dict(benign, signature=sign_card(benign, key))
    assert verify_card(signed_benign, registry)

    for i in range(1, 10):
        spoof = json.load(open(os.path.join(root, case, f"spoofed_{i:02d}.json")))
        assert not verify_card(spoof, registry), ("unsigned spoof passed", i)
        forged = dict(spoof, signature=sign_card(spoof, b"attacker-own-key"))
        assert not verify_card(forged, registry), ("wrong-key spoof passed", i)


    tampered = dict(benign, name="R<evil> Forecaster")
    key_compromised = dict(tampered, signature=sign_card(tampered, key))
    assert verify_card(key_compromised, registry), "signed impostor must be able to pass"


if __name__ == "__main__":
    demo()
    print("ok")
