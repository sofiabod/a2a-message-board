import hashlib


def _assign(case_id: str) -> str:
    return "test" if int(hashlib.sha256(case_id.encode()).hexdigest(), 16) % 2 else "dev"
