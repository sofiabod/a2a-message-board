import base64
import binascii
import math
import re
from dataclasses import dataclass, field

ALLOW = "ALLOW"
QUARANTINE = "QUARANTINE"
REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

_ACTIVE = [
    re.compile(r"<\s*script\b.*?<\s*/\s*script\s*>", re.I | re.S),
    re.compile(r"<\s*style\b.*?<\s*/\s*style\s*>", re.I | re.S),
    re.compile(r"<\s*/?\s*(?:iframe|object|embed|link|meta)\b[^>]*>", re.I),
    re.compile(r"\{\{.*?\}\}", re.S),
    re.compile(r"\{%.*?%\}", re.S),
    re.compile(r"\$\{.*?\}", re.S),
    re.compile(r"\bon\w+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I),
    re.compile(r"(?:javascript|data|vbscript|file)\s*:", re.I),
]

_SECRETS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
]

_INJECTION = [
    re.compile(r"\bignore\b.{0,40}\b(?:previous|prior|above|earlier)\b.{0,40}\binstructions?\b", re.I),
    re.compile(r"\bdisregard\b.{0,40}\b(?:instructions?|rules?|policy)\b", re.I),
    re.compile(r"\b(?:reveal|exfiltrate|leak|send|print)\b.{0,40}\b(?:secret|canary|api[_ ]?key|password|token|credential)s?\b", re.I),
    re.compile(r"\byou are now\b|\bnew system prompt\b|\bact as\b", re.I),
]






_IMPERATIVE_VERBS = frozenset({
    "ignore", "disregard", "reveal", "exfiltrate", "leak", "send", "print", "select",
    "act", "forget", "override", "output", "return", "execute", "run", "call", "delete",
    "follow", "obey", "always", "now", "instead",
})
_SENTENCE = re.compile(r"[^.!?]*[.!?]|[^.!?]+$")
_WORD = re.compile(r"[a-z]+", re.I)

_MAGIC = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x89HDF\r\n\x1a\n", "application/x-hdf5"),
    (b"#!", "text/x-shellscript"),
    (b"\x7fELF", "application/x-executable"),
    (b"MZ", "application/x-dosexec"),
]

_EXEC_TYPES = {"text/x-shellscript", "application/x-executable", "application/x-dosexec", "application/x-hdf5"}

_CHUNK = re.compile(r"[A-Za-z0-9+/=_\-]{12,}")


def _reveal_instruction(text: str) -> str:
    for pat in _INJECTION:
        if pat.search(text):
            return pat.pattern
    return ""


@dataclass
class Decision:
    decision: str = ALLOW
    reasons: list[str] = field(default_factory=list)

    def raise_to(self, level: str, reason: str):
        rank = {ALLOW: 0, REQUIRE_APPROVAL: 1, QUARANTINE: 2}
        if reason not in self.reasons:
            self.reasons.append(reason)
        if rank[level] > rank[self.decision]:
            self.decision = level


def inert_normalize(text: str) -> tuple[str, list[str]]:
    reasons = []
    out = text
    for pat in _ACTIVE:
        if pat.search(out):
            reasons.append("active_content_stripped")
            out = pat.sub(" ", out)
    return out, reasons


def strip_injection(text: str, imperative_verbs=_IMPERATIVE_VERBS) -> str:
    kept = []
    for sent in _SENTENCE.findall(text):
        words = [w.lower() for w in _WORD.findall(sent)]
        if words and words[0] in imperative_verbs:
            continue
        kept.append(sent)
    return "".join(kept).strip()


def _detect_mime(data: bytes) -> str | None:
    for sig, mime in _MAGIC:
        if data.startswith(sig):
            return mime
    return None


def mime_check(declared: str, data: bytes) -> list[str]:
    detected = _detect_mime(data)
    reasons = []
    if detected and detected != declared:
        reasons.append("mime_mismatch")
    if detected in _EXEC_TYPES:
        reasons.append("executable_attachment")
    return reasons


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _decodes_to_text(m: str) -> bool:
    try:
        data = base64.b64decode(m + "=" * (-len(m) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    return bool(data) and data.isascii() and all(32 <= b < 127 or b in (9, 10, 13) for b in data)


def dlp_scan(thread_text: str, canaries: list[str]) -> list[str]:
    reasons = []
    for pat in _SECRETS:
        if pat.search(thread_text):
            reasons.append("secret_detected")
            break
    for c in canaries:
        if c and c in thread_text:
            reasons.append("canary_leak")
            break
    for m in _CHUNK.findall(thread_text):
        if len(m) >= 20 and _entropy(m) >= 4.0 and not _decodes_to_text(m):
            reasons.append("high_entropy_transfer")
            break
    return reasons


def screen(messages: list[str], trajectory: list[str], canaries: list[str] = (),
           attachments: list[tuple[str, bytes]] = ()) -> Decision:
    d = Decision()
    thread = "\n".join(messages)

    _, inert_reasons = inert_normalize(thread)
    for r in inert_reasons:
        d.raise_to(QUARANTINE, r)

    for msg in messages:
        for pat in _INJECTION:
            if pat.search(msg):
                d.raise_to(QUARANTINE, "prompt_injection")

    for declared, data in attachments:
        for r in mime_check(declared, data):
            d.raise_to(QUARANTINE, r)

    corpus = thread + "\n" + "\n".join(trajectory)
    for r in dlp_scan(corpus, list(canaries)):
        d.raise_to(QUARANTINE if r == "canary_leak" else REQUIRE_APPROVAL, r)

    return d
