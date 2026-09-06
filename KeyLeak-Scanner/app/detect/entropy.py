import math
import re
from collections import Counter

# Candidate secret-looking tokens: quoted or bare runs of base64url-ish chars, 20+ long.
CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}")

# Keywords that must appear near a high-entropy candidate for it to count as a secret.
# Gates entropy scoring against minified JS, which is naturally high-entropy everywhere.
KEYWORD_RE = re.compile(r"key|token|secret|password|api|auth|credential", re.IGNORECASE)

PROXIMITY_WINDOW = 40


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def find_high_entropy_candidates(text: str, min_len: int = 20, min_entropy: float = 4.0) -> list[tuple[str, int]]:
    """Return (candidate, start_index) pairs that are long, high-entropy, and near a keyword."""
    results = []
    for m in CANDIDATE_RE.finditer(text):
        candidate = m.group(0)
        if len(candidate) < min_len:
            continue
        entropy = shannon_entropy(candidate)
        if entropy <= min_entropy:
            continue
        start = max(0, m.start() - PROXIMITY_WINDOW)
        end = min(len(text), m.end() + PROXIMITY_WINDOW)
        window = text[start:end]
        if not KEYWORD_RE.search(window):
            continue
        results.append((candidate, m.start()))
    return results
