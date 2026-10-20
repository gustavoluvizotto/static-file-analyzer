"""Hashes and byte entropy, computed over bytes already read into memory."""

from __future__ import annotations

import hashlib
import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: 0.0 (one repeated byte) to 8.0 (uniform)."""
    if not data:
        return 0.0
    size = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / size
        entropy -= p * math.log2(p)
    return entropy


def hash_bytes(data: bytes) -> dict[str, object]:
    """Return md5, sha256 and entropy (rounded to 4 decimals) for `data`."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(shannon_entropy(data), 4),
    }
