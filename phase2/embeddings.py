"""Turn text into a 256-number vector for pgvector.

This uses "feature hashing": each word is hashed to one of 256 slots. It's free, offline
and deterministic, but it only matches shared WORDS, not meaning ("car" won't match "auto").

In production you'd call an embedding model instead (e.g. Voyage AI, which Anthropic
recommends, or a local sentence-transformers model) and change DIM to that model's size,
in schema.sql too. Nothing about tenant isolation changes when you do.
"""
import hashlib
import math
from collections import Counter

from ai import _tokens

DIM = 256


def embed(text: str) -> list[float]:
    vec = [0.0] * DIM
    for word, count in Counter(_tokens(text)).items():
        h = int.from_bytes(hashlib.md5(word.encode()).digest()[:8], "little")
        sign = 1.0 if (h >> 32) & 1 else -1.0       # random sign keeps collisions from piling up
        vec[h % DIM] += sign * (1 + math.log(count))
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def to_pg(vec: list[float]) -> str:
    """pgvector's text format: '[0.1,0.2,...]'. Pass it as a parameter and cast with ::vector."""
    return "[" + ",".join(f"{v:.6f}" for v in vec) + "]"
