"""Feature extraction for SQL injection payload classification.

The model intentionally uses explainable handcrafted features. This is more
suitable for a university security project than a black-box model because the
same features can be displayed in the dashboard and discussed in the report.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

import numpy as np

SQL_KEYWORDS = [
    "select",
    "union",
    "drop",
    "insert",
    "update",
    "delete",
    "or",
    "and",
    "where",
    "sleep",
    "benchmark",
    "xp_cmdshell",
    "information_schema",
    "concat",
    "having",
    "order",
    "group",
    "from",
    "table",
]

SPECIAL_CHARS = "'\";#()-=*/\\%<>"
ENCODING_PATTERNS = ["%27", "%22", "%23", "%2d", "%2f", "0x", "char(", "cast("]
COMMENT_PATTERNS = ["--", "#", "/*", "*/"]


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy for a string.

    Encoded or obfuscated payloads often have unusual character distribution.
    Entropy is not a standalone SQL injection signal, but it helps the model.
    """
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def extract_features(payload: str) -> list[float]:
    """Convert a payload into numeric features used by the ML classifier."""
    text = payload or ""
    lowered = text.lower()
    length = len(text)
    words = re.findall(r"[a-zA-Z_]+", lowered)
    keyword_hits = sum(1 for keyword in SQL_KEYWORDS if keyword in lowered)
    sql_keyword_density = keyword_hits / max(1, len(words))

    special_count = sum(1 for ch in text if ch in SPECIAL_CHARS)
    quote_count = text.count("'") + text.count('"')
    semicolon_count = text.count(";")
    comment_count = sum(lowered.count(pattern) for pattern in COMMENT_PATTERNS)
    encoded_count = sum(lowered.count(pattern) for pattern in ENCODING_PATTERNS)
    equals_count = text.count("=")
    boolean_logic_count = len(re.findall(r"\b(or|and)\b\s+[^\s]+\s*=", lowered))
    digit_count = sum(ch.isdigit() for ch in text)
    whitespace_count = sum(ch.isspace() for ch in text)
    uppercase_count = sum(ch.isupper() for ch in text)
    alpha_count = sum(ch.isalpha() for ch in text)
    suspicious_function_count = len(
        re.findall(r"\b(sleep|benchmark|load_file|outfile|xp_cmdshell)\b", lowered)
    )
    tautology_count = len(
        re.findall(r"(?:'|\")?\s*\d+\s*(?:'|\")?\s*=\s*(?:'|\")?\s*\d+", lowered)
    ) + len(re.findall(r"(?:'|\")?[a-z]\w*\s*(?:'|\")?\s*=\s*(?:'|\")?[a-z]\w*", lowered))

    return [
        float(length),
        float(special_count),
        float(quote_count),
        float(semicolon_count),
        float(comment_count),
        float(encoded_count),
        float(equals_count),
        float(keyword_hits),
        float(sql_keyword_density),
        float(boolean_logic_count),
        float(digit_count),
        float(whitespace_count),
        float(uppercase_count / max(1, length)),
        float(alpha_count / max(1, length)),
        float(shannon_entropy(text)),
        float(suspicious_function_count),
        float(tautology_count),
        float("union" in lowered and "select" in lowered),
        float("information_schema" in lowered),
        float("--" in lowered or "#" in lowered),
    ]


FEATURE_NAMES = [
    "length",
    "special_count",
    "quote_count",
    "semicolon_count",
    "comment_count",
    "encoded_count",
    "equals_count",
    "sql_keyword_hits",
    "sql_keyword_density",
    "boolean_logic_count",
    "digit_count",
    "whitespace_count",
    "uppercase_ratio",
    "alpha_ratio",
    "entropy",
    "suspicious_function_count",
    "tautology_count",
    "union_select_combo",
    "information_schema_flag",
    "comment_token_flag",
]


def vectorize(payloads: Iterable[str]) -> np.ndarray:
    """Vectorize many payloads into a two-dimensional NumPy array."""
    return np.array([extract_features(payload) for payload in payloads], dtype=float)
