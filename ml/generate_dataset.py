"""Generate a compact labeled dataset for SQL injection detection.

The dataset is intentionally transparent: it combines normal web-login inputs
with common educational SQL injection payload patterns. The model is not a
replacement for parameterized queries; it is a detection layer for monitoring,
alerting, and defense-in-depth.
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

NORMAL_INPUTS = [
    "admin",
    "alice",
    "bob",
    "student2026",
    "information_security",
    "pass1234",
    "hello world",
    "customer_support",
    "2026-05-22",
    "john_doe",
    "report_final",
    "semester6",
    "lahore",
    "karachi",
    "qasim123",
    "Aisha_112",
    "securePassword99",
    "email@example.com",
    "find user by id",
    "normal search query",
    "blue notebook",
    "project dashboard",
    "csrf token value",
    "user profile update",
    "abc_xyz_123",
    "login attempt failed",
    "read only mode",
    "data science class",
    "network security",
    "software engineering",
]

SQLI_PAYLOADS = [
    "' OR '1'='1' -- ",
    "' OR 1=1 -- ",
    "admin' -- ",
    "' OR 'a'='a",
    "' OR 1=1#",
    "\" OR \"1\"=\"1\" -- ",
    "' UNION SELECT username, password FROM users -- ",
    "' UNION SELECT NULL, NULL, NULL -- ",
    "'; DROP TABLE users; --",
    "'; DELETE FROM users WHERE '1'='1'; --",
    "' AND 1=2 UNION SELECT 1,2,3 -- ",
    "1 OR 1=1",
    "1; SELECT * FROM users",
    "105 OR 1=1",
    "' OR sleep(5) -- ",
    "' OR benchmark(1000000,md5('x')) -- ",
    "' OR EXISTS(SELECT * FROM users) -- ",
    "' HAVING 1=1 -- ",
    "' ORDER BY 1--",
    "' GROUP BY username--",
    "' AND 'x'='x",
    "%27%20OR%201%3D1--",
    "0x27204f5220313d312d2d",
    "' OR '1' LIKE '1",
    "') OR ('1'='1",
    "anything' OR 'x'='x",
    "' UNION SELECT table_name FROM information_schema.tables -- ",
    "' UNION SELECT column_name FROM information_schema.columns -- ",
    "'; EXEC xp_cmdshell('whoami'); --",
    "admin'/*",
]


def mutate_payload(payload: str) -> str:
    """Create small variations so the model sees multiple forms."""
    variants = [
        payload,
        payload.upper(),
        payload.replace(" ", "/**/"),
        payload.replace("'", "%27"),
        payload.replace("--", "-- "),
        f"{payload} ",
    ]
    return random.choice(variants)


def build_rows(seed: int = 42) -> list[dict[str, str | int]]:
    random.seed(seed)
    rows: list[dict[str, str | int]] = []

    for value in NORMAL_INPUTS:
        rows.append({"payload": value, "label": 0})
        rows.append({"payload": f"{value}_{random.randint(1, 999)}", "label": 0})
        rows.append({"payload": value.title(), "label": 0})

    for payload in SQLI_PAYLOADS:
        rows.append({"payload": payload, "label": 1})
        for _ in range(5):
            rows.append({"payload": mutate_payload(payload), "label": 1})

    random.shuffle(rows)
    return rows


def write_dataset(output: Path) -> None:
    rows = build_rows()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["payload", "label"])
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="ml/dataset.csv")
    args = parser.parse_args()
    write_dataset(Path(args.output))
    print(f"Dataset written to {args.output}")
