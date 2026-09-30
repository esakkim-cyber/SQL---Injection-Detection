# Security Analysis

## 1. Threat Model

The protected asset is the demo user database. The attacker controls login form inputs and tries to make the database execute unintended SQL.

### Attacker Goals

- Bypass authentication.
- Extract usernames or passwords.
- Modify or destroy database tables.
- Trigger time-based blind SQL injection.
- Hide payloads with comments or encoding.
- Repeat attempts until one works.

### Trust Boundaries

| Boundary | Risk |
|---|---|
| Browser to Flask app | User input is untrusted |
| Flask app to database | SQL queries must not contain executable user input |
| Detection engine to logs | Payloads must be logged safely and displayed escaped |
| Dashboard to user | Logs must not execute HTML or scripts |

## 2. Vulnerability Demonstrated

The vulnerable route uses string concatenation:

```python
query = "SELECT ... WHERE username = '" + username + "' AND password_plain = '" + password + "'"
```

A malicious username like:

```text
' OR '1'='1' --
```

changes the SQL condition to a true condition and comments out the password check.

## 3. Detection Analysis

### Regex Detection

Strengths:

- Fast.
- Easy to explain.
- Good for known patterns.
- Useful for immediate blocking.

Weaknesses:

- Attackers can obfuscate payloads.
- Regex can produce false positives.
- Signatures need maintenance.

### Machine Learning Detection

Strengths:

- Learns combinations of suspicious features.
- Useful for payloads that do not exactly match one regex.
- Provides probability for scoring.

Weaknesses:

- Synthetic dataset is not enough for production.
- Can be bypassed by adversarial examples.
- Needs retraining and validation.

### Behavioral Detection

Strengths:

- Catches repeated failures and bursts.
- Works even when individual payloads are not obvious.

Weaknesses:

- In-memory state resets on restart.
- Distributed attackers can spread attempts across IPs.

## 4. Prevention Analysis

### Parameterized Queries

This is the strongest implemented prevention method. Bound parameters keep user input as data and prevent it from changing SQL structure.

### Input Validation

The secure login accepts usernames only if they match:

```text
^[A-Za-z0-9_]{3,30}$
```

This blocks obvious SQL syntax in usernames.

### Mini-WAF Blocking

The WAF blocks high-risk payloads before database execution. It is useful as defense-in-depth, but it should not replace secure coding.

### ORM Usage

SQLAlchemy models reduce raw SQL usage and make safer data access easier.

### Password Hashing

The secure route verifies `password_hash`, so stored passwords are not directly compared as plaintext in the secure path.

## 5. Risk Scoring

The system calculates risk from:

- Regex rule weights
- ML probability
- Anomaly score

Severity levels:

| Risk Score | Severity |
|---|---|
| 0-39 | LOW |
| 40-69 | MEDIUM |
| 70-84 | HIGH |
| 85-100 | CRITICAL |

Secure mode blocks when risk score is at least `70` by default.

## 6. Security Controls Matrix

| Attack Type | Regex | ML | Anomaly | Validation | Prepared Query | Logging | Alert |
|---|---:|---:|---:|---:|---:|---:|---:|
| Login tautology | Yes | Yes | Sometimes | Yes | Yes | Yes | Yes |
| UNION SELECT | Yes | Yes | Sometimes | Yes | Yes | Yes | Yes |
| DROP TABLE | Yes | Yes | Sometimes | Yes | Yes | Yes | Yes |
| Encoded quote | Yes | Yes | Sometimes | Yes | Yes | Yes | Yes |
| Time delay | Yes | Yes | Sometimes | Yes | Yes | Yes | Yes |
| Many failed logins | No | No | Yes | Yes | Yes | Yes | Sometimes |

## 7. Secure Development Practices Applied

- Defense in depth: detection + validation + parameterization + monitoring.
- Least exposure: vulnerable route is clearly isolated for lab demonstration.
- Explainability: matched rules and ML features are shown.
- Testing: unit tests prove detection and prepared-statement behavior.
- Dockerization: consistent environment for grading and demonstration.
- Logging: all security-relevant events are captured.

## 8. Remaining Limitations

This project is intentionally educational. For production, add:

- HTTPS and secure cookies.
- CSRF protection.
- Real user management and account lockout.
- Centralized logging such as ELK, Wazuh, or Splunk.
- Larger real-world dataset.
- Database least-privilege user permissions.
- Secrets management instead of plain environment variables.
- Rate limiting with Redis or another shared store.
- Full external alert integrations.
- Regular dependency scanning.

## 9. Conclusion

The project demonstrates both the vulnerability and the defense. The vulnerable mode proves the attack impact, while secure mode shows that prepared statements, validation, detection, logging, and alerts provide a strong practical protection architecture.
