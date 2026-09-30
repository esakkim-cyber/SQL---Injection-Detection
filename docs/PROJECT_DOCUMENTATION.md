# Project Documentation

## 1. Project Name

**SQL Injection Detection and Prevention System**

## 2. Goal

The project solves a security problem: detecting and preventing SQL injection attacks in web applications. It includes a deliberately vulnerable login flow for demonstration, then compares it with a secure implementation using multiple prevention methods.

## 3. System Architecture

```text
Browser UI
   |
   v
Flask Routes
   |
   +--> Mini-WAF middleware
   |       +--> Regex Detector
   |       +--> ML Detector
   |       +--> Anomaly Detector
   |
   +--> Vulnerable Login Demo  -> raw concatenated SQL
   |
   +--> Secure Login Demo      -> validation + prepared statement + password hash
   |
   +--> Logging Service        -> SecurityEvent table
   |
   +--> Alert Service          -> Alert table + optional external channels
   |
   v
MySQL Database in Docker
```

## 4. File-by-File Explanation

### `app/__init__.py`

Creates the Flask app, loads configuration, initializes the database, loads the detection engine, and registers the Mini-WAF middleware.

Important behavior:

- Every request is inspected before route execution.
- The WAF stores its analysis in `g.waf_result`.
- Secure routes use the result to block high-risk requests.
- Vulnerable routes run in monitor mode so the before/after demo remains visible.

### `app/config.py`

Reads environment variables for database URL, ML model path, WAF threshold, and alert settings.

Important variables:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | MySQL or SQLite connection string |
| `ML_MODEL_PATH` | Path to trained Random Forest model |
| `RISK_BLOCK_THRESHOLD` | Minimum risk score required to block |
| `ENABLE_VULNERABLE_DEMO` | Keeps vulnerable lab route enabled or disabled |
| `GLOBAL_WAF_BLOCKING` | Reserved option for future global blocking |

### `app/database.py`

Creates database tables and seeds demo users.

Seeded users:

| Username | Password | Role |
|---|---|---|
| admin | password123 | admin |
| alice | alice123 | student |
| bob | bob123 | student |

The secure route uses password hashes. The plaintext field exists only for the vulnerable demonstration route.

### `app/models.py`

Defines database models:

| Model | Purpose |
|---|---|
| `User` | Demo users |
| `SecurityEvent` | Logs all detection and prevention events |
| `Alert` | Stores high-risk alert notifications |

### `app/services/detection_engine.py`

Main hybrid detection engine. It combines:

1. Regex signatures
2. Machine-learning classifier
3. Behavioral anomaly detection

It returns a structured `DetectionResult` with:

- payload
- regex result
- ML probability
- anomaly result
- risk score
- severity
- matched regex rules
- recommendation

### Regex Rules Implemented

| Rule | Detects |
|---|---|
| Quote or SQL comment | `'`, `--`, `#`, `%27` |
| UNION SELECT | Data extraction attempts |
| DROP/DELETE | Destructive statements |
| Boolean tautology | `OR 1=1`, `AND 'x'='x` |
| Stacked query | `; SELECT`, `; DROP` |
| SQL metadata | `information_schema`, system tables |
| Time-based payload | `sleep`, `benchmark`, `waitfor delay` |
| xp_cmdshell | SQL Server command execution procedure |
| Encoded injection | URL/hex/char encoded attacks |
| Inline SQL comment | `/**/` obfuscation |

### `app/services/ml_detector.py`

Loads the trained model from `app/models/sql_injection_rf.joblib`. If the model file is missing, the app still runs but ML probability remains `0.0` until training is completed.

### `app/services/anomaly_detector.py`

Tracks behavior per IP address:

- Too many requests in a short time
- Multiple failed logins in a short time

This demonstrates behavioral or anomaly-based detection.

### `app/services/auth_service.py`

Contains three login flows:

#### Vulnerable Flow

```python
query = "SELECT ... WHERE username = '" + username + "' AND password_plain = '" + password + "'"
```

This is intentionally unsafe and is used only for demonstration.

#### Secure Flow

Security features:

- Whitelist validation for username
- Parameterized SQL query
- Password hash verification

#### Prepared-Only Flow

Shows that prepared statements alone prevent the SQL logic from being changed, even when a payload is passed as input.

### `app/services/alert_service.py`

Creates alerts when an event is high or critical risk. Alerts are always stored in the database. Optional channels can be added through environment variables.

### `app/routes.py`

Defines all frontend pages and APIs:

| Route | Purpose |
|---|---|
| `/` | Project overview |
| `/login` | Vulnerable vs secure login demo |
| `/playground` | Detection-only payload analyzer |
| `/attack-lab` | Predefined before/after use cases |
| `/dashboard` | Logs, charts, metrics |
| `/alerts` | Alert center |
| `/documentation` | Project documentation map |
| `/api/analyze` | JSON detection API |
| `/api/attack-simulation` | Runs demo payload comparisons |
| `/api/stats` | Dashboard statistics |
| `/api/events` | Event log JSON |

## 5. Machine Learning Details

### `ml/generate_dataset.py`

Builds a labeled dataset from:

- normal usernames
- normal passwords
- normal search strings
- common SQL injection payloads
- encoded payloads
- mutated payloads

### `ml/feature_engineering.py`

Extracts explainable features such as:

| Feature | Why it helps |
|---|---|
| payload length | Attacks can be longer than usernames |
| quote count | SQL injection often uses quotes |
| comment count | `--`, `#`, `/* */` comment out query parts |
| keyword count | `UNION`, `SELECT`, `DROP`, `OR` are strong signals |
| entropy | Encoded/obfuscated strings can have unusual distribution |
| encoded count | `%27`, `0x`, `char()` indicate encoding tricks |
| tautology count | Detects `1=1`, `x=x` patterns |
| function count | Detects `sleep`, `benchmark`, `xp_cmdshell` |

### `ml/train_model.py`

Trains and compares:

- Random Forest
- Naive Bayes
- SVM

The deployed model is Random Forest because it performs well on nonlinear handcrafted features and provides feature importance.

Training output is stored in:

```text
app/models/sql_injection_rf.joblib
docs/ml_model_metrics.json
```

## 6. Prevention Methods

### A. Parameterized Queries

The secure route uses bound parameters:

```python
stmt = text("SELECT ... FROM users WHERE username = :username")
db.session.execute(stmt, {"username": username})
```

This prevents the input from changing SQL syntax.

### B. Input Validation

The secure route accepts only:

```text
A-Z, a-z, 0-9, underscore, length 3-30
```

### C. Mini-WAF

The Mini-WAF analyzes payloads before the database query. If the risk score exceeds the threshold, it blocks the request.

### D. ORM / SQLAlchemy

SQLAlchemy is used for database access, table models, and safer query patterns.

### E. Password Hashing

Secure login checks a stored password hash instead of comparing plaintext passwords.

### F. Logging and Monitoring

Every demo attempt is logged with:

- IP address
- endpoint
- payload
- detection methods
- risk score
- severity
- action taken
- mode
- timestamp

### G. Alerts

High and critical events generate alerts for the dashboard.

## 7. Use Cases Covered

| Use Case | Vulnerable Mode | Secure Mode |
|---|---|---|
| Normal correct login | succeeds | succeeds |
| Wrong password | fails | fails |
| `' OR '1'='1' --` | bypass possible | blocked |
| `admin' --` | bypass possible | blocked |
| `UNION SELECT` | detected/logged | blocked |
| `DROP TABLE` | detected/logged; DB may reject stacked query | blocked |
| encoded injection | detected/logged | blocked |
| repeated failed login | anomaly risk increases | logged and can block |
| prepared statement comparison | not used | payload treated as literal text |

## 8. Testing

Tests are in `tests/`.

Run:

```bash
pytest -q
```

Tests cover:

- Regex detection of classic tautology payloads
- Low risk for normal usernames
- Feature extraction vector length
- Keyword feature behavior
- Vulnerable login bypass demonstration
- Prepared statement prevention
- Secure login success for valid user

## 9. Security Limitations

This is a strong educational project but not a production WAF. Limitations:

- ML dataset is synthetic and small.
- In-memory anomaly tracking resets when the container restarts.
- The vulnerable login route is intentionally unsafe.
- External alert integrations are placeholders unless credentials are configured.
- Production systems need HTTPS, secrets management, account lockout, CSRF protection, secure cookies, and centralized monitoring.

## 10. Best Presentation Script

1. Explain SQL injection and why it matters.
2. Show vulnerable raw SQL query.
3. Run a normal login.
4. Run a malicious payload in vulnerable mode.
5. Show detection output.
6. Run the same payload in secure mode.
7. Explain prepared statements.
8. Run the Attack Lab.
9. Show dashboard and alerts.
10. Explain ML features and evaluation.
11. End with limitations and future work.
