# Use Cases and Demonstration Script

## Use Case 1 - Normal Login Works

**Purpose:** Prove the application still works for legitimate users.

Steps:

1. Open `/login`.
2. Select **Secure WAF + prepared**.
3. Enter `alice` and `alice123`.
4. Submit.

Expected result:

- Login succeeds.
- Risk score remains low.
- Query preview shows parameterized query.

## Use Case 2 - Vulnerable Login Bypass

**Purpose:** Demonstrate the problem before prevention.

Steps:

1. Open `/login`.
2. Select **Vulnerable raw SQL**.
3. Enter username:

```text
' OR '1'='1' --
```

4. Enter any password, such as `wrong`.
5. Submit.

Expected result:

- Vulnerable mode may return a logged-in user.
- Regex detects quote/comment/tautology.
- ML probability is high.
- Event is logged.

Explanation:

The payload changes the WHERE condition so it becomes true for rows in the users table. The `--` comments out the remaining password check.

## Use Case 3 - Secure Mode Blocks Attack

**Purpose:** Show prevention after detection.

Steps:

1. Use the same payload.
2. Select **Secure WAF + prepared**.
3. Submit.

Expected result:

- Request is blocked before database execution.
- Dashboard receives a blocked security event.
- Alert center receives a high-risk alert.

## Use Case 4 - Prepared Statement Prevents Bypass

**Purpose:** Show that SQL parameters treat the attack as data.

Steps:

1. Select **Prepared only comparison**.
2. Submit the same payload.

Expected result:

- No login bypass.
- Query preview shows named parameters.
- Message says payload was treated as a literal username.

## Use Case 5 - UNION SELECT Attack Detection

Payload:

```text
' UNION SELECT 1, username, password_plain, role FROM users --
```

Expected result:

- Regex rule `UNION SELECT` fires.
- ML probability is high.
- Secure mode blocks the request.
- Alert is generated.

## Use Case 6 - Destructive SQL Attempt

Payload:

```text
'; DROP TABLE users; --
```

Expected result:

- Regex detects stacked query and destructive keyword.
- Secure mode blocks the request.
- Vulnerable route logs the attempt. Modern drivers may reject multiple statements, which is still useful evidence in the demo.

## Use Case 7 - Encoded Attack

Payload:

```text
%27 OR 1=1--
```

Expected result:

- Regex detects encoded quote pattern.
- ML detects high-risk features.
- Secure mode blocks or rejects input validation.

## Use Case 8 - Time-Based Blind Payload

Payload:

```text
' OR sleep(5) --
```

Expected result:

- Regex detects time-based attack keyword.
- Risk score becomes high.
- Secure mode blocks before database execution.

## Use Case 9 - Anomaly Detection

Steps:

1. Try multiple wrong logins quickly.
2. Observe dashboard logs.

Expected result:

- Failed login behavior contributes to anomaly risk.
- Repeated activity is logged.

## Use Case 10 - Dashboard Evidence

Steps:

1. Run the Attack Lab.
2. Open `/dashboard`.

Expected result:

- Total event count increases.
- Blocked count increases.
- Severity chart shows high/critical events.
- Detection methods chart shows regex/ML/anomaly counts.
- Latest events table contains payload, risk score, and action taken.

## Use Case 11 - Alert Center

Steps:

1. Run high-risk payloads.
2. Open `/alerts`.

Expected result:

- Alert title shows severity.
- Message includes endpoint, IP, risk score, detection methods, action, and payload.

## Use Case 12 - Detection Playground

Steps:

1. Open `/playground`.
2. Enter any payload.
3. Click **Analyze Payload**.

Expected result:

- Risk meter updates.
- Regex matches display.
- ML feature snapshot displays.
- No database query is executed.
