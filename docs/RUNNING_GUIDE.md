# Step-by-Step Running Guide

Project: **SQL Injection Detection and Prevention System**

Requested Windows folder:

```text
<path to your clone>
```

## 1. Requirements

Install these before running:

- Docker Desktop
- A web browser such as Chrome, Edge, or Firefox
- Optional: Git, Python 3.11, VS Code

## 2. Extract the Project

Extract the zip so the project files are directly inside:

```text
<path to your clone>
```

The folder should contain:

```text
app/
ml/
docs/
tests/
Dockerfile
docker-compose.yml
README.md
requirements.txt
run.py
```

## 3. Start with Docker Compose

Open PowerShell or Command Prompt and run:

```powershell
cd sql-injection-detection
docker compose up -d --build
```

This starts two containers:

| Container | Purpose |
|---|---|
| `sqli_lab_mysql` | MySQL database with seeded demo users |
| `sqli_detection_web` | Flask + ML + dashboard web application |

## 4. Verify the Containers

```powershell
docker compose ps
```

Both services should show `running` or `healthy`.

To view web logs:

```powershell
docker compose logs -f web
```

## 5. Open the Web App

Go to:

```text
http://localhost:5000
```

## 6. Demo Credentials

| Username | Password | Role |
|---|---|---|
| admin | password123 | admin |
| alice | alice123 | student |
| bob | bob123 | student |

## 7. Recommended Demonstration Flow

### Step A - Normal Secure Login

1. Open `http://localhost:5000/login`.
2. Select **Secure WAF + prepared**.
3. Enter:

```text
username: alice
password: alice123
```

4. Result should show successful secure login.

### Step B - Vulnerable Before Case

1. On the same login page, select **Vulnerable raw SQL**.
2. Enter:

```text
username: ' OR '1'='1' --
password: wrong
```

3. Result should show that vulnerable mode may log in because the raw SQL logic was changed.
4. The detection section should show a high risk score.

### Step C - Secure After Case

1. Select **Secure WAF + prepared**.
2. Use the same payload:

```text
username: ' OR '1'='1' --
password: wrong
```

3. Result should show **Blocked by Mini-WAF before database execution**.

### Step D - Prepared Statements Only

1. Select **Prepared only comparison**.
2. Use the same payload again.
3. Result should show no bypass because the payload is treated as literal text.

### Step E - Full Attack Lab

1. Open `http://localhost:5000/attack-lab`.
2. Click **Run Full Attack Lab**.
3. Show the table comparing vulnerable, secure, and prepared-only behavior.

### Step F - Dashboard and Alerts

1. Open `http://localhost:5000/dashboard`.
2. Show total events, blocked events, risk scores, severity distribution, detection methods, and evidence logs.
3. Open `http://localhost:5000/alerts`.
4. Show alerts generated for high/critical attempts.

## 8. Stop the Project

```powershell
docker compose down
```

## 9. Reset the Database

Use this when you want a clean demonstration:

```powershell
docker compose down -v
docker compose up -d --build
```

## 10. Re-train the ML Model Manually

Inside the project folder:

```powershell
docker compose exec web python ml/train_model.py --dataset ml/dataset.csv --output app/models/sql_injection_rf.joblib --metrics docs/ml_model_metrics.json
```

Or locally without Docker:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python ml/generate_dataset.py --output ml/dataset.csv
python ml/train_model.py --dataset ml/dataset.csv --output app/models/sql_injection_rf.joblib --metrics docs/ml_model_metrics.json
python run.py
```

## 11. Troubleshooting

### Port 5000 already used

Change the left side of the port mapping in `docker-compose.yml`:

```yaml
ports:
  - "5050:5000"
```

Then open:

```text
http://localhost:5050
```

### MySQL port conflict

The database is mapped to host port `3307`, not `3306`, to reduce conflicts. If needed, change:

```yaml
ports:
  - "3308:3306"
```

### Docker build cache issue

```powershell
docker compose build --no-cache
docker compose up -d
```

### Completely clean restart

```powershell
docker compose down -v --remove-orphans
docker compose up -d --build
```
