#!/usr/bin/env sh
set -e

# Wait for MySQL when DATABASE_URL points to the Compose service named "db".
if [ -n "$MYSQL_HOST" ]; then
  echo "Waiting for MySQL at $MYSQL_HOST:${MYSQL_PORT:-3306}..."
  until nc -z "$MYSQL_HOST" "${MYSQL_PORT:-3306}"; do
    sleep 2
  done
fi

# Re-train if the model is missing because a volume override replaced it.
if [ ! -f "${ML_MODEL_PATH:-/app/app/models/sql_injection_rf.joblib}" ]; then
  python ml/generate_dataset.py --output ml/dataset.csv
  python ml/train_model.py --dataset ml/dataset.csv --output "${ML_MODEL_PATH:-app/models/sql_injection_rf.joblib}" --metrics docs/ml_model_metrics.json
fi

exec "$@"
