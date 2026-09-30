FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .
RUN chmod +x docker/entrypoint.sh \
    && python ml/generate_dataset.py --output ml/dataset.csv \
    && python ml/train_model.py --dataset ml/dataset.csv --output app/models/sql_injection_rf.joblib --metrics docs/ml_model_metrics.json

EXPOSE 5000
ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["gunicorn", "-b", "0.0.0.0:5000", "run:app", "--workers", "1", "--threads", "4", "--timeout", "120"]
