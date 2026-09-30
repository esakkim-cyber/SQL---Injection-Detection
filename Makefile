.PHONY: build up down logs train test zip

build:
	docker compose build

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f web

train:
	python ml/generate_dataset.py --output ml/dataset.csv
	python ml/train_model.py --dataset ml/dataset.csv --output app/models/sql_injection_rf.joblib --metrics docs/ml_model_metrics.json

test:
	pytest -q

zip:
	cd .. && zip -r final-project-SQLInjection.zip final-project-SQLInjection -x "*/__pycache__/*" "*.pyc" ".venv/*"
