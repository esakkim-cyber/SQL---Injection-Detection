"""Train and evaluate the SQL injection machine-learning detector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from ml.feature_engineering import FEATURE_NAMES, vectorize
from ml.generate_dataset import write_dataset


def train(dataset_path: Path, output_path: Path, metrics_path: Path) -> dict:
    """Train three classifiers and save the best Random Forest pipeline.

    Random Forest is kept as the deployed model because it gives strong accuracy
    on nonlinear handcrafted features while still offering feature importance.
    Naive Bayes and SVM are evaluated for comparison in the report.
    """
    if not dataset_path.exists():
        write_dataset(dataset_path)

    df = pd.read_csv(dataset_path)
    X = vectorize(df["payload"].astype(str).tolist())
    y = df["label"].astype(int).to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=180,
            max_depth=12,
            class_weight="balanced",
            random_state=42,
        ),
        "NaiveBayes": GaussianNB(),
        "SVM": Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("svm", SVC(C=2.0, kernel="rbf", probability=True, random_state=42)),
            ]
        ),
    }

    comparison: dict[str, dict[str, float | list[list[int]] | str]] = {}
    fitted_models = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        fitted_models[name] = model
        preds = model.predict(X_test)
        comparison[name] = {
            "accuracy": round(float(accuracy_score(y_test, preds)), 4),
            "f1": round(float(f1_score(y_test, preds)), 4),
            "confusion_matrix": confusion_matrix(y_test, preds).tolist(),
            "classification_report": classification_report(y_test, preds, output_dict=False),
        }

    # Use RandomForest for deployment and store metadata alongside the model.
    deployed = fitted_models["RandomForest"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": deployed,
            "feature_names": FEATURE_NAMES,
            "threshold": 0.62,
            "comparison": comparison,
        },
        output_path,
    )

    if hasattr(deployed, "feature_importances_"):
        importances = sorted(
            zip(FEATURE_NAMES, deployed.feature_importances_), key=lambda item: item[1], reverse=True
        )
    else:
        importances = []

    metrics = {
        "dataset_rows": int(len(df)),
        "positive_samples": int(df["label"].sum()),
        "negative_samples": int((df["label"] == 0).sum()),
        "feature_names": FEATURE_NAMES,
        "model_comparison": comparison,
        "deployed_model": "RandomForest",
        "feature_importance": [
            {"feature": name, "importance": round(float(score), 4)} for name, score in importances
        ],
    }
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="ml/dataset.csv")
    parser.add_argument("--output", default="app/models/sql_injection_rf.joblib")
    parser.add_argument("--metrics", default="docs/ml_model_metrics.json")
    args = parser.parse_args()

    result = train(Path(args.dataset), Path(args.output), Path(args.metrics))
    print(json.dumps(result["model_comparison"], indent=2))
