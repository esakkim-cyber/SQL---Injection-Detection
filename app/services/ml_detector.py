"""Machine-learning detector wrapper."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

from ml.feature_engineering import FEATURE_NAMES, extract_features


@dataclass
class MLResult:
    """Structured ML prediction result."""

    detected: bool
    probability: float
    label: int
    feature_values: dict[str, float]


class MLDetector:
    """Load and run the trained Random Forest classifier."""

    def __init__(self, model_path: str | Path, threshold: float = 0.62):
        self.model_path = Path(model_path)
        self.threshold = threshold
        self.model_bundle: dict[str, Any] | None = None
        self.model = None
        self.feature_names = FEATURE_NAMES
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path.exists():
            self.model_bundle = joblib.load(self.model_path)
            self.model = self.model_bundle.get("model")
            self.feature_names = self.model_bundle.get("feature_names", FEATURE_NAMES)
            self.threshold = float(self.model_bundle.get("threshold", self.threshold))
        else:
            # The app remains usable even if the model was not trained yet. The
            # README explains how to run ml/train_model.py to create the file.
            self.model_bundle = None
            self.model = None

    def predict(self, payload: str) -> MLResult:
        features = extract_features(payload)
        feature_map = {name: float(value) for name, value in zip(self.feature_names, features)}

        if self.model is None:
            return MLResult(
                detected=False,
                probability=0.0,
                label=0,
                feature_values=feature_map,
            )

        if hasattr(self.model, "predict_proba"):
            probability = float(self.model.predict_proba([features])[0][1])
        else:
            probability = float(self.model.predict([features])[0])

        label = int(probability >= self.threshold)
        return MLResult(
            detected=bool(label),
            probability=round(probability, 4),
            label=label,
            feature_values=feature_map,
        )
