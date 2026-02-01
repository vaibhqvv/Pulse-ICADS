import os
import logging
from typing import Optional
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

import config

logger = logging.getLogger(__name__)

# running min/max for score normalization
_score_min = float("inf")
_score_max = float("-inf")


def _update_score_range(raw_score: float) -> None:
    global _score_min, _score_max
    if raw_score < _score_min:
        _score_min = raw_score
    if raw_score > _score_max:
        _score_max = raw_score


def _reset_score_range() -> None:
    global _score_min, _score_max
    _score_min = float("inf")
    _score_max = float("-inf")


def train_model(X: np.ndarray) -> IsolationForest:
    if X.ndim == 1:
        X = X.reshape(1, -1)

    logger.info(f"Training Isolation Forest on {X.shape[0]} samples, "
                f"{X.shape[1]} features")

    model = IsolationForest(
        n_estimators=config.N_ESTIMATORS,
        contamination=config.CONTAMINATION,
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X)

    _reset_score_range()

    # initialize min/max range with training data
    raw_scores = model.decision_function(X)
    for s in raw_scores:
        _update_score_range(s)

    logger.info(f"Model trained. Initial score range: [{_score_min:.4f}, {_score_max:.4f}]")
    return model


def save_model(model: IsolationForest, path: Optional[str] = None) -> None:
    path = path or config.MODEL_PATH
    joblib.dump(model, path)
    logger.info(f"Model saved to {path}")


def load_model(path: Optional[str] = None) -> IsolationForest:
    path = path or config.MODEL_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found: {path}")

    model = joblib.load(path)
    logger.info(f"Model loaded from {path}")
    return model


def load_or_train_model() -> IsolationForest:
    try:
        return load_model()
    except FileNotFoundError:
        logger.warning("No saved model found — generating synthetic baseline for cold start")
        X = generate_synthetic_baseline(n_samples=1000)
        model = train_model(X)
        save_model(model)
        return model


def generate_synthetic_baseline(n_samples: int = 1000) -> np.ndarray:
    rng = np.random.RandomState(config.RANDOM_STATE)

    packets_per_sec = rng.uniform(30, 200, n_samples)
    bytes_per_sec = rng.uniform(2000, 20000, n_samples)
    unique_src_ips = rng.uniform(1, 10, n_samples)
    top_ip_ratio = rng.uniform(0.2, 0.8, n_samples)
    alerts_per_sec = rng.uniform(0, 2, n_samples)

    X = np.column_stack([
        packets_per_sec,
        bytes_per_sec,
        unique_src_ips,
        top_ip_ratio,
        alerts_per_sec,
    ])
    logger.info(f"Generated {n_samples} synthetic baseline samples")
    return X


def predict_anomaly_score(model: IsolationForest, feature_vector: np.ndarray) -> float:
    if feature_vector.ndim == 1:
        feature_vector = feature_vector.reshape(1, -1)

    # sklearn returns lower scores for anomalies, we invert
    raw_score = model.decision_function(feature_vector)[0]
    _update_score_range(raw_score)

    score_range = _score_max - _score_min + 1e-9
    anomaly_score = 1.0 - ((raw_score - _score_min) / score_range)

    # clamp to [0, 1]
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    return anomaly_score


def classify_alert(
    anomaly_score: float,
    anomaly_threshold: Optional[float] = None,
    attack_threshold: Optional[float] = None,
    suricata_severity: Optional[int] = None,
) -> str:
    anomaly_threshold = anomaly_threshold or config.ANOMALY_THRESHOLD
    attack_threshold = attack_threshold or config.ATTACK_THRESHOLD

    # severity 1 always forces attack
    if suricata_severity == 1:
        return "attack"

    if anomaly_score < anomaly_threshold:
        return "normal"
    elif anomaly_score < attack_threshold:
        return "suspicious"
    else:
        return "attack"


def normalize_features(features: dict) -> np.ndarray:
    feature_order = [
        "packets_per_sec",
        "bytes_per_sec",
        "unique_src_ips",
        "top_ip_ratio",
        "alerts_per_sec",
    ]

    normalized = []
    for name in feature_order:
        value = features.get(name, 0)
        f_range = config.FEATURE_RANGES[name]
        f_min = f_range["min"]
        f_max = f_range["max"]

        if f_max - f_min == 0:
            norm_val = 0.0
        else:
            norm_val = (value - f_min) / (f_max - f_min)
        norm_val = max(0.0, min(1.0, norm_val))
        normalized.append(norm_val)

    return np.array(normalized)
