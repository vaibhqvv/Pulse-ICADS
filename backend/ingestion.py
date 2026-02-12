import os
import sys
import json
import time
import logging
import threading
from datetime import datetime, timezone
from collections import deque
from typing import Optional, IO

import numpy as np

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

import config
import ml_model
import firebase_client
from feature_extractor import FeatureExtractor

logging.basicConfig(
    level=logging.INFO,
    format=config.LOG_FORMAT,
    datefmt=config.LOG_DATE_FORMAT,
)
logger = logging.getLogger(__name__)

model = None
is_model_ready = False
training_samples = []
training_start_time = None
extractor = FeatureExtractor()
recent_alerts = deque(maxlen=60)
last_retrain_time = time.time()
last_metrics_update = 0


def parse_eve_line(line: str) -> Optional[dict]:
    try:
        event = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        logger.debug("Skipping malformed JSON line...")
        return None

    if event.get("event_type") != "alert":
        return None

    alert_info = event.get("alert", {})
    parsed = {
        "event_type": "alert",
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "src_ip": event.get("src_ip", "0.0.0.0"),
        "dest_ip": event.get("dest_ip", "0.0.0.0"),
        "src_port": event.get("src_port", 0),
        "dest_port": event.get("dest_port", 0),
        "proto": event.get("proto", "UNKNOWN"),
        "alert": {
            "signature": alert_info.get("signature", "Unknown Alert"),
            "severity": alert_info.get("severity", 3),
            "category": alert_info.get("category", "Uncategorized"),
            "signature_id": alert_info.get("signature_id", 0),
        },
        "packet_count": event.get("pcap_cnt", 1),
        "bytes": event.get("flow", {}).get("bytes_toserver", 0)
                 + event.get("flow", {}).get("bytes_toclient", 0),
    }
    return parsed


def severity_int_to_str(severity_int: int) -> str:
    severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}
    return severity_map.get(severity_int, "medium")


def build_alert_doc(event: dict, classification: str, anomaly_score: float,
                    features: dict) -> dict:
    alert_info = event.get("alert", {})
    suricata_severity = alert_info.get("severity", 3)

    return {
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "src_ip": event.get("src_ip", "0.0.0.0"),
        "dest_ip": event.get("dest_ip", "0.0.0.0"),
        "src_port": event.get("src_port", 0),
        "dest_port": event.get("dest_port", 0),
        "protocol": event.get("proto", "UNKNOWN"),
        "alert_type": alert_info.get("signature", "Unknown Alert"),
        "severity": severity_int_to_str(suricata_severity),
        "category": alert_info.get("category", "Uncategorized"),
        "classification": classification,
        "anomaly_score": float(f"{anomaly_score:.4f}"),
        "packet_count": features.get("packets_per_sec", 0) * config.FEATURE_WINDOW_SEC,
        "bytes": int(features.get("bytes_per_sec", 0) * config.FEATURE_WINDOW_SEC),
        "source": "suricata",
        "acknowledged": False,
    }


def process_window():
    global is_model_ready, training_samples, model

    features = extractor.compute_features()
    summary = extractor.get_window_summary()
    event_count = extractor.get_event_count()

    feature_vector = ml_model.normalize_features(features)

    if is_model_ready and model is not None:
        # detection phase
        anomaly_score = ml_model.predict_anomaly_score(model, feature_vector)

        events = extractor.get_raw_events()
        min_severity = min(
            (e.get("alert", {}).get("severity", 4) for e in events),
            default=4
        )

        classification = ml_model.classify_alert(
            anomaly_score,
            suricata_severity=min_severity,
        )

        if min_severity == 1:
            anomaly_score = max(anomaly_score, 0.9)

        logger.info(f"Window: {event_count} events | Score: {anomaly_score:.3f} | "
                    f"Class: {classification} | PPS: {features['packets_per_sec']:.1f}")

        for event in events:
            alert_doc = build_alert_doc(event, classification, anomaly_score, features)
            try:
                firebase_client.write_alert(alert_doc)
            except Exception as e:
                logger.error(f"Failed to write alert: {e}")

        if classification == "attack":
            system_status = "critical"
        elif classification == "suspicious":
            system_status = "warning"
        else:
            system_status = "normal"

        summary["anomaly_score"] = anomaly_score
        summary["classification"] = classification
        try:
            firebase_client.write_traffic_snapshot(summary)
        except Exception as e:
            logger.error(f"Failed to write snapshot: {e}")

        recent_alerts.append({
            "time": time.time(),
            "classification": classification,
            "score": anomaly_score,
        })

    else:
        # training phase
        training_samples.append(feature_vector)
        elapsed = time.time() - (training_start_time or time.time())
        progress = min(100, int((elapsed / config.TRAINING_DURATION_SEC) * 100))

        logger.info(f"Training: {len(training_samples)} samples collected | "
                    f"Progress: {progress}% | PPS: {features['packets_per_sec']:.1f}")

        system_status = "training"

        if (elapsed >= config.TRAINING_DURATION_SEC and
                len(training_samples) >= config.MIN_TRAINING_SAMPLES):
            _complete_training()

    extractor.reset()


def _complete_training():
    global model, is_model_ready, training_samples

    X = np.array(training_samples)
    logger.info(f"Training phase complete. Fitting model on {X.shape[0]} samples...")

    model = ml_model.train_model(X)
    ml_model.save_model(model)

    is_model_ready = True
    training_samples = []

    try:
        firebase_client.update_system_config({
            "model_trained": True,
            "model_trained_at": datetime.now(timezone.utc),
            "model_training_samples": X.shape[0],
        })
    except Exception as e:
        logger.warning(f"Failed to update model config: {e}")

    logger.info("=== Model trained and ready for detection ===")


def update_live_metrics_tick():
    global last_metrics_update

    now = time.time()
    if (now - last_metrics_update) < config.LIVE_METRICS_INTERVAL_SEC:
        return
    last_metrics_update = now

    one_min_ago = now - 60
    alerts_last_min = sum(1 for a in recent_alerts if float(a["time"]) > one_min_ago)

    features = extractor.compute_features()

    progress = 100
    if is_model_ready:
        model_status = "ready"
        system_status = "normal"
    else:
        model_status = "training"
        system_status = "training"
        elapsed = now - (training_start_time or now)
        progress = min(100, int((elapsed / config.TRAINING_DURATION_SEC) * 100))

    if recent_alerts:
        current_score = recent_alerts[-1].get("score", 0.0)
        last_class = recent_alerts[-1].get("classification", "normal")
        if last_class == "attack":
            system_status = "critical"
        elif last_class == "suspicious":
            system_status = "warning"
    else:
        current_score = 0.0

    metrics = {
        "packets_per_sec": features.get("packets_per_sec", 0),
        "bytes_per_sec": features.get("bytes_per_sec", 0),
        "active_connections": features.get("unique_src_ips", 0),
        "alerts_last_minute": alerts_last_min,
        "current_anomaly_score": float(f"{current_score:.4f}"),
        "model_status": model_status,
        "model_training_progress": progress if not is_model_ready else 100,
        "system_status": system_status if is_model_ready else "training",
        "last_updated": int(now * 1000),
    }

    try:
        firebase_client.update_live_metrics(metrics)
    except Exception as e:
        logger.warning(f"Failed to update live metrics: {e}")


def retrain_if_needed():
    global last_retrain_time

    if not is_model_ready:
        return

    if (time.time() - last_retrain_time) < config.RETRAIN_INTERVAL_SEC:
        return

    if recent_alerts:
        last_class = recent_alerts[-1].get("classification", "normal")
        if last_class == "attack":
            logger.info("Skipping retrain — attack currently detected")
            return

    logger.info("Starting periodic model retraining in background thread...")
    last_retrain_time = time.time()

    thread = threading.Thread(target=_retrain_model, daemon=True)
    thread.start()


def _retrain_model():
    global model

    try:
        normal_samples = ml_model.generate_synthetic_baseline(n_samples=500)
        new_model = ml_model.train_model(normal_samples)
        ml_model.save_model(new_model)
        model = new_model

        firebase_client.update_system_config({
            "model_trained_at": datetime.now(timezone.utc),
            "model_training_samples": 500,
        })

        logger.info("Periodic retraining complete — new model active")
    except Exception as e:
        logger.error(f"Retraining failed: {e}")


class EveJsonHandler(FileSystemEventHandler if HAS_WATCHDOG else object):

    def __init__(self, filepath: str):
        self.filepath: str = filepath
        self.file: Optional[IO[str]] = None
        self._open_file()

    def _open_file(self) -> None:
        try:
            f = open(self.filepath, "r", encoding="utf-8")
            f.seek(0, 2)
            self.file = f
            logger.info(f"Watching {self.filepath} for new events...")
        except FileNotFoundError:
            logger.warning(f"Eve.json not found at {self.filepath}. "
                           f"Will retry when file appears.")
            self.file = None

    def on_modified(self, event):
        if event.src_path.endswith("eve.json"):
            self.read_new_lines()

    def read_new_lines(self) -> None:
        if self.file is None:
            self._open_file()
            
        f = self.file
        if f is None:
            return

        for line in f:
            line = line.strip()
            if not line:
                continue

            parsed = parse_eve_line(line)
            if parsed:
                extractor.add_event(parsed)

    def close(self) -> None:
        f = self.file
        if f is not None:
            f.close()
            self.file = None


def run_with_watchdog(eve_path: str):
    handler = EveJsonHandler(eve_path)
    observer = Observer()

    eve_dir = os.path.dirname(os.path.abspath(eve_path))
    observer.schedule(handler, eve_dir, recursive=False)
    observer.start()
    logger.info(f"Watchdog observer started on {eve_dir}")

    try:
        while True:
            handler.read_new_lines()

            if extractor.is_window_complete():
                process_window()

            update_live_metrics_tick()
            retrain_if_needed()

            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Shutting down ingestion pipeline...")
    finally:
        observer.stop()
        observer.join()
        handler.close()


def run_with_polling(eve_path: str):
    handler = EveJsonHandler(eve_path)
    logger.info("Running in polling mode (watchdog not available)")

    try:
        while True:
            handler.read_new_lines()

            if extractor.is_window_complete():
                process_window()

            update_live_metrics_tick()
            retrain_if_needed()

            time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Shutting down ingestion pipeline...")
    finally:
        handler.close()


def main():
    global model, is_model_ready, training_start_time

    logger.info("=" * 60)
    logger.info("Pulse Ingestion Pipeline Starting")
    logger.info("=" * 60)

    try:
        firebase_client.initialize()
        logger.info("Firebase initialized")
    except Exception as e:
        logger.error(f"Firebase initialization failed: {e}")
        logger.info("Continuing without Firebase (dry run mode)")

    if os.path.exists(config.MODEL_PATH):
        logger.info(f"Found existing model at {config.MODEL_PATH}")
        model = ml_model.load_model()
        is_model_ready = True
        logger.info("Model loaded — starting in detection mode")
    else:
        logger.info("No existing model found — starting 2-minute training phase")
        logger.info(f"Collecting normal traffic samples for {config.TRAINING_DURATION_SEC}s...")
        is_model_ready = False
        training_start_time = time.time()

    try:
        sys_config = firebase_client.get_system_config()
        config.ANOMALY_THRESHOLD = sys_config.get("anomaly_threshold", config.ANOMALY_THRESHOLD)
        config.ATTACK_THRESHOLD = sys_config.get("attack_threshold", config.ATTACK_THRESHOLD)
        config.BASELINE_PPS = sys_config.get("baseline_packets_per_sec", config.BASELINE_PPS)
        logger.info(f"Thresholds: anomaly={config.ANOMALY_THRESHOLD}, "
                    f"attack={config.ATTACK_THRESHOLD}, baseline={config.BASELINE_PPS}")
    except Exception as e:
        logger.warning(f"Could not load system config: {e}. Using defaults.")

    eve_path = config.EVE_JSON_PATH
    logger.info(f"Eve.json path: {eve_path}")

    if HAS_WATCHDOG:
        run_with_watchdog(eve_path)
    else:
        run_with_polling(eve_path)


if __name__ == "__main__":
    main()
