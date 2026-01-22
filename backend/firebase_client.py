import logging
import time
from datetime import datetime, timezone

import firebase_admin
from firebase_admin import credentials, firestore, db as realtime_db

import config

logger = logging.getLogger(__name__)

_initialized = False


def initialize():
    global _initialized
    if _initialized:
        return

    try:
        cred = credentials.Certificate(config.FIREBASE_SERVICE_ACCOUNT_KEY)
        firebase_admin.initialize_app(cred, {
            "databaseURL": config.FIREBASE_DATABASE_URL,
        })
        _initialized = True
        logger.info("Firebase Admin SDK initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {e}")
        raise


def _get_firestore_client():
    initialize()
    return firestore.client()


def write_alert(alert_doc: dict) -> str:
    db_client = _get_firestore_client()

    if isinstance(alert_doc.get("timestamp"), str):
        alert_doc["timestamp"] = datetime.fromisoformat(
            alert_doc["timestamp"].replace("Z", "+00:00")
        )
    elif not isinstance(alert_doc.get("timestamp"), datetime):
        alert_doc["timestamp"] = datetime.now(timezone.utc)

    alert_doc.setdefault("acknowledged", False)

    # retry with exponential backoff
    for attempt in range(1, 4):
        try:
            _, doc_ref = db_client.collection("alerts").add(alert_doc)
            logger.info(f"Alert written: {doc_ref.id} | "
                        f"{alert_doc.get('classification', 'unknown')} | "
                        f"{alert_doc.get('alert_type', 'unknown')}")
            return doc_ref.id
        except Exception as e:
            wait_time = 2 ** attempt
            logger.warning(f"Firebase write attempt {attempt}/3 failed: {e}. "
                           f"Retrying in {wait_time}s...")
            time.sleep(wait_time)

    logger.error("Failed to write alert after 3 attempts")
    raise Exception("Firebase write_alert failed after 3 retries")


def write_traffic_snapshot(snapshot: dict) -> None:
    db_client = _get_firestore_client()

    if "timestamp" not in snapshot:
        snapshot["timestamp"] = datetime.now(timezone.utc)
    elif isinstance(snapshot["timestamp"], str):
        snapshot["timestamp"] = datetime.fromisoformat(
            snapshot["timestamp"].replace("Z", "+00:00")
        )

    for attempt in range(1, 4):
        try:
            db_client.collection("traffic_snapshots").add(snapshot)
            logger.debug(f"Traffic snapshot written: "
                         f"{snapshot.get('packets_per_sec', 0):.1f} pps, "
                         f"score={snapshot.get('anomaly_score', 0):.3f}")
            return
        except Exception as e:
            wait_time = 2 ** attempt
            logger.warning(f"Snapshot write attempt {attempt}/3 failed: {e}. "
                           f"Retrying in {wait_time}s...")
            time.sleep(wait_time)

    logger.error("Failed to write traffic snapshot after 3 attempts")


def update_live_metrics(metrics: dict) -> None:
    initialize()

    if "last_updated" not in metrics:
        metrics["last_updated"] = int(time.time() * 1000)

    try:
        ref = realtime_db.reference("/live_metrics")
        ref.set(metrics)
        logger.debug(f"Live metrics updated: {metrics.get('system_status', 'unknown')}")
    except Exception as e:
        logger.warning(f"Failed to update live metrics: {e}")


def get_system_config() -> dict:
    db_client = _get_firestore_client()

    try:
        doc = db_client.collection("system_config").document("main").get()
        if doc.exists:
            config_data = doc.to_dict()
            logger.debug(f"System config loaded: thresholds="
                         f"{config_data.get('anomaly_threshold', 'N/A')}/"
                         f"{config_data.get('attack_threshold', 'N/A')}")
            return config_data
        else:
            logger.info("No system_config/main found, using defaults")
            return _default_system_config()
    except Exception as e:
        logger.warning(f"Failed to read system config: {e}. Using defaults.")
        return _default_system_config()


def update_system_config(updates: dict) -> None:
    db_client = _get_firestore_client()
    updates["last_updated"] = datetime.now(timezone.utc)

    try:
        db_client.collection("system_config").document("main").set(
            updates, merge=True
        )
        logger.info(f"System config updated: {list(updates.keys())}")
    except Exception as e:
        logger.error(f"Failed to update system config: {e}")


def _default_system_config() -> dict:
    return {
        "anomaly_threshold": config.ANOMALY_THRESHOLD,
        "attack_threshold": config.ATTACK_THRESHOLD,
        "baseline_packets_per_sec": config.BASELINE_PPS,
        "contamination": config.CONTAMINATION,
        "model_trained": False,
        "model_trained_at": None,
        "model_training_samples": 0,
        "notification_enabled": True,
        "severity_filter_min": "low",
        "last_updated": datetime.now(timezone.utc),
    }
