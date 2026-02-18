import argparse
import logging
import random
import time
import sys
from datetime import datetime, timezone

import numpy as np

import config
import firebase_client
import ml_model

logging.basicConfig(
    level=logging.INFO,
    format=config.LOG_FORMAT,
    datefmt=config.LOG_DATE_FORMAT,
)
logger = logging.getLogger(__name__)

NORMAL_SRC_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.20",
    "192.168.1.25", "192.168.1.30", "192.168.1.35",
    "192.168.2.10", "192.168.2.50", "10.0.1.5", "10.0.1.8",
]

ATTACK_SRC_IPS = [
    "203.0.113.1", "203.0.113.5", "203.0.113.12",
    "198.51.100.2", "198.51.100.8",
]


def generate_alert(mode: str) -> dict:
    params = config.SIMULATION[mode]

    alert_info = random.choice(config.SIMULATED_ALERT_TYPES)

    severity_choices = list(params["severity_weights"].keys())
    severity_probs = list(params["severity_weights"].values())
    severity = random.choices(severity_choices, weights=severity_probs, k=1)[0]

    if mode == "attack":
        src_ip = random.choice(ATTACK_SRC_IPS)
    else:
        src_ip = random.choice(NORMAL_SRC_IPS)

    dest_ip = random.choice(config.SIMULATED_DEST_IPS)
    dest_port = random.choice(config.SIMULATED_DEST_PORTS)
    src_port = random.randint(1024, 65535)

    protocol = random.choices(
        ["TCP", "UDP", "ICMP"],
        weights=[0.6, 0.3, 0.1] if mode == "normal" else [0.4, 0.4, 0.2],
        k=1,
    )[0]

    score_lo, score_hi = params["anomaly_score_range"]
    anomaly_score = round(float(random.uniform(score_lo, score_hi)), 4)

    classification = ml_model.classify_alert(anomaly_score)

    if severity == "critical" and mode == "attack":
        anomaly_score = max(anomaly_score, 0.9)
        classification = "attack"

    pps_lo, pps_hi = params["packets_per_sec_range"]
    bps_lo, bps_hi = params["bytes_per_sec_range"]
    packet_count = random.randint(int(pps_lo * 10), int(pps_hi * 10))
    byte_count = random.randint(int(bps_lo * 10), int(bps_hi * 10))

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "alert_type": alert_info["type"],
        "severity": severity,
        "category": alert_info["category"],
        "classification": classification,
        "anomaly_score": anomaly_score,
        "packet_count": packet_count,
        "bytes": byte_count,
        "source": "simulation",
        "acknowledged": False,
    }


def generate_traffic_snapshot(mode: str, anomaly_score: float) -> dict:
    params = config.SIMULATION[mode]

    pps_lo, pps_hi = params["packets_per_sec_range"]
    bps_lo, bps_hi = params["bytes_per_sec_range"]
    ips_lo, ips_hi = params["unique_src_ips_range"]

    packets_per_sec = round(float(random.uniform(pps_lo, pps_hi)), 2)
    bytes_per_sec = round(float(random.uniform(bps_lo, bps_hi)), 2)
    unique_src_ips = random.randint(ips_lo, ips_hi)

    is_spike = packets_per_sec > (config.BASELINE_PPS * 3)
    classification = ml_model.classify_alert(anomaly_score)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "unique_src_ips": unique_src_ips,
        "alert_count": random.randint(0, 10) if mode == "normal" else random.randint(10, 50),
        "anomaly_score": round(float(anomaly_score), 4),
        "is_spike": is_spike,
    }


def generate_live_metrics(mode: str, anomaly_score: float) -> dict:
    params = config.SIMULATION[mode]
    pps_lo, pps_hi = params["packets_per_sec_range"]
    bps_lo, bps_hi = params["bytes_per_sec_range"]

    classification = ml_model.classify_alert(anomaly_score)

    if classification == "attack":
        system_status = "critical"
    elif classification == "suspicious":
        system_status = "warning"
    else:
        system_status = "normal"

    return {
        "packets_per_sec": round(float(random.uniform(pps_lo, pps_hi)), 2),
        "bytes_per_sec": round(float(random.uniform(bps_lo, bps_hi)), 2),
        "active_connections": random.randint(5, 20) if mode == "normal" else random.randint(50, 300),
        "alerts_last_minute": random.randint(0, 5) if mode == "normal" else random.randint(20, 80),
        "current_anomaly_score": round(float(anomaly_score), 4),
        "model_status": "ready",
        "model_training_progress": 100,
        "system_status": system_status,
        "last_updated": int(time.time() * 1000),
    }


def run_simulation(mode: str, duration: int):
    params = config.SIMULATION[mode]
    alerts_per_min = params["alerts_per_minute"]
    interval = 60.0 / alerts_per_min

    mode_display = "🟢 NORMAL" if mode == "normal" else "🔴 DDoS ATTACK"
    logger.info(f"")
    logger.info(f"{'='*60}")
    logger.info(f"  Simulation Mode: {mode_display}")
    logger.info(f"  Duration: {duration}s | Rate: {alerts_per_min} alerts/min")
    logger.info(f"{'='*60}")
    logger.info(f"")

    start_time = time.time()
    alert_count = 0
    snapshot_count = 0
    last_snapshot_time = start_time
    last_metrics_time = start_time

    try:
        while (time.time() - start_time) < duration:
            alert = generate_alert(mode)
            try:
                firebase_client.write_alert(alert)
                alert_count += 1
            except Exception as e:
                logger.error(f"Failed to write alert: {e}")

            if (time.time() - last_snapshot_time) >= 10:
                snapshot = generate_traffic_snapshot(mode, alert["anomaly_score"])
                try:
                    firebase_client.write_traffic_snapshot(snapshot)
                    snapshot_count += 1
                except Exception as e:
                    logger.error(f"Failed to write snapshot: {e}")
                last_snapshot_time = time.time()

            if (time.time() - last_metrics_time) >= 2:
                metrics = generate_live_metrics(mode, alert["anomaly_score"])
                try:
                    firebase_client.update_live_metrics(metrics)
                except Exception as e:
                    logger.error(f"Failed to update metrics: {e}")
                last_metrics_time = time.time()

            if alert_count % 10 == 0 and alert_count > 0:
                elapsed = time.time() - start_time
                remaining = duration - elapsed
                logger.info(f"  [{mode.upper()}] Sent {alert_count} alerts | "
                            f"{remaining:.0f}s remaining")

            time.sleep(interval)

    except KeyboardInterrupt:
        logger.info("Simulation interrupted by user")

    elapsed = time.time() - start_time
    logger.info(f"")
    logger.info(f"{'─'*60}")
    logger.info(f"  {mode_display} Summary:")
    logger.info(f"    Alerts sent:     {alert_count}")
    logger.info(f"    Snapshots:       {snapshot_count}")
    logger.info(f"    Duration:        {elapsed:.1f}s")
    logger.info(f"    Avg rate:        {alert_count/max(elapsed/60, 0.01):.1f} alerts/min")
    logger.info(f"{'─'*60}")

    return alert_count, snapshot_count


def run_mixed_mode(duration: int):
    logger.info(f"")
    logger.info(f"{'='*60}")
    logger.info(f"  🔄 MIXED MODE — Alternating Normal ↔ Attack")
    logger.info(f"  Total duration: {duration}s")
    logger.info(f"  Switching every 60 seconds")
    logger.info(f"{'='*60}")
    logger.info(f"")

    start_time = time.time()
    total_alerts = 0
    total_snapshots = 0
    cycle = 0

    try:
        while (time.time() - start_time) < duration:
            cycle += 1
            remaining = duration - (time.time() - start_time)
            cycle_duration = min(60.0, remaining)

            if cycle_duration <= 0:
                break

            mode = "normal" if cycle % 2 == 1 else "attack"
            logger.info(f"")
            logger.info(f"  --- Cycle {cycle}: Switching to {mode.upper()} "
                        f"for {cycle_duration:.0f}s ---")

            alerts, snapshots = run_simulation(mode, int(cycle_duration))
            total_alerts += alerts
            total_snapshots += snapshots

    except KeyboardInterrupt:
        logger.info("Mixed simulation interrupted by user")

    elapsed = time.time() - start_time
    logger.info(f"")
    logger.info(f"{'='*60}")
    logger.info(f"  🔄 MIXED MODE Complete")
    logger.info(f"    Total alerts:    {total_alerts}")
    logger.info(f"    Total snapshots: {total_snapshots}")
    logger.info(f"    Total duration:  {elapsed:.1f}s")
    logger.info(f"    Cycles:          {cycle}")
    logger.info(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Pulse Traffic Simulator",
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "attack", "mixed"],
        default="mixed",
        help="Simulation mode (default: mixed)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="Total simulation duration in seconds (default: 300)",
    )

    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  Pulse Traffic Simulator v1.0")
    logger.info("  Mode: %s | Duration: %ds", args.mode, args.duration)
    logger.info("=" * 60)

    try:
        firebase_client.initialize()
        logger.info("Firebase connected")
    except Exception as e:
        logger.error(f"Firebase initialization failed: {e}")
        logger.error("Cannot run simulation without Firebase. Exiting.")
        sys.exit(1)

    try:
        ml_model.load_or_train_model()
    except Exception as e:
        logger.warning(f"Could not load ML model: {e}. Using default thresholds.")

    try:
        firebase_client.update_system_config({
            "model_trained": True,
            "model_training_samples": 1000,
            "model_trained_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        logger.warning(f"Could not update system config: {e}")

    if args.mode == "mixed":
        run_mixed_mode(args.duration)
    else:
        run_simulation(args.mode, args.duration)

    logger.info("")
    logger.info("Simulation complete. Check the ICADS dashboard!")


if __name__ == "__main__":
    main()
