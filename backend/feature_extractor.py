import time
import logging
from typing import Optional, List, Dict
from collections import Counter

import config

logger = logging.getLogger(__name__)


class FeatureExtractor:

    def __init__(self, window_sec: Optional[int] = None):
        self.window_sec: int = window_sec or config.FEATURE_WINDOW_SEC
        self.events: List[dict] = []
        self.window_start: float = time.time()
        self.reset()

    def reset(self) -> None:
        self.events = []
        self.window_start = time.time()

    def add_event(self, event: dict):
        event["_received_at"] = time.time()
        self.events.append(event)

    def is_window_complete(self) -> bool:
        return (time.time() - self.window_start) >= self.window_sec

    def compute_features(self) -> dict:
        elapsed = time.time() - self.window_start
        if elapsed <= 0:
            elapsed = 0.001

        if not self.events:
            logger.debug("No events in window — returning zero features")
            return {
                "packets_per_sec": 0.0,
                "bytes_per_sec": 0.0,
                "unique_src_ips": 0,
                "top_ip_ratio": 0.0,
                "alerts_per_sec": 0.0,
            }

        total_packets = sum(e.get("packet_count", 1) for e in self.events)
        total_bytes = sum(e.get("bytes", 0) for e in self.events)

        src_ips = [e.get("src_ip", "unknown") for e in self.events]
        unique_src_ips = len(set(src_ips))

        # top ip ratio = alerts from most common ip / total
        ip_counts = Counter(src_ips)
        if ip_counts:
            top_ip_count = ip_counts.most_common(1)[0][1]
            top_ip_ratio = top_ip_count / len(self.events)
        else:
            top_ip_ratio = 0.0

        alert_count = sum(
            1 for e in self.events
            if e.get("event_type") == "alert" or "alert" in e
        )

        features = {
            "packets_per_sec": float(f"{total_packets / elapsed:.2f}"),
            "bytes_per_sec": float(f"{total_bytes / elapsed:.2f}"),
            "unique_src_ips": unique_src_ips,
            "top_ip_ratio": float(f"{top_ip_ratio:.4f}"),
            "alerts_per_sec": float(f"{alert_count / elapsed:.2f}"),
        }

        logger.debug(f"Features computed: {features}")
        return features

    def get_window_summary(self) -> dict:
        features = self.compute_features()
        elapsed = time.time() - self.window_start

        # spike = 3x baseline
        is_spike = features["packets_per_sec"] > (config.BASELINE_PPS * 3)

        return {
            **features,
            "alert_count": len([
                e for e in self.events
                if e.get("event_type") == "alert" or "alert" in e
            ]),
            "is_spike": is_spike,
            "window_duration_sec": float(f"{elapsed:.1f}"),
        }

    def get_event_count(self) -> int:
        return len(self.events)

    def get_raw_events(self) -> list:
        return list(self.events)
