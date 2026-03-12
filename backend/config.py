import os
from dotenv import load_dotenv

load_dotenv()
FIREBASE_SERVICE_ACCOUNT_KEY = os.getenv(
    "FIREBASE_SERVICE_ACCOUNT_KEY",
    os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")
)
FIREBASE_DATABASE_URL = os.getenv(
    "FIREBASE_DATABASE_URL"
)
EVE_JSON_PATH = os.getenv(
    "EVE_JSON_PATH",
    "/var/log/suricata/eve.json"
)

MODEL_PATH = os.getenv(
    "MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "model.pkl")
)
N_ESTIMATORS = 100           # number of trees in the forest
CONTAMINATION = 0.1          # expected fraction of anomalies (10%)
RANDOM_STATE = 42            # reproducible results

# minimum samples required before model can be trained
MIN_TRAINING_SAMPLES = 20

# training phase duration in seconds
TRAINING_DURATION_SEC = 120

# retraining interval in seconds
RETRAIN_INTERVAL_SEC = 1800

ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.5"))
ATTACK_THRESHOLD = float(os.getenv("ATTACK_THRESHOLD", "0.75"))

BASELINE_PPS = float(os.getenv("BASELINE_PPS", "100"))

FEATURE_WINDOW_SEC = 10

LIVE_METRICS_INTERVAL_SEC = 2

FEATURE_RANGES = {
    "packets_per_sec":  {"min": 0,   "max": 10000},
    "bytes_per_sec":    {"min": 0,   "max": 10000000},
    "unique_src_ips":   {"min": 1,   "max": 500},
    "top_ip_ratio":     {"min": 0.0, "max": 1.0},
    "alerts_per_sec":   {"min": 0,   "max": 100},
}

SIMULATION = {
    "normal": {
        "alerts_per_minute": 5,
        "anomaly_score_range": (0.1, 0.3),
        "packets_per_sec_range": (50, 150),
        "bytes_per_sec_range": (3000, 15000),
        "unique_src_ips_range": (2, 5),
        "duration_sec": 60,
        "severity_weights": {"low": 0.5, "medium": 0.3, "high": 0.15, "critical": 0.05},
    },
    "attack": {
        "alerts_per_minute": 75,
        "anomaly_score_range": (0.7, 0.95),
        "packets_per_sec_range": (2000, 8000),
        "bytes_per_sec_range": (500000, 5000000),
        "unique_src_ips_range": (3, 5),     
        "duration_sec": 60,
        "severity_weights": {"low": 0.05, "medium": 0.1, "high": 0.35, "critical": 0.5},
    },
}

SIMULATED_ALERT_TYPES = [
    {"type": "ET DOS Potential DDoS Outbound Flooder", "category": "Attempted Denial of Service"},
    {"type": "ET DOS Inbound UDP Flood", "category": "Attempted Denial of Service"},
    {"type": "ET DOS Potential SYN Flood", "category": "Attempted Denial of Service"},
    {"type": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak"},
    {"type": "ET DOS Likely Inbound HTTP DDoS Flood", "category": "Attempted Denial of Service"},
    {"type": "GPL ICMP PING *NIX", "category": "Misc activity"},
    {"type": "ET SCAN Nmap Scripting Engine User-Agent Detected", "category": "Attempted Information Leak"},
]

SIMULATED_DEST_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.5"]

SIMULATED_DEST_PORTS = [80, 443, 22, 53, 8080]

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
