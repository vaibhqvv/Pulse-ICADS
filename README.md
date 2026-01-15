# Pulse — Real-Time Network Traffic Anomaly Detection System

Real-time network threat detection platform combining **Suricata IDS**, **Isolation Forest ML**, a **Python ingestion pipeline**, **Firebase backend**, and a **React dashboard**.

> B.Tech Semester Capstone Project

---

## Architecture

```
Network Traffic → Suricata IDS → eve.json
                                    ↓
              Python Ingestion Pipeline
                ├── feature_extractor.py (5 features / 10s window)
                ├── ml_model.py (Isolation Forest scoring)
                └── firebase_client.py (writes to Firebase)
                                    ↓
              Firebase (Firestore + Realtime DB + Auth + FCM)
                                    ↓
              React Dashboard (real-time charts, alerts, analytics)
```

## Quick Start

### 1. Firebase Setup
1. Create a Firebase project at [console.firebase.google.com](https://console.firebase.google.com)
2. Enable **Firestore**, **Realtime Database**, **Authentication** (Email/Password), and **Cloud Messaging**
3. Download service account key → save as `backend/serviceAccountKey.json`
4. Copy web app config values to `frontend/.env.local`

### 2. Backend
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # Edit with your Firebase values
```

**Run simulation (no Suricata needed):**
```bash
python simulate.py --mode mixed --duration 300
```

**Run real ingestion (requires Suricata):**
```bash
python ingestion.py
```

### 3. Frontend
```bash
cd frontend
npm install
cp .env.example .env.local   # Edit with your Firebase config
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) and login.

## Project Structure

```
pulse/
├── backend/                # Python ML + config
│   ├── config.py           # Centralized configuration
│   ├── ml_model.py         # Isolation Forest module
│   ├── feature_extractor.py# 5-feature sliding window
│   ├── firebase_client.py  # Firebase Admin SDK wrapper
│   ├── ingestion.py        # Core log watcher pipeline
│   ├── simulate.py         # Synthetic traffic generator
│   ├── requirements.txt    # Python dependencies
│   ├── firebase/           # Firebase security rules
│   │   ├── firestore.rules
│   │   └── database.rules.json
│   └── suricata/           # IDS config
│       ├── suricata.yaml
│       └── local.rules     # 10 custom DDoS rules
├── frontend/               # React dashboard
│   ├── src/
│   │   ├── firebase/       # Firebase SDK init & queries
│   │   ├── hooks/          # Custom React hooks
│   │   ├── context/        # Auth context provider
│   │   ├── utils/          # Formatters, classifiers
│   │   ├── components/     # 14 reusable components
│   │   └── pages/          # 5 pages (Login, Dashboard, Alerts, Analytics, Settings)
│   └── index.html
└── README.md
```

## ML Model

- **Algorithm:** Isolation Forest (100 trees, 10% contamination)
- **Features (5):** packets_per_sec, bytes_per_sec, unique_src_ips, top_ip_ratio, alerts_per_sec
- **Training:** 2-minute warm-up on startup, periodic retraining every 30 min
- **Classification:** Normal (< 0.5) → Suspicious (0.5–0.75) → Attack (≥ 0.75)

## Tech Stack

| Layer | Technology |
|-------|-----------|
| IDS | Suricata 6+ |
| Backend | Python 3.10+, scikit-learn, firebase-admin |
| Database | Firebase Firestore + Realtime DB |
| Auth | Firebase Authentication |
| Frontend | React 18, Vite, TailwindCSS, Recharts |
| Notifications | Firebase Cloud Messaging |
