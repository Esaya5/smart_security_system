"""
Central configuration for the Smart Security Camera + Crime Heat Map system.
Secrets are read from environment variables / a local .env file.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

# --- Storage ---------------------------------------------------------------
DATA_DIR = BASE_DIR / "data"
KEY_PATH = DATA_DIR / "secret.key"
ENCODINGS_PATH = DATA_DIR / "encodings.enc"
DB_PATH = DATA_DIR / "system.db"
SNAPSHOT_DIR = BASE_DIR / "snapshots"
EVAL_DIR = BASE_DIR / "evaluation"
EVAL_DATASET_DIR = EVAL_DIR / "test_dataset"
EVAL_REPORT_PATH = EVAL_DIR / "evaluation_report.json"

# --- Flask -----------------------------------------------------------------
DEFAULT_SECRET = "dev-only-change-me"
SECRET_KEY = os.getenv("FACEGUARD_FLASK_SECRET", DEFAULT_SECRET)
# Debug mode and network binding default to the SAFE option.
DEBUG = os.getenv("FACEGUARD_DEBUG", "false").lower() == "true"
HOST = os.getenv("FACEGUARD_HOST", "127.0.0.1")
PORT = int(os.getenv("FACEGUARD_PORT", "5000"))
LOGIN_MAX_FAILURES = 5          # failed logins allowed per IP ...
LOGIN_WINDOW_SECONDS = 300      # ... inside this window

# --- Recognition -----------------------------------------------------------
MATCH_TOLERANCE = 0.5           # lower = stricter match
FRAME_SKIP = 2                  # process every Nth frame
RESIZE_SCALE = 0.5              # downscale frame before recognition
KNOWN_LOG_COOLDOWN_SECONDS = 30  # log the same known person at most this often

# --- Alerting --------------------------------------------------------------
ALERT_COOLDOWN_SECONDS = 60
ALERTS_ENABLED = os.getenv("FACEGUARD_ALERTS_ENABLED", "true").lower() == "true"
EMAIL_ENABLED = os.getenv("FACEGUARD_EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("FACEGUARD_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("FACEGUARD_SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("FACEGUARD_SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("FACEGUARD_SMTP_PASSWORD", "")
ALERT_RECIPIENTS = [
    a.strip() for a in os.getenv("FACEGUARD_ALERT_RECIPIENTS", "").split(",") if a.strip()
]

# --- Data retention ---------------------------------------------------------
SNAPSHOT_RETENTION_DAYS = int(os.getenv("FACEGUARD_RETENTION_DAYS", "30"))

# --- Crime heat map ---------------------------------------------------------
CAMPUS_LAT = float(os.getenv("FACEGUARD_CAMPUS_LAT", "-28.7382"))   # Kimberley, SA
CAMPUS_LNG = float(os.getenv("FACEGUARD_CAMPUS_LNG", "24.7633"))
# Street-level analysis. The KDE bandwidth is a real-world distance, so the
# heat follows individual streets instead of smearing into one city-wide blob.
HEATMAP_BANDWIDTH_M = float(os.getenv("FACEGUARD_HEAT_BANDWIDTH_M", "120"))
HEATMAP_CELL_M = float(os.getenv("FACEGUARD_HEAT_CELL_M", "35"))
STREET_RADIUS_M = float(os.getenv("FACEGUARD_STREET_RADIUS_M",
                                  "150"))  # "this street" lookup radius
HEATMAP_MAX_CELLS = 12000


def ensure_directories() -> None:
    for d in (DATA_DIR, SNAPSHOT_DIR, EVAL_DATASET_DIR):
        d.mkdir(parents=True, exist_ok=True)
