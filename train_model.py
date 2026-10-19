import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "datasets" / "cowrie_dataset" / "logs"
MODEL_PATH = BASE_DIR / "honeypot_model.joblib"
DATA_PATH = BASE_DIR / "ml_training_data.csv"

# Aggregate historical login activity by source IP.
stats = {}
for file_path in sorted(LOG_DIR.glob("cowrie.json*")):
    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict):
                continue

            event_type = event.get("eventid")
            if event_type not in (
                "cowrie.login.failed",
                "cowrie.login.success",
                "cowrie.command.input",
                "cowrie.session.file_download",
            ):
                continue

            ip = event.get("src_ip") or event.get("src_ip6")
            if not ip:
                continue

            row = stats.setdefault(str(ip), {
                "failed_logins": 0,
                "successful_logins": 0,
                "commands": 0,
                "downloads": 0,
            })

            if event_type == "cowrie.login.failed":
                row["failed_logins"] += 1
            elif event_type == "cowrie.login.success":
                row["successful_logins"] += 1
            elif event_type == "cowrie.command.input":
                row["commands"] += 1
            elif event_type == "cowrie.session.file_download":
                row["downloads"] += 1

df = pd.DataFrame.from_dict(stats, orient="index")
df.index.name = "source_ip"
df = df.fillna(0)

if len(df) < 10:
    raise SystemExit("Not enough source IPs to train a baseline model.")

# Heuristic labels: 1 means suspicious under this simple rule.
df["label"] = (
    (df["failed_logins"] >= 10)
    | (df["downloads"] > 0)
).astype(int)

features = [
    "failed_logins",
    "successful_logins",
    "commands",
    "downloads",
]
X = df[features]
y = df["label"]

if y.nunique() < 2 or y.value_counts().min() < 2:
    raise SystemExit(
        "Need at least two examples in each class. "
        "Check the heuristic labels before training."
    )

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = make_pipeline(
    StandardScaler(),
    RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    ),
)
model.fit(X_train, y_train)

predictions = model.predict(X_test)
print("=== HEURISTIC-LABEL BASELINE ===")
print("Source IPs:", len(df))
print("Training rows:", len(X_train))
print("Test rows:", len(X_test))
print("Label counts:", y.value_counts().to_dict())
print(classification_report(y_test, predictions, zero_division=0))

df.reset_index().to_csv(DATA_PATH, index=False)
joblib.dump({"model": model, "features": features}, MODEL_PATH)

print("Training data saved:", DATA_PATH)
print("Model saved:", MODEL_PATH)
print("Note: metrics measure agreement with heuristic labels,")
print("not independently verified malicious activity.")
