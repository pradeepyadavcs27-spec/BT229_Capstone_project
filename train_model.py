import json
import re
import sys
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             precision_score, recall_score, f1_score)
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else BASE_DIR / "datasets" / "cowrie_dataset" / "logs"
FAILURE_THRESHOLD, WINDOW_SECONDS = 10, 60
SUSPICIOUS = re.compile(r"\b(wget|curl|chmod|crontab|nc|netcat|ncat|socat|tftp)\b|/etc/(shadow|passwd)", re.I)

FEATURES = ["n_events", "n_sessions", "failed_logins", "successful_logins",
            "success_ratio", "unique_usernames", "unique_passwords",
            "command_events", "suspicious_commands", "active_seconds"]


def ts(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def build_dataset():
    files = sorted(LOG_DIR.glob("cowrie.json*"))
    if not files:
        sys.exit(f"No cowrie.json* files found in {LOG_DIR}")
    print(f"Reading {len(files)} files from {LOG_DIR}")

    ip = defaultdict(lambda: {"n_events": 0, "sessions": set(), "failed": 0, "success": 0,
                              "users": set(), "pwds": set(), "cmds": 0, "susp": 0,
                              "first": None, "last": None, "rule_flag": 0})
    window = defaultdict(deque)

    for f in files:
        print("  ", f.name)
        with f.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(e, dict):
                    continue
                src = e.get("src_ip") or e.get("src_ip6")
                if not src:
                    continue
                d = ip[str(src)]
                t = ts(e.get("timestamp") or "")
                d["n_events"] += 1
                if e.get("session"):
                    d["sessions"].add(e["session"])
                if t is not None:
                    d["first"] = t if d["first"] is None else min(d["first"], t)
                    d["last"] = t if d["last"] is None else max(d["last"], t)

                eid = e.get("eventid")
                if eid in ("cowrie.login.failed", "cowrie.login.success"):
                    if e.get("username"):
                        d["users"].add(e["username"])
                    if e.get("password"):
                        d["pwds"].add(e["password"])
                if eid == "cowrie.login.failed":
                    d["failed"] += 1
                    if t is not None:
                        q = window[str(src)]
                        while q and t - q[0] > WINDOW_SECONDS:
                            q.popleft()
                        q.append(t)
                        if len(q) >= FAILURE_THRESHOLD:
                            d["rule_flag"] = 1
                elif eid == "cowrie.login.success":
                    d["success"] += 1
                elif eid == "cowrie.command.input":
                    d["cmds"] += 1
                    if SUSPICIOUS.search(e.get("input") or ""):
                        d["susp"] += 1

    rows = []
    for addr, d in ip.items():
        logins = d["failed"] + d["success"]
        rows.append({
            "source_ip": addr,
            "n_events": d["n_events"],
            "n_sessions": len(d["sessions"]),
            "failed_logins": d["failed"],
            "successful_logins": d["success"],
            "success_ratio": d["success"] / logins if logins else 0.0,
            "unique_usernames": len(d["users"]),
            "unique_passwords": len(d["pwds"]),
            "command_events": d["cmds"],
            "suspicious_commands": d["susp"],
            "active_seconds": (d["last"] - d["first"]) if d["first"] is not None else 0.0,
            "label": d["rule_flag"],
        })
    return pd.DataFrame(rows)


def main():
    df = build_dataset()
    df.to_csv(BASE_DIR / "ip_features.csv", index=False)
    print(f"\nFeature table: {len(df)} IPs  |  brute-force label=1: {int(df.label.sum())} "
          f"({df.label.mean():.1%})")
    if df.label.nunique() < 2:
        sys.exit("Only one class present - cannot train a classifier on this data.")

    X, y = df[FEATURES], df["label"]
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
    print(f"Train: {len(X_tr)}  Test: {len(X_te)}")

    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                random_state=42, n_jobs=-1)
    rf.fit(X_tr, y_tr)
    pred = rf.predict(X_te)
    print("\n=== RANDOM FOREST (test set) ===")
    print(classification_report(y_te, pred, target_names=["normal/other", "brute-force"], digits=3))
    cm = confusion_matrix(y_te, pred)
    print("Confusion matrix [[TN FP] [FN TP]]:\n", cm)
    imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda x: -x[1])
    print("\nFeature importance:")
    for name, v in imp:
        print(f"  {name:22s} {v:.3f}")

    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    iso.fit(X_tr)
    iso_pred = (iso.predict(X_te) == -1).astype(int)
    print("\n=== ISOLATION FOREST (no labels used for training) ===")
    print(f"Anomalies flagged in test set: {iso_pred.sum()} / {len(iso_pred)}")
    print(f"Precision vs rule label: {precision_score(y_te, iso_pred, zero_division=0):.3f}")
    print(f"Recall    vs rule label: {recall_score(y_te, iso_pred, zero_division=0):.3f}")

    joblib.dump({"model": rf, "features": FEATURES}, BASE_DIR / "brute_force_rf.joblib")
    joblib.dump({"model": iso, "features": FEATURES}, BASE_DIR / "isolation_forest.joblib")
    (BASE_DIR / "model_report.json").write_text(json.dumps({
        "ips": int(len(df)), "positive_labels": int(df.label.sum()),
        "random_forest": {
            "precision": float(precision_score(y_te, pred)),
            "recall": float(recall_score(y_te, pred)),
            "f1": float(f1_score(y_te, pred)),
            "confusion_matrix": cm.tolist(),
            "feature_importance": {k: float(v) for k, v in imp}},
        "isolation_forest": {
            "precision_vs_rule": float(precision_score(y_te, iso_pred, zero_division=0)),
            "recall_vs_rule": float(recall_score(y_te, iso_pred, zero_division=0))}},
        indent=2))
    print("\nSaved: ip_features.csv, brute_force_rf.joblib, isolation_forest.joblib, model_report.json")


if __name__ == "__main__":
    main()
