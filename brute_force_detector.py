
import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "datasets" / "cowrie_dataset" / "logs"

# Example threshold: 10 failed logins from one IP within 60 seconds.
FAILURE_THRESHOLD = 10
WINDOW_SECONDS = 60


def parse_timestamp(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).timestamp()
    except (TypeError, ValueError):
        return None


def detect_brute_force(log_dir=LOG_DIR):
    # Each source IP has its own queue of recent failure timestamps.
    recent_failures = defaultdict(deque)
    alerts = []
    total_failed_logins = 0
    invalid_lines = 0

    files = sorted(log_dir.glob("cowrie.json*"))

    if not files:
        raise FileNotFoundError(f"No Cowrie logs found in {log_dir}")

    for file_path in files:
        print(f"Scanning login events: {file_path.name}")

        with file_path.open(
            "r", encoding="utf-8", errors="replace"
        ) as handle:
            for line in handle:
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    invalid_lines += 1
                    continue

                if not isinstance(event, dict):
                    continue

                if event.get("eventid") != "cowrie.login.failed":
                    continue

                ip = event.get("src_ip") or event.get("src_ip6")
                timestamp = parse_timestamp(event.get("timestamp"))

                if not ip or timestamp is None:
                    continue

                total_failed_logins += 1
                queue = recent_failures[str(ip)]

                # Remove failures older than the configured time window.
                while queue and timestamp - queue[0] > WINDOW_SECONDS:
                    queue.popleft()

                queue.append(timestamp)

                if len(queue) == FAILURE_THRESHOLD:
                    alerts.append({
                        "source_ip": str(ip),
                        "failed_logins_in_window": len(queue),
                        "window_seconds": WINDOW_SECONDS,
                        "timestamp": event.get("timestamp"),
                        "classification": "Possible brute-force activity",
                    })

    report = {
        "dataset": "Historical Cowrie logs",
        "threshold": FAILURE_THRESHOLD,
        "window_seconds": WINDOW_SECONDS,
        "failed_login_events_scanned": total_failed_logins,
        "invalid_lines": invalid_lines,
        "alert_count": len(alerts),
        "alerts": alerts,
        "note": (
            "Alerts are heuristic indicators. They do not prove "
            "that an attack succeeded."
        ),
    }

    output_path = BASE_DIR / "brute_force_report.json"
    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n=== BRUTE-FORCE DETECTION SUMMARY ===")
    print(f"Failed login events scanned: {total_failed_logins:,}")
    print(f"Threshold: {FAILURE_THRESHOLD} failures")
    print(f"Time window: {WINDOW_SECONDS} seconds")
    print(f"Potential alerts: {len(alerts):,}")
    print(f"Report saved to: {output_path}")

    print("\nFirst 10 alerts:")
    for alert in alerts[:10]:
        print(
            f"{alert['source_ip']} | "
            f"{alert['failed_logins_in_window']} failures | "
            f"{alert['timestamp']}"
        )

    return report


if __name__ == "__main__":
    detect_brute_force()
