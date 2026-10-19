
import json
from pathlib import Path

BASE_DIR = Path.home() / "iot-honeypot"

COWRIE_LOG = BASE_DIR / "var/log/cowrie/cowrie.json"
HTTP_LOG = BASE_DIR / "logs/http_decoy.jsonl"
OUTPUT_FILE = BASE_DIR / "logs/normalized_events.jsonl"


def read_jsonl(path):
    events = []

    if not path.exists():
        print(f"Log file not found: {path}")
        return events

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON: {path.name}, line {line_number}")

    return events


def normalize_cowrie(event):
    return {
        "timestamp": event.get("timestamp"),
        "source": "cowrie",
        "source_ip": event.get("src_ip"),
        "device_id": event.get("sensor", "unknown"),
        "event_type": event.get("eventid", "unknown"),
        "session_id": event.get("session"),
        "username": event.get("username"),
        "details": event.get("input", event.get("message", "")),
    }


def normalize_http(event):
    return {
        "timestamp": event.get("timestamp"),
        "source": "http_decoy",
        "source_ip": event.get("source_ip"),
        "device_id": event.get("device_id", "unknown"),
        "event_type": "http.request",
        "session_id": None,
        "username": None,
        "details": {
            "method": event.get("method"),
            "path": event.get("path"),
            "user_agent": event.get("user_agent", ""),
        },
    }


def main():
    cowrie_events = read_jsonl(COWRIE_LOG)
    http_events = read_jsonl(HTTP_LOG)

    normalized = [
        normalize_cowrie(event) for event in cowrie_events
    ]
    normalized.extend(
        normalize_http(event) for event in http_events
    )

    normalized.sort(key=lambda event: event.get("timestamp") or "")

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        for event in normalized:
            file.write(json.dumps(event) + "\n")

    print("========== EVENT NORMALIZER ==========")
    print(f"Cowrie events read: {len(cowrie_events)}")
    print(f"HTTP events read:   {len(http_events)}")
    print(f"Total normalized:   {len(normalized)}")
    print(f"Output: {OUTPUT_FILE}")
    print("=======================================")


if __name__ == "__main__":
    main()
