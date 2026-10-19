
import json
import sqlite3
import hashlib
from pathlib import Path

BASE_DIR = Path.home() / "iot-honeypot"
DB_FILE = BASE_DIR / "data" / "honeypot.db"
EVENT_FILE = BASE_DIR / "logs" / "normalized_events.jsonl"


def initialize_database():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT NOT NULL,
                source_ip TEXT,
                device_id TEXT,
                event_type TEXT,
                session_id TEXT,
                username TEXT,
                details TEXT,
                fingerprint TEXT UNIQUE
            )
        """)

        # Support databases created by the earlier version.
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(events)")
        }

        if "fingerprint" not in columns:
            conn.execute("ALTER TABLE events ADD COLUMN fingerprint TEXT")

            # Backfill fingerprints for existing records.
            rows = conn.execute("""
                SELECT id, timestamp, source, source_ip, device_id,
                       event_type, session_id, username, details
                FROM events
            """).fetchall()

            for row in rows:
                event_data = {
                    "timestamp": row[1],
                    "source": row[2],
                    "source_ip": row[3],
                    "device_id": row[4],
                    "event_type": row[5],
                    "session_id": row[6],
                    "username": row[7],
                    "details": json.loads(row[8]) if row[8] else "",
                }
                fingerprint = hashlib.sha256(
                    json.dumps(
                        event_data, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()

                conn.execute(
                    "UPDATE events SET fingerprint = ? WHERE id = ?",
                    (fingerprint, row[0]),
                )

            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_events_fingerprint
                ON events(fingerprint)
            """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_source_ip
            ON events(source_ip)
        """)

    print(f"Database initialized: {DB_FILE}")


def import_normalized_events():
    if not EVENT_FILE.exists():
        print(f"Event file not found: {EVENT_FILE}")
        return

    imported = 0
    skipped = 0

    with sqlite3.connect(DB_FILE) as conn:
        with EVENT_FILE.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON on line {line_number}")
                    continue

                normalized_event = {
                    "timestamp": event.get("timestamp"),
                    "source": event.get("source", "unknown"),
                    "source_ip": event.get("source_ip"),
                    "device_id": event.get("device_id"),
                    "event_type": event.get("event_type"),
                    "session_id": event.get("session_id"),
                    "username": event.get("username"),
                    "details": event.get("details", ""),
                }

                fingerprint = hashlib.sha256(
                    json.dumps(
                        normalized_event,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()

                cursor = conn.execute("""
                    INSERT OR IGNORE INTO events (
                        timestamp, source, source_ip, device_id,
                        event_type, session_id, username, details,
                        fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    normalized_event["timestamp"],
                    normalized_event["source"],
                    normalized_event["source_ip"],
                    normalized_event["device_id"],
                    normalized_event["event_type"],
                    normalized_event["session_id"],
                    normalized_event["username"],
                    json.dumps(normalized_event["details"]),
                    fingerprint,
                ))

                if cursor.rowcount == 1:
                    imported += 1
                else:
                    skipped += 1

    print(f"New events imported: {imported}")
    print(f"Duplicate events skipped: {skipped}")


def show_summary():
    with sqlite3.connect(DB_FILE) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        print(f"Total events in database: {total}")

        rows = conn.execute("""
            SELECT source, COUNT(*)
            FROM events
            GROUP BY source
            ORDER BY source
        """).fetchall()

        for source, count in rows:
            print(f"  {source}: {count}")


if __name__ == "__main__":
    initialize_database()
    import_normalized_events()
    show_summary()
