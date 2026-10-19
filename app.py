from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = Path(
    os.environ.get(
        "COWRIE_JSON_LOG",
        str(BASE_DIR / "var/log/cowrie/cowrie.json"),
    )
).expanduser()

# This dashboard intentionally stays on localhost. Do not change host to 0.0.0.0.
app = Flask(__name__, template_folder="templates")


@app.get("/api/http-events")
def api_http_events():
    db_path = BASE_DIR / "data" / "honeypot.db"

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT timestamp, source_ip, device_id,
                       event_type, details
                FROM events
                WHERE source = 'http_decoy'
                ORDER BY timestamp DESC
                LIMIT 100
            """).fetchall()

        return jsonify({
            "total": len(rows),
            "events": [
                {
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "device_id": row["device_id"],
                    "event_type": row["event_type"],
                    "details": json.loads(row["details"])
                    if row["details"] else {},
                }
                for row in rows
            ],
        })

    except (sqlite3.Error, json.JSONDecodeError):
        app.logger.exception("Could not retrieve HTTP decoy events")
        return jsonify({"error": "Could not retrieve HTTP decoy events."}), 500


# These are heuristic indicators, not proof of malicious activity.
# Keep account-management commands separate from references to /etc/passwd.
SUSPICIOUS_PATTERNS = [
    ("download tool", re.compile(r"\b(wget|curl|fetch)\b", re.I)),
    ("permission change", re.compile(r"^\s*(?:sudo\s+)?chmod\b", re.I)),
    (
        "account change",
        re.compile(r"^\s*(?:sudo\s+)?(?:passwd|useradd|adduser|usermod)\b", re.I),
    ),
    (
        "sensitive file",
        re.compile(r"/etc/(?:shadow|sudoers)\b|\.ssh/authorized_keys\b", re.I),
    ),
    (
        "firewall change",
        re.compile(r"^\s*(?:sudo\s+)?(?:iptables|nft|ufw)\b", re.I),
    ),
    (
        "persistence",
        re.compile(r"\bcrontab\b|\bsystemctl\s+enable\b|/\.local/bin\b", re.I),
    ),
    (
        "remote shell",
        re.compile(r"\b(nc|netcat|ncat|socat)\b|\bbash\s+-i\b", re.I),
    ),
]


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def iso_time(value: Any) -> str | None:
    dt = parse_time(value)
    return dt.isoformat().replace("+00:00", "Z") if dt else (str(value) if value else None)


def suspicious_reasons(command: str) -> list[str]:
    """Return heuristic labels for command text; these labels are not verdicts."""
    if not command:
        return []
    return [label for label, pattern in SUSPICIOUS_PATTERNS if pattern.search(command)]


def read_events() -> list[dict[str, Any]]:
    """Read Cowrie's JSON-lines file. Bad/incomplete lines are skipped safely."""
    events: list[dict[str, Any]] = []
    try:
        with LOG_PATH.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(raw, dict):
                    continue

                event = dict(raw)
                event["timestamp"] = iso_time(event.get("timestamp"))
                event["eventid"] = str(event.get("eventid", "unknown"))
                event["src_ip"] = str(
                    event.get("src_ip") or event.get("src_ip6") or "unknown"
                )
                event["session"] = str(event.get("session") or "")

                # Only login events should provide a username. Do not treat a
                # command's text as a username.
                event["username"] = str(event.get("username") or "unknown")
                event["command"] = str(event.get("input") or event.get("command") or "")
                event["message"] = str(event.get("message") or event.get("eventid") or "")
                event["_raw_timestamp"] = event.get("timestamp") or ""
                event["suspicious_reasons"] = (
                    suspicious_reasons(event["command"])
                    if event["eventid"].lower() == "cowrie.command.input"
                    else []
                )
                events.append(event)
    except FileNotFoundError:
        app.logger.warning("Cowrie log file not found: %s", LOG_PATH)
        return []
    except OSError:
        app.logger.exception("Could not read Cowrie log at %s", LOG_PATH)
        return []

    events.sort(
        key=lambda e: parse_time(e.get("timestamp"))
        or datetime.min.replace(tzinfo=timezone.utc)
    )
    return events


def is_command_event(event: dict[str, Any]) -> bool:
    eventid = str(event.get("eventid", "")).lower()
    return eventid == "cowrie.command.input"


def get_login_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        e
        for e in events
        if str(e.get("eventid", "")).lower()
        in {"cowrie.login.success", "cowrie.login.failed"}
    ]


def get_command_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if is_command_event(e) and e.get("command")]


def enrich_usernames(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fill missing usernames from login events in the same session."""
    session_users: dict[str, str] = {}
    for event in events:
        eid = str(event.get("eventid", "")).lower()
        if event.get("session") and eid in {
            "cowrie.login.success",
            "cowrie.login.failed",
        }:
            user = event.get("username")
            if user and user != "unknown":
                session_users[event["session"]] = str(user)

    enriched = []
    for original in events:
        event = dict(original)
        if event.get("session") and (
            not event.get("username") or event["username"] == "unknown"
        ):
            event["username"] = session_users.get(event["session"], "unknown")
        enriched.append(event)
    return enriched


def build_sessions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events = enrich_usernames(events)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        session_id = event.get("session")
        if session_id:
            grouped[str(session_id)].append(event)

    sessions = []
    for session_id, rows in grouped.items():
        rows.sort(
            key=lambda e: parse_time(e.get("timestamp"))
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        login_rows = [
            e
            for e in rows
            if str(e.get("eventid", "")).lower()
            in {"cowrie.login.success", "cowrie.login.failed"}
        ]
        success = any(
            str(e.get("eventid", "")).lower() == "cowrie.login.success"
            for e in login_rows
        )
        failed = any(
            str(e.get("eventid", "")).lower() == "cowrie.login.failed"
            for e in login_rows
        )
        commands = [e for e in rows if is_command_event(e) and e.get("command")]
        start_dt = parse_time(rows[0].get("timestamp"))
        end_dt = parse_time(rows[-1].get("timestamp"))
        reasons = sorted(
            {
                reason
                for event in commands
                for reason in event.get("suspicious_reasons", [])
            }
        )
        users = [
            str(e.get("username"))
            for e in login_rows
            if e.get("username") and e.get("username") != "unknown"
        ]

        sessions.append(
            {
                "session": session_id,
                "username": users[-1]
                if users
                else next(
                    (
                        str(e.get("username"))
                        for e in rows
                        if e.get("username") != "unknown"
                    ),
                    "unknown",
                ),
                "src_ip": next(
                    (e.get("src_ip") for e in rows if e.get("src_ip") != "unknown"),
                    "unknown",
                ),
                "start": rows[0].get("timestamp"),
                "end": rows[-1].get("timestamp"),
                "duration_seconds": round(
                    max(0.0, (end_dt - start_dt).total_seconds()), 1
                )
                if start_dt and end_dt
                else None,
                "login_success": success,
                "login_failed": failed,
                "command_count": len(commands),
                "event_count": len(rows),
                "event_types": dict(
                    Counter(str(e.get("eventid", "unknown")) for e in rows)
                ),
                "suspicious": bool(reasons),
                "suspicious_reasons": reasons,
                "commands": [
                    {
                        "timestamp": e.get("timestamp"),
                        "command": e.get("command"),
                        "src_ip": e.get("src_ip"),
                        "suspicious_reasons": e.get("suspicious_reasons", []),
                    }
                    for e in commands
                ],
                "events": [
                    {
                        "timestamp": e.get("timestamp"),
                        "eventid": e.get("eventid"),
                        "message": e.get("message"),
                        "command": e.get("command"),
                        "username": e.get("username"),
                        "src_ip": e.get("src_ip"),
                    }
                    for e in rows
                ],
            }
        )

    sessions.sort(
        key=lambda s: parse_time(s.get("start"))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return sessions


def filter_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    q = request.args.get("q", "").strip().lower()
    event_type = request.args.get("type", "all").strip().lower()
    ip = request.args.get("ip", "").strip().lower()
    username = request.args.get("username", "").strip().lower()
    suspicious_only = request.args.get("suspicious", "").lower() in {
        "1",
        "true",
        "yes",
    }
    start = parse_time(request.args.get("from"))
    end = parse_time(request.args.get("to"))
    filtered = []

    for event in enrich_usernames(events):
        dt = parse_time(event.get("timestamp"))
        if start and (not dt or dt < start):
            continue
        if end and (not dt or dt > end):
            continue
        if event_type != "all" and event_type not in str(event.get("eventid", "")).lower():
            continue
        if ip and ip not in str(event.get("src_ip", "")).lower():
            continue
        if username and username not in str(event.get("username", "")).lower():
            continue
        if suspicious_only and not event.get("suspicious_reasons"):
            continue
        haystack = " ".join(
            str(event.get(k, ""))
            for k in (
                "eventid",
                "username",
                "src_ip",
                "command",
                "message",
                "session",
            )
        ).lower()
        if q and q not in haystack:
            continue
        filtered.append(event)
    return filtered


def make_stats(events: list[dict[str, Any]]) -> dict[str, Any]:
    events = enrich_usernames(events)
    logins = get_login_events(events)
    commands = get_command_events(events)
    sessions = build_sessions(events)
    event_counts = Counter(str(e.get("eventid", "unknown")) for e in events)
    ip_counts = Counter(str(e.get("src_ip", "unknown")) for e in events)
    username_counts = Counter(
        str(e.get("username", "unknown"))
        for e in logins
        if e.get("username") and e.get("username") != "unknown"
    )
    command_counts = Counter(
        str(e.get("command", "")) for e in commands if e.get("command")
    )
    minute_counts: Counter[str] = Counter()

    for event in events:
        dt = parse_time(event.get("timestamp"))
        if dt:
            minute_counts[dt.strftime("%Y-%m-%d %H:%M")] += 1

    return {
        "total_events": len(events),
        "total_sessions": len(sessions),
        "login_attempts": len(logins),
        "successful_logins": sum(
            str(e.get("eventid", "")).lower() == "cowrie.login.success"
            for e in logins
        ),
        "failed_logins": sum(
            str(e.get("eventid", "")).lower() == "cowrie.login.failed"
            for e in logins
        ),
        "unique_ips": len(
            {
                e.get("src_ip")
                for e in events
                if e.get("src_ip") and e.get("src_ip") != "unknown"
            }
        ),
        "command_types_count": len(command_counts),
        # Count only command-input events, not arbitrary events carrying text.
        "suspicious_events": sum(
            bool(e.get("suspicious_reasons")) for e in get_command_events(events)
        ),
        "top_commands": [
            {"command": k, "count": v} for k, v in command_counts.most_common(8)
        ],
        "top_ips": [{"ip": k, "count": v} for k, v in ip_counts.most_common(8)],
        "top_usernames": [
            {"username": k, "count": v} for k, v in username_counts.most_common(8)
        ],
        "event_types": [
            {"eventid": k, "count": v} for k, v in event_counts.most_common(10)
        ],
        "timeline": [
            {"time": k, "count": v} for k, v in sorted(minute_counts.items())[-60:]
        ],
        "recent_commands": [
            {
                "timestamp": e.get("timestamp"),
                "command": e.get("command"),
                "src_ip": e.get("src_ip"),
                "username": e.get("username"),
                "session": e.get("session"),
                "suspicious_reasons": e.get("suspicious_reasons", []),
            }
            for e in reversed(commands[-10:])
        ],
        "last_event_at": events[-1].get("timestamp") if events else None,
        "log_path": str(LOG_PATH),
        "log_available": LOG_PATH.exists(),
    }


def build_report(events: list[dict[str, Any]]) -> dict[str, Any]:
    stats = make_stats(events)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "Cowrie JSON log",
        "log_path": str(LOG_PATH),
        "note": "Suspicious labels are heuristic indicators, not proof of compromise or malicious intent.",
        **stats,
        "suspicious_commands": [
            e
            for e in get_command_events(enrich_usernames(events))
            if e.get("suspicious_reasons")
        ],
        "sessions": build_sessions(events),
        "recent_events": [
            {
                k: e.get(k)
                for k in (
                    "timestamp",
                    "eventid",
                    "username",
                    "src_ip",
                    "command",
                    "message",
                    "session",
                    "suspicious_reasons",
                )
            }
            for e in reversed(events[-100:])
        ],
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/stats")
def api_stats():
    return jsonify(make_stats(read_events()))


@app.get("/api/events")
def api_events():
    all_events = read_events()
    filtered = filter_events(all_events)
    try:
        requested_limit = int(request.args.get("limit", 500))
    except ValueError:
        requested_limit = 500
    limit = min(max(requested_limit, 1), 5000)
    output = [
        {
            k: event.get(k)
            for k in (
                "timestamp",
                "eventid",
                "username",
                "src_ip",
                "command",
                "message",
                "session",
                "suspicious_reasons",
            )
        }
        for event in reversed(filtered[-limit:])
    ]
    return jsonify({"total": len(filtered), "returned": len(output), "events": output})


@app.get("/api/sessions")
def api_sessions():
    sessions = build_sessions(read_events())
    q = request.args.get("q", "").strip().lower()
    status = request.args.get("status", "all").lower()
    suspicious = request.args.get("suspicious", "").lower() in {"1", "true", "yes"}
    filtered = []

    for session in sessions:
        if q and q not in " ".join(
            str(session.get(k, "")) for k in ("session", "username", "src_ip")
        ).lower():
            continue
        if status == "success" and not session["login_success"]:
            continue
        if status == "failed" and not session["login_failed"]:
            continue
        if suspicious and not session["suspicious"]:
            continue
        filtered.append(session)

    return jsonify({"total_sessions": len(filtered), "sessions": filtered})


@app.get("/api/report")
def api_report():
    response = jsonify(build_report(read_events()))
    response.headers["Content-Disposition"] = (
        'attachment; filename="iot-honeypot-report.json"'
    )
    return response


@app.get("/api/export.csv")
def api_export_csv():
    events = filter_events(read_events())
    output = io.StringIO(newline="")
    fields = [
        "timestamp",
        "eventid",
        "username",
        "src_ip",
        "command",
        "message",
        "session",
        "suspicious_reasons",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for event in events:
        row = dict(event)
        row["suspicious_reasons"] = "; ".join(event.get("suspicious_reasons", []))
        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="iot-honeypot-events.csv"'
        },
    )
@app.get("/api/brute-force")
def api_brute_force():
    report_path = BASE_DIR / "brute_force_report.json"

    if not report_path.exists():
        return jsonify({
            "error": "Brute-force report not found. Run brute_force_detector.py first."
        }), 404

    try:
        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError):
        app.logger.exception("Could not read brute-force report")
        return jsonify({"error": "Could not read brute-force report."}), 500

    return jsonify(report)


@app.get("/api/db-stats")
def api_db_stats():
    db_path = BASE_DIR / "data" / "honeypot.db"

    if not db_path.exists():
        return jsonify({"error": "SQLite database not found."}), 404

    try:
        with sqlite3.connect(db_path) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            rows = conn.execute("""
                SELECT source, COUNT(*)
                FROM events
                GROUP BY source
                ORDER BY source
            """).fetchall()

        return jsonify({
            "database": str(db_path),
            "total_events": total,
            "events_by_source": [
                {"source": source, "count": count}
                for source, count in rows
            ],
        })

    except sqlite3.Error:
        app.logger.exception("Could not query SQLite database")
        return jsonify({"error": "Could not query SQLite database."}), 500



if __name__ == "__main__":
    # Keep this bound to loopback for a local lab dashboard.
    app.run(host="127.0.0.1", port=5000, debug=False)
