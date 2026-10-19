
import json
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "datasets" / "cowrie_dataset" / "logs"


def analyze_dataset(log_dir=LOG_DIR):
    """Analyze Cowrie JSON logs one line at a time."""

    event_counts = Counter()
    source_ips = Counter()
    usernames = Counter()
    failed_ips = Counter()
    successful_ips = Counter()
    commands = Counter()

    total_events = 0
    invalid_lines = 0
    login_failed = 0
    login_success = 0
    command_events = 0
    sessions = set()

    log_files = sorted(log_dir.glob("cowrie.json*"))

    if not log_files:
        raise FileNotFoundError(
            f"No Cowrie log files found in: {log_dir}"
        )

    print(f"Found {len(log_files)} Cowrie log files.")

    for log_file in log_files:
        print(f"Reading: {log_file.name}")

        with log_file.open(
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
                    invalid_lines += 1
                    continue

                total_events += 1

                event_id = str(event.get("eventid", "unknown"))
                event_counts[event_id] += 1

                src_ip = event.get("src_ip") or event.get("src_ip6")
                if src_ip:
                    source_ips[str(src_ip)] += 1

                session = event.get("session")
                if session:
                    sessions.add(str(session))

                username = event.get("username")
                if username:
                    usernames[str(username)] += 1

                if event_id == "cowrie.login.failed":
                    login_failed += 1
                    if src_ip:
                        failed_ips[str(src_ip)] += 1

                elif event_id == "cowrie.login.success":
                    login_success += 1
                    if src_ip:
                        successful_ips[str(src_ip)] += 1

                elif event_id == "cowrie.command.input":
                    command_events += 1
                    command = event.get("input") or event.get("command")
                    if command:
                        commands[str(command)] += 1

    report = {
        "total_events": total_events,
        "invalid_lines": invalid_lines,
        "files_scanned": len(log_files),
        "unique_source_ips": len(source_ips),
        "unique_sessions": len(sessions),
        "failed_logins": login_failed,
        "successful_logins": login_success,
        "command_events": command_events,
        "top_event_types": event_counts.most_common(15),
        "top_source_ips": source_ips.most_common(15),
        "top_failed_login_ips": failed_ips.most_common(15),
        "top_successful_login_ips": successful_ips.most_common(15),
        "top_usernames": usernames.most_common(15),
        "top_commands": commands.most_common(15),
    }

    report_path = BASE_DIR / "historical_report.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("\n=== HISTORICAL DATASET SUMMARY ===")
    print(f"Files scanned:       {len(log_files):,}")
    print(f"Valid events:        {total_events:,}")
    print(f"Invalid lines:       {invalid_lines:,}")
    print(f"Unique source IPs:   {len(source_ips):,}")
    print(f"Unique sessions:     {len(sessions):,}")
    print(f"Failed logins:       {login_failed:,}")
    print(f"Successful logins:   {login_success:,}")
    print(f"Command events:      {command_events:,}")
    print(f"\nReport saved to: {report_path}")

    print("\nTop 10 failed-login source IPs:")
    for ip, count in failed_ips.most_common(10):
        print(f"{ip:>20}  {count:,}")

    print("\nTop 10 commands:")
    for command, count in commands.most_common(10):
        print(f"{count:>8,}  {command[:100]}")

    return report


if __name__ == "__main__":
    analyze_dataset()
