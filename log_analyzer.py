
import json
from pathlib import Path
from collections import Counter

LOG_FILE = Path.home() / "iot-honeypot/var/log/cowrie/cowrie.json"


def analyze_logs():
    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    events = []
    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON on line {line_number}")

    print("\n========== COWRIE LOG ANALYZER ==========")
    print(f"Total events: {len(events)}")

    logins = [
        event for event in events
        if event.get("eventid") in (
            "cowrie.login.success",
            "cowrie.login.failed"
        )
    ]

    print(f"\nLogin attempts: {len(logins)}")
    print(f"Successful logins: {sum(e.get('eventid') == 'cowrie.login.success' for e in logins)}")
    print(f"Failed logins: {sum(e.get('eventid') == 'cowrie.login.failed' for e in logins)}")

    usernames = Counter(
        event.get("username", "unknown") for event in logins
    )
    print("\nMost-used usernames:")
    for username, count in usernames.most_common(10):
        print(f"  {username}: {count}")

    source_ips = Counter(
        event.get("src_ip", "unknown") for event in logins
    )
    print("\nSource IP addresses:")
    for ip, count in source_ips.most_common(10):
        print(f"  {ip}: {count}")

    commands = Counter(
        event.get("input", "")
        for event in events
        if event.get("eventid") == "cowrie.command.input"
        and event.get("input")
    )
    print("\nCommands entered:")
    if commands:
        for command, count in commands.most_common(15):
            print(f"  {command}: {count}")
    else:
        print("  No command-input events found.")

    print("\n=========================================")


if __name__ == "__main__":
    analyze_logs()
