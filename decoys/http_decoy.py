from flask import Flask, request, jsonify
from datetime import datetime, timezone
from pathlib import Path
import json

app = Flask(__name__)

DEVICE_ID = "IOT-CAM-001"
LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "http_decoy.jsonl"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


@app.before_request
def record_request():
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": DEVICE_ID,
        "source_ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


@app.get("/")
def device_home():
    return jsonify({
        "device": DEVICE_ID,
        "type": "Smart Camera",
        "firmware": "1.0.4",
        "status": "online",
    })


@app.get("/admin")
def admin_page():
    return jsonify({
        "device": DEVICE_ID,
        "page": "Device Administration",
        "authentication": "required",
    }), 401


@app.get("/api/status")
def device_status():
    return jsonify({
        "device": DEVICE_ID,
        "status": "online",
        "firmware": "1.0.4",
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)