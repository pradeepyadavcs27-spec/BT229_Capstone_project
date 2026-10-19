# IoT Deception Honeypot Network for Proactive Cyber Threat Detection and Analysis

## 1. Project Overview

This project implements a local IoT deception environment for collecting, analyzing, and visualizing suspicious interactions. It combines an SSH honeypot, an HTTP IoT decoy, historical brute-force analysis, event storage, and a machine-learning prototype.

The system is intended for controlled cybersecurity research and demonstration.

## 2. Objectives

- Capture SSH login attempts and command activity using Cowrie.
- Simulate an IoT device management interface using an HTTP decoy.
- Store and analyze honeypot events.
- Identify potential brute-force activity using rule-based detection.
- Train a Random Forest prototype using historical Cowrie activity.
- Visualize events and analysis results in a Flask dashboard.
- Export event information for further investigation.

## 3. Technology Stack

- Python
- Flask
- Cowrie SSH honeypot
- SQLite
- Pandas
- Scikit-learn
- Joblib
- HTML, CSS, and JavaScript
- Chart.js

## 4. System Architecture

1. Cowrie records SSH interactions.
2. The HTTP decoy records requests to a simulated IoT device.
3. Event records are analyzed and stored in the local database.
4. A rule-based detector analyzes historical failed-login activity.
5. A Random Forest model produces prototype classifications.
6. Flask API endpoints supply data to the dashboard.
7. The dashboard displays events, sessions, charts, and detection results.

## 5. Current Demonstration Results

- SQLite database: 18 events at the recorded checkpoint.
- Cowrie log: 13 events at the recorded checkpoint.
- HTTP IoT decoy: 5 requests at the recorded checkpoint.
- Historical dataset: 5,184,564 events analyzed across 68 files.
- Historical brute-force analysis: 369,551 failed-login events and 2,020 potential alerts.
- ML training dataset: 5,886 source-IP records.
- ML prototype: Random Forest classifier trained and saved.
- Flask dashboard and ML API: tested successfully.

These are recorded checkpoint results; live counts may change.

## 6. Machine-Learning Limitations

The training labels are generated using heuristic rules based on login and activity features. The reported 100% test accuracy measures agreement with these generated labels, not independently verified real-world attack detection. Predictions should be treated as preliminary indicators requiring analyst review.

## 7. Running the Project

Run the following commands in Ubuntu/WSL from the project directory:

```bash
cd ~/iot-honeypot
source cowrie-env/bin/activate
python app.py
```

Open the local dashboard at:

http://127.0.0.1:5000

The model can be retrained with:

```bash
python train_model.py
```

The application uses local API endpoints, including `/api/stats`, `/api/events`, `/api/db-stats`, `/api/ml-status`, and `/api/ml-predict`.

## 8. Safety and Scope

This project is intended for an isolated local lab. Keep honeypot services restricted to the lab environment. Do not expose them to the public internet or use them to collect credentials from systems without authorization.

## 9. Future Improvements

- Add more IoT device emulations and protocols.
- Improve correlation between SSH and HTTP events.
- Create independently labeled evaluation scenarios.
- Evaluate detection precision, recall, and false-positive rates against verified labels.
- Integrate model predictions into the dashboard's event review workflow.
- Improve automated report generation.

## 10. Conclusion

The prototype demonstrates local honeypot event collection, historical brute-force analysis, event visualization, and a machine-learning classification workflow. Further evaluation with independently labeled data is required before making claims about real-world detection accuracy.
# BT229_Capstone_project
Major Project

## Dataset
Historical Cowrie honeypot logs: 68 files, April to June 2021, about 5.18 million events,
10,103 unique attacker IPs. Source: PASTE LINK HERE.
Place the logs in `datasets/cowrie_dataset/logs/`. The dataset is not committed to git.

## Machine learning
`train_model.py` builds one feature row per attacker IP, labels brute-force IPs with the
10-failures-in-60-seconds rule, and trains a Random Forest (supervised) and an Isolation Forest
(unsupervised).

    pip install -r requirements.txt
    python train_model.py datasets/cowrie_dataset/logs

Random Forest on a 25% held-out test set: precision 0.965, recall 0.991, F1 0.978.
Labels come from the rule-based detector, so this measures how well behavior reproduces that
rule, not independent ground truth. The Isolation Forest agreed poorly with the brute-force
label (precision 0.10).
