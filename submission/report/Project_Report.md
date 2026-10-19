## Chapter 3: Requirements and Design

### 3.1 Hardware and Software Requirements

**Hardware**
- Computer capable of running Ubuntu through WSL2.
- CPU and RAM sufficient for Python, Flask, and local log analysis.
- Internet connection for initial software installation and dashboard chart-library access, if required.

**Software**
- Windows with WSL2 and Ubuntu.
- Python virtual environment.
- Cowrie SSH honeypot.
- Flask web framework.
- SQLite database.
- Pandas, scikit-learn, and Joblib.
- HTML, CSS, JavaScript, and Chart.js.

### 3.2 System Architecture

The system consists of these components:

1. **Interaction layer:** A controlled client connects to the SSH honeypot or sends requests to the simulated HTTP IoT device.
2. **Collection layer:** Cowrie records SSH sessions, login attempts, and command activity. The HTTP decoy records requests to the simulated device.
3. **Storage layer:** Events are stored in logs and SQLite for retrieval and analysis.
4. **Analysis layer:** Historical logs are analyzed, and rule-based logic identifies potential brute-force activity.
5. **Machine-learning layer:** A Random Forest prototype classifies aggregated activity using four features: failed logins, successful logins, commands, and downloads.
6. **Presentation layer:** A Flask dashboard displays statistics, event history, session information, HTTP-decoy requests, and historical detection results.

### 3.3 Data Flow

Client interaction → Honeypot logging → Event storage → Analysis and detection → Dashboard and reports.

The ML workflow separately aggregates historical activity, creates heuristic labels, trains a Random Forest classifier, and saves the model for inference through a Flask API.

### 3.4 Database Design

The SQLite `events` table contains the following fields:

- `id`: event identifier.
- `timestamp`: event time.
- `source`: event source, such as Cowrie or the HTTP decoy.
- `source_ip`: source address recorded by the honeypot.
- `device_id`: associated device identifier.
- `event_type`: type of recorded event.
- `session_id`: session identifier, when available.
- `username`: associated username, when available.
- `details`: additional event information.
- `fingerprint`: event fingerprint field.

### 3.5 Security and Isolation

The dashboard is configured to listen on `127.0.0.1:5000`, restricting access to the local machine interface. Honeypot services should remain confined to the controlled lab. Public exposure, router port forwarding, and unauthorized testing are outside the project's scope.

## Chapter 4: Implementation

### 4.1 Cowrie SSH Honeypot

Cowrie captures SSH interaction events. A controlled local session was used to verify successful login recording, command logging, and session closure. The dashboard displayed the session and its recorded commands.

### 4.2 HTTP IoT Decoy

The simulated smart-camera management service records HTTP requests. At the recorded checkpoint, five requests were visible in the dashboard for device `IOT-CAM-001`. Recorded paths included `/`, `/favicon.ico`, and `/admin`.

### 4.3 SQLite Event Storage

At the recorded checkpoint, the database contained 13 Cowrie events and five HTTP-decoy events, for a total of 18 events. The database schema supports event source, timestamp, device, event type, session, username, and additional details.

### 4.4 Historical Log Analysis

The historical analyzer processed 68 Cowrie log files, reporting 5,184,564 events, 10,103 unique source IPs, 612,527 unique sessions, 369,551 failed logins, 213,932 successful logins, and 14,912 command events.

### 4.5 Brute-Force Detection

The rule-based detector uses a threshold of ten failed logins from one source IP within 60 seconds. Analysis reported 369,551 failed-login events and 2,020 potential alerts. Alerts are heuristic indicators and may overlap; they are not confirmed unique attacks.

### 4.6 Random Forest Prototype

A Random Forest classifier was trained using aggregated historical source-IP activity. The features were failed logins, successful logins, command count, and download count. Heuristic rules generated the training labels. The saved model was loaded successfully, and a sample prediction returned the suspicious class.

The reported test accuracy was 100% against the heuristic labels. Because these labels were derived from rules using the same activity features, this score does not demonstrate independently verified attack-detection accuracy.

### 4.7 Flask Dashboard and API

The dashboard displays Cowrie event statistics, charts, command activity, session investigation, HTTP-decoy requests, historical brute-force results, and event export controls. The following endpoints were tested and returned HTTP 200:

- `/`
- `/api/stats`
- `/api/events`
- `/api/db-stats`
- `/api/ml-status`

The `/api/ml-predict` endpoint was also tested successfully using a sample feature record.

## Chapter 5: Results and Evaluation

### 5.1 Controlled SSH Demonstration

A local SSH interaction was recorded by Cowrie. The dashboard showed the successful login and commands such as `whoami`, `pwd`, `ls`, and `exit`.

### 5.2 HTTP Decoy Demonstration

The HTTP decoy recorded five requests at the checkpoint. The dashboard displayed timestamps, device ID, source IP, request method and path, and user-agent information.

### 5.3 Historical Dataset Analysis

The analyzer processed 5.18 million events from 68 files. This demonstrates the ability to summarize a large historical log collection. The historical data is separate from the controlled local demonstration.

### 5.4 Machine-Learning Results

The model trained on 5,886 aggregated source-IP records, with 4,708 training records and 1,178 test records. Its reported classification metrics were 100% against the generated heuristic labels. These results should be interpreted as agreement with the labeling rules, not proof of generalization to independently verified attacks.

### 5.5 Limitations and Threats to Validity

- The HTTP decoy represents a limited simulated IoT interface.
- The controlled demonstration primarily used localhost traffic.
- Historical Cowrie data does not represent live attacks against this lab.
- Brute-force alerts can overlap and require analyst review.
- ML labels are heuristic-generated rather than independently verified.
- The model requires evaluation using separately labeled scenarios before real-world performance claims can be made.
- Cross-source correlation and live ML scoring in the dashboard require further validation.

## Chapter 6: Conclusion and Future Work

The project demonstrates a local IoT deception prototype combining SSH and HTTP interaction logging, SQLite event storage, historical log analysis, heuristic brute-force detection, a Random Forest prototype, and a Flask dashboard.

Future work includes additional IoT protocol emulation, stronger cross-source event correlation, independently labeled evaluation datasets, false-positive analysis, and integration of model predictions into the dashboard's event-review workflow.
# IoT Deception Honeypot Network for Proactive Cyber Threat Detection and Analysis

## Abstract

This project develops a local IoT deception environment to collect, analyze, and visualize suspicious interactions. It integrates Cowrie SSH monitoring, an HTTP IoT decoy, SQLite event storage, historical brute-force analysis, a Random Forest machine-learning prototype, and a Flask dashboard. The prototype demonstrates event collection and analysis in a controlled lab. Independent evaluation is required to establish real-world detection performance.

## Chapter 1: Introduction

### 1.1 Background
### 1.2 Problem Statement
### 1.3 Objectives
### 1.4 Project Scope

## Chapter 2: Literature Review

### 2.1 Honeypot Systems
### 2.2 IoT Deception
### 2.3 Brute-Force Detection
### 2.4 Machine Learning for Cybersecurity

## Chapter 3: Requirements and Design

### 3.1 Hardware and Software Requirements
### 3.2 System Architecture
### 3.3 Data Flow
### 3.4 Database Design
### 3.5 Security and Isolation

## Chapter 4: Implementation

### 4.1 Cowrie SSH Honeypot
### 4.2 HTTP IoT Decoy
### 4.3 SQLite Event Storage
### 4.4 Historical Log Analysis
### 4.5 Brute-Force Detection
### 4.6 Random Forest Prototype
### 4.7 Flask Dashboard and API

## Chapter 5: Results and Evaluation

### 5.1 Controlled SSH Demonstration
### 5.2 HTTP Decoy Demonstration
### 5.3 Historical Dataset Analysis
### 5.4 Machine-Learning Results
### 5.5 Limitations and Threats to Validity

## Chapter 6: Conclusion and Future Work

## References

## Appendix A: Installation and Execution

## Appendix B: Demonstration Evidence
