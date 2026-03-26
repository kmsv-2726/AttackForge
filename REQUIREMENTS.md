# AI Cyber Attack Simulator — Master Requirements

## What this project is (in plain English)

This project builds a **safe, fake hacking environment** for security research.
It has two AIs:

1. **The Simulator** — pretends to be a hacker. Generates realistic log files
   that look like real cyberattacks happened (phishing, ransomware, insider threats).
   Nothing real is hacked. It only produces data.

2. **The Detector** — reads those fake logs and tries to catch the attacks.
   This is the AI we are actually training and improving.

The simulator exists to **manufacture training data** for the detector, because
real attack data is rare and companies won't share it.

---

## The goal

> Generate realistic fake cyberattack logs → train an AI to detect them →
> measure how good the detection is → make the attacks sneakier → improve detection.

This loop (simulate → detect → measure → evolve) is the core research contribution.

---

## Project folder structure

```
cyber-attack-simulator/
│
├── simulator/
│   ├── log_generator.py        ← generates normal (benign) log events
│   ├── attacks/
│   │   ├── phishing.py         ← simulates phishing attack behavior
│   │   ├── ransomware.py       ← simulates ransomware behavior
│   │   └── insider_threat.py  ← simulates malicious insider behavior
│   └── scenario_runner.py     ← runs a full attack scenario end to end
│
├── detector/
│   ├── features.py            ← converts raw logs into ML-ready features
│   ├── model.py               ← defines the ML model(s)
│   └── train.py               ← trains and saves the detector model
│
├── data/
│   ├── normal_logs/           ← CSV files of benign activity
│   └── attack_logs/           ← CSV files with injected attack events
│
├── evaluation/
│   └── metrics.py             ← precision, recall, F1, ROC-AUC, confusion matrix
│
├── notebooks/
│   └── explore.ipynb          ← visualizations and experiment results
│
├── configs/
│   └── attack_configs.yaml    ← tunable parameters for each attack type
│
├── REQUIREMENTS.md            ← this file
└── requirements.txt           ← pip install list
```

---

## Tech stack

| Purpose              | Library              |
|----------------------|----------------------|
| Language             | Python 3.10+         |
| Data handling        | pandas, numpy        |
| Fake data generation | faker, random        |
| ML models            | scikit-learn         |
| Deep learning (later)| PyTorch              |
| Visualization        | matplotlib, seaborn  |
| Config files         | PyYAML               |
| Notebooks            | jupyter              |

Install all at once:
```
pip install pandas numpy faker scikit-learn torch matplotlib seaborn pyyaml jupyter
```

---

## The three attack types we simulate

### 1. Phishing
**What it is:** Fake emails trick users into entering their passwords.
**What it looks like in logs:**
- Many failed login attempts from unusual IPs
- Successful login from a new geographic location right after failures
- Password reset events
- Logins at unusual hours (e.g. 3am)

**Key log fields to generate:**
`timestamp, user_id, event_type, source_ip, success, location`

---

### 2. Ransomware
**What it is:** Malicious software that encrypts all your files and demands payment.
**What it looks like in logs:**
- Sudden spike: thousands of file READ then WRITE events in seconds
- Files being renamed (e.g. `report.docx` → `report.docx.locked`)
- High CPU usage events
- New process spawned from unusual location

**Key log fields to generate:**
`timestamp, process_name, file_path, event_type, file_size_bytes`

---

### 3. Insider Threat
**What it is:** An employee (or their stolen account) stealing data.
**What it looks like in logs:**
- Accessing files in departments they don't work in
- Copying unusually large amounts of data to USB or cloud
- Logging in outside of normal working hours
- Accessing many files rapidly in a short window

**Key log fields to generate:**
`timestamp, user_id, department, file_path, action, bytes_transferred`

---

## Log format standard

All logs are saved as CSV files with these shared base fields:

```
timestamp        — ISO format datetime e.g. 2024-03-15 14:32:01
event_id         — unique ID for this log row
event_type       — LOGIN, FILE_ACCESS, NETWORK, PROCESS, AUTH_FAIL etc.
user_id          — username e.g. john.smith
source_ip        — IPv4 address
hostname         — machine name e.g. DESKTOP-A4X2
label            — 0 = normal, 1 = attack  (added during injection step)
attack_type      — "none", "phishing", "ransomware", "insider_threat"
```

Additional fields vary per event type (see attack sections above).

---

## The ML detector

### Phase 1 — Anomaly detection (unsupervised, Week 6)
- **Model:** Isolation Forest (scikit-learn)
- **Input:** numeric feature vectors extracted from log windows
- **Why:** Doesn't need labeled data. Learns what "normal" looks like, flags outliers.
- **Output:** score per log window (-1 = anomaly, 1 = normal)

### Phase 2 — Supervised classifier (Week 7)
- **Model:** Random Forest Classifier (scikit-learn)
- **Input:** same feature vectors, but now with labels (0=normal, 1=attack)
- **Why:** More accurate when we have labeled training data
- **Output:** probability that a window is an attack

### Features to extract from raw logs (features.py)
```
login_count              — logins in last 5 minutes
failed_login_rate        — failed / total logins
unique_ips               — distinct IPs seen
files_accessed_per_min   — file events per minute
bytes_transferred        — total bytes in window
hour_of_day              — 0-23, captures time anomalies
is_weekend               — boolean
new_ip_flag              — IP not seen before for this user
```

---

## Evaluation metrics (evaluation/metrics.py)

| Metric        | Plain English                                      |
|---------------|----------------------------------------------------|
| Precision     | Of all alerts raised, how many were real attacks?  |
| Recall        | Of all real attacks, how many did we catch?        |
| F1 Score      | Balance of precision and recall (higher = better) |
| ROC-AUC       | Overall quality score (0.5 = random, 1.0 = perfect)|
| MTTD          | Average minutes until an attack was first detected |
| False alarm rate | How often it cried wolf on normal activity      |

---

## The adversarial loop (Week 9)

After the detector is trained, we make the simulator "sneakier" by:
- Spreading attack events over longer time windows (harder to spot spikes)
- Randomizing timing to blend into normal traffic patterns
- Reducing the volume of attack events (lower signal)

Then we re-run the detector and measure if scores drop.
This shows the arms race between attacker and defender — the core research value.

---

## Weekly implementation plan

| Week | Task                                     | File(s) to build                        |
|------|------------------------------------------|-----------------------------------------|
| 1    | Generate normal (benign) logs            | simulator/log_generator.py              |
| 2    | Inject attack events into logs           | simulator/attacks/ (all three)          |
| 3    | Phishing scenario end-to-end             | simulator/attacks/phishing.py (full)    |
| 4    | Ransomware + insider threat scenarios    | simulator/attacks/ransomware.py, insider_threat.py |
| 5    | Feature extraction from logs             | detector/features.py                    |
| 6    | Train anomaly detector                   | detector/model.py, detector/train.py    |
| 7    | Train supervised classifier              | detector/train.py (extend)              |
| 8    | Evaluation framework                     | evaluation/metrics.py                   |
| 9    | Adversarial loop — make attacks sneakier | configs/attack_configs.yaml + re-eval   |
| 10   | Visualizations, write-up, demo           | notebooks/explore.ipynb                 |

---

## Rules for the LLM implementing this

1. **Always check which week/file is being built before writing code.**
2. **Every log generator must output a valid CSV** with the base fields defined above.
3. **Labels must always be included** — every row gets `label=0` (normal) or `label=1` (attack).
4. **Keep each file focused** — log_generator.py only generates logs, features.py only extracts features. No mixing responsibilities.
5. **Write docstrings** on every function explaining what it does in plain English.
6. **Use config files** for tunable numbers (attack duration, volume, timing) — never hardcode magic numbers.
7. **Test every file** by running it standalone before moving to the next week.
