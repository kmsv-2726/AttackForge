# AI Cyber Attack Simulator

> A research framework that simulates realistic cyberattacks, generates labeled log data,
> and trains ML-based detection models — creating a closed feedback loop between
> attacker simulation and defender improvement.

---

## What is this?

Most security AI systems are trained on old, unrealistic datasets.
This project addresses that gap with a **safe, configurable simulation engine**
that generates realistic attack data on demand — which is then used to train
and rigorously evaluate detection models.

Think of it as a **flight simulator for cybersecurity AI**.
No real systems are harmed. All attacks are simulated. The training value is real.

---

## The core idea

```
Simulate attack → Generate logs → Train detector → Measure accuracy
       ↑                                                    |
       └──────── Make attacker sneakier ←───────────────────┘
```

This feedback loop — where the simulator evolves to evade the detector,
forcing the detector to improve — makes this a research-grade system
rather than a simple data generator.

---

## Attack types simulated

| Attack | What it mimics | Key signals in logs |
|---|---|---|
| **Phishing** | Fake emails steal credentials | Failed logins → sudden success from new IP |
| **Ransomware** | Malware encrypts all files | Thousands of file reads/writes in seconds |
| **Insider Threat** | Employee stealing data | After-hours access, unusual departments, bulk transfers |

---

## Architecture

```
cyber-attack-simulator/
│
├── simulator/                  ← The "fake hacker"
│   ├── log_generator.py        ← Generates normal (benign) activity logs
│   ├── scenario_runner.py      ← Runs a full attack scenario end to end
│   └── attacks/
│       ├── phishing.py         ← Phishing credential theft simulation
│       ├── ransomware.py       ← Ransomware file encryption simulation
│       └── insider_threat.py   ← Malicious insider data theft simulation
│
├── detector/                   ← The "security guard AI"
│   ├── features.py             ← Extracts ML features from raw log CSVs
│   ├── model.py                ← Defines Isolation Forest & Random Forest models
│   └── train.py                ← Trains and compares both detectors
│
├── evaluation/                 ← The "measuring stick"
│   └── metrics.py              ← Precision, recall, F1, ROC-AUC, MTTD
│
├── data/                       ← (Ignored by git)
│   ├── normal_logs/            ← CSVs of benign activity
│   └── attack_logs/            ← CSVs with injected attack events
│
├── models/                     ← (Ignored by git)
│   └── *.pkl                   ← Saved model weights and ROC curves
│
├── configs/
│   └── attack_configs.yaml     ← Tunable parameters for each attack type
│
└── notebooks/
    └── explore.ipynb           ← Visualizations and experiment results
```

---

## Tech stack

| Purpose | Library |
|---|---|
| Language | Python 3.10+ |
| Data handling | pandas, numpy |
| Realistic fake data | faker |
| ML models | scikit-learn |
| Deep learning (Phase 2) | PyTorch |
| Visualization | matplotlib, seaborn |
| Configuration | PyYAML |
| Notebooks | Jupyter |

---

## Getting started

**1. Clone the repo**
```bash
git clone https://github.com/your-username/cyber-attack-simulator.git
cd cyber-attack-simulator
```

**2. Install dependencies**
```bash
pip install pandas numpy faker scikit-learn torch matplotlib seaborn pyyaml jupyter
```

**3. Generate normal log data**
```bash
python simulator/log_generator.py
```
This creates `data/normal_logs/normal_logs_<timestamp>.csv` with realistic log events.

**4. Run attack scenarios**
```bash
python simulator/scenario_runner.py --attack all
```

**5. Train and compare detectors**
```bash
python detector/train.py
```

**6. Evaluate with full metrics (standalone)**
```bash
python evaluation/metrics.py --model both
```

---

## Log format

Every log file — normal or attack — follows this standard schema:

| Field | Type | Example |
|---|---|---|
| `timestamp` | datetime | `2024-03-15 14:32:01` |
| `event_id` | UUID | `3f2a1c...` |
| `event_type` | string | `LOGIN`, `FILE_ACCESS`, `AUTH_FAIL` |
| `user_id` | string | `john.smith` |
| `source_ip` | IPv4 | `192.168.1.42` |
| `hostname` | string | `DESKTOP-A4X2` |
| `label` | int | `0` = normal, `1` = attack |
| `attack_type` | string | `none`, `phishing`, `ransomware`, `insider_threat` |

Additional fields (file paths, bytes transferred, process names) are added
per event type — see `REQUIREMENTS.md` for full schema.

---

## ML models

### Phase 1 — Anomaly detection (unsupervised)
- **Model:** Isolation Forest
- **Status:** ✓ COMPLETE
- **Mechanism:** Trained on normal traffic only to identify deviations.
- **Advantage:** No labeled data needed to start.

### Phase 2 — Supervised classifier
- **Model:** Random Forest Classifier
- **Status:** ✓ COMPLETE
- **Mechanism:** Trained on labeled attack vs. normal examples.
- **Advantage:** Higher accuracy, capable of classifying attack types.

### Features extracted from logs
```
login_count             failed_login_rate       unique_ips
files_accessed_per_min  bytes_transferred       hour_of_day
is_weekend              new_ip_flag             event_burst_rate
```

---

## Evaluation metrics

| Metric | What it means |
|---|---|
| **Precision** | Of all alerts raised, how many were real attacks? |
| **Recall** | Of all real attacks, how many were caught? |
| **F1 Score** | Balanced score of precision and recall |
| **ROC-AUC** | Overall quality (0.5 = random, 1.0 = perfect) |
| **MTTD** | Mean Time to Detect — average minutes until attack found |
| **False alarm rate** | How often it wrongly flagged normal activity |

---

## Build plan progress

| Week | Status | What was built |
|---|---|---|
| 1 | ✓ | Normal log generator (`log_generator.py`) |
| 2 | ✓ | Attack event injection into logs |
| 3 | ✓ | Phishing attack simulator (full scenario) |
| 4 | ✓ | Ransomware + insider threat simulators |
| 5 | ✓ | Feature extraction from raw logs |
| 6 | ✓ | Anomaly detection model (Isolation Forest) |
| 7 | ✓ | Supervised classifier (Random Forest) |
| 8 | ✓ | Evaluation framework + metrics (`metrics.py`) |
| 9 | | Adversarial loop — make attacks sneakier, retest |
| 10 | | Visualizations, write-up, demo |

---

## Research value

This project addresses a real gap: **publicly available attack datasets are often outdated
and don't reflect modern multi-stage attack patterns**.

The novel contribution is the adversarial feedback loop — the simulator
evolves attacks to evade the detector, generating progressively
harder training data. This mirrors how real-world attackers and defenders
actually operate, making trained models more robust than those trained on static datasets.

### Potential paper angles
- "Adaptive attack simulation for improving ML-based intrusion detection"
- "Closing the training data gap in network intrusion detection with generative simulation"
- Comparison: detector trained on synthetic adaptive data vs. static benchmark datasets

---

## Disclaimer

This project is built strictly for **security research and education**.
It does not perform any real network attacks.
All generated data is synthetic.
Do not use any component of this project against real systems without explicit authorization.

---

## License

MIT License — free to use, modify, and build on with attribution.
