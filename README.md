# 🕵️‍♂️ TorTrace-AI

**Multi-Layer Tor Network Attribution System**
*Advanced AI-powered network forensics for identifying probable Tor entry (guard) nodes using statistical correlation, deep learning, and graph neural networks.*

> Developed for **TN Police Hackathon 2025** — Problem Statement: *Tor Network User Tracing*

---

## Table of Contents

* [Project Summary](#project-summary)
* [Problem Statement](#problem-statement)
* [Solution Overview](#solution-overview)
* [Key Features](#key-features)
* [Architecture & Workflow](#architecture--workflow)
* [Technical Approach](#technical-approach)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Quick Start](#quick-start)
* [Usage Examples](#usage-examples)
* [Project Structure](#project-structure)
* [Results](#results)
* [Validation & Testing](#validation--testing)
* [Roadmap](#roadmap)
* [Legal & Ethical Notice](#legal--ethical-notice)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgments](#acknowledgments)
* [References](#references)

---

## Project Summary

TorTrace-AI is a modular, production-minded toolset that combines **statistical timing correlation**, **deep-learning website fingerprinting (CNN-LSTM)**, and **graph neural networks (GNNs)** to produce ranked candidate guard nodes for Tor circuits. It includes PCAP analysis, automated Tor relay collection, an API for programmatic interaction, and a Flask dashboard for visualization and reporting.

---

## Problem Statement

The Tor network offers anonymity by forwarding traffic through multiple relays. This makes attribution of malicious activity and identification of origin IPs difficult for lawful investigations. TorTrace-AI provides a multi-method approach to increase confidence in guard node attribution while producing forensically useful artifacts.

---

## Solution Overview

TorTrace-AI performs three independent analyses on observed traffic and network state and combines results via an ensemble confidence scoring mechanism:

1. **Statistical Timing Correlation** — correlates inter-packet timing between entry and exit sides.
2. **Website Fingerprinting (CNN-LSTM)** — classifies websites from encrypted packet timing/size sequences.
3. **Graph Neural Network (GNN)** — predicts probable guard nodes from the Tor topology and centrality features.

Outputs are aggregated, assigned confidence scores, and presented in JSON reports and a web dashboard.

---

## Key Features

* Automated collection and storage of **9,000+ Tor relay** records.
* PCAP ingestion and Tor flow extraction.
* Multi-method guard node ranking with confidence scoring.
* Court-ready JSON forensic reports and logs.
* Real-time Flask dashboard for analysis and export.
* Modular codebase suitable for research, validation, and extension.

---

## Architecture & Workflow

```
Tor Network (Consensus) → data_collection/tor_collector.py → SQLite (tor_relays.db)
Network Traffic (PCAP)  → traffic_analysis/pcap_analyzer.py → timing/size feature sequences
Features → correlation/timing_correlator.py  → timing candidates
         → ml_models/website_fingerprinter.py → fingerprint candidates
         → ml_models/gnn_guard_predictor.py → GNN candidates
Ensemble → aggregator → JSON report + dashboard API
```

Screenshots (stored in `data/output_screenshots/`):

* `PCAP Traffic Analyzer Output.png`
* `Timing Correlation Output.png`
* `Website Fingerprinting Output.png`
* `Graph Neural Network (GNN) Predictor Output.png`
* `Dashboard.png`

---

## Technical Approach

### Multi-Method Consensus Attribution

* Independent methods reduce single-point false positives.
* Ensemble scoring reconciles timing, fingerprint, and graph confidences.

### Graph Neural Network

* Tor represented as a directed graph.
* Node features: PageRank, betweenness, degree centrality, relay flags.
* Supervised GNN predicts guard-node probability.

### CNN-LSTM Fingerprinting

* Inputs: packet inter-arrival times and packet sizes (sequence).
* CNN extracts local temporal patterns; LSTM models sequence dependencies.
* Outputs site classification probabilities.

### Statistical Timing Correlation

* Uses cross-correlation of packet timing sequences across observed flows.
* Produces candidate guard sets with correlation scores and p-values.

---

## Prerequisites

* Ubuntu 20.04+ (or similar Linux)
* Python 3.10+
* Tor (installed and running)
* `tcpdump`/`tshark` (for packet capture) — root privileges may be required
* Recommended: GPU for DL model training/inference (optional)

---

## Installation

```bash
# Clone repo
git clone https://github.com/Yashwanth2408/TorTrace-AI.git
cd TorTrace-AI

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure Tor control port (edit /etc/tor/torrc if needed)
# e.g., add:
# ControlPort 9051
# HashedControlPassword <your-hashed-password>

# Restart Tor
sudo systemctl restart tor

# Run unit/integration tests
python test_system.py
```

---

## Quick Start

1. **Collect Tor relay data**

```bash
python data_collection/tor_collector.py
```

2. **Capture or provide PCAP**

```bash
# Live capture (example; requires root)
sudo tcpdump -i any -w data/pcap_files/sample.pcap 'port 9001 or port 9030'

# Or use existing PCAP
mv /path/to/capture.pcap data/pcap_files/sample.pcap
```

3. **Analyze PCAP**

```bash
python traffic_analysis/pcap_analyzer.py --pcap data/pcap_files/sample.pcap --out data/pcap_files/analysis_results.json
```

4. **Run analysis modules**

```bash
# Timing correlator
python correlation/timing_correlator.py --input data/pcap_files/analysis_results.json --output data/results/timing_candidates.json

# Website fingerprinting
python ml_models/website_fingerprinter.py --input data/pcap_files/analysis_results.json --output data/results/fingerprint_candidates.json

# GNN guard predictor
python ml_models/gnn_guard_predictor.py --db data/tor_relays.db --input data/pcap_files/analysis_results.json --output data/results/gnn_candidates.json
```

5. **Aggregate & export**

```bash
python correlation/ensemble_aggregator.py --inputs data/results/*.json --output data/results/attribution_report.json
```

6. **Launch dashboard**

```bash
cd visualization
python dashboard_app.py
```

Open: `http://localhost:5000`

---

## Usage Examples

### Programmatic: Timing correlator API

```python
from correlation.timing_correlator import TimingCorrelator

tc = TimingCorrelator(db_path='data/tor_relays.db')
patterns = tc.load_traffic_patterns('data/pcap_files/analysis_results.json')
candidates = tc.find_guard_node_candidates(patterns, top_k=5)
print(candidates)
```

### Parse ensemble results (JSON)

```python
import json

with open('data/results/attribution_report.json') as f:
    report = json.load(f)
for item in report['candidates'][:10]:
    print(item['relay_fingerprint'], item['combined_score'])
```

---

## Project Structure

```
TorTrace-AI/
├── data_collection/         # tor_collector.py
├── traffic_analysis/        # pcap_analyzer.py, generate_sample_traffic.py
├── correlation/             # timing_correlator.py, ensemble_aggregator.py
├── ml_models/               # website_fingerprinter.py, gnn_guard_predictor.py
├── visualization/           # dashboard_app.py, templates/
├── data/                    # tor_relays.db, pcap_files/, output_screenshots/
├── tests/                   # unit & integration tests
├── test_system.py           # integration test runner
├── requirements.txt
└── README.md
```

---

## Results (Reported)

> These numbers reflect validation performed during hackathon testing and research runs.

* **Collected Relays:** 9,196 active relays (SQLite snapshot)
* **Analysis Speed:** Example: 330 packets processed in <1s (hardware dependent)
* **GNN Accuracy:** Reported 100% on observed guard nodes in controlled validation; **interpret with caution** (dataset bias possible)
* **Dashboard Latency:** <100 ms API response in tested environment

---

## Validation & Testing

Run the test harness:

```bash
python test_system.py
```

Expected tests:

* Tor Network Collection
* Traffic Generation / Sample Data
* PCAP Analysis
* Timing Correlation
* Website Fingerprinting
* GNN Prediction
* Dashboard API

---

## Roadmap

**Completed**

* Tor relay collection
* PCAP analysis pipeline
* Timing correlation engine
* CNN-LSTM fingerprint model
* GNN predictor
* Flask dashboard
* Integration tests

**In Progress**

* Live Tor traffic validation on diverse datasets
* Improved ensemble weighting and calibration
* Retraining ML models on larger labeled datasets

**Future**

* Live monitoring mode with alerting
* Multi-circuit correlation
* Automated, signed evidence chain (blockchain or notarization)
* Hardened deployment (containers, CI/CD, role-based access control)

---

## Legal & Ethical Notice

**Important:** This tool is intended for authorized law enforcement and legitimate cybersecurity research. Usage of this repository may involve access to sensitive network data and must comply with:

* Local and national laws governing network monitoring and interception.
* Proper authorization and documented legal authority for capturing and analyzing network traffic.
* Privacy, civil liberties, and data protection requirements.
* Ethical best practices in digital forensics.

**Unauthorized use for surveillance or privacy invasion is strictly prohibited.** The authors and contributors are not responsible for misuse.

---

## Contributing

Contributions that improve safety, reproducibility, model robustness, and legal/ethical safeguards are welcome. Please:

1. Open issues for bugs and feature requests.
2. Submit PRs against `main` with tests and documentation.
3. Follow a responsible disclosure process for vulnerabilities.

---

## License

This project was developed for **TN Police Hackathon 2025** (Problem Statement #4). Check the repository for a specific license file if you intend to reuse or redistribute code. If none exists, contact the project maintainer for licensing details.

---

## Contact

**Developer:** Yash
**Institution:** VIT Chennai
**Email:** [yashwanthbalaji.2408@gmail.com](mailto:yashwanthbalaji.2408@gmail.com)
**GitHub:** [https://github.com/Yashwanth2408](https://github.com/Yashwanth2408)

---

## Acknowledgments

* Tamil Nadu Police — TN Police Hackathon 2025
* The Tor Project — consensus data and documentation
* Academic research on traffic analysis, website fingerprinting, and GNNs
* Open-source Python ecosystem

---

## References

1. Tor network architecture and threat modeling literature
2. Statistical traffic analysis techniques
3. Deep learning for encrypted traffic classification (CNN, LSTM)
4. Graph neural networks for network analysis

---

**Built with purpose — for authorized cybersecurity research and lawful investigations.**
