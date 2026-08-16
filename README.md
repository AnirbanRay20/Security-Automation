# Python Security Automation & AI/ML Threat Detection Suite

Three Python automation tools for the SOC: a dependency-free port
scanner, a log-enrichment pipeline (ip-api.com + VirusTotal), and an
ML-based phishing/threat classifier.

## Repository Layout
```
.
├── port_scanner.py           # Task 1 — multithreaded TCP scanner + banner grabbing
├── log_enricher.py           # Task 2 — regex IP extraction + ip-api.com enrichment
├── virustotal_check.py       # Task 4 — VirusTotal v3 enrichment
├── ml_threat_detector.py     # Task 3 — Random Forest + Isolation Forest
├── phishing.csv              # UCI "Phishing Websites" dataset (11,055 rows, 30 features)
├── sample_data/
│   ├── sample_firewall.log       # sample input log for log_enricher.py
│   ├── ip_api_sample.json        # mocked ip-api.com responses
│   └── virustotal_sample.json    # mocked VirusTotal responses
├── requirements.txt
├── .env.example
└── .gitignore
```

## External API Fallback / Mock Mode

`ip-api.com` and the VirusTotal API were not reachable from the
environment this suite was developed and tested in (network egress was
restricted to a small allow-list that didn't include either domain).
Per the assignment's fallback guidance, both `log_enricher.py` and
`virustotal_check.py` accept a `--mock` flag that reads pre-saved
sample JSON from `sample_data/` instead of making a live HTTP call,
exercising the exact same parsing/formatting code path either way. All
outputs shown below were captured by actually running these scripts
(mock mode for the two external APIs; live execution for the scanner
and the ML pipeline). No real API keys appear anywhere in this
repository — set `VT_API_KEY` via `.env` (see `.env.example`) to run
`virustotal_check.py` live.

---

## Task 1 — Port Scanner

```
python3 port_scanner.py <target_ip> <start_port> <end_port> [--timeout SECONDS] [--threads N]
```

Real output against a local test listener on port 9999:
```
Scan results for 127.0.0.1 (ports 9990-10005):
Port    State   Banner
--------------------------------------------------
9999    open    220 test-service ready
```

Uses only `socket` and `threading` (no `nmap`/`subprocess`). A
`threading.Lock` guards the shared results list so concurrent worker
threads can't corrupt it when appending simultaneously; a
per-connection timeout (default 1s) keeps a single filtered port from
stalling the whole scan; banner bytes are decoded with
`errors="replace"` so a non-UTF-8 banner degrades gracefully instead
of crashing the scan.

---

## Task 2 — Log Enricher (ip-api.com)

```
python3 log_enricher.py sample_data/sample_firewall.log --mock
```

Real output (mock mode, 3 unique public IPs extracted from the sample
firewall/auth log, private ranges skipped):
```json
{
  "192.0.2.44": {
    "country": "Germany",
    "isp": "Example Consumer ISP GmbH",
    "hosting": false,
    "proxy": false,
    "mobile": false
  },
  "198.51.100.23": {
    "country": "Netherlands",
    "isp": "Example Cloud Provider B.V.",
    "hosting": true,
    "proxy": true,
    "mobile": false
  },
  "203.0.113.5": {
    "country": "United States",
    "isp": "Example Hosting Ltd.",
    "hosting": true,
    "proxy": false,
    "mobile": false
  }
}
```

Private-range filtering deliberately checks membership in
`10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` explicitly (rather
than the broader `ipaddress.IPv4Address.is_private`), matching the
task's exact scope — `is_private` also excludes loopback and
documentation/TEST-NET ranges, which would over-filter relative to
what was asked.

**Live mode failure handling** (real output, run against the actual
unreachable endpoint rather than simulated) — confirms the script
degrades gracefully instead of crashing:
```json
{
  "203.0.113.5": {
    "error": "request failed: 403 Client Error: Forbidden for url: http://ip-api.com/json/203.0.113.5"
  }
}
```

---

## Task 4 — VirusTotal Enrichment

```
export VT_API_KEY=your_real_key_here
python3 virustotal_check.py sample_data/sample_firewall.log
# or, offline:
python3 virustotal_check.py sample_data/sample_firewall.log --mock
```

Real output (mock mode) for two of the extracted IPs:
```json
{
  "198.51.100.23": {
    "malicious_detections": 14,
    "harmless_detections": 23,
    "last_analysis_date": "2025-08-13T16:00:00+00:00"
  },
  "203.0.113.5": {
    "malicious_detections": 7,
    "harmless_detections": 24,
    "last_analysis_date": "2025-08-13T16:00:00+00:00"
  }
}
```

`VT_API_KEY` is read only from the environment (via `python-dotenv` +
`.env`, listed in `.env.example`, excluded via `.gitignore`) — never
hardcoded. Live mode returns a clean error message (not a traceback)
on a 401 (bad key), 429 (rate limit), or 404 (IP not found), and when
`VT_API_KEY` isn't set at all it exits with a clear instruction rather
than an unhandled `KeyError`.

### Input → Process → Output

All three data-gathering scripts follow the same automation shape:
**Input** is a target the analyst provides (an IP/port range for the
scanner, a log file path for the enrichers); **Process** is the
script's core logic (socket connection attempts and banner parsing for
`port_scanner.py`; regex extraction, deduplication, and an external
API call for `log_enricher.py` and `virustotal_check.py`); **Output**
is a structured, machine-parseable result (a formatted table or JSON)
that a human analyst or a downstream SOAR step can consume without
manual reformatting.

---

## Task 3 — Machine Learning Threat Detector

**Dataset:** UCI Machine Learning Repository, "Phishing Websites"
(Mohammad, R. & McCluskey, L., 2012), 11,055 rows, 30 lexical/URL
features, binary `class` label (`1` = legitimate, `-1` = phishing).
Mirrored as `phishing.csv` in this repository for reproducibility.

First five rows:
```
   Index  UsingIP  LongURL  ...  LinksPointingToPage  StatsReport  class
0      0        1        1  ...                    1            1     -1
1      1        1        0  ...                    0           -1     -1
2      2        1        0  ...                   -1            1     -1
3      3        1        0  ...                    1            1      1
4      4       -1        0  ...                   -1           -1      1
```

Class distribution:
```
 1    6157   (legitimate)
-1    4897   (phishing)
```

Preprocessing: 0 rows dropped for nulls, 0 duplicate rows found —
11,054 rows remain after dropping the non-informative `Index` column
(one row less than the raw file's row count due to how the header is
counted; verified against `len(df)` directly).

**Random Forest — full `classification_report` on the 20% test split
(`random_state=42`):**
```
                precision    recall  f1-score   support

 phishing (-1)       0.97      0.96      0.96       976
legitimate (1)       0.97      0.98      0.97      1235

      accuracy                           0.97      2211
     macro avg       0.97      0.97      0.97      2211
  weighted avg       0.97      0.97      0.97      2211
```

**Isolation Forest** (unsupervised; `contamination` set to the
training set's observed phishing proportion; evaluated post hoc
against the true labels):

### Model Comparison

| Model | Accuracy | Precision | Recall | F1 Score | Notes |
|---|---|---|---|---|---|
| Random Forest | 0.9692 | 0.9687 | 0.9765 | 0.9726 | Supervised; trained on labelled data; near-ceiling performance on this feature set |
| Isolation Forest | 0.4858 | 0.5410 | 0.5231 | 0.5319 | Unsupervised; no label information used during training; performs close to random on this dataset |

### Discussion (≈190 words)

Raw accuracy is a misleading metric on security datasets because the
classes are rarely balanced in production — most traffic/logins/URLs
are benign, so a model that always predicts "benign" can score high
accuracy while catching zero real threats. Precision and recall
separate the two failure modes that actually matter operationally:
precision (of everything flagged malicious, how much really was)
controls analyst fatigue from false positives, while recall (of
everything actually malicious, how much was caught) controls how many
real intrusions slip through as false negatives — and in a SOC, a
missed true positive is usually far more costly than an extra alert to
triage. The F1 score is the harmonic mean of precision and recall,
useful as a single number when neither false positives nor false
negatives can be ignored, though a SOC should still look at precision
and recall separately since the acceptable trade-off point differs by
use case.

The supervised Random Forest's core limitation is that it can only
recognize attack patterns present (and correctly labelled) in its
training data — it will not reliably catch a genuinely novel phishing
technique with different structural features. The unsupervised
Isolation Forest's limitation is visible directly in the results
above: without label information to anchor what "malicious" looks
like for this specific feature set, it performs close to chance,
illustrating that anomaly detection alone is not a drop-in replacement
for a trained classifier when the anomaly class doesn't manifest as a
statistical outlier in the feature space used.

---

## Task 5 — SOAR Workflow Description (≈230 words)

The three tools map onto distinct stages of a SOAR pipeline. **Data
collection** is `port_scanner.py`: run on a schedule or triggered by a
change-detection event, it produces a structured open-port/banner
inventory that feeds the asset-visibility layer the rest of the
pipeline depends on. **Enrichment** is `log_enricher.py` and
`virustotal_check.py` together: when a firewall or auth log produces a
public IP of interest, the SOAR platform calls both scripts to attach
geolocation/ISP/hosting-proxy context and vendor reputation scores
before any human ever looks at the alert, turning a bare IP address
into an actionable, contextualized event. **Detection** is
`ml_threat_detector.py`'s Random Forest classifier, invoked against
new observations (e.g., a submitted URL, or features derived from an
enriched IP) to produce a malicious/benign classification with an
associated confidence score from `predict_proba`.

That confidence score is what determines the SOAR platform's branch:
a high-confidence malicious classification (e.g., ≥ 0.90) combined
with a corroborating VirusTotal `malicious_detections` count above a
small threshold (e.g., ≥ 5 vendors) triggers **automated response** —
blocking the source IP at the firewall via the Task-1/Part-2 iptables
rules, no human in the loop. A mid-confidence result (roughly 0.60–0.90,
or a high ML confidence with zero corroborating VirusTotal
detections) escalates to a human analyst for review rather than acting
automatically, since this is the range where false positives are most
likely and an automated block risks disrupting legitimate traffic —
the SOC accepts slower response for these cases specifically to avoid
that cost. Anything below ~0.60 confidence is logged but not
escalated, on the assumption that the false-negative risk of ignoring
a weak signal is lower than the analyst-fatigue cost of paging someone
for it.
