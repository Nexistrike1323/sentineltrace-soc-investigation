# SentinelTrace

**Evidence-Based SOC Investigation Platform**

SentinelTrace is a local-first Security Operations Center (SOC) investigation platform designed to ingest security events, normalize telemetry, identify suspicious activity, preserve supporting evidence, and generate investigation reports.

It combines a Python-based detection engine, FastAPI backend, and React-based analyst dashboard.

The project is intended for SOC learning, security research, controlled testing, and local investigation workflows.

## Features

- JSON and JSONL security event ingestion.
- Windows Security and Sysmon event normalization.
- Wazuh Windows event normalization.
- Timestamp, host, user, IP address, and session context extraction.
- Rule-based security event detection.
- Evidence-backed findings with timestamps and event fingerprints.
- Investigation event explorer and evidence timeline.
- JSON and Markdown investigation reports.
- SHA-256 artifact integrity verification.
- Local investigation storage.
- Windows event collection through PowerShell.
- React dashboard for investigation workflows.

## Architecture

```text
Windows Event Logs / JSON / JSONL / Wazuh
                    |
                    v
          Windows Event Collector
                    |
                    v
             Event Parser
                    |
                    v
          Event Normalization
                    |
                    v
           Detection Engine
                    |
                    v
             Five Detection Rules
                    |
                    v
          Evidence-backed Findings
                    |
                    v
            FastAPI Backend
                    |
          +---------+---------+
          |                   |
          v                   v
   Investigation Store    Report Generator
          |                   |
          +---------+---------+
                    |
                    v
           React Analyst UI
```

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python 3.12+ |
| API | FastAPI |
| API Server | Uvicorn |
| Frontend | React 19 |
| Language | TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS |
| Charts | Recharts |
| Icons | Lucide React |
| Testing | Pytest |
| Event Collection | Windows PowerShell |

## Detection Rules

SentinelTrace currently implements five detection rules.

| Rule ID | Detection | Description |
|---|---|---|
| ST-001 | Failed Login Followed by Success | Detects repeated failed authentication attempts followed by a successful login within a defined time window. |
| ST-002 | Suspicious PowerShell Activity | Identifies suspicious PowerShell execution indicators, including encoded commands and download or execution patterns. |
| ST-003 | Public IP RDP Logon | Identifies successful Remote Desktop logons from globally routable IP addresses. |
| ST-004 | Password Spraying | Detects repeated authentication failures against multiple distinct usernames from the same source. |
| ST-005 | Security Log Cleared | Detects Windows Security log-clearing event ID 1102. |

Detection findings include relevant evidence such as event identifiers, timestamps, host information, usernames, source IP addresses, and event fingerprints where available.

**Important:** These are rule-based detections, not definitive proof of compromise. Findings require analyst validation and environmental context.

## Project Structure

```text
sentineltrace-soc-investigation/
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── scripts/
│   └── collect_windows_events.ps1
├── src/
│   └── sentineltrace/
│       ├── api.py
│       ├── cli.py
│       ├── detections.py
│       ├── engine.py
│       ├── models.py
│       ├── parser.py
│       └── reporter.py
├── tests/
├── data/
│   ├── raw/
│   └── investigations/
├── reports/
├── pyproject.toml
└── LICENSE
```

## Requirements

- Python 3.12 or later.
- Node.js 22 or a compatible supported version.
- npm.
- Git.

The Windows event collector requires Windows PowerShell and access to the relevant Windows event channels.

## Installation

Clone the repository:

```bash
git clone https://github.com/Nexistrike1323/sentineltrace-soc-investigation.git

cd sentineltrace-soc-investigation
```

### 1. Set up the Python environment

Linux / WSL:

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .
```

Install API dependencies:

```bash
python -m pip install fastapi uvicorn python-multipart
```

Install testing dependency:

```bash
python -m pip install pytest
```

### 2. Set up the frontend

```bash
cd frontend

npm ci
```

## Running SentinelTrace

Run the backend API from the repository root:

```bash
uvicorn sentineltrace.api:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

Run the frontend in a separate terminal:

```bash
cd frontend

npm run dev
```

Open:

```text
http://localhost:5173
```

## Command-Line Usage

SentinelTrace also provides a command-line interface for event analysis.

Example:

```bash
sentineltrace run --input data/raw/events.json --out reports
```

Supported input formats:

- JSON
- JSONL

The CLI reports successfully parsed events, rejected records, generated findings, and report locations.

Generated reports include JSON and Markdown output. Parser errors are saved separately when present.

## Windows Event Collection

The PowerShell collector is located at:

```text
scripts/collect_windows_events.ps1
```

Run it from an elevated PowerShell session when the required event log permissions demand it:

```powershell
Set-ExecutionPolicy -Scope Process Bypass

.\scripts\collect_windows_events.ps1
```

The collector supports the configured Windows Security, Sysmon (when available), and Terminal Services Local Session Manager event channels.

Collection depends on the channels and events available on the host. Missing optional channels, such as Sysmon, do not necessarily indicate a collector failure.

Review the collector output before importing it into SentinelTrace.

## API Endpoints

Base URL:

```text
http://127.0.0.1:8000
```

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | API health status |
| POST | `/api/investigations` | Upload and analyze an event file |
| GET | `/api/investigations` | List investigations |
| GET | `/api/investigations/{id}` | Retrieve investigation details |
| GET | `/api/investigations/{id}/events` | Retrieve investigation events |
| GET | `/api/investigations/{id}/timeline` | Retrieve event timeline |
| GET | `/api/investigations/{id}/report` | Retrieve report data |
| GET | `/api/investigations/{id}/report/markdown` | Retrieve Markdown report |
| GET | `/api/investigations/{id}/integrity` | Verify investigation artifact integrity |

The upload endpoint accepts `.json` and `.jsonl` files with a maximum upload size of 25 MB.

## Investigation Integrity

SentinelTrace generates a SHA-256 integrity manifest for stored investigation artifacts.

The integrity endpoint checks stored artifact hashes against the generated manifest and reports verified, mismatched, or missing artifacts.

**Integrity limitation:** The manifest is stored locally alongside the investigation artifacts. An attacker with write access to both the artifacts and manifest could modify both. This is an integrity verification mechanism, not independently trusted or tamper-proof evidence storage.

## Testing

Run the backend test suite:

```bash
python -m pytest -q
```

Build the frontend:

```bash
cd frontend

npm run lint
npm run build
```

## Data Storage and Privacy

SentinelTrace is designed for local investigation workflows.

- Uploaded investigation files are stored locally.
- Reports are generated locally.
- The application does not require a paid cloud API.
- Security telemetry should be treated as sensitive data.
- Do not commit real security logs, investigation evidence, credentials, or private data to source control.

Review `.gitignore` before committing or publishing any data.

## Security Considerations and Limitations

- Detection rules are heuristic and require analyst validation.
- Public IP addresses alone do not establish malicious activity.
- Local SHA-256 manifests do not provide independently trusted chain-of-custody guarantees.
- The current application is intended for local development and controlled investigation workflows.
- Production deployment requires additional security controls, including authentication, authorization, access control, secure deployment configuration, and appropriate evidence retention.

## Roadmap

Potential future improvements include:

- Additional detection rules and telemetry sources.
- Expanded event correlation.
- SQLite-backed investigation storage.
- Authentication and role-based access control.
- Enhanced investigation audit trails.
- Improved detection tuning and analyst feedback workflows.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

## Author

**Meka Venkata Neeraj**

GitHub: [Nexistrike1323](https://github.com/Nexistrike1323)
