# CAN-Sentinel — Member 4 Dashboard

## Project overview
CAN-Sentinel is an educational demonstration dashboard for simulated Controller Area Network (CAN) traffic and potential intrusion alerts related to automotive Electronic Control Units (ECUs). The dashboard is built with Python and PyQt5.

## Features
- Simulated CAN messages with timestamp, CAN ID, payload, and status.
- Traffic filtering by CAN ID and NORMAL/SUSPICIOUS status.
- Separate alert history with severity and reason.
- Alert filtering by severity and reason.
- CSV export of filtered traffic and filtered alert history.
- Export confirmation showing the number of records written.
- Start/stop monitoring controls and session summary cards.
- Clear visible traffic/alert rows without deleting stored records.
- Clear all session data with confirmation.
- Severity colors and a visible demonstration-mode limitation notice.

## Requirements
- Python 3.10 or newer.
- PyQt5 (installed using `requirements.txt`).

## Setup on Windows (PowerShell)
Run these commands from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python dashboard.py
```

If PowerShell blocks activation, you can run the environment's Python directly:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe dashboard.py
```

## Automated validation
Install dependencies first, then run:

```powershell
python -m py_compile dashboard.py tests\test_dashboard.py
python -m unittest discover -s tests -v
```

On a headless Linux CI environment, use:
```bash
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -v
```

## Manual validation checklist
1. Launch the dashboard.
2. Start monitoring; confirm rows and summary counters update.
3. Stop monitoring; confirm new messages stop.
4. Filter traffic by CAN ID and status.
5. Wait for a suspicious demo message (every seventh generated message) and inspect Alert History.
6. Filter alerts by severity and reason.
7. Export filtered traffic and confirm the CSV header and row count.
8. Export filtered alert history and confirm severity/reason columns and row count.
9. Clear the traffic display and verify stored records can still be exported.
10. Clear the alert display and verify stored alert history can still be exported.
11. Use Clear All Session Data, confirm the prompt, and verify counters and records reset.
12. Cancel a CSV save dialog and verify no file is created.

## Screenshots
Capture real screenshots from the running application and save them in `screenshots/`:
- `dashboard-traffic.png`
- `dashboard-alerts.png`

Do not add mock or generated screenshots as evidence of a successful GUI run.

## Demo limitations and safety
Traffic is simulated, payloads are illustrative, and suspicious messages are marked using a simple demonstration rule. The dashboard is not connected to a real vehicle/ECU and does not use a trained machine-learning model. Do not use it as a real automotive security monitor.

## Week 3 Day 1 — Integration interface

- Proposed common traffic schema and detection-result schema are documented in `INTEGRATION-CONTRACT.md`.
- `integration/adapter.py` validates and normalizes incoming dictionaries without depending on PyQt.
- The current demo generator routes its simulated traffic and alerts through the adapter.
- Run adapter tests with `python -m unittest tests.test_adapter -v` if `tests` is a package, or use `python -m unittest discover -s tests -p "test_adapter.py" -v` (recommended).
- Member 2 and Member 3 formats/transport still need confirmation; the adapter accepts common aliases but is not proof of live integration.
