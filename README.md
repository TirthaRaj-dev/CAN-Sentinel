
# CAN-Sentinel: Automotive ECU Intrusion Detection System

## Project Overview

CAN-Sentinel is a demonstration dashboard for monitoring simulated
Controller Area Network (CAN) messages and displaying potential intrusion
alerts related to automotive Electronic Control Units (ECUs).

The dashboard is developed using Python and PyQt5.

## Features

- Simulated CAN traffic generation.
- Display of timestamps, CAN IDs, payloads, and message status.
- Filtering by CAN ID and message status.
- Separate intrusion alert history.
- Alert severity levels: LOW, MEDIUM, HIGH, and CRITICAL.
- Filtering alerts by severity and reason.
- Export of filtered CAN traffic to CSV.
- Export of filtered alert history to CSV.
- Start and stop monitoring controls.
- Clear traffic display without deleting stored records.
- Clear all session data with confirmation.
- Dashboard summary counters.

## Requirements

- Python 3.10 or later.
- PyQt5.
- Git (optional, for repository management).

## Installation on Windows

Open PowerShell in the project directory.

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Run the Dashboard

```powershell
python dashboard.py
```

## Run Automated Tests

```powershell
python -m py_compile dashboard.py tests\test_dashboard.py
python -m unittest discover -s tests -v
```

## Manual Testing Checklist

1. Launch the dashboard.
2. Start monitoring and confirm messages appear.
3. Stop monitoring and verify new messages stop appearing.
4. Filter messages using a CAN ID.
5. Filter traffic by NORMAL or SUSPICIOUS status.
6. Open Alert History and check severity and reason filters.
7. Export filtered traffic to CSV.
8. Export filtered alerts to CSV.
9. Clear the traffic display and confirm stored records remain exportable.
10. Clear all session data and confirm the counters and tables reset.

## Screenshots

Save genuine screenshots of the running dashboard in the `screenshots/`
directory. Suggested filenames:

- `dashboard-traffic.png`
- `dashboard-alerts.png`

## Demo Limitations

This version uses simulated CAN messages and demonstration alert logic.
It does not connect to a real vehicle or ECU and does not use a trained
machine-learning model.

It is intended for educational demonstration and development testing.
