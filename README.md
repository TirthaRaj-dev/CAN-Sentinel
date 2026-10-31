# CAN-Sentinel — Member 4 — Week 3 Day 5

Automotive ECU Intrusion Detection System dashboard integration validation.

## Requirements

- Python 3.10+ (use the Python version supported by the team environment)
- PyQt5
- Member 2's CAN sniffer and Member 3's detector, running with a mutually agreed transport/schema for live validation

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Launch in demonstration mode

```powershell
$env:CAN_SENTINEL_SOURCE = "demo"
$env:CAN_SENTINEL_DETECTION_SOURCE = "off"
python dashboard.py
```

Demo mode creates simulated traffic. It does not connect to a vehicle and does not represent the trained detector's output.

## File-based integration smoke test

The bundled JSONL files are fixtures. To read them from the beginning:

```powershell
$env:CAN_SENTINEL_SOURCE = "file"
$env:CAN_SENTINEL_SNIFFER_FILE = "$PWD\integration\sample_sniffer.jsonl"
$env:CAN_SENTINEL_SNIFFER_FROM_START = "1"
$env:CAN_SENTINEL_DETECTION_SOURCE = "file"
$env:CAN_SENTINEL_DETECTION_FILE = "$PWD\integration\sample_detection.jsonl"
$env:CAN_SENTINEL_DETECTION_FROM_START = "1"
python dashboard.py
```

Confirm the actual live transport and message schema with Members 2 and 3 before configuring their output. The worker supports file/TCP input options as described in `INTEGRATION-CONTRACT.md` and README environment settings. Queue clients are intended for modules sharing the same Python process.

## Day 5 validation

Run the tests:

```powershell
python -m py_compile dashboard.py integration\adapter.py integration\sniffer_client.py integration\detection_client.py integration\workers.py tests\test_integration.py
python -m unittest discover -s tests -p "test_integration.py" -v
python -m unittest discover -s tests -v
```

Then follow the manual checklist in `VALIDATION-STATUS.md`. In particular, validate actual live traffic and detector output together, filtering, alert matching, CSV exports, start/stop behavior, UI responsiveness, and error handling.

## Screenshots

Save genuine screenshots of the locally running integrated prototype under `screenshots/`. Include the traffic view and alert history if both are available. Do not use sample-data screenshots as evidence of live integration.

## Known limitations

- Sample files are fixtures, not real teammate module output.
- Integration depends on both modules providing the agreed fields and transport.
- Alert detection quality depends on Member 3's detector; the dashboard visualizes results rather than preventing attacks.
- An alert may be retained even if the corresponding traffic row is unavailable.
