# Week 3 — Day 5 Validation Status

## Scope

This validation package checks the dashboard integration contracts and client behavior for CAN traffic from Member 2 and detection events from Member 3. Sample JSONL files are demonstration fixtures; they are not proof that the teammates' live modules are connected.

## Day 5 checklist

- [ ] Confirm Member 2's actual output transport, host/port or file path, and record schema.
- [ ] Confirm Member 3's actual output transport, host/port or file path, and record schema.
- [ ] Start both real modules and configure the dashboard using the agreed interfaces.
- [ ] Verify incoming traffic timestamps, CAN IDs, payloads, and status.
- [ ] Verify detection timestamp, suspected CAN ID, severity, and reason.
- [ ] Verify alert-to-traffic matching where a CAN ID/payload match exists.
- [ ] Verify CAN ID/status filters and alert severity/reason filters.
- [ ] Export traffic and alert CSV files and inspect their contents.
- [ ] Start and stop monitoring; verify that the GUI remains responsive.
- [ ] Verify malformed records, stream closure, and connection errors do not crash the GUI.
- [ ] Confirm visible table row limits while full session records remain exportable.
- [ ] Capture genuine screenshots from the locally running integrated prototype and place them in `screenshots/`.

## Automated checks

Run from the repository root:

```powershell
python -m py_compile dashboard.py integration\adapter.py integration\sniffer_client.py integration\detection_client.py integration\workers.py tests\test_integration.py
python -m unittest discover -s tests -p "test_integration.py" -v
python -m unittest discover -s tests -v
```

The integration tests use temporary JSONL files and validate both client contracts. They do not test real ECU hardware, teammate processes, the GUI event loop, or the trained detector. Complete the manual checklist before marking the integrated prototype validated.

## Known limitations

- File/TCP JSONL are supported interface options; use the actual transport agreed with Members 2 and 3.
- Sample records and simulated dashboard traffic are demonstration data.
- Alert matching is based on available CAN ID and payload/time information; missing matching traffic does not invalidate the alert.
- IDS alerts can include false positives and false negatives; dashboard display is not attack prevention.
- Screenshots must be captured from the real local run; no placeholder screenshot is included.
