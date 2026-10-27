# Week 3 Day 1 validation status

Prepared: adapter contract, sample inputs, dashboard demo-path adapter use, and unit tests.

Run from the repository root in PowerShell:

```powershell
python -m py_compile dashboard.py integrationdapter.py tests	est_adapter.py
python -m unittest discover -s tests -p "test_adapter.py" -v
python -m unittest discover -s tests -v
```

The adapter tests do not require PyQt. Full dashboard tests may require the dependencies in
`requirements.txt`. Only commit after the commands pass in the project environment and after
checking `git diff --check`.

Still required before calling this live integration: obtain/inspect the actual Member 2 and
Member 3 outputs, agree on the field names and transport, then update the contract/adapter if
necessary. No live module connection is implemented in Day 1.

Suggested commit: `feat: define sniffer and detection integration interfaces`
