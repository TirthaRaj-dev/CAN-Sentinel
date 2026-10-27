# CAN-Sentinel integration contract — Week 3 Day 1

## Important status

This contract is a proposed shared interface. Member 2's sniffer output and Member 3's
actual detection output were not available for inspection when this adapter was written.
Do not describe their modules as integrated until both teammates confirm/adapt to this contract.

## Traffic message (Member 2 → dashboard)

A Python dictionary per CAN frame:

```python
{
    "timestamp": "2026-10-27T17:30:00.000Z",
    "can_id": "0x100",
    "payload": "0A FF 00 11",
    "status": "NORMAL"
}
```

Required fields: `can_id`, `payload`. `timestamp` is preserved if supplied; otherwise an
UTC ISO-8601 timestamp is generated. `status` defaults to `NORMAL`; valid values are
`NORMAL` and `SUSPICIOUS`. Aliases accepted for adapting existing code: `canId`/`id`,
`data`, `state`, `time`, `ts`. CAN ID and payload are normalized to uppercase text.

## Detection result (Member 3 → dashboard)

```python
{
    "timestamp": "2026-10-27T17:30:00.015Z",
    "can_id": "0x100",
    "severity": "HIGH",
    "reason": "Abnormal message frequency"
}
```

Required fields: `can_id`, `severity`, `reason`. Severity must be `LOW`, `MEDIUM`, `HIGH`,
or `CRITICAL`. `timestamp` is kept as the detector's event time (or generated if absent).
Optional `payload`/`data` can be supplied. `level` and `description`/`message` aliases are
accepted. A detection marks its corresponding traffic row `SUSPICIOUS`; the traffic timestamp
is not overwritten by the alert timestamp.

## Transport is not decided yet

This day defines data structures only. It does not assume CSV, file tailing, sockets, or a
Unix-domain socket transport. The project brief mentions Unix Domain Sockets, but Members 2
and 3 must confirm the actual transport and serialization before live connection work.

## Offline sample

`integration.adapter.sample_integration_input()` returns one traffic record and one detector
result. It lets the interface and tests be validated without starting either teammate's module.
