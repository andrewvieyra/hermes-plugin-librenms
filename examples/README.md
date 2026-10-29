# Examples

Each file is a ready-to-use `librenms_plan` payload (`description` and `operations`). Hostnames, names
and ids refer to a small demo instance (`core-sw1`, `edge-rtr1` and `access-sw2` under `example.net`,
locations `SFO-1` and `NYC-2`); adjust them for yours. Fault ids change all the time: look the current
one up with `librenms_query` `faults` first.

| File | What it shows | Needs |
|---|---|---|
| `move-and-maintenance.json` | A device moved to another location (with `override_sysLocation`, so the next poll keeps it there) and a two-hour maintenance window, which the plan marks as irreversible | |
| `ensure-location-and-group.json` | Idempotent creates: a location and a static device group whose member is named by hostname | |
| `uplink-descriptions.json` | Port descriptions set by device and `ifName`; the plan warns that they stay pinned until cleared | |
| `ack-alert.json` | Acknowledging one fault with a note; `until_clear: false` lets LibreNMS raise it again if it gets worse or better | |
| `add-device-snmpv3.json` | Adding a device over SNMPv3 with its credentials named as environment variables, never written into the plan | `allow_device_add: true`; `LIBRENMS_SNMP_V3_USER`, `LIBRENMS_SNMP_V3_AUTH`, `LIBRENMS_SNMP_V3_PRIV` set |

Try the slash command inside a Hermes session first:

```
/librenms status
```

then ask the agent, for example: "Plan the change in examples/move-and-maintenance.json and show me the
diff."
