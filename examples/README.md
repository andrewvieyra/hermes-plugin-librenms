# Examples

## Plans

Each file here is a ready-to-use `librenms_plan` payload (`description` and `operations`). Hostnames, names
and ids refer to a small demo instance (`core-sw1`, `edge-rtr1` and `access-sw2` under `example.net`,
locations `SFO-1` and `NYC-2`); adjust them for yours. Fault ids change all the time: look the current
one up with `librenms_query` `faults` first.

| File | What it shows | Needs |
|---|---|---|
| `move-and-maintenance.json` | A device moved to another location (with `override_sysLocation`, so the next poll keeps it there) and a two-hour maintenance window, which the plan marks as irreversible | |
| `ensure-location-and-group.json` | Idempotent creates: a location and a static device group whose member is named by hostname | |
| `uplink-descriptions.json` | Port descriptions set by device and `ifName`; the plan warns that they stay pinned until cleared | |
| `ack-alert.json` | Acknowledging one fault with a note; `until_clear: false` lets LibreNMS raise it again if it gets worse or better | |
| `add-device-snmpv3.json` | Adding a device over SNMPv3 with its credentials named as environment variables, never written into the plan | `allow_device_add: true`; `LIBRENMS_SNMP_V3_USER`, `LIBRENMS_SNMP_V3_AUTH_PASS`, `LIBRENMS_SNMP_V3_PRIV_PASS` set |

## Conversations

`conversations/` holds conversations with the agent about the same demo network, as the question skill
`librenms:ask` has the model hold them: each turn is what the user asked, the read-only calls the model made
(`librenms_report` arguments, built from the ids earlier answers gave), and the answer. Every value an answer
quotes in backticks is a value those calls returned, and each count, percentage and state is the one under the
key that holds it: `tests/test_conversation.py` runs each conversation against the test suite's fake LibreNMS,
set to noon UTC on 2026-10-28 with `librenms_timezone: UTC`, and checks both, the counts and states against the
keys it pins them to. Ask the same questions of your own network in your own words.

| File | What it shows |
|---|---|
| `conversations/wan-port-down.json` | Which ports on a router are down, whether they alert (and who acknowledged what), what is on the other end when LibreNMS does not monitor it, when the port went down and whether it did before, and the bill on that circuit |
| `conversations/busiest-port.json` | "The switch" when there are two: asking which, the busiest port, why last week's traffic is not in the API, the same for the other switch, and a long list read three at a time |
| `conversations/alerts.json` | What is alerting, since when (from the answer already given), how high the CPU of the critical one is, what alerted yesterday and which device alerted most this week |
| `conversations/where-is.json` | Where an IP address is plugged in, that port's speed, the switch's uplink, the other end of it, and its flaps today and yesterday |

## Trying them

Try the slash command inside a Hermes session first:

```
/librenms status
```

then ask the agent, for example: "Plan the change in examples/move-and-maintenance.json and show me the
diff." or "Which ports on edge-rtr1 are down?" (`/librenms:ask which ports on edge-rtr1 are down?` loads the
question skill first).
