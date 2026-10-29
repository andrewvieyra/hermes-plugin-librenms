# Forwarding audit events

The audit file (`audit.jsonl`, see [audit.md](audit.md)) is the source of truth. Sinks forward the
same events, as they happen, to a syslog server or an HTTP collector for installs that have no log
shipper on the Hermes machine. They are forwarded from the call that writes the file, so
`audit_log: false` stops both.

## Configuration

`plugins.entries.librenms.settings.audit_sinks` is a list. Any mix of sinks works, and each event
goes to all of them.

```yaml
plugins:
  entries:
    librenms:
      settings:
        audit_sinks:
          - type: syslog
            host: siem.example.com
            port: 6514
            protocol: tls        # udp | tcp | tls
            format: json         # json | cef
            facility: local0     # a facility name, or its number 0-23
            app_name: hermes-librenms
            verify_ssl: /etc/ssl/siem-ca.pem    # true (default) | false | a CA bundle file or directory
          - type: http
            url: https://splunk.example.com:8088/services/collector/event
            headers:
              Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
            format: hec          # json | hec
            timeout: 5
```

Keep a collector token in the profile's `.env` (`<HERMES_HOME>/.env`: `~/.hermes/.env` for the
default profile, `~/.hermes/profiles/<name>/.env` for a named one) and write it as `${VAR}` where
the entry needs it. Hermes' config loader replaces every `${VAR}` (or `${env:VAR}`) in the settings,
in `headers`, `url` and `host` alike, with the active profile's secret when the plugin reads its
settings, on the thread of the call that emits the event. The Desktop's settings form has a masked
field for this, `audit_sink_secret`, which stores the token as `LIBRENMS_AUDIT_SINK_SECRET`:

```yaml
            headers:
              Authorization: "Splunk ${LIBRENMS_AUDIT_SINK_SECRET}"
```

Once `audit_sinks` holds a placeholder, edit it in `config.yaml`, not in the Desktop's settings
form. Hermes fills that form from the settings as loaded, with every `${VAR}` already replaced by
its value, so the `audit_sinks` editor shows the token in clear, and saving that field writes the
token into `config.yaml` as a literal (which status then warns about). This is Hermes' behaviour,
not the plugin's; the masked `audit_sink_secret` field itself never shows or writes the token.

A placeholder still there after Hermes' expansion is a variable this profile does not set. That
entry is ignored (the other sinks still work), and Hermes' log names the variable and the profile's
`.env`, never a value: `librenms audit_sinks[1] (http) ignored: header Authorization holds
${SPLUNK_HEC_TOKEN}, which is not set for this Hermes profile; set it in ~/.hermes/profiles/netops/.env`.
The plugin never reads a placeholder itself: on the background thread that sends events no Hermes
profile is bound, and the process environment there holds another profile's values. Once Hermes
has the variable for the profile, the next event builds the sink.

A credential written straight into `config.yaml` (an `Authorization` header, or any header whose
name holds `token`, `key`, `secret`, `auth` or `pass`, with no `${VAR}` in its value) still works,
but `/librenms status` warns about it, and so does Hermes' log when the plugin loads, naming the
entry and the header only and saying to write the placeholder in `config.yaml` itself. The check
reads `config.yaml` as written, through Hermes, since the settings the plugin gets hold the
expanded values.

`/librenms status` shows how many sinks are configured and their types, never their hosts, URLs or
headers; the `config_digest` on every event covers the same.

## Transport

Events hold users' messages (the `request` field) and HTTP sinks carry a collector token, so the
transport is held to the same rules as the connection to LibreNMS:

- **No redirect is followed.** A collector that answers 301, 302, 303, 307 or 308 fails the send.
  Python's `urllib` would follow the first three for a POST and send the `Authorization` header to
  whatever host the `Location` header names.
- **Clear text only to this machine.** `udp` and `tcp` syslog, and an `http://` URL, are accepted
  when the host is a loopback address or `localhost` (for a local relay such as rsyslog or a
  Splunk forwarder), and otherwise only with `allow_insecure_transport: true`. Prefer `tls` and
  `https://`.
- **Verification on.** `verify_ssl: false` on `tls` syslog or an `https://` collector needs
  `allow_insecure_transport: true`. For a private CA, give its bundle (a file, or a directory of
  hashed certificates) in `verify_ssl` or `ca_file` instead.
- **No credentials in the URL.** An `http` sink URL with a user name or password is refused; put
  the credential in a header.
- **Proxies.** An `http` sink to a loopback host (`127.0.0.0/8`, `::1`, `localhost`,
  `*.localhost`) always connects directly, never through `HTTP_PROXY`, `HTTPS_PROXY` or
  `ALL_PROXY`, whatever `NO_PROXY` says: the clear text allowed to this machine must not travel to
  a proxy elsewhere. An `http` sink to any other host uses the environment's `HTTPS_PROXY` /
  `HTTP_PROXY` / `NO_PROXY`, as `urllib` does; there is no per-sink proxy option. Syslog never
  uses a proxy.
- **IPv6.** UDP syslog resolves the host with `getaddrinfo`, so an IPv6 collector, or a name with
  only AAAA records, works; TCP and TLS connect the same way.

An entry that cannot be used is ignored; the other sinks still work. That covers: not a mapping, a
type other than `syslog` or `http`, a syslog sink without a host, an unknown protocol, format,
framing or facility, an `app_name` that is not 1 to 48 printable ASCII characters without spaces,
a port that is not a whole number from 1 to 65535, a timeout that is not a number of seconds from
0.1 to 600 (`true` and `false` are not numbers here), a `verify_ssl` that is not a flag or the path
of an existing CA bundle, a `verify_ssl` path and a `ca_file` both given, a URL that is not
`http://` or `https://` with a host, headers that are not a mapping of header names to single-line
text, a `${VAR}` placeholder Hermes left unexpanded (above), and the clear-text and unverified cases
above without `allow_insecure_transport`. When the
sinks are built (at the first event of a process, and again after their settings change), Hermes'
log gets one line per ignored entry, naming it by its place in `audit_sinks` as written in
config.yaml (counting from 0, the same number `Settings.errors` uses for an entry that is not a
mapping) and its kind, with the reason: `librenms audit_sinks[1] (http) ignored: an http:// url
sends events ...`. Neither that line nor any delivery failure quotes the entry's host, URL, headers
or file paths, which can carry a credential or name the OS account. An `audit_sinks` value that is
not a list forwards nothing, and `Settings.errors` (shown by `/librenms status`) names only its
type; a non-mapping entry is named there by its index.

| Sink option | Meaning |
|---|---|
| `type` | `syslog` or `http` |
| `host`, `port` | Syslog collector; port default 514 |
| `protocol` | Syslog: `udp` (default), `tcp`, or `tls`. TLS uses the system trust store unless `verify_ssl` or `ca_file` names a CA bundle |
| `framing` | TCP and TLS framing: `newline` (default for tcp, what rsyslog, syslog-ng, Graylog and Wazuh accept) or `octet-counting` (RFC 6587; default for tls, which RFC 5425 requires) |
| `format` | Syslog: `json` (the audit record as the message body) or `cef` (below). HTTP: `json` or `hec` |
| `facility` | Syslog facility name (`local0` by default, `user`, `daemon`, `auth`, `local7`, …) or number 0 to 23 |
| `app_name` | Syslog APP-NAME, default `hermes-librenms` |
| `url`, `headers` | HTTP collector and request headers; `${VAR}` placeholders, expanded by Hermes |
| `timeout` | Connect and send timeout in seconds, default 5, from 0.1 to 600 |
| `verify_ssl` | For `tls` syslog and `https://` collectors. `true` (default), `false` (needs `allow_insecure_transport`), or a CA bundle path. Read like a flag setting: `true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`; any other value that is not an existing path, an empty one included, makes the entry unusable rather than unverified |
| `ca_file` | The other spelling of a CA bundle path |
| `sourcetype` | HEC only, default `hermes:librenms:audit` |

## Delivery rules

- Events are queued and sent from one background thread. A LibreNMS operation never waits for a
  sink.
- Each event is tried three times per sink with a short backoff, then dropped for that sink. The
  file still has it.
- The queue holds 1,000 events. If a sink is down for long enough to fill it, further events are
  dropped for the sinks, never for the file. Failures are logged once per sink every five minutes,
  not once per event, naming the sink by its index and kind and the reason by an HTTP status or an
  error class.
- The sinks are built from the settings when the first event of a process is sent, and built again
  when an event finds `audit_sinks` (any entry, its place in the list, or a value Hermes expanded
  into it) or `allow_insecure_transport` changed, so an edit to `config.yaml` applies from the next
  event without a restart, like every other setting. Events already queued
  when the change is seen are still delivered by the old sinks while they drain, for up to two
  seconds.
- A gateway that serves several Hermes profiles keeps one set of sinks, with its own queue and
  thread, per profile, each built from that profile's settings and secrets.
- On shutdown the plugin waits up to two seconds in all for the queues to drain.

Sinks are for convenience and near-real-time alerting. If you need guaranteed delivery, ship the
file with Filebeat, Fluent Bit, Vector or a forwarder, which buffer to disk. UDP confirms nothing:
a lost datagram is lost without a failure, and a receiver need not take a message over 2,048 bytes
(RFC 5426), so it may truncate or drop one. An event with a long request text or error easily
passes that. Use `tls` where it matters.

A UDP syslog message is never longer than 8,192 bytes: a larger datagram fails outright (Linux
refuses one over 65,507 bytes, macOS over 9,216) or arrives cut mid-JSON (rsyslog's default
maximum message size is 8 KiB). An event that would be longer is fitted rather than dropped: its
strings are cut to 500, then 100 characters (each ending `… [truncated N chars]`), and when that is
not enough (a long list, such as a large prune's `plan_ids`) only the common fields and the actor
are sent. A fitted message carries `"truncated": true`; the file keeps the whole event. TCP, TLS
and HTTP messages are sent whole (every string of an event is cut to 2,000 characters; see
[audit.md](audit.md#events)).

## Syslog details

Messages are RFC 5424:

```
<134>1 2026-10-28T19:01:02Z hermes-01 hermes-librenms 41233 step_done - {"ts":"2026-10-28T19:01:02Z","schema":1,"plugin":"librenms","event":"step_done",…}
```

`PRI` is facility × 8 + severity. The host is the machine's name, `PROCID` the process that
produced the event, `MSGID` the event name. There is no structured data. The message body is the
full JSON record, so a receiver that parses JSON gets every field.

Severity mapping:

| Severity | Events |
|---|---|
| warning (4) | `plan_rejected`, `apply_refused`, `rollback_refused`, `query_refused`, `step_failed`, `step_conflict`, `revert_failed`, `revert_conflict`, `revert_irreversible`, `run_recovered`, `apply_finished` with a failed outcome, `rollback_finished` that is not fully rolled back, `eventlog_linked` that could not link |
| notice (5) | `apply_started`, `rollback_started`, `plans_pruned`, `audit_pruned`, `approval_requested`, `approval_decided` |
| informational (6) | everything else |

## CEF

With `format: cef` the body is one Common Event Format line, which ArcSight, Splunk, QRadar,
Sentinel, Graylog and Wazuh parse natively:

```
CEF:0|andrewvieyra|hermes-plugin-librenms|0.1.0|apply_refused|apply refused|7|rt=1793214040000 dvchost=hermes-01 dvcpid=41233 request=https://nms.example.com suser=Andrew cs1Label=plan_id cs1=lnp-20261028T190000Z-ab12 cs2Label=actor_kind cs2=model cs3Label=via cs3=tool cs4Label=platform cs4=signal cs5Label=chat cs5=Andrew cs7Label=request_text cs7=Move core-sw1 to NYC-2 cs8Label=config_digest cs8=0d9e2c61a7b3 msg=write_mode is operator_only: …
```

| CEF key | Source |
|---|---|
| `rt` | event time, epoch milliseconds |
| `dvchost`, `dvcpid` | host and pid |
| `request` | `librenms_url` |
| `suser` | actor user name, user id or sender id |
| `act` | step action (`create`, `update`, `delete`, `maintenance`, …) |
| `externalId` | LibreNMS object id |
| `outcome` | apply outcome, or the status of a step, a revert or a rollback |
| `msg` | error, reason or description |
| `cs1` … `cs8`, `cn1` | plan id, actor kind, via, platform (or surface, or source), chat, resource, request text, config digest; `cn1` the HTTP status |

A label is written only with its value. CEF defines six custom string fields; `cs7` and `cs8` go
beyond them, and a strict parser may keep them as plain extension keys. CEF severity is 7 for
warnings, 4 for notices, 2 for informational.

## HTTP details

`format: json` posts the record as the body. `format: hec` wraps it for Splunk's HTTP Event
Collector: `{"time": <epoch>, "sourcetype": "hermes:librenms:audit", "host": …, "event": <record>}`.
Every request carries `Content-Type: application/json` and
`User-Agent: hermes-plugin-librenms/<version>`. Any answer other than a 2xx fails the send. Any
collector that accepts a JSON POST with static headers works with `format: json`.

## Receiver examples

- **rsyslog**: `module(load="imtcp") input(type="imtcp" port="514")`, or `imudp` for UDP on
  localhost, or `imtcp` with `StreamDriver.Mode="1"` for TLS. The message body is the JSON record:
  store the raw line and let your search tool parse it, or parse it with `mmjsonparse`.
- **Graylog**: a Syslog TCP input (TLS enabled); enable "Store full message" and add a JSON
  extractor on the `message` field.
- **Wazuh**: a `<remote>` syslog block on the manager, then a decoder for `hermes-librenms`.
- **Splunk HEC**: create an HEC token with sourcetype `hermes:librenms:audit`; use `format: hec`
  and put the token in `${SPLUNK_HEC_TOKEN}`.
- **Elastic**: point Filebeat at the file instead; it maps `ts` to `@timestamp` with one
  processor.

TLS syslog uses the standard library's certificate verification. Verify it against your receiver
before relying on it.
