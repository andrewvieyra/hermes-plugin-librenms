# LibreNMS API v0 coverage

How the plugin maps onto the LibreNMS API v0, route by route: all 145 registrations of
`routes/api.php`, in the order LibreNMS registers them (the numbers below). Each route is one of:

- **query**: readable through `librenms_query` with `path` relative to `/api/v0`. Device
  references in the path (`{hostname}`) are resolved to the numeric id with `GET devices/{hostname}`
  first, and so is `?hostname=` on the routes marked "(`?hostname=` resolved)", because those
  filters silently return every device's rows for a name they do not know. A numeric id is checked
  with the same `GET`, and `0` is refused, because several of them read an unknown id or `0` as no
  filter at all. On every other route a `hostname` parameter (matched as PHP names it) is refused:
  LibreNMS ignores it there and would return every device's rows. The refusal names the path that
  filters by device where there is one (`logs/eventlog/<hostname>`, `services/<hostname>`). No path
  segment may decode to a `/`, which LibreNMS would read as another route. An unknown hostname is
  refused naming up to five hostnames that contain its first label. An object id that LibreNMS
  reads as no filter, or as another id, is refused (#4, #35, #39, #43, #68, #69, #99-#102, #106,
  #109, #111, #112, #114, #127, #137: `0`, a negative or a non-number; `poller_group/0` on #56),
  and a MAC that the exact-match routes compare with the stored 12 hex digits is sent in that form
  (#122, #131). Results are capped at `max_query_results` rows and `max_result_chars` characters
  (rows past that are cut, with the `next_offset` to read them from), strings are clipped, and every
  credential-bearing key (SNMP communities and v3 passwords, service check parameters, tokens,
  keys) is masked at any depth. An answer larger than the client reads (16 MiB) is refused with
  how to narrow that route: `limit` and `offset` only on the logs routes, which LibreNMS pages.
- **plan**: written only through a reviewed plan (`librenms_plan`, then `librenms_apply`), as the
  resource operation named. Every write path uses numeric ids, is verified by re-reading and has a
  journaled inverse or an explicit inverse kind. Operations behind a gate say which.
- **report**: also read by `librenms_report`, which builds its paths from fixed words and resolved
  ids and checks each against this same table before sending it (see Reports below).
- **refused**: `librenms_query` refuses it, with the reason given; no setting enables it.
- **not in 0.1.0**: the plugin never sends it, for the reason given.

"Planning reads" marks a route the resources also read while planning, checking preconditions,
verifying a write or rolling back. Unknown paths are refused before anything is sent:
`librenms_query` matches a path against these routes in registration order, exactly as LibreNMS
does, so a path that would reach a refused route by shadowing (a mistyped device sub-path, for
example) is refused as that route.

Logs routes (`logs/*`) are paged by LibreNMS: `limit` (default 50, at most `max_query_results`),
`offset` (sent as `start`; `params.start` is read alike, and refused when the two disagree),
`sortorder` (`asc`/`desc`, sent as `ASC`/`DESC`; default `DESC`), `from`, `to`. A result is
`truncated`, with `next_offset`, while `total` exceeds the offset plus the rows returned; `where` and
`sort` are refused there, since they would see one page. Every other route sends all its rows, of
which the query keeps those `where` holds for, orders them by `sort`, and shows `limit` of them from
`offset` on (`get_device_ports` orders by `ifIndex` and `list_devices` by hostname, but
`get_all_ports`, `list_sensors`, `list_links` and `list_fdb` have no `ORDER BY`, so their pages line
up only when sorted by id); `params.start`, which only `list_logs` reads, is refused there, and
`params.offset`, which no route reads, everywhere. In every query,
`params` values must be text, numbers, booleans or lists of them (joined with commas), and
`api_token` and `_method` are refused in any case, and also spelled with `.`, a space or `[`,
which PHP turns into `_`. Every other name must be one PHP reads as written: a leading or inner
space, a dot or a `[` makes PHP read another name (`" limit"` is `limit`, and the last of two wins)
or an array (`hostname[]` is `hostname`), which would pass the paging clamps and the device checks.
`hostname`, `limit`, `start`, `sortorder` and `columns` must also be written in lower case.
`columns` is trimmed (LibreNMS checks trimmed names but selects them as sent, so a blank after a
comma was an HTTP 500) and must hold column names only.

## Reports

`librenms_report` reads these routes, nothing else, at most 30 requests a call:

| View | Routes |
|---|---|
| every view | #83 `devices` (once; scope, names, states; not `events` of the authlog, which is no device's); for `scope.group` #21 and #20 by the group's id; for a `scope.location` no device is at, #134 |
| `find` | #134, #21, #28; #103 when the term holds an interface name; #83 with `type=ipv4`, `ipv6` or `mac` when it is an address, and once more with an address no device holds when every device answered (an older LibreNMS reads an unknown `type` as no filter) |
| `devices` | #60 for each down device on the page (at most 20) |
| `ports`, `capacity` | #71 for each device of a scope of at most 10 devices, else #105 once (when it is too large to read, #71 per device within the budget; the answer is partial when the budget does not reach every device); for `scope.port_group` (`ports`) #28 and #29 by the group's id, then #99 for each of its ports when it has at most 10. Always a `columns` list of the ports table's own columns: `port_id`, `device_id`, `ifIndex`, `ifName`, `ifDescr`, `ifAlias`, `ifType`, `ifAdminStatus`, `ifOperStatus`, `ifSpeed`, `ifDuplex`, `ifMtu`, `ifLastChange`, `port_descr_speed`, `ifInOctets_rate`, `ifOutOctets_rate`, `ifInErrors_delta`, `ifOutErrors_delta`, `poll_time`, `poll_period`, `ignore`, `disabled` (a column LibreNMS lacks is an HTTP 400, so never `ifHighSpeed`, which the current schema folds into `ifSpeed`) |
| `port` | #71 (by device id) or #103 to find the port by name; #99 with `with=statistics`; then #64, #102, #132 and #36 (`state=1,2,3,4,5`), each of which may fail and leave the answer partial (#102 missing from an older LibreNMS is a note instead) |
| `neighbours` | #64 for each device of a scope of at most 10 devices, else #128 once; then the ports of the devices at both ends (every local device, and each monitored neighbour whose port LibreNMS matched) as `ports` reads them: #71 per device up to 10, the local devices first, else #105, and when that is too large to read #71 per device within the request budget, the local devices first (a failed read, or a neighbour the budget leaves out, leaves those links without their figures, partial) |
| `locate` | a MAC: #104, #122 (its 12 hex digits) and #125 (the MAC with colons); an IPv4 address: #125, then #104 and #122 for each MAC found (at most 3); then #133 (`?hostname=`, at most 5 devices, else once), #64 for the devices that learned it (at most 10, else #128) and #99 for the router interfaces of the ARP entries (at most 5), each of which may fail and leave the answer partial |
| `vlans` | #63 for each device of a scope of at most 10 devices, else #133 once; with `filter.vlan`, #71 with `with=vlans` for each device that has it, when they are at most 10 |
| `alerts` | #36 once (per severity when the answer is too large to read); #71 (`columns=port_id,ifIndex,ifName,ifDescr,ifAlias`) for each device, at most 10, with a port fault whose details hold no label, each of which may fail and leave the answer partial |
| `alert_history` | #44 once (a failure leaves the rules unnamed, partial); #97 from the window's start, newest first, paged: by device id for a scope of at most 10 devices, else every device's |
| `health` | #132 once (not when `filter.class` names only processors, memory pools or storage); when it is too large to read, #68 per device of the scope within the budget (the classes, each class's ids, each sensor); #68 for processors, memory pools (by default) or storage (asked for) of at most 5 devices, a listing and at most 8 of each; for the sensors of the page on a port, #71 (`columns=port_id,ifIndex,ifName,ifDescr,ifAlias`, at most 10 devices; past that the answer is partial) and #74 where the ifIndex names no port, or for a temperature, bias or voltage sensor on an inventory entity of those devices; for such a sensor on another device, only for a scope of at most 5 devices, #74 first and #71 only when that entity is a transceiver's; each by device id, each of which may fail and leave the answer partial (#74 missing from an older LibreNMS is a note instead, read once) |
| `routing` | #10, #13 and #15 once each, the protocols asked for (`?hostname=` the device id for a scope of one device; #10 `?remote_asn=` for `filter.remote_as`, alone); #71 (as `health`) for the devices of the page's OSPF neighbours |
| `events` | the log `filter.log` names: #95 (default), #96 or #98, from the window's start, newest first, paged as `alert_history` reads #97 (the device path, by id, for a scope of at most 10 devices; #98 has none, and is read after #1, for LibreNMS's clock, instead of #83); #71 (`columns=port_id,ifIndex,ifName,ifDescr,ifAlias`, at most 10 devices) to name the ports of the page and summary, and for `filter.port` (a name, or a number: a name or a port_id), each of which may fail and leave the answer partial |
| `bills` | #108 once (`period=previous` for `filter.period` `previous`) |
| `help` | none: answered by the plugin |

## System

| # | Route | Coverage |
|---|---|---|
| 1 | `GET ping` | query; report: `events` of the authlog reads it first, for LibreNMS's clock (the `Date` of its answer, `pong`, which LibreNMS gives without a query) |
| 2 | `GET system` | query; also `librenms_query {"action": "status"}`, and recorded in every plan's `audit` block |
| 3 | `GET /api/v0` (index) | query (`path: ""`): the route names this LibreNMS has |
| 145 | `ANY {path?}` (catch-all) | not a route: LibreNMS answers `This API route doesn't exist.` (also for a known path with the wrong method), which the client reports as error kind `route`. `librenms_query` refuses a path no read route matches before sending it |

## Alert templates, pollers

| # | Route | Coverage |
|---|---|---|
| 4 | `GET alert_templates/{id}` | query; `{id}` must be a positive number (`0` lists every template) |
| 5 | `GET alert_templates` | query |
| 6 | `POST alert_templates` | not in 0.1.0: LibreNMS renders the template with Blade on the server before validating it, so a template is code that runs inside LibreNMS; and the API cannot delete one, so a create would have no inverse |
| 7 | `PUT alert_templates` | not in 0.1.0: as #6; an edit also wipes and replaces the template's rule mappings |
| 8 | `GET pollers` | query |
| 9 | `GET pollers/log` | query |
| 56 | `GET poller_group/{poller_group_id_or_name?}` | query; planning reads (a device's `poller_group` must exist). `poller_group/0` is refused: LibreNMS reads `"0"` as no group and lists every group, while 0 is the General group, which has no row |

## Routing

| # | Route | Coverage |
|---|---|---|
| 10 | `GET bgp` | query (`?hostname=` resolved); report: `routing` |
| 11 | `GET bgp/{id}` | query |
| 12 | `POST bgp/{id}` (`edit_bgp_descr`) | not in 0.1.0: the API cannot clear a description (so setting one where there was none has no inverse), longer values are silently truncated, and LibreNMS defines no permission for it, so by default only an admin may |
| 13 | `GET ospf` | query (`?hostname=` resolved); report: `routing` |
| 14 | `GET ospf_ports` | query |
| 15 | `GET ospfv3` | query (`?hostname=` resolved). LibreNMS answers HTTP 500 `Error retrieving ospfv3_nbrs` when it holds no OSPFv3 neighbour (for the device asked for, or at all); `ospfv3NbrRtrId` is the neighbour's router id as a 32-bit number. Report: `routing`, which writes that router id dotted, reads that answer as none, and the 404 of a LibreNMS without this route as none with a note (also when OSPFv3 is the only protocol asked for) |
| 16 | `GET ospfv3_ports` | query (`?hostname=` resolved) |
| 48 | `GET routing/vrf/{id}` | query |
| 49 | `GET routing/ipsec/data/{hostname}` | query |
| 117 | `GET routing/bgp/cbgp` | query (`?hostname=` resolved) |
| 118 | `GET routing/vrf` | query (`?hostname=` resolved) |
| 119 | `GET routing/mpls/services` | query (`?hostname=` resolved) |
| 120 | `GET routing/mpls/saps` | query (`?hostname=` resolved) |

## Oxidized

| # | Route | Coverage |
|---|---|---|
| 17 | `GET oxidized/{hostname?}` | query: the device list Oxidized polls (hostname, os, ip, ports), not configurations. LibreNMS matches the hostname column exactly, so the value is sent as given. The answer is a bare JSON array |
| 18 | `GET oxidized/config/search/{searchstring}` | refused: it searches every stored device configuration, which would confirm whether a guessed password or community is in use, and LibreNMS does not filter its answer by the token's device access |
| 19 | `GET oxidized/config/{device_name}` | refused: it returns a device's full stored configuration, secrets included |

## Device groups

| # | Route | Coverage |
|---|---|---|
| 20 | `GET devicegroups/{name}` | query; planning reads (static membership); report: `scope.group`, by the group's id, never `full=1` |
| 21 | `GET devicegroups` | query; planning reads (lookup by name); report: `scope.group`, `find` |
| 22 | `POST devicegroups` | plan: `device_group` `create` (static with `devices`, or dynamic with `rules`); also the rollback of a delete |
| 23 | `PATCH devicegroups/{name}` | plan: `device_group` `update` (`name`, `desc`, `rules`, static membership as the full list, with `devices`, `devices_add` or `devices_remove`); also its rollback |
| 24 | `DELETE devicegroups/{name}` | plan: `device_group` `delete` (`allow_delete`; rollback re-creates it with a new id, and alert rules, user permissions and maintenance linked to the old id are not restored) |
| 25 | `POST devicegroups/{name}/devices` | not used: membership changes go through #23 with the full list, so one request, one verification and one inverse cover them |
| 26 | `DELETE devicegroups/{name}/devices` | not used: without a `devices` key it removes every member; #23 is used instead |
| 27 | `POST devicegroups/{name}/maintenance` | plan: `device_group` `maintenance` (irreversible: the API cannot end maintenance) |

## Port groups

| # | Route | Coverage |
|---|---|---|
| 28 | `GET port_groups` | query; report: `find`, `scope.port_group` |
| 29 | `GET port_groups/{name}` | query; report: `scope.port_group` (`ports`), by the group's id, never `full=1` (every column of every port) |
| 30 | `GET portgroups/multiport/bits/{id}` | refused: graph image |
| 31 | `GET portgroups/{group}` | refused: graph image |
| 32 | `POST port_groups` | not in 0.1.0: the API cannot delete a port group, so a create would have no inverse |
| 33 | `POST port_groups/{port_group_id}/assign` | not in 0.1.0: port groups are left to the web UI in this release |
| 34 | `POST port_groups/{port_group_id}/remove` | not in 0.1.0: as #33 |

## Alerts

| # | Route | Coverage |
|---|---|---|
| 35 | `GET faults/{id}` | query; planning reads. `{id}` must be a positive number (`0` or a negative id lists every open fault). Rows carry `entities` (the labels of the ports, sensors, processors, storage, services or BGP peers the rule matched, at most 10) instead of `details` (every column of every table the rule joins, for every matched row, and the alert's contacts); `fields: ["details"]` returns it without `contacts` |
| 36 | `GET faults` | query, rows as #35; planning reads (the other open faults of the same device and rule); report: `port` (`state=1,2,3,4,5`, the faults whose entity is the port; never their `details`) and `alerts` (the states `filter.state` names, every open one by default; `severity` when one is filtered, `alert_rule` for a rule's id; again one severity at a time when the answer is too large to read; only the labels of `details`) |
| 37 | `PUT faults/{id}` | plan: `alert` `ack` (note tagged `[hermes:<plan id>]`; rollback unmutes, lossy); also the rollback of an unmute |
| 38 | `PUT faults/unmute/{id}` | plan: `alert` `unmute` (rollback acknowledges again, lossy); also the rollback of an ack |
| 39 | `GET alerts/{id}` | query (legacy alias of #35, checked and shaped alike) |
| 40 | `GET alerts` | query (legacy alias of #36, shaped alike) |
| 41 | `PUT alerts/{id}` | not used: the plugin sends #37 |
| 42 | `PUT alerts/unmute/{id}` | not used: the plugin sends #38 |
| 43 | `GET rules/{id}` | query, `{id}` a positive number (`0` lists every rule); planning reads (the full rule, for an exact snapshot) |
| 44 | `GET rules` | query; planning reads (lookup by name, and the id of a rule just created, which the create does not return); report: `alert_history` (the rules' names, severities and settings, once) |
| 45 | `POST rules` | plan: `alert_rule` `create` (`alert_operation_id` required, scoped to devices, groups or locations unless `global: true`); also the rollback of a delete |
| 46 | `PUT rules` | plan: `alert_rule` `update`, always with the rule's full body, never a sparse one (omitted mappings would be cleared); rollback `PUT`s the snapshot body |
| 47 | `DELETE rules/{id}` | plan: `alert_rule` `delete` (`allow_delete`; rollback re-creates it with a new id, without its alert history and template mappings) |

## Services

Every service operation needs `allow_services`: a service runs a Nagios plugin with its parameters
on the poller.

| # | Route | Coverage |
|---|---|---|
| 50 | `GET services` | query (check parameters masked); planning reads |
| 51 | `GET services/{hostname}` | query; planning reads |
| 52 | `POST services/{hostname}` | plan: `service` `create`; also the rollback of a delete |
| 53 | `DELETE services/{id}` | plan: `service` `delete` (`allow_delete` too; rollback re-creates it with a new id, and its graph history stays with the old one) |
| 54 | `PATCH services/{id}` | plan: `service` `update` (only the changed columns; LibreNMS answers 500 to an edit that changes nothing) |

## Syslog

| # | Route | Coverage |
|---|---|---|
| 55 | `POST syslogsink` | not in 0.1.0: it appends syslog lines that can raise alerts and cannot be removed, and would let the model forge the log it reads |

## Devices

| # | Route | Coverage |
|---|---|---|
| 57 | `GET devices/{hostname}` | query (SNMP credentials masked); planning reads |
| 58 | `GET devices/{hostname}/discover` | refused in `librenms_query`: this GET schedules a rediscovery, a write. plan: `device` `discover` (rollback not needed) |
| 59 | `GET devices/{hostname}/availability` | query |
| 60 | `GET devices/{hostname}/outages` | query; report: `devices` (`down_since`, by device id, for at most 20 down devices a page) |
| 61 | `GET devices/{hostname}/graphs/health/{type}/{sensor_id?}` | refused: graph image (`devices/{hostname}/health` lists the graphs) |
| 62 | `GET devices/{hostname}/graphs/wireless/{type}/{sensor_id?}` | refused: graph image (`devices/{hostname}/wireless` lists the graphs) |
| 63 | `GET devices/{hostname}/vlans` | query; report: `vlans` for a scope of at most 10 devices, by device id (its rows carry no `device_id`) |
| 64 | `GET devices/{hostname}/links` | query; report: `port` (by device id, the links on the port), `neighbours` for a scope of at most 10 devices, `locate` (the devices that learned the MAC, to tell uplinks from edge ports) |
| 65 | `GET devices/{hostname}/graphs` | query (the list of graphs, not images) |
| 66 | `GET devices/{hostname}/fdb` | query |
| 67 | `GET devices/{hostname}/nac` | query |
| 68 | `GET devices/{hostname}/health/{type?}/{sensor_id?}` | query; `{sensor_id}` must be a positive number (`0` lists every sensor of the class). Without a type the sensor classes and `device_processor`, `device_storage`, `device_mempool`; with one (`device_` optional) each one's `{sensor_id, desc}`; with an id its full row; report: `health` (processors, memory pools, storage; every sensor when #132 is too large to read) |
| 69 | `GET devices/{hostname}/wireless/{type?}/{sensor_id?}` | query; `{sensor_id}` must be a positive number (MySQL reads `1abc` as 1) |
| 70 | `GET devices/{hostname}/wireless-sensors` | query |
| 71 | `GET devices/{hostname}/ports` | query; planning reads (port lookup by `ifName` or `ifDescr`); report: `ports` and `capacity` for a scope of at most 10 devices, and when #105 is too large to read; `port` to find a port by name on `scope.device`; `neighbours` for the devices at both ends of the links (as `ports` reads them); `vlans` with `with=vlans` for the devices of one VLAN (at most 10); `alerts`, `health` and `routing` for the port names of the rows of a page (a port fault whose details hold no label, a sensor on a port, an OSPF neighbour's interface; at most 10 devices, and the answer is partial when the page needs more); always by device id with a `columns` list |
| 72 | `GET devices/{hostname}/ip` | query |
| 73 | `GET devices/{hostname}/port_stack` | query |
| 74 | `GET devices/{hostname}/transceivers` | query; report: `health` (by device id, to tie a sensor to a port through its transceiver's entity: a dBm sensor whose ifIndex names no port, an optic's temperature, bias or voltage sensor on an inventory entity: on a device whose ports the page names, or for a scope of at most 5 devices) |
| 75 | `GET devices/{hostname}/components` | query. LibreNMS answers an object keyed by component id; it is returned as rows with the key as `id`, so `limit` and `fields` apply |
| 76 | `GET devices/{hostname}/groups` | query |
| 77 | `GET devices/{hostname}/maintenance` | query; read after a maintenance step to verify it |
| 78 | `GET devices/{hostname}/ports/{ifname}` | refused: LibreNMS misreads interface names that contain `/`; find the `port_id` with #71 (`params: {"columns": "port_id,ifName"}`) and query `ports/{port_id}` |
| 79 | `GET devices/{hostname}/ports/{ifname}/{type}` | refused: graph image |
| 80 | `GET devices/{hostname}/services/{id}/graphs/{datasource}` | refused: graph image |
| 81 | `POST devices/{hostname}/eventlog` | not in 0.1.0: it appends an eventlog row that cannot be removed (LibreNMS accepts it even from a global-read token), and the eventlog is the record plans are linked to |
| 82 | `GET devices/{hostname}/{type}` | refused: LibreNMS serves every device sub-path it has no other route for as a graph image, so a mistyped sub-path lands here too |
| 83 | `GET devices` | query (SNMP credentials masked); planning reads (`type=location_id`: the devices at a location); report: every view (one listing a report, named fields only), `find` (`type=ipv4`, `ipv6` or `mac` for an address). `type` with `query`: `hostname`, `display`, `location`, `serial`, `version`, `hardware`, `features` match part of the value, `sysName`, `os`, `type`, `location_id`, `device_id` the whole, `ipv4`, `ipv6` an address on a port and `mac` an ARP entry on one; `up`, `down`, `disabled`, `ignored`, `active` need no `query`; any other `type` is no filter at all |
| 84 | `POST devices` | plan: `device` `create` (`allow_device_add`; SNMP credentials only as `{"env": "LIBRENMS_SNMP_…"}` references, resolved at apply time; rollback deletes the device) |
| 85 | `DELETE devices/{hostname}` | plan: `device` `delete` (`allow_delete`; irreversible: LibreNMS drops the device's RRD history, ports, alerts and group membership, and re-adding makes a new device) |
| 86 | `PATCH devices/{hostname}` | plan: `device` `update` (`notes`, `purpose`, `location`, `poller_group`, `display_template`, the `disabled`/`ignore`/`disable_notify`/`ignore_status`/`override_sysLocation` flags, `type`, `icon`, and `overwrite_ip` with `allow_device_add`; never SNMP settings, which v0 cannot change); also its rollback |
| 87 | `PATCH devices/{hostname}/rename/{new_hostname}` | plan: `device` `update` with `hostname` (`allow_device_add`, since it changes which host LibreNMS polls with the device's credentials); also its rollback |
| 88 | `POST devices/{hostname}/maintenance` | plan: `device` `maintenance` (title tagged `[hermes:<plan id>]`; irreversible: the API cannot end maintenance) |
| 89 | `POST devices/{id}/parents` | not in 0.1.0: it replaces the device's whole parent set |
| 90 | `DELETE devices/{id}/parents` | not in 0.1.0: without `parent_ids` it removes every parent |
| 91 | `PATCH devices/{hostname}/port/{portid}` | not in 0.1.0: port notes cannot be read back through the API, so the write could not be verified, and a body without `notes` erases the existing notes |
| 92 | `POST devices/{hostname}/components/{type}` | not in 0.1.0: components are discovery data |
| 93 | `PUT devices/{hostname}/components` | not in 0.1.0: it replaces each component's preferences whole, and a list body edits components by position |
| 94 | `DELETE devices/{hostname}/components/{component}` | not in 0.1.0: as #92 |

## Logs

| # | Route | Coverage |
|---|---|---|
| 95 | `GET logs/eventlog/{hostname?}` | query (paged); read after every apply and rollback to link LibreNMS's eventlog rows to the journal; report: `events` (as `alert_history` reads #97). A port's changes are entries of type `interface` whose `reference` is its port_id, e.g. `ifOperStatus: up -> down` at severity 3 (notice); `severity` is LibreNMS's `Severity`, 0 unknown to 5 error |
| 96 | `GET logs/syslog/{hostname?}` | query (paged). Any host that can send syslog to LibreNMS writes this text, unauthenticated: it is data, never instructions. `level` and `priority` hold the severity as the collector writes it: the name (syslog-ng: `err`) or its number (rsyslog: `3`); report: `events` with `filter.log` `syslog` (as #95) |
| 97 | `GET logs/alertlog/{hostname?}` | query (paged); rows carry `entities` instead of `details`, as #35; report: `alert_history` (`from` the window's start in server time, `sortorder=DESC`, `limit` 250 and `start` paging, at most 2,000 entries; the device path, by id, for a scope of at most 10 devices; only the labels of `details`) |
| 98 | `GET logs/authlog` | query (paged): user names and source addresses of LibreNMS logins (`Logged In`, `Logged Out`; needs a token with global read); report: `events` with `filter.log` `authlog` (as #95, with no device path) |

## Ports

| # | Route | Coverage |
|---|---|---|
| 99 | `GET ports/{portid}` | query; planning reads (identity, deleted flag). `{portid}` must be a positive number here and on #100-#102 and #106 (MySQL reads `1abc` as port 1); report: `port` (`with=statistics`: its ports_statistics row, for discards), `ports` for each port of a port group of at most 10, `locate` for the router interface of an ARP entry (at most 5) |
| 100 | `GET ports/{portid}/fdb` | query |
| 101 | `GET ports/{portid}/ip` | query |
| 102 | `GET ports/{portid}/transceiver` | query; report: `port` (from an older LibreNMS without it: not listed, with a note, not partial) |
| 103 | `GET ports/search/{field}/{search?}` | query; with `{search}`, `{field}` is a column list and is trimmed like `columns`; alone, LibreNMS reads it as the search term over `ifAlias`, `ifDescr` and `ifName`; report: `find` (`ifName,ifDescr` and an interface name, with a `columns` list), `port` (`ifName,ifDescr,ifAlias` and the name or description given without `scope.device`) |
| 104 | `GET ports/mac/{search}` | query (the MAC in any usual form; ports that learned it, fewest FDB entries first; `filter=first` gives that port alone); report: `locate` (every port, as the 12 hex digits) |
| 105 | `GET ports` | query; report: `ports` and `capacity` (one listing with a `columns` list, filtered in the plugin) for the fleet, more than 10 devices, or a port group of more than 10 ports. LibreNMS sends it in no set order and without paging, so the plugin orders and pages it |
| 106 | `GET ports/{portid}/description` | query; planning reads |
| 107 | `PATCH ports/{portid}/description` | plan: `port` `update` (`description`; `""` clears it and unpins it, so the poller sets it from the device again; the body always carries the key, since LibreNMS clears the description when the key is missing; rollback restores the text, lossy) |

## Bills

| # | Route | Coverage |
|---|---|---|
| 108 | `GET bills` | query; report: `bills`, once (`period=previous` for the last period that ended: LibreNMS joins each bill to its latest `bill_history` row whose period ended within the last 40 days) |
| 109 | `GET bills/{bill_id}` | query; `{bill_id}` must be a positive number (LibreNMS answers anything else with every bill) |
| 110 | `GET bills/{bill_id}/graphs/{graph_type}` | refused: graph image |
| 111 | `GET bills/{bill_id}/graphdata/{graph_type}` | query; `{bill_id}` must be a positive number, as on #112 and #114 |
| 112 | `GET bills/{bill_id}/history` | query |
| 113 | `GET bills/{bill_id}/history/{bill_hist_id}/graphs/{graph_type}` | refused: graph image |
| 114 | `GET bills/{bill_id}/history/{bill_hist_id}/graphdata/{graph_type}` | query |
| 115 | `POST bills` | not in 0.1.0: billing is left to the web UI in this release; create and edit share the route, and an edit replaces the bill's port list |
| 116 | `DELETE bills/{bill_id}` | not in 0.1.0: as #115 |

## Resources

| # | Route | Coverage |
|---|---|---|
| 121 | `GET resources/fdb` | query |
| 122 | `GET resources/fdb/{mac}` | query; LibreNMS compares `{mac}` with the stored 12 hex digits exactly, so a MAC in any usual form is sent as those digits, and anything else is refused (`0` would list the whole table); report: `locate` (each entry's VLAN and last update) |
| 123 | `GET resources/fdb/{mac}/detail` | query (parses any form); the MAC as LibreNMS writes it and its vendor (`mac_oui`) are returned under `extra` |
| 124 | `GET resources/ip/addresses/{address_family?}` | query |
| 125 | `GET resources/ip/arp/{query}/{cidr?}` | query; report: `locate` (an IPv4 address, or the MAC as `00:11:22:33:44:55`, which LibreNMS's `FILTER_VALIDATE_MAC` takes) |
| 126 | `GET resources/ip/networks/{address_family?}` | query |
| 127 | `GET resources/ip/networks/{id}/ip` | query; `{id}` must be a positive number |
| 128 | `GET resources/links` | query; report: `neighbours` for a scope of more than 10 devices, `locate` when more than 10 devices learned the MAC |
| 129 | `GET resources/links/{id}` | query |
| 130 | `GET resources/nac` | query |
| 131 | `GET resources/nac/{mac}` | query; `{mac}` normalised as #122 |
| 132 | `GET resources/sensors` | query. LibreNMS ignores every filter on this route and returns the whole table; the result is cut at the row limit. Prefer #68 and #70 for one device; report: `port` (the dBm sensors on the port, filtered in the plugin), `health` (every sensor, kept to the scope and filtered in the plugin) |
| 133 | `GET resources/vlans` | query (`?hostname=` resolved); report: `vlans` for a scope of more than 10 devices, `locate` (`?hostname=` a device id, for each of at most 5 devices that learned the MAC, else once) to number a forwarding entry's VLAN |
| 134 | `GET resources/locations` | query; planning reads (lookup by name); report: `find`, `scope.location` when no device is at the location named |

## Inventory, port security

| # | Route | Coverage |
|---|---|---|
| 135 | `GET inventory/{hostname}` | query |
| 136 | `GET inventory/{hostname}/all` | query |
| 137 | `GET port_security/port/{portid}` | query; `{portid}` must be a positive number (`0` lists every port's entries) |
| 138 | `GET port_security/device/{hostname}` | query |
| 139 | `GET port_security` | query |

## Locations

| # | Route | Coverage |
|---|---|---|
| 140 | `POST locations` | plan: `location` `create` (`lat` and `lng` required: LibreNMS cannot create a location without coordinates through the API); also the rollback of a delete |
| 141 | `GET location/{location_id_or_name}` | query; planning reads |
| 142 | `PATCH locations/{location_id_or_name}` | plan: `location` `update` (`location`, `lat`, `lng`); also its rollback |
| 143 | `DELETE locations/{location}` | plan: `location` `delete` (`allow_delete`; rollback re-creates it with a new id and points its former devices at it again; alert-rule scoping and maintenance links to the old id are lost) |
| 144 | `POST locations/{location}/maintenance` | plan: `location` `maintenance` (irreversible: the API cannot end maintenance) |

## Totals

| Coverage | Routes |
|---|---|
| query | 89 GET routes |
| refused | 13 GET routes: 9 graph images (#30, #31, #61, #62, #79, #80, #82, #110, #113), Oxidized configuration and search (#18, #19), the rediscovery GET (#58, a plan operation instead) and the ifName route (#78) |
| plan | 22 write routes and the rediscovery GET, across 7 resources |
| not used (another route does the same) | 4 (#25, #26, #41, #42) |
| not in 0.1.0 | 16 (#6, #7, #12, #32, #33, #34, #55, #81, #89, #90, #91, #92, #93, #94, #115, #116) |
| catch-all | 1 (#145) |
