"""In-memory stand-in for a LibreNMS 26.10 instance, speaking the subset of API v0 the plugin uses.

It is a ``requests``-compatible session and behaves like LibreNMS where the plugin depends on it (specs/ln-*.md):
``X-Auth-Token`` auth answered with Laravel's bare 401; the catch-all 404 ``This API route doesn't exist.`` for an
unknown path and for a known path with the wrong method; a web server's 301 for a trailing slash; the ``{status,
<key>, message, count}`` envelope, with ``count`` only where PHP returns an array, and the web server's ``Date``
(``send_date``); 200 or 201 per handler; lists that 404 when empty; writes answered with a message only (the new
location's id inside it, the new service as JSON inside it); the no-op traps (an unchanged service edit is a 500, an
unchanged group name a 422) and the silent no-ops (unknown device fields, ``"true"``/``"false"`` for a device flag,
a location edit not sent as JSON); alert-rule writes that return no id and rebuild everything the body omits; fault
ack and unmute that change every open sibling when the rule does not notify per entity (or has more open faults than
its limit); ids that are never reused; a device added with poller group 0 put in the default group; eventlog paging
with an exact ``DESC`` and an id-valued numeric ``from``; the eventlog rows DeviceObserver writes; and SNMP secrets
in clear for an admin token. The read-only routes the report views read answer as their handlers do too: the result key,
``count`` only for a PHP array, 404s for empty lists where the handler sends one, an unknown hostname in a filter read
as no filter (and an unknown ``devices`` ``type`` as none), the ``ipv4``, ``ipv6`` and ``mac`` device filters, column
lists checked trimmed but selected as sent, ``with=vlans`` on a device's ports and on one port (each port's ports_vlans
rows, ``untagged`` as PortVlan reads it, and on one port the port it lazy-loads to do so), ``resources/fdb/{mac}``
compared exactly, the alert log's details decoded, components as an object keyed by id, a device's health classes,
ids and single sensors, processors, memory pools and storage volumes, and ``ospfv3``'s HTTP 500 for no neighbour. Bills
are modelled for CDR bills in the current period only.

Test hooks: :meth:`FakeLibreNMS.fail_on` (a forced answer or exception, optionally after the write took effect),
:meth:`~FakeLibreNMS.touch` (an edit made outside the plugin), :meth:`~FakeLibreNMS.after` (another client's write
landing during a request), :meth:`~FakeLibreNMS.poll` (the poller refreshing a port's ifAlias),
:meth:`~FakeLibreNMS.redirect_all`, ``calls`` / :meth:`~FakeLibreNMS.writes`, ``admin_secrets``,
``missing_routes`` (an older LibreNMS), ``schedules`` (maintenance, which no v0 route can read back) and the
settings ``default_poller_group`` and ``default_max_entities``.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Any, Callable, Dict, Iterator, List, Set, Tuple
from urllib.parse import unquote, urlsplit

TOKEN = "7|hermesFakeToken0123456789abcdefABCDEF"
# Every credential in the seeded dataset, so a test can prove none of them reaches a plan, a result or the audit log.
SECRETS = ("c0re-Community!", "Auth-S3cret-v3", "Priv-S3cret-v3", "acc3ss-Community", "lab-Community", "Sup3rS3cret!")

_CATCH_ALL = "This API route doesn't exist."
_TABLES = (
    "devices", "locations", "device_groups", "services", "rules", "faults", "ports", "eventlog", "poller_groups",
    "port_groups", "links", "sensors", "transceivers", "components", "bgp_peers", "ospf_nbrs", "alert_log", "syslog",
    "vlans", "ports_fdb", "ports_nac", "ipv4_mac", "outages", "availability", "bills", "ipv4_addresses",
    "ipv6_addresses", "ports_statistics", "ports_vlans", "processors", "mempools", "storage", "ospfv3_nbrs",
)  # fmt: skip
_ID_KEYS = {
    "devices": "device_id", "services": "service_id", "ports": "port_id", "eventlog": "event_id",
    "sensors": "sensor_id", "bgp_peers": "bgpPeer_id", "syslog": "seq", "vlans": "vlan_id",
    "ports_fdb": "ports_fdb_id", "ports_nac": "ports_nac_id", "availability": "availability_id", "bills": "bill_id",
    "ipv4_addresses": "ipv4_address_id", "ipv6_addresses": "ipv6_address_id", "ports_statistics": "port_id",
    "ports_vlans": "port_vlan_id", "processors": "processor_id", "mempools": "mempool_id", "storage": "storage_id",
}  # fmt: skip

# App\Http\Resources\Device, in its key order (dependency_parent_* only where list_devices loads parents).
_DEVICE_KEYS = (
    "device_id", "hostname", "sysName", "ip", "overwrite_ip", "community", "authlevel", "authname", "authpass",
    "authalgo", "cryptopass", "cryptoalgo", "snmpver", "port", "transport", "timeout", "retries", "snmp_disable",
    "bgpLocalAs", "sysObjectID", "sysDescr", "sysContact", "version", "hardware", "features", "location_id", "os",
    "status", "status_reason", "ignore", "disabled", "uptime", "agent_uptime", "last_polled", "last_poll_attempted",
    "last_polled_timetaken", "last_discovered_timetaken", "last_discovered", "last_ping", "last_ping_timetaken",
    "purpose", "type", "serial", "icon", "poller_group", "override_sysLocation", "notes", "port_association_mode",
    "max_depth", "disable_notify", "inserted", "display", "display_template", "snmpEngineID", "ignore_status",
    "mtu_status",
)  # fmt: skip
_UNMASKABLE = ("community", "authpass", "cryptopass")
_DEVICE_FILLABLE = frozenset(
    {"disable_notify", "disabled", "features", "hardware", "hostname", "display_template", "icon", "ignore",
     "ignore_status", "ip", "location_id", "notes", "os", "override_sysLocation", "overwrite_ip", "poller_group",
     "purpose", "serial", "status", "status_reason", "sysDescr", "sysName", "sysObjectID", "snmpEngineID", "type",
     "version", "uptime"}
)  # fmt: skip
_DEVICE_FLAGS = frozenset({"status", "ignore", "ignore_status", "disabled", "disable_notify", "override_sysLocation"})
_OBSERVED = ("os", "sysName", "version", "hardware", "features", "serial", "icon", "type", "ip")
_ASSOCIATION_MODES = {"ifIndex": 1, "ifName": 2, "ifDescr": 3, "ifAlias": 4}
# The ports table in schema order (no ifHighSpeed: the poller folds it into ifSpeed). The counters are bigint unsigned:
# ifInOctets_rate is bytes per second over poll_period, ifLastChange the device's sysUpTime in timeticks.
_COUNTERS = tuple(
    f"if{way}{counter}{suffix}"
    for counter in ("UcastPkts", "Errors", "Octets")
    for way in ("In", "Out")
    for suffix in ("", "_prev", "_delta", "_rate")
)
_PORT_COLUMNS = (
    "port_id", "device_id", "port_descr_type", "port_descr_descr", "port_descr_circuit", "port_descr_speed",
    "port_descr_notes", "ifDescr", "ifName", "portName", "ifIndex", "ifSpeed", "ifSpeed_prev", "ifConnectorPresent",
    "ifOperStatus", "ifOperStatus_prev", "ifAdminStatus", "ifAdminStatus_prev", "ifDuplex", "ifMtu", "ifType",
    "ifAlias", "ifPhysAddress", "ifLastChange", "ifVlan", "ifTrunk", "ifVrf", "ignore", "disabled", "deleted",
    "pagpOperationMode", "pagpPortState", "pagpPartnerDeviceId", "pagpPartnerLearnMethod", "pagpPartnerIfIndex",
    "pagpPartnerGroupIfIndex", "pagpPartnerDeviceName", "pagpEthcOperationMode", "pagpDeviceId", "pagpGroupIfIndex",
    *_COUNTERS, "poll_time", "poll_prev", "poll_period",
)  # fmt: skip
# ports_statistics (PortStatistic, one row per port), which ports/{id}?with=statistics adds as "statistics".
_PORT_STATISTICS_COLUMNS = ("port_id",) + tuple(
    f"if{way}{counter}{suffix}"
    for way, counter in (("In", "NUcastPkts"), ("Out", "NUcastPkts"), ("In", "Discards"), ("Out", "Discards"),
                         ("In", "UnknownProtos"), ("In", "BroadcastPkts"), ("Out", "BroadcastPkts"),
                         ("In", "MulticastPkts"), ("Out", "MulticastPkts"))
    for suffix in ("", "_prev", "_delta", "_rate")
)  # fmt: skip
_SERVICE_COLUMNS = (
    "service_id", "device_id", "service_ip", "service_type", "service_desc", "service_param", "service_ignore",
    "service_status", "service_changed", "service_message", "service_disabled", "service_ds", "service_template_id",
    "service_name",
)  # fmt: skip
_SERVICE_INTS = frozenset(
    {"service_id", "device_id", "service_ignore", "service_status", "service_changed", "service_disabled",
     "service_template_id"}
)  # fmt: skip
_EVENT_COLUMNS = ("event_id", "device_id", "datetime", "message", "type", "reference", "username", "severity")
_FAULT_COLUMNS = (
    "id", "rule_id", "device_id", "entity_type", "entity_id", "entity_key", "state", "alerted", "open", "severity",
    "note", "info", "details", "first_seen", "last_seen", "timestamp",
)  # fmt: skip
# The read-only tables behind the report routes, each a table's columns in schema order (what a toBase() query or a
# model's toArray() returns; the models behind them hide nothing).
_LINK_COLUMNS = (
    "id", "local_port_id", "local_device_id", "remote_port_id", "active", "protocol", "remote_hostname",
    "remote_device_id", "remote_port", "remote_platform", "remote_version",
)  # fmt: skip
_SENSOR_COLUMNS = (
    "sensor_id", "sensor_deleted", "sensor_class", "device_id", "poller_type", "sensor_oid", "sensor_index",
    "sensor_type", "sensor_descr", "group", "sensor_divisor", "sensor_multiplier", "sensor_current", "sensor_limit",
    "sensor_limit_warn", "sensor_limit_low", "sensor_limit_low_warn", "sensor_alert", "sensor_custom",
    "entPhysicalIndex", "entPhysicalIndex_measured", "lastupdate", "sensor_prev", "user_func", "rrd_type", "category",
)  # fmt: skip
_TRANSCEIVER_COLUMNS = (
    "id", "created_at", "updated_at", "device_id", "port_id", "index", "entity_physical_index", "type", "vendor",
    "oui", "model", "revision", "serial", "date", "ddm", "encoding", "cable", "distance", "wavelength", "connector",
    "channels",
)  # fmt: skip
_BGP_COLUMNS = (
    "bgpPeer_id", "device_id", "vrf_id", "astext", "bgpPeerIdentifier", "bgpPeerRemoteAs", "bgpPeerState",
    "bgpPeerAdminStatus", "bgpPeerLastErrorCode", "bgpPeerLastErrorSubCode", "bgpPeerLastErrorText", "bgpPeerIface",
    "bgpLocalAddr", "bgpPeerRemoteAddr", "bgpPeerDescr", "bgpPeerInUpdates", "bgpPeerOutUpdates",
    "bgpPeerInTotalMessages", "bgpPeerOutTotalMessages", "bgpPeerFsmEstablishedTime", "bgpPeerInUpdateElapsedTime",
    "context_name",
)  # fmt: skip
_OSPF_COLUMNS = (
    "id", "device_id", "port_id", "ospf_nbr_id", "ospfNbrIpAddr", "ospfNbrAddressLessIndex", "ospfNbrRtrId",
    "ospfNbrOptions", "ospfNbrPriority", "ospfNbrState", "ospfNbrEvents", "ospfNbrLsRetransQLen",
    "ospfNbmaNbrStatus", "ospfNbmaNbrPermanence", "ospfNbrHelloSuppressed", "context_name",
)  # fmt: skip
_OSPFV3_COLUMNS = (
    "id", "device_id", "ospfv3_instance_id", "port_id", "router_id", "ospfv3NbrIfIndex", "ospfv3NbrIfInstId",
    "ospfv3NbrRtrId", "ospfv3NbrAddressType", "ospfv3NbrAddress", "ospfv3NbrOptions", "ospfv3NbrPriority",
    "ospfv3NbrState", "ospfv3NbrEvents", "ospfv3NbrLsRetransQLen", "ospfv3NbmaNbrStatus", "ospfv3NbmaNbrPermanence",
    "ospfv3NbrHelloSuppressed", "ospfv3NbrIfId", "ospfv3NbrRestartHelperStatus", "ospfv3NbrRestartHelperAge",
    "ospfv3NbrRestartHelperExitReason", "context_name",
)  # fmt: skip
# processors, mempools and storage: what devices/{hostname}/health/device_<kind>/{id} returns of one (toArray()).
_PROCESSOR_COLUMNS = (
    "processor_id", "entPhysicalIndex", "hrDeviceIndex", "device_id", "processor_oid", "processor_index",
    "processor_type", "processor_usage", "processor_descr", "processor_precision", "processor_perc_warn",
)  # fmt: skip
_MEMPOOL_COLUMNS = (
    "mempool_id", "mempool_index", "entPhysicalIndex", "mempool_type", "mempool_class", "mempool_precision",
    "mempool_descr", "device_id", "mempool_perc", "mempool_perc_oid", "mempool_used", "mempool_used_oid",
    "mempool_free", "mempool_free_oid", "mempool_total", "mempool_total_oid", "mempool_largestfree",
    "mempool_lowestfree", "mempool_deleted", "mempool_perc_warn", "polling_method",
)  # fmt: skip
_STORAGE_COLUMNS = (
    "storage_id", "device_id", "type", "storage_index", "storage_type", "storage_descr", "storage_size",
    "storage_size_oid", "storage_units", "storage_used", "storage_used_oid", "storage_free", "storage_free_oid",
    "storage_perc", "storage_perc_oid", "storage_perc_warn", "storage_deleted",
)  # fmt: skip
# list_available_health_graphs: per kind its table, columns, id and description column (a sensor class otherwise).
_HEALTH_KINDS = {
    "processor": ("processors", _PROCESSOR_COLUMNS, "processor_id", "processor_descr"),
    "storage": ("storage", _STORAGE_COLUMNS, "storage_id", "storage_descr"),
    "mempool": ("mempools", _MEMPOOL_COLUMNS, "mempool_id", "mempool_descr"),
}
_ALERT_LOG_COLUMNS = ("id", "rule_id", "device_id", "fault_id", "state", "details", "time_logged")
_SYSLOG_COLUMNS = ("device_id", "facility", "priority", "level", "tag", "timestamp", "program", "msg", "seq")
_VLAN_COLUMNS = ("vlan_id", "device_id", "vlan_vlan", "vlan_domain", "vlan_name", "vlan_type", "vlan_state")
# ports_vlans (PortVlan): a port's membership of a VLAN, tagged or not, as with=vlans returns it.
_PORT_VLAN_COLUMNS = (
    "port_vlan_id", "device_id", "port_id", "vlan", "baseport", "priority", "state", "cost", "untagged",
)  # fmt: skip
_FDB_COLUMNS = ("ports_fdb_id", "port_id", "mac_address", "vlan_id", "device_id", "created_at", "updated_at")
_NAC_COLUMNS = (
    "ports_nac_id", "auth_id", "device_id", "port_id", "domain", "username", "mac_address", "ip_address",
    "host_mode", "authz_status", "authz_by", "authc_status", "method", "timeout", "time_left", "vlan",
    "time_elapsed", "created_at", "updated_at", "historical",
)  # fmt: skip
_ARP_COLUMNS = ("id", "port_id", "device_id", "mac_address", "ipv4_address", "context_name")
_BILL_COLUMNS = (
    "bill_id", "bill_name", "bill_type", "bill_cdr", "bill_day", "bill_quota", "rate_95th_in", "rate_95th_out",
    "rate_95th", "dir_95th", "total_data", "total_data_in", "total_data_out", "rate_average_in",
    "rate_average_out", "rate_average", "bill_last_calc", "bill_custid", "bill_ref", "bill_notes", "bill_autoadded",
)  # fmt: skip
# Component::getComponents: each component's own columns but its id and device, then its preferences.
_COMPONENT_COLUMNS = ("type", "label", "status", "ignore", "disabled", "error")
# AlertRule::toArray, then what list_alert_rules eager-loads (the mapping ids and the alert operation).
_RULE_KEYS = (
    "id", "severity", "extra", "disabled", "name", "proc", "notes", "query", "builder", "invert_map",
    "notify_per_entity", "max_entities", "alert_operation_id", "devices", "groups", "locations",
)  # fmt: skip
_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "devices": {
        **dict.fromkeys(_DEVICE_KEYS),
        **{"snmpver": "v2c", "port": 161, "transport": "udp", "snmp_disable": 0, "status": 1, "status_reason": "",
           "ignore": 0, "disabled": 0, "uptime": 0, "agent_uptime": 0, "os": "generic", "type": "network",
           "poller_group": 0, "override_sysLocation": 0, "port_association_mode": 1, "max_depth": 0,
           "disable_notify": 0, "ignore_status": 0, "mtu_status": 0},
    },
    "locations": {"lat": None, "lng": None, "timestamp": None, "fixed_coordinates": 0},
    "device_groups": {"desc": None, "type": "static", "rules": None, "pattern": None, "devices": []},
    "services": {"service_ip": None, "service_desc": "", "service_param": "", "service_ignore": 0, "service_status": 3,
                 "service_changed": 0, "service_message": "Service not yet checked", "service_disabled": 0,
                 "service_ds": "{}", "service_template_id": 0, "service_name": ""},
    "rules": {"extra": {"options": {"override_query": False}}, "disabled": 0, "proc": None, "notes": "",
              "query": None, "invert_map": 0, "notify_per_entity": False, "max_entities": None,
              "alert_operation_id": None, "devices": [], "groups": [], "locations": []},
    "faults": {"entity_type": None, "entity_id": None, "entity_key": "", "alerted": 1, "open": 1, "severity": "ok",
               "note": "", "info": None, "details": None, "first_seen": None, "last_seen": None},
    "ports": {**dict.fromkeys(_PORT_COLUMNS),
              **{"ignore": 0, "disabled": 0, "deleted": 0, "ifMtu": 1500, "ifLastChange": 0, "ifVrf": 0}},
    "ports_statistics": dict.fromkeys(_PORT_STATISTICS_COLUMNS),
    "eventlog": {"type": "system", "reference": None, "username": None, "severity": 2},
    "port_groups": {"desc": None, "ports": []},
    "links": {**dict.fromkeys(_LINK_COLUMNS), "active": 1, "protocol": "lldp", "remote_device_id": 0},
    "sensors": {**dict.fromkeys(_SENSOR_COLUMNS), "sensor_deleted": 0, "poller_type": "snmp", "sensor_divisor": 1,
                "sensor_multiplier": 1, "sensor_alert": 1, "sensor_custom": "No", "rrd_type": "GAUGE"},
    "transceivers": {**dict.fromkeys(_TRANSCEIVER_COLUMNS), "ddm": False, "channels": 1},
    "components": {"label": "", "status": 0, "ignore": 0, "disabled": 0, "error": "", "prefs": {}},
    "bgp_peers": {**dict.fromkeys(_BGP_COLUMNS), "bgpPeerAdminStatus": "start", "bgpPeerLastErrorCode": 0,
                  "bgpPeerLastErrorSubCode": 0, "bgpPeerLastErrorText": "", "context_name": ""},
    "ospf_nbrs": {**dict.fromkeys(_OSPF_COLUMNS), "ospfNbrAddressLessIndex": 0, "context_name": ""},
    "ospfv3_nbrs": {**dict.fromkeys(_OSPFV3_COLUMNS), "ospfv3NbrAddressType": "ipv6", "context_name": ""},
    "processors": {**dict.fromkeys(_PROCESSOR_COLUMNS), "processor_precision": 1, "processor_perc_warn": 75},
    "mempools": {**dict.fromkeys(_MEMPOOL_COLUMNS), "mempool_precision": 1, "mempool_deleted": 0,
                 "mempool_perc_warn": 90, "mempool_class": "system", "polling_method": "snmp"},
    "storage": {**dict.fromkeys(_STORAGE_COLUMNS), "type": "hrstorage", "storage_units": 4096, "storage_deleted": 0,
                "storage_perc_warn": 60},
    "alert_log": {"fault_id": None, "details": None},
    "syslog": {"facility": "local7", "priority": "info", "level": "info", "tag": "", "program": ""},
    "vlans": {"vlan_domain": 1, "vlan_type": "ethernet", "vlan_state": 0},
    "ports_vlans": {"baseport": 0, "priority": 0, "state": "unknown", "cost": 0, "untagged": 0},
    "ports_fdb": {"vlan_id": 0},
    "ports_nac": {**dict.fromkeys(_NAC_COLUMNS), "historical": 0},
    "ipv4_mac": {"context_name": ""},
    "outages": {"up_again": None},
    "bills": {**dict.fromkeys(_BILL_COLUMNS), "bill_type": "cdr", "bill_day": 1, "bill_quota": 0, "dir_95th": "in",
              "bill_autoadded": 0, "ports": []},
}  # fmt: skip

# The parameter of a route that takes the rest of the path (``->where('search', '.*')``).
_REST = {"search_ports": "search"}
# Every route the fake answers, in routes/api.php order: (method, template, route name, handler).
_ROUTES = (
    ("GET", "", None, "_index"),
    ("GET", "ping", "ping", "_ping"),
    ("GET", "system", "server_info", "_server_info"),
    ("GET", "bgp", "list_bgp", "_list_bgp"),
    ("GET", "bgp/{id}", "get_bgp", "_get_bgp"),
    ("GET", "ospf", "list_ospf", "_list_ospf"),
    ("GET", "ospfv3", "list_ospfv3", "_list_ospfv3"),
    ("GET", "devicegroups/{name}", "get_devices_by_group", "_get_devices_by_group"),
    ("GET", "devicegroups", "get_device_groups", "_get_device_groups"),
    ("POST", "devicegroups", "add_device_group", "_add_device_group"),
    ("PATCH", "devicegroups/{name}", "update_device_group", "_update_device_group"),
    ("DELETE", "devicegroups/{name}", "delete_device_group", "_delete_device_group"),
    ("POST", "devicegroups/{name}/maintenance", "maintenance_devicegroup", "_maintenance_devicegroup"),
    ("GET", "port_groups", "get_port_groups", "_get_port_groups"),
    ("GET", "port_groups/{name}", "get_ports_by_group", "_get_ports_by_group"),
    ("GET", "faults/{id}", "get_alert", "_list_alerts"),
    ("GET", "faults", "list_alerts", "_list_alerts"),
    ("PUT", "faults/{id}", "ack_alert", "_ack_alert"),
    ("PUT", "faults/unmute/{id}", "unmute_alert", "_unmute_alert"),
    ("GET", "alerts/{id}", None, "_list_alerts"),  # the legacy aliases have no route name
    ("GET", "alerts", None, "_list_alerts"),
    ("GET", "rules/{id}", "get_alert_rule", "_list_alert_rules"),
    ("GET", "rules", "list_alert_rules", "_list_alert_rules"),
    ("POST", "rules", "add_rule", "_add_edit_rule"),
    ("PUT", "rules", "edit_rule", "_add_edit_rule"),
    ("DELETE", "rules/{id}", "delete_rule", "_delete_rule"),
    ("GET", "services", "list_services", "_list_services"),
    ("GET", "services/{hostname}", "list_services_device", "_list_services"),
    ("POST", "services/{hostname}", "add_service_for_host", "_add_service_for_host"),
    ("DELETE", "services/{id}", "del_service_from_host", "_del_service_from_host"),
    ("PATCH", "services/{id}", "edit_service_for_host", "_edit_service_for_host"),
    ("GET", "poller_group/{poller_group_id_or_name?}", "get_poller_group", "_get_poller_group"),
    ("GET", "devices/{hostname}", "get_device", "_get_device"),
    ("GET", "devices/{hostname}/discover", "trigger_device_discovery", "_trigger_device_discovery"),
    ("GET", "devices/{hostname}/availability", "device_availability", "_device_availability"),
    ("GET", "devices/{hostname}/outages", "device_outages", "_device_outages"),
    ("GET", "devices/{hostname}/vlans", "get_vlans", "_get_vlans"),
    ("GET", "devices/{hostname}/links", "list_links_device", "_list_links"),
    ("GET", "devices/{hostname}/fdb", "get_fdb", "_get_fdb"),
    ("GET", "devices/{hostname}/health/{type?}/{sensor_id?}", "list_available_health_graphs", "_list_health"),
    ("GET", "devices/{hostname}/ports", "get_device_ports", "_get_device_ports"),
    ("GET", "devices/{hostname}/transceivers", "get_transceivers", "_get_transceivers"),
    ("GET", "devices/{hostname}/components", "get_components", "_get_components"),
    ("GET", "devices/{hostname}/maintenance", "device_under_maintenance", "_device_under_maintenance"),
    ("GET", "devices", "list_devices", "_list_devices"),
    ("POST", "devices", "add_device", "_add_device"),
    ("DELETE", "devices/{hostname}", "del_device", "_del_device"),
    ("PATCH", "devices/{hostname}", "update_device_field", "_update_device"),
    ("PATCH", "devices/{hostname}/rename/{new_hostname}", "rename_device", "_rename_device"),
    ("POST", "devices/{hostname}/maintenance", "maintenance_device", "_maintenance_device"),
    ("GET", "logs/eventlog/{hostname?}", "list_eventlog", "_list_logs"),
    ("GET", "logs/syslog/{hostname?}", "list_syslog", "_list_logs"),
    ("GET", "logs/alertlog/{hostname?}", "list_alertlog", "_list_logs"),
    ("GET", "ports/{portid}", "get_port_info", "_get_port_info"),
    ("GET", "ports/{portid}/transceiver", "get_port_transceiver", "_get_port_transceiver"),
    ("GET", "ports/search/{field}/{search?}", "search_ports", "_search_ports"),
    ("GET", "ports/mac/{search}", "search_mac", "_search_mac"),
    ("GET", "ports", "get_all_ports", "_get_all_ports"),
    ("GET", "ports/{portid}/description", "get_port_description", "_get_port_description"),
    ("PATCH", "ports/{portid}/description", "update_port_description", "_update_port_description"),
    ("GET", "bills", "list_bills", "_list_bills"),
    ("GET", "bills/{bill_id}", "get_bill", "_list_bills"),
    ("GET", "resources/fdb", "list_fdb", "_list_fdb"),
    ("GET", "resources/fdb/{mac}", "list_fdb_mac", "_list_fdb"),
    ("GET", "resources/fdb/{mac}/detail", "list_fdb_detail", "_list_fdb_detail"),
    ("GET", "resources/ip/arp/{query}/{cidr?}", "list_arp", "_list_arp"),
    ("GET", "resources/links", "list_links", "_list_links"),
    ("GET", "resources/links/{id}", "get_link", "_get_link"),
    ("GET", "resources/nac", "list_nac", "_list_nac"),
    ("GET", "resources/nac/{mac}", "list_nac_mac", "_list_nac"),
    ("GET", "resources/sensors", "list_sensors", "_list_sensors"),
    ("GET", "resources/vlans", "list_vlans", "_list_vlans"),
    ("GET", "resources/locations", "list_locations", "_list_locations"),
    ("POST", "locations", "add_location", "_add_location"),
    ("GET", "location/{location_id_or_name}", "get_location", "_get_location"),
    ("PATCH", "locations/{location_id_or_name}", "edit_location", "_edit_location"),
    ("DELETE", "locations/{location}", "del_location", "_del_location"),
    ("POST", "locations/{location}/maintenance", "maintenance_location", "_maintenance_location"),
)


class Headers(MutableMapping):
    """Case-insensitive header mapping, as ``requests`` gives one (the fake must not import requests)."""

    def __init__(self, data: Any = None):
        self._items: Dict[str, Tuple[str, str]] = {}
        for key, value in dict(data or {}).items():
            self[key] = value

    def __getitem__(self, key: str) -> str:
        return self._items[key.lower()][1]

    def __setitem__(self, key: str, value: str) -> None:
        self._items[key.lower()] = (key, value)

    def __delitem__(self, key: str) -> None:
        del self._items[key.lower()]

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self._items.values())

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return repr(dict(self.items()))


class FakeResponse:
    """An answer read the way the client reads a streamed ``requests`` response: :meth:`iter_content` hands out the
    body in chunks (counted in ``streamed``) and :meth:`close` is recorded in ``closed``."""

    def __init__(self, status_code: int, headers: Any = None, body: bytes = b""):
        self.status_code = status_code
        self.headers = Headers(headers)
        self.headers.setdefault("Content-Length", str(len(body)))
        self.content = body
        self.streamed = 0
        self.closed = False

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)  # ValueError on an empty or non-JSON body, as requests raises

    def iter_content(self, chunk_size: int | None = 1) -> Iterator[bytes]:
        size = chunk_size or len(self.content) or 1
        for start in range(0, len(self.content), size):
            piece = self.content[start : start + size]
            self.streamed += len(piece)
            yield piece

    def close(self) -> None:
        self.closed = True


def _json(status: int, payload: Any) -> FakeResponse:
    return FakeResponse(status, {"Content-Type": "application/json"}, json.dumps(payload, indent=4).encode())


def _api_success(
    result: Any = None, key: str | None = None, message: str = "", code: int = 200, *, array: bool = False,
    extra: Dict[str, Any] | None = None,
) -> FakeResponse:  # fmt: skip
    """``api_success``: the result under *key* unless null, ``message`` unless empty, and ``count`` only when PHP
    handed over an array (*array*); an Eloquent model or Collection gets none."""
    out: Dict[str, Any] = {"status": "ok"}
    if result is not None:
        out[key] = result
    if message:
        out["message"] = message
    if array:
        out["count"] = len(result)
    out.update(extra or {})
    return _json(code, out)


def _api_error(code: int, message: Any) -> FakeResponse:
    return _json(code, {"status": "error", "message": message})


def _server_error() -> FakeResponse:
    """An exception no handler caught, rendered by Laravel in production: no envelope, no detail."""
    return _json(500, {"message": "Server Error"})


def _redirect(location: str) -> FakeResponse:
    page = b"<html><head><title>301 Moved Permanently</title></head></html>"
    return FakeResponse(301, {"Location": location, "Content-Type": "text/html"}, page)


@dataclass
class _Req:
    params: Dict[str, str]
    body: Any  # the body decoded as JSON; None when absent or not JSON
    headers: Headers
    args: Dict[str, Any] = field(default_factory=dict)
    name: str | None = None  # the route that matched (list_logs reads it)

    def array(self) -> Dict[str, Any] | None:
        """``json_decode($request->getContent(), true)`` as the handlers index it: an object, ``{}`` for a JSON list
        (it has no string keys), None when the body is missing or not JSON."""
        if isinstance(self.body, dict):
            return self.body
        return {} if isinstance(self.body, list) else None

    def is_json(self) -> bool:
        return "json" in self.headers.get("Content-Type", "").lower()

    def json_input(self) -> Dict[str, Any]:
        """``$request->json()->all()``: the body, trimmed with ``""`` made null when the request says it is JSON
        (Laravel's TrimStrings and ConvertEmptyStringsToNull)."""
        data = self.array() or {}
        return _clean(data) if self.is_json() else data

    def all_input(self) -> Dict[str, Any]:
        """``$request->all()``: the query merged with a body it only sees when the request says it is JSON."""
        return {**self.params, **(_clean(self.array() or {}) if self.is_json() else {})}


class FakeLibreNMS:
    """``session``-compatible LibreNMS: ``request(method, url, params=, data=, headers=, ...)`` as ``requests`` takes
    it. Tables are plain dicts keyed by id in ``tables`` (``devices``, ``locations``, ``device_groups``, ``services``,
    ``rules``, ``faults``, ``ports``, ``eventlog``, ``poller_groups``, and the read-only ones in :data:`_TABLES`); a
    group's members, a port group's ports, a bill's ports and a rule's mappings are lists in its row. Dynamic groups
    are not evaluated: their members are whatever the row says."""

    def __init__(self, base_url: str = "https://librenms.test", token: str = TOKEN):
        self.base_url = base_url
        self.token = token
        self.username = "hermes"  # the LibreNMS user owning the token, named in ack notes and eventlog rows
        self.admin_secrets = True  # an admin token unmasks SNMP secrets; a global-read token gets null instead
        self.add_schedule_note_to_device = False  # that user's preference: maintenance notes appended to the device
        self.default_poller_group = 0  # config default_poller_group: where add_device puts a device sent group 0
        self.default_max_entities = 20  # config alert_rule.default_max_entities: the limit of a rule that sets none
        self.service_types = ["dns", "http", "icmp", "ping", "snmp", "ssh", "tcp"]  # the check_* plugins installed
        self.missing_routes: Set[str] = set()  # route names an older LibreNMS lacks: not indexed, answered 404
        self.oui: Dict[str, str] = {}  # the vendor of a MAC prefix (6 hex digits), as LibreNMS's OUI table has it
        self.system = {
            "local_ver": "26.10.0",
            "local_sha": "91b9a40b4cc42b27a06f3289a38b053ca6320218",
            "local_date": "2026-10-27T10:15:59+00:00",
            "local_branch": "master",
            "db_schema": "2026_03_25_120000_add_ssl_certificate_permissions (412)",
            "php_ver": "8.3.12",
            "python_ver": "3.11.2",
            "database_ver": "MariaDB 10.11.6",
            "rrdtool_ver": "1.7.2",
            "netsnmp_ver": "5.9.3",
        }
        self.tables: Dict[str, Dict[int, Dict[str, Any]]] = {name: {} for name in _TABLES}
        self._last_ids = dict.fromkeys(_TABLES, 0)  # AUTO_INCREMENT: the id of a deleted row is never handed out again
        self.alert_operations: Dict[int, Dict[str, Any]] = {}
        self.attribs: Dict[int, Dict[str, Any]] = {}  # devices_attribs; a description set via the API pins ifName:<x>
        self.schedules: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []
        self.failures: List[Dict[str, Any]] = []
        self.hooks: Dict[str, List[Callable[[], None]]] = {}
        self.redirect_to: str | None = None
        self.now = datetime(2026, 10, 28, 12, 0, 0)  # the server clock (UTC); each write moves it on a second
        self.send_date = True  # every answer carries a Date header, as the web server in front of LibreNMS sends it
        self._routes = [
            (verb, _compile(tpl, _REST.get(name)), name, tpl, getattr(self, handler))
            for verb, tpl, name, handler in _ROUTES
        ]

    # -- fixtures and test hooks ----------------------------------------------------------------
    def seed(self, table: str, row: Dict[str, Any]) -> Dict[str, Any]:
        """Insert *row* into *table* with that table's defaults; the id comes from the row or is the next one never
        used, as MySQL's AUTO_INCREMENT hands them out."""
        rows = self.tables[table]
        key = _ID_KEYS.get(table, "id")
        row = {**copy.deepcopy(_DEFAULTS.get(table, {})), **row}
        row[key] = row.get(key) or max([self._last_ids[table], *rows]) + 1
        self._last_ids[table] = max(self._last_ids[table], row[key])
        if table == "devices":
            row["inserted"] = row["inserted"] or _iso(self._tick())
            row["display"] = _display(row)
        elif table == "locations":
            row["timestamp"] = row["timestamp"] or self._tick()
        elif table == "rules":
            row["query"] = row["query"] or _rule_sql(row["builder"])
        rows[row[key]] = row
        return row

    def fail_on(
        self, method: str, path_regex: str, status: int = 500, body: Any = None, *, headers: Any = None,
        exc: BaseException | None = None, commit: bool = False, times: int | None = None,
    ) -> None:  # fmt: skip
        """Force the answer to *method* (``"*"`` for any) on a path that fully matches *path_regex* (decoded,
        relative to ``/api/v0``): *status* with *body* (a dict is sent as JSON, a str as HTML; by default Laravel's
        bare ``Server Error`` for a 5xx, else an error envelope), or raise *exc* as a transport failure would.
        ``commit=True`` lets the request take effect first, as when LibreNMS fails after writing. *times* limits how
        often it fires (default: every time); ``failures.clear()`` removes them all."""
        rule = {"method": method.upper(), "regex": re.compile(path_regex), "status": status, "body": body}
        self.failures.append({**rule, "headers": headers, "exc": exc, "commit": commit, "times": times})

    def touch(self, table: str, row_id: int, **fields: Any) -> Dict[str, Any]:
        """Simulate an edit made outside the plugin (the web UI, another tool, the poller): set *fields* as stored."""
        row = self.tables[table][row_id]
        row.update(fields)
        return row

    def poll(self, port_id: int, if_alias: str | None) -> None:
        """The poller's next run for *port_id*: a port whose description the API did not pin takes the device's
        ifAlias (which ends a ``"repoll"``); a pinned one keeps what was set."""
        port = self.tables["ports"][port_id]
        if f"ifName:{port['ifName']}" not in self.attribs.get(port["device_id"], {}):
            port["ifAlias"] = if_alias

    def after(self, route: str, hook: Callable[[], None]) -> None:
        """Run *hook* each time the route named *route* has handled a request, before LibreNMS answers: something
        else that lands at the same moment (another client's write)."""
        self.hooks.setdefault(route, []).append(hook)

    def redirect_all(self, location: str | None) -> None:
        """Answer every request with a 301 to *location*, as a web server in front of LibreNMS might; None stops."""
        self.redirect_to = location

    def writes(self) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["method"] != "GET"]

    # -- session interface ----------------------------------------------------------------------
    def request(
        self, method: str, url: str, params: Any = None, data: Any = None, headers: Any = None, timeout: Any = None,
        verify: Any = None, allow_redirects: Any = None, stream: Any = None, proxies: Any = None,
    ) -> FakeResponse:  # fmt: skip
        prefix = self.base_url + "/api/v0"
        parts = urlsplit(url)
        assert url.startswith(prefix) and not parts.query and not parts.fragment, url
        rest = url[len(prefix) :]
        assert rest == "" or rest.startswith("/"), url
        raw = data.decode("utf-8") if isinstance(data, bytes) else data
        try:
            body = None if raw is None else json.loads(raw)
        except ValueError:
            body = None
        req = _Req({k: _param(v) for k, v in (params or {}).items() if v is not None}, body, Headers(headers))
        call = {
            "method": method.upper(),
            "path": unquote(rest[1:]),
            "params": req.params,
            "json": body,
            "data": raw,
            "headers": req.headers,
            "timeout": timeout,
            "verify": verify,
            "allow_redirects": allow_redirects,
            "stream": stream,
            "status": None,
        }
        self.calls.append(call)
        response = self._answer(call["method"], call["path"], rest, req)
        call["status"] = response.status_code
        if self.send_date:  # the web server's Date, from the server clock (UTC)
            response.headers.setdefault("Date", format_datetime(self.now.replace(tzinfo=timezone.utc), usegmt=True))
        return response

    def _answer(self, method: str, path: str, rest: str, req: _Req) -> FakeResponse:
        if self.redirect_to is not None:
            return _redirect(self.redirect_to)
        if rest.endswith("/"):  # what LibreNMS's stock .htaccess does with a trailing slash
            return _redirect(self.base_url + "/api/v0" + rest.rstrip("/"))
        if _token(req.headers) != self.token:
            return _json(401, {"message": "Unauthenticated."})
        forced = self._forced(method, path, commit=False)
        if forced is not None:
            return forced
        response = self._dispatch(method, path, req)
        forced = self._forced(method, path, commit=True)
        return response if forced is None else forced

    def _forced(self, method: str, path: str, *, commit: bool) -> FakeResponse | None:
        for rule in self.failures:
            if rule["commit"] != commit or rule["times"] == 0 or rule["method"] not in ("*", method):
                continue
            if not rule["regex"].fullmatch(path):
                continue
            if rule["times"] is not None:
                rule["times"] -= 1
            if rule["exc"] is not None:
                raise rule["exc"]
            body = rule["body"]
            if body is None:
                body = (
                    {"message": "Server Error"} if rule["status"] >= 500 else {"status": "error", "message": "forced"}
                )
            if isinstance(body, str):
                return FakeResponse(
                    rule["status"], {"Content-Type": "text/html", **(rule["headers"] or {})}, body.encode()
                )
            response = _json(rule["status"], body)
            response.headers.update(rule["headers"] or {})
            return response
        return None

    def _dispatch(self, method: str, path: str, req: _Req) -> FakeResponse:
        for verb, regex, name, _template, handler in self._routes:
            match = regex.fullmatch(path)
            if match is not None and verb == method and name not in self.missing_routes:
                req.args, req.name = match.groupdict(), name
                response = handler(req)
                for hook in self.hooks.get(name, ()):
                    hook()
                return response
        return _api_error(404, _CATCH_ALL)

    # -- shared lookups and side effects ----------------------------------------------------------
    def _tick(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now

    def _device(self, ref: str | None) -> Dict[str, Any] | None:
        """``DeviceCache::get``: all digits is a device_id, anything else an exact hostname (case-insensitive)."""
        if ref is None:
            return None
        return self.tables["devices"].get(int(ref)) if _digits(ref) else self._by_hostname(ref)

    def _by_hostname(self, hostname: str) -> Dict[str, Any] | None:
        return next((d for d in self.tables["devices"].values() if d["hostname"].lower() == hostname.lower()), None)

    def _device_out(self, d: Dict[str, Any], *, parents: bool = False) -> Dict[str, Any]:
        out = {key: d[key] for key in _DEVICE_KEYS}
        if not self.admin_secrets:
            out.update(dict.fromkeys(_UNMASKABLE))
        location = self.tables["locations"].get(d["location_id"])
        out["location"] = location["location"] if location else None
        out["lat"] = location["lat"] if location else None
        out["lng"] = location["lng"] if location else None
        if parents:
            out.update(dependency_parent_id=None, dependency_parent_hostname=None)
        return out

    def _log(
        self, device_id: int, message: str, type_: str = "system", severity: int = 3, reference: Any = None
    ) -> None:
        row = {"device_id": device_id, "datetime": _raw(self._tick()), "message": message, "type": type_,
               "reference": reference, "username": self.username, "severity": severity}  # fmt: skip
        self.seed("eventlog", row)

    def _fill_device(self, d: Dict[str, Any], update: Dict[str, Any]) -> None:
        """``$device->fill($update)->save()`` and DeviceObserver: columns outside ``$fillable`` are dropped, a boolean
        cast compares PHP truthiness (so ``"false"`` on a set flag is no change), MySQL without strict mode stores a
        non-numeric string in a tinyint as 0, and tracked changes write eventlog rows."""
        before = dict(d)
        for name, value in update.items():
            if name not in _DEVICE_FILLABLE:
                continue
            if name in _DEVICE_FLAGS:
                if _truthy(value) != bool(d[name]):
                    d[name] = _tinyint(value)
            elif name in ("location_id", "poller_group"):
                d[name] = None if value is None and name == "location_id" else _php_int(value)
            else:
                d[name] = value
        d["display"] = _display(d)
        for name in _OBSERVED:
            if d[name] != before[name]:
                self._log(d["device_id"], f"{name}: {before[name]} -> {d[name]}")
        if d["location_id"] != before["location_id"]:
            old, new = (
                self.tables["locations"].get(i, {}).get("location") for i in (before["location_id"], d["location_id"])
            )
            self._log(d["device_id"], f"Location: {old} -> {new}")

    def _named(self, table: str, column: str, name: Any) -> Dict[str, Any] | None:
        return next((row for row in self.tables[table].values() if _same(row[column], name)), None)

    def _location(self, ref: str) -> Dict[str, Any] | None:
        """Groups and locations in a path: all digits is an id, anything else the name."""
        return self.tables["locations"].get(int(ref)) if _digits(ref) else self._named("locations", "location", ref)

    def _location_first_or_create(self, name: Any) -> int:
        return (self._named("locations", "location", name) or self.seed("locations", {"location": name}))["id"]

    def _group(self, ref: str) -> Dict[str, Any] | None:
        return self.tables["device_groups"].get(int(ref)) if _digits(ref) else self._named("device_groups", "name", ref)

    def _drop(self, table: str, column: str, value: Any) -> None:
        rows = self.tables[table]
        for key in [key for key, row in rows.items() if row[column] == value]:
            del rows[key]

    def _schedule(self, data: Dict[str, Any], title: str, notes: str, **targets: List[int]) -> Tuple[Any, str] | None:
        """The AlertSchedule the three maintenance handlers save: ``end`` only when ``duration`` has a colon (else
        the schedule keeps its lapsed default), ``start`` exactly ``Y-m-d H:i:s``. Returns (duration, start) or None
        for a start Carbon cannot parse (the handler then dies with a 500)."""
        start = data["start"] if data.get("start") is not None else self.now.strftime("%Y-%m-%d %H:%M:00")
        try:
            begins = datetime.strptime(str(start), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        duration = data["duration"]
        end = "1970-01-02 00:00:01"
        if ":" in str(duration):
            hours, minutes = str(duration).split(":")[:2]
            end = (begins + timedelta(hours=_php_float(hours), minutes=_php_float(minutes))).strftime(
                "%Y-%m-%d %H:%M:00"
            )
        behavior = _php_int(data.get("behavior", -1))
        self.schedules.append({
            "schedule_id": len(self.schedules) + 1, "title": title, "notes": notes,
            "behavior": behavior if behavior in (1, 2, 3) else 1, "recurring": 0, "start": _raw(begins), "end": end,
            "devices": [], "device_groups": [], "locations": [], **targets,
        })  # fmt: skip
        self._tick()
        return duration, start

    def _under_maintenance(self, d: Dict[str, Any]) -> bool:
        now = _raw(self.now)
        groups = {g["id"] for g in self.tables["device_groups"].values() if d["device_id"] in g["devices"]}
        return any(
            s["start"] <= now < s["end"]
            and (
                d["device_id"] in s["devices"] or groups & set(s["device_groups"]) or d["location_id"] in s["locations"]
            )
            for s in self.schedules
        )

    def _remove_device(self, device_id: int) -> None:
        """What DeviceObserver deletes with a device (its ports, services, alerts, eventlog, static membership and
        alert-rule device maps)."""
        del self.tables["devices"][device_id]
        for table in ("ports", "services", "faults", "eventlog"):
            self._drop(table, "device_id", device_id)
        for row in (*self.tables["device_groups"].values(), *self.tables["rules"].values()):
            if device_id in row["devices"]:
                row["devices"].remove(device_id)
        self.attribs.pop(device_id, None)

    # -- index, system --------------------------------------------------------------------------
    def _index(self, r: _Req) -> FakeResponse:
        base = self.base_url + "/api/v0/"
        names = {
            name: base + tpl for _v, _rx, name, tpl, _h in self._routes if name and name not in self.missing_routes
        }
        return _json(200, dict(sorted(names.items())))

    def _ping(self, r: _Req) -> FakeResponse:
        return _json(200, {"message": "pong"})

    def _server_info(self, r: _Req) -> FakeResponse:
        return _api_success([dict(self.system)], "system", array=True)

    # -- devices ----------------------------------------------------------------------------------
    def _list_devices(self, r: _Req) -> FakeResponse:
        kind, query = r.params.get("type"), r.params.get("query", "")
        rows = list(self.tables["devices"].values())
        if kind in ("hostname", "display", "serial", "version", "hardware", "features"):
            rows = [d for d in rows if _like(d[kind], f"%{query}%")]
        elif kind == "location":
            rows = [
                d
                for d in rows
                if _like(self.tables["locations"].get(d["location_id"], {}).get("location"), f"%{query}%")
            ]
        elif kind in ("device_id", "os", "sysName", "location_id", "type"):
            rows = [d for d in rows if d[kind] is not None and _same(str(d[kind]), query)]
        elif kind in ("ipv4", "ipv6", "mac"):  # whereHas('ports.ipv4' | 'ports.ipv6' | 'ports.macs'): exact
            rows = [d for d in rows if d["device_id"] in self._holding(kind, query)]
        elif kind in _STATE_FILTERS:
            rows = [d for d in rows if _STATE_FILTERS[kind](d)]
        order = re.fullmatch(r"([a-z_]+)(?: (desc|asc))?", r.params.get("order", ""), re.I)
        column = order.group(1) if order else "hostname"
        key = next((k for k in _DEVICE_KEYS if k.lower() == column.lower()), None)
        if key is None:  # an unknown column passes the regex and fails in SQL
            return _server_error()
        rows.sort(key=lambda d: _sort_key(d[key]), reverse=bool(order and (order.group(2) or "").lower() == "desc"))
        return _api_success([self._device_out(d, parents=True) for d in rows], "devices", array=True)

    def _holding(self, kind: str, query: str) -> Set[int]:
        """The devices with a port that holds *query*: an IPv4 address, an IPv6 address (full or compressed), or a MAC
        in the ARP table (``ipv4_mac``, the Port ``macs`` relation), compared exactly as stored."""
        table, columns = {
            "ipv4": ("ipv4_addresses", ("ipv4_address",)),
            "ipv6": ("ipv6_addresses", ("ipv6_address", "ipv6_compressed")),
            "mac": ("ipv4_mac", ("mac_address",)),
        }[kind]
        ports = {row["port_id"] for row in self.tables[table].values() if any(row[c] == query for c in columns)}
        return {self.tables["ports"][i]["device_id"] for i in ports if i in self.tables["ports"]}

    def _get_device(self, r: _Req) -> FakeResponse:
        d = self._device(r.args["hostname"])
        if d is None:
            return _api_error(404, f"Device {r.args['hostname']} does not exist")
        return _api_success([self._device_out(d)], "devices", array=True)

    def _add_device(self, r: _Req) -> FakeResponse:
        data = r.json_input()
        if not data:
            return _api_error(400, "No information has been provided to add this new device")
        if _empty(data.get("hostname")):
            return _api_error(400, "Missing the device hostname")
        hostname = _php_str(data["hostname"])
        if not _HOSTNAME.fullmatch(hostname):
            return _api_error(400, f"Invalid hostname or IP: {hostname}")
        mode = data.get("port_association_mode")
        if _numeric(mode):
            mode = next((name for name, i in _ASSOCIATION_MODES.items() if i == _php_int(mode)), mode)
        errors: Dict[str, List[str]] = {}
        if data.get("port") is not None and not (_numeric(data["port"]) and 1 <= _php_float(data["port"]) <= 65535):
            errors["port"] = ["The port field must be between 1 and 65535."]
        if data.get("transport") is not None and data["transport"] not in ("udp", "tcp", "udp6", "tcp6"):
            errors["transport"] = ["The selected transport is invalid."]
        if mode is not None and mode not in _ASSOCIATION_MODES:
            errors["port_association_mode"] = ["The selected port association mode is invalid."]
        if errors:
            return _api_error(422, errors)
        if self._by_hostname(hostname) is not None:
            return _api_error(400, f"Device {hostname} already exists")
        location_id = None
        if not _empty(data.get("location")):
            location_id = self._location_first_or_create(data["location"])  # add_device creates unknown locations
        elif not _empty(data.get("location_id")):
            location_id = _php_int(data["location_id"])
        ping_only = _truthy(data.get("snmp_disable")) or _truthy(data.get("ping_only"))
        snmpver = data.get("snmpver") or data.get("version") or "v2c"
        row = {
            "hostname": hostname,
            "sysName": data.get("sysName") or hostname,
            "overwrite_ip": data.get("overwrite_ip"),
            "display_template": data.get("display_template"),
            "poller_group": _php_int(data.get("poller_group")) or self.default_poller_group,  # ValidateDeviceAndCreate
            "location_id": location_id,
            "override_sysLocation": int(_truthy(data.get("override_sysLocation"))),
            "hardware": data.get("hardware"),
            "os": data.get("os") or ("ping" if ping_only else "generic"),
            "snmp_disable": int(ping_only),
            "snmpver": snmpver,
            "port": _php_int(data.get("port") or 161),
            "transport": data.get("transport") or "udp",
            "port_association_mode": _ASSOCIATION_MODES[mode or "ifIndex"],
        }
        if snmpver == "v3":
            authpass, cryptopass = data.get("authpass"), data.get("cryptopass")
            row.update(
                authlevel=data.get("authlevel")
                or ("authPriv" if authpass and cryptopass else "authNoPriv" if authpass else "noAuthNoPriv"),
                authname=data.get("authname") or "root",
                authpass=authpass,
                authalgo=data.get("authalgo") or ("MD5" if authpass else None),
                cryptopass=cryptopass,
                cryptoalgo=data.get("cryptoalgo") or ("AES" if cryptopass else None),
            )
        else:
            row["community"] = data.get("community") or "public"  # else LibreNMS tries its default credentials
        d = self.seed("devices", row)
        self._log(d["device_id"], f"Device {hostname} has been created")
        message = f"Device {hostname} ({d['device_id']}) has been added successfully"
        return _api_success([self._device_out(d)], "devices", message, array=True)

    def _del_device(self, r: _Req) -> FakeResponse:
        d = self._device(r.args["hostname"])
        if d is None:
            return _api_error(404, f"Device {r.args['hostname']} not found")
        snapshot = self._device_out(d)
        self._remove_device(d["device_id"])
        self._log(0, f"Device {d['hostname']} has been removed")
        return _api_success([snapshot], "devices", f"Removed device {d['hostname']}\n", array=True)

    def _update_device(self, r: _Req) -> FakeResponse:
        d = self._device(r.args["hostname"])
        if d is None:
            return _api_error(404, f"Device {r.args['hostname']} not found")
        data = r.array() or {}
        names, values = data.get("field"), data.get("data")
        if _empty(names):
            return _api_error(400, "Device field to patch has not been supplied")
        if isinstance(names, list) and isinstance(values, list):
            if not all(isinstance(n, str) for n in names):
                return _server_error()
            if any(n in ("device_id", "hostname") for n in names):
                return _api_error(500, "Device field is not allowed to be updated")
            if len(names) != len(values):
                return _api_error(
                    500,
                    f"Device fields failed to be updated as the number of fields ({len(names)}) does not match "
                    f"the supplied data ({len(values)})",
                )
            self._fill_device(d, dict(self._device_pair(n, v) for n, v in zip(names, values)))
            return _api_success(message="Device fields have been updated")
        if not isinstance(names, str):  # an array field without an array of data indexes PHP with an array
            return _server_error()
        if names in ("device_id", "hostname"):
            return _api_error(500, "Device field is not allowed to be updated")
        self._fill_device(d, dict([self._device_pair(names, values)]))
        return _api_success(message=f"Device {names} field has been updated")

    def _device_pair(self, name: str, value: Any) -> Tuple[str, Any]:
        """The ``location`` pseudo-field: a location name, found or created, written as ``location_id``."""
        return ("location_id", self._location_first_or_create(value)) if name == "location" else (name, value)

    def _rename_device(self, r: _Req) -> FakeResponse:
        d, new = self._device(r.args["hostname"]), r.args["new_hostname"]
        if _empty(new):
            return _api_error(500, "Missing new hostname")
        if d is None:
            return _api_error(404, "Existing device not found")
        old = d["hostname"]
        if new != old:
            other = self._by_hostname(new)
            if other is not None and other is not d:  # DeviceObserver leaves the device itself out (a case change)
                message = f"Renaming of {old} failed because there is already a device with the hostname {new}"
                self._log(d["device_id"], message, severity=5)
                return _api_error(500, message)
            d.update(hostname=new, ip=None)
            d["display"] = _display(d)
            self._log(d["device_id"], f"Hostname changed -> {new} ({self.username})")
        return _api_success(message="Device has been renamed")

    def _maintenance_device(self, r: _Req) -> FakeResponse:
        data = r.json_input()
        if not data:
            return _api_error(400, "No information has been provided to set this device into maintenance")
        ref = r.args["hostname"]
        d = self.tables["devices"].get(int(ref)) if _digits(ref) else self._by_hostname(ref)
        if d is None:
            return _api_error(404, f"Device {ref} not found")
        if _empty(data.get("duration")):
            return _api_error(400, "Duration not provided")
        notes = "" if _empty(data.get("notes")) else _php_str(data["notes"])
        title = data["title"] if data.get("title") is not None else d["display"] or d["hostname"]
        saved = self._schedule(data, title, notes, devices=[d["device_id"]])
        if saved is None:
            return _server_error()
        if notes and self.add_schedule_note_to_device:
            stamp = self.now.strftime("%Y-%m-%d %H:%M")
            d["notes"] = (d["notes"] + "\n" if d["notes"] else "") + f"{stamp} Alerts delayed: {notes}"
        return _maintenance_answer(f"Device {d['hostname']} ({d['device_id']})", data, *saved)

    def _device_under_maintenance(self, r: _Req) -> FakeResponse:
        ref = r.args["hostname"]
        if _digits(ref):  # DeviceCache gives an admin an empty device for an unknown id: not under maintenance
            d = self.tables["devices"].get(int(ref))
        else:
            d = self._by_hostname(ref)
            if d is None:
                return _api_error(404, f"Device {ref} not found")
        return _api_success(d is not None and self._under_maintenance(d), "is_under_maintenance")

    def _trigger_device_discovery(self, r: _Req) -> FakeResponse:
        d = self._device(r.args["hostname"])
        if d is None:
            return _api_error(404, f"Device {r.args['hostname']} does not exist")
        changed = int(d["last_discovered"] is not None)
        d["last_discovered"] = None
        return _api_success({"status": changed, "message": "Device will be rediscovered"}, "result", array=True)

    def _get_device_ports(self, r: _Req) -> FakeResponse:
        """``get_device_ports``: the columns asked for (``ifName`` alone by default) by ifIndex; ``with=vlans`` adds
        ``port_id`` to them and each port's ports_vlans rows as ``vlans`` (:meth:`_port_vlans`)."""
        d = self._device(r.args["hostname"])
        columns = _columns(r.params.get("columns"), ("ifName",))
        if isinstance(columns, FakeResponse):
            return columns
        with_vlans = r.params.get("with") == "vlans"
        if with_vlans and "port_id" not in columns:
            columns = [*columns, "port_id"]
        device_id = d["device_id"] if d else None
        ports = [p for p in self.tables["ports"].values() if p["device_id"] == device_id and not p["deleted"]]
        if not ports:
            return _api_error(404, "No ports found")
        ports.sort(key=lambda p: p["ifIndex"])
        rows = []
        for p in ports:
            rows.append({c: p[c] for c in columns})
            if with_vlans:
                rows[-1]["vlans"] = self._port_vlans(p)
        return _api_success(rows, "ports")

    def _port_vlans(self, port: Dict[str, Any], *, with_port: bool = False) -> List[Dict[str, Any]]:
        """A port's ports_vlans rows, ``untagged`` read through ``PortVlan::getUntaggedAttribute``: 1 also when the row
        says 0 but the VLAN is the port's own ``ifVlan`` (PHP's loose ``==``, so ``"10"`` is 10). That accessor
        lazy-loads the row's port whenever it says 0, and the relation is then serialised under ``port``
        (*with_port*): ``get_port_info`` does so, ``get_device_ports`` hides it."""
        rows = self._rows("ports_vlans", _PORT_VLAN_COLUMNS, port_id=port["port_id"])
        for row in rows:
            if row["untagged"]:
                continue
            if port["ifVlan"] not in (None, "") and str(row["vlan"]) == str(port["ifVlan"]):
                row["untagged"] = 1
            if with_port:
                row["port"] = {k: port[k] for k in _PORT_COLUMNS}
        return rows

    def _get_poller_group(self, r: _Req) -> FakeResponse:
        ref = r.args["poller_group_id_or_name"]
        groups = self.tables["poller_groups"]
        if _empty(ref):  # also "0": every group, as a list
            return _api_success([dict(g) for g in groups.values()], "get_poller_group")
        group = (
            groups.get(int(ref)) if _digits(ref) else next((g for g in groups.values() if g["group_name"] == ref), None)
        )
        if group is None:
            return _api_error(404, "Poller Group does not exist")
        return _api_success(dict(group), "get_poller_group")

    # -- locations --------------------------------------------------------------------------------
    def _list_locations(self, r: _Req) -> FakeResponse:
        rows = [
            {"id": loc["id"], "location": loc["location"], "lat": _decimal(loc["lat"]), "lng": _decimal(loc["lng"]),
             "timestamp": _raw(loc["timestamp"]), "fixed_coordinates": loc["fixed_coordinates"]}
            for loc in self.tables["locations"].values()
            if loc["location"] is not None
        ]  # fmt: skip
        if not rows:
            return _api_error(404, "Locations do not exist")
        return _api_success(rows, "locations", array=True)

    def _get_location(self, r: _Req) -> FakeResponse:
        loc = self._location(r.args["location_id_or_name"])
        if loc is None:
            return _api_error(404, "Location does not exist")
        return _api_success(_location_model(loc), "get_location")

    def _add_location(self, r: _Req) -> FakeResponse:
        data = r.array()
        if data is None or any(_empty(data.get(k)) for k in ("location", "lat", "lng")):
            return _api_error(400, "Required fields missing (location, lat and lng needed)")
        name = _php_str(data["location"])[:255]
        if self._named("locations", "location", name) is not None:
            return _server_error()  # the unique index, with no validation before it
        lat, lng = round(_php_float(data["lat"]), 8), round(_php_float(data["lng"]), 8)
        fixed = data.get("fixed_coordinates")
        if fixed is None:
            fixed = bool(lat and lng and abs(lat) <= 90 and abs(lng) <= 180)
        loc = self.seed("locations", {"location": name, "lat": lat, "lng": lng, "fixed_coordinates": _tinyint(fixed)})
        return _api_success(message=f"Location added with id #{loc['id']}", code=201)

    def _edit_location(self, r: _Req) -> FakeResponse:
        loc = self._location(r.args["location_id_or_name"])
        if loc is None:
            return _api_error(400, "Failed to update location")
        data = r.all_input()
        update = {k: data[k] for k in ("location", "lat", "lng") if k in data}
        for k in ("lat", "lng"):
            if update.get(k) is not None:
                update[k] = round(_php_float(update[k]), 8)
        clash = self._named("locations", "location", update.get("location"))
        if clash is not None and clash is not loc:
            return _server_error()
        if any(loc[k] != v for k, v in update.items()):
            loc.update(update, timestamp=self._tick())
        return _api_success(message="Location updated successfully", code=201)

    def _del_location(self, r: _Req) -> FakeResponse:
        loc = self._location(r.args["location"])
        if loc is None:
            return _api_error(400, "Failed to delete  (Does not exists)")
        for d in self.tables["devices"].values():  # a query-builder update: no observer, no eventlog
            if d["location_id"] == loc["id"]:
                d["location_id"] = None
        del self.tables["locations"][loc["id"]]
        return _api_success(
            message=f"Location {_php_json(_location_model(loc))} has been deleted successfully", code=201
        )

    def _maintenance_location(self, r: _Req) -> FakeResponse:
        data = r.json_input()
        if not data:
            return _api_error(400, "No information has been provided to set this location into maintenance")
        if _empty(data.get("duration")):
            return _api_error(400, "Duration not provided")
        loc = self._location(r.args["location"])
        if loc is None:
            return _api_error(404, f"Location {r.args['location']} does not exist")
        title = data["title"] if data.get("title") is not None else loc["location"]
        saved = self._schedule(data, title, _php_str(data.get("notes")), locations=[loc["id"]])
        if saved is None:
            return _server_error()
        return _maintenance_answer(f"Location {loc['location']} ({loc['id']})", data, *saved)

    # -- device groups ----------------------------------------------------------------------------
    def _get_device_groups(self, r: _Req) -> FakeResponse:
        groups = sorted(self.tables["device_groups"].values(), key=lambda g: g["name"].lower())
        if not groups:
            return _api_error(404, "No device groups found")
        rows = [{k: copy.deepcopy(g[k]) for k in ("id", "name", "desc", "type", "rules", "pattern")} for g in groups]
        return _api_success(rows, "groups", f"Found {len(rows)} device groups", array=True)

    def _get_devices_by_group(self, r: _Req) -> FakeResponse:
        group = self._group(r.args["name"])
        if group is None:
            return _api_error(404, "Device group not found")
        members = [self.tables["devices"][i] for i in sorted(group["devices"]) if i in self.tables["devices"]]
        if not members:
            return _api_error(404, f"No devices found in group {r.args['name']}")
        if _truthy(r.params.get("full")):
            return _api_success([self._device_out(d) for d in members], "devices", array=True)
        return _api_success([{"device_id": d["device_id"]} for d in members], "devices", array=True)

    def _add_device_group(self, r: _Req) -> FakeResponse:
        data = r.array()
        if data is None:
            return _api_error(400, "We couldn't parse the provided json. " + _json_error(r.body))
        errors = self._group_errors(data, None)
        if errors:
            return _api_error(422, errors)
        rules = None
        if not _empty(data.get("rules")):
            rules = json.loads(data["rules"])
            if not _rule_sql(rules):
                return _api_error(500, "We couldn't parse your rule")
        group = self.seed("device_groups", {"name": data["name"], "type": data["type"], "desc": data.get("desc")})
        if data["type"] == "dynamic":
            group["rules"] = {**rules, "joins": []}  # the model's saving hook adds the joins
        elif not self._sync(group, data["devices"]):
            return _server_error()  # the group was saved before sync() failed on a device that does not exist
        return _api_success(group["id"], "id", f"Device group {group['name']} created", 201)

    def _sync(self, group: Dict[str, Any], wanted: List[Any]) -> bool:
        """``devices()->sync()``: detach what is not wanted, then attach the rest one by one, stopping (False) at a
        device that does not exist with what came before it already attached."""
        ids = [_php_int(i) for i in wanted]
        group["devices"] = [i for i in group["devices"] if i in ids]
        for device_id in ids:
            if device_id not in self.tables["devices"]:
                return False
            if device_id not in group["devices"]:
                group["devices"].append(device_id)
        return True

    def _update_device_group(self, r: _Req) -> FakeResponse:
        data = r.array()
        if data is None:
            return _api_error(400, "We couldn't parse the provided json. " + _json_error(r.body))
        group = self._group(r.args["name"])
        if group is None:
            return _api_error(404, f"Device group {r.args['name']} not found")
        errors = self._group_errors(data, group)
        if errors:
            return _api_error(422, errors)
        rules = json.loads(data["rules"]) if not _empty(data.get("rules")) else None
        if rules is not None and not _rule_sql(rules):
            return _api_error(500, "We couldn't parse your rule")
        filled = {**group, **{k: data[k] for k in ("name", "desc", "type") if k in data}}
        if filled["type"] == "static" and "devices" in data and not self._sync(group, data["devices"]):
            return _server_error()  # membership changed, name/desc/type not saved: sync() runs before save()
        group.update({k: filled[k] for k in ("name", "desc", "type")})
        if group["type"] == "dynamic" and rules is not None:
            group["rules"] = {**rules, "joins": []}
        return _api_success(message=f"Device group {r.args['name']} updated")

    def _group_errors(self, data: Dict[str, Any], group: Dict[str, Any] | None) -> Dict[str, List[str]]:
        """The handlers' Laravel validation; on update the name's unique rule does not leave out the group itself."""
        errors: Dict[str, List[str]] = {}
        name, kind = data.get("name"), data.get("type")
        if group is None and _blank(name):
            errors["name"] = ["The name field is required."]
        elif "name" in data and not isinstance(name, str):
            errors["name"] = ["The name field must be a string."]
        elif "name" in data and self._named("device_groups", "name", name) is not None:
            errors["name"] = ["The name has already been taken."]
        if group is not None and "desc" in data and not isinstance(data["desc"], str):
            errors["desc"] = ["The desc field must be a string."]
        if group is None and _blank(kind):
            errors["type"] = ["The type field is required."]
        elif "type" in data and kind not in ("dynamic", "static"):
            errors["type"] = ["The selected type is invalid."]
        if kind == "static" and "devices" not in data:
            errors["devices"] = ["The devices field must be present when type is static."]
        elif "devices" in data and not isinstance(data["devices"], list):
            errors["devices"] = ["The devices field must be an array."]
        elif "devices" in data:
            for i, value in enumerate(data["devices"]):
                if isinstance(value, bool) or not (isinstance(value, int) or _digits(value)):
                    errors[f"devices.{i}"] = [f"The devices.{i} field must be an integer."]
        if kind == "dynamic" and _empty(data.get("rules")):
            errors["rules"] = ["The rules field is required when type is dynamic."]
        elif data.get("rules") is not None and not _json_string(data["rules"]):
            errors["rules"] = ["The rules field must be a valid JSON string."]
        return errors

    def _delete_device_group(self, r: _Req) -> FakeResponse:
        group = self._group(r.args["name"])
        if group is None:
            return _api_error(404, f"Device group {r.args['name']} not found")
        del self.tables["device_groups"][group["id"]]  # alert_group_map has no foreign key: rule mappings stay
        return _api_success(message=f"Device group {r.args['name']} deleted")

    def _maintenance_devicegroup(self, r: _Req) -> FakeResponse:
        data = r.json_input()
        if not data:
            return _api_error(400, "No information has been provided to set this device into maintenance")
        group = self._group(r.args["name"])
        if group is None:
            return _api_error(404, f"Device group {r.args['name']} not found")
        if _empty(data.get("duration")):
            return _api_error(400, "Duration not provided")
        title = data["title"] if data.get("title") is not None else group["name"]
        saved = self._schedule(data, title, _php_str(data.get("notes")), device_groups=[group["id"]])
        if saved is None:
            return _server_error()
        return _maintenance_answer(f"Device group {group['name']} ({group['id']})", data, *saved)

    # -- services ---------------------------------------------------------------------------------
    def _list_services(self, r: _Req) -> FakeResponse:
        state, ref = r.params.get("state"), r.args.get("hostname")
        if state is not None and not _numeric(state):
            return _api_error(400, "No valid service state provided, valid option is 0=Ok, 1=Warning, 2=Critical")
        device_id = int(ref) if _digits(ref) else None
        if ref is not None and device_id is None:
            d = self._by_hostname(ref)
            if d is None:
                return _api_error(500, "No valid hostname or device id provided")
            device_id = d["device_id"]
        rows = [{k: s[k] for k in _SERVICE_COLUMNS} for s in self.tables["services"].values()]
        if state is not None:
            rows = [s for s in rows if s["service_status"] == _php_float(state)]
            rows = [
                s for s in rows if not s["service_disabled"] and not s["service_ignore"]
            ]  # a state filter adds these
        if "type" in r.params:
            rows = [s for s in rows if _like(s["service_type"], r.params["type"])]
        if device_id is not None:
            rows = [s for s in rows if s["device_id"] == device_id]
        rows.sort(key=lambda s: _sort_key(s["service_ip"]))
        return _api_success([rows], "services", array=True)  # "double array for backwards compat"

    def _add_service_for_host(self, r: _Req) -> FakeResponse:
        ref = r.args["hostname"]
        d = self._device(ref)
        if d is None:
            return _api_error(404, f"Device {ref} not found")
        data = r.array()
        if data is None or _empty(data.get("type")):
            return _api_error(400, "Required fields missing (hostname and type needed)")
        if data["type"] not in self.service_types:
            available = ", ".join(self.service_types)
            return _api_error(400, f"The service {data['type']} does not exist.\n Available service types: {available}")
        if data.get("ip") is None or isinstance(data["ip"], (dict, list)):
            return _server_error()  # addService(string $ip): a TypeError
        model = {
            "device_id": d["device_id"],
            "service_ip": _php_str(data["ip"]) or d["overwrite_ip"] or d["hostname"],
            "service_type": data["type"],
            "service_desc": _elvis(data.get("desc")),
            "service_param": _elvis(data.get("param")),
            "service_ignore": int(_truthy(data.get("ignore"))),
            "service_status": 3,
            "service_message": "Service not yet checked",
            "service_ds": "{}",
            "service_disabled": int(_truthy(data.get("disable"))),
            "service_template_id": 0,
            "service_name": _php_str(data.get("name")),
        }
        model["service_id"] = self.seed("services", dict(model))["service_id"]
        message = f"Service {data['type']} has been added to device {ref} (#{_php_json(model)})"
        return _api_success(message=message, code=201)

    def _edit_service_for_host(self, r: _Req) -> FakeResponse:
        ref, data = r.args["id"], r.body
        failed = _api_error(500, f"Failed to update the service with id {ref}")
        if not _numeric(ref):
            return failed
        if not isinstance(data, dict) or not data or any(k not in _SERVICE_COLUMNS for k in data):
            return _server_error()  # an empty SET, a non-object body or an unknown column fails in SQL
        service = self.tables["services"].get(_php_int(ref)) if _digits(ref) else None
        if service is None:
            return failed
        update = {k: _service_value(k, v) for k, v in data.items()}
        if all(service[k] == v for k, v in update.items()):
            return failed  # MySQL counts changed rows, so an edit that changes nothing "fails"
        old_id, new_id = service["service_id"], update.get("service_id", service["service_id"])
        if new_id != old_id and new_id in self.tables["services"]:
            return _server_error()  # rewriting the primary key onto another service
        service.update(update)
        self.tables["services"][new_id] = self.tables["services"].pop(old_id)
        return _api_success(message="Service updated successfully", code=201)

    def _del_service_from_host(self, r: _Req) -> FakeResponse:
        ref = r.args["id"]
        if _empty(ref):
            return _api_error(400, "No service_id has been provided to delete")
        if not _digits(ref) or int(ref) not in self.tables["services"]:
            return _api_error(500, "Failed to delete the service")
        del self.tables["services"][int(ref)]
        return _api_success(message="Service has been deleted successfully", code=201)

    # -- alert rules ------------------------------------------------------------------------------
    def _rule_out(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: copy.deepcopy(rule[k]) for k in _RULE_KEYS}
        operation = self.alert_operations.get(rule["alert_operation_id"])
        out["default_operation_step_duration_seconds"] = (
            operation["default_operation_step_duration_seconds"] if operation else None
        )
        out["operations"] = copy.deepcopy(operation["segments"]) if operation else []
        return out

    def _list_alert_rules(self, r: _Req) -> FakeResponse:
        ref = r.args.get("id")
        rules = sorted(self.tables["rules"].values(), key=lambda rule: rule["id"])
        if _truthy(ref):
            rules = [rule for rule in rules if _numeric(ref) and rule["id"] == _php_float(ref)]
        return _api_success([self._rule_out(rule) for rule in rules], "rules", array=True)

    def _add_edit_rule(self, r: _Req) -> FakeResponse:
        """``add_edit_rule``, behind both POST and PUT: ``rule_id`` alone decides create or edit, and every key the body
        leaves out is rebuilt (mappings emptied, ``disabled`` 0, ``extra`` from scratch), except the few that are
        written only when present."""
        data = r.array()
        if data is None:
            return _api_error(500, "We couldn't parse the provided json")
        rule_id = data.get("rule_id")
        devices_in = _php_list(data.get("devices"))
        if not devices_in and rule_id is None:
            return _api_error(400, "Missing the devices or global device (-1)")
        devices: List[int | None] = []
        for value in devices_in:
            if _numeric(value) and _php_float(value) == -1:  # "global"; LibreNMS drops it
                continue
            if isinstance(value, int) or _digits(value):
                devices.append(_php_int(value))
            else:  # getidbyname(): null for a hostname it does not know
                devices.append((self._by_hostname(_php_str(value)) or {}).get("device_id"))
        builder = data.get("builder")
        if builder is not None and not isinstance(builder, (dict, list)):
            builder = _json_or_none(_php_str(builder))
        elif builder is None:
            builder = data.get("rule")
        if _empty(builder):
            return _api_error(400, "Missing the alert builder rule")
        name = _strip_tags(_php_str(data.get("name")))
        if _empty(name):
            return _api_error(400, "Missing the alert rule name")
        if data.get("severity") not in ("ok", "warning", "critical"):
            return _api_error(400, "Missing the severity")
        override = data.get("override_query", False)
        extra: Dict[str, Any] = {"options": {"override_query": override}}
        extra.update({k: _filter_bool(data[k]) for k in ("invert", "recovery", "acknowledgement") if k in data})
        if override == "on" or override is True:
            query = data.get("adv_query")
        else:
            query = _rule_sql(builder)
            if not query:
                return _api_error(500, "We couldn't parse your rule")
        others = [rule for rule in self.tables["rules"].values() if _same(rule["name"], name)]
        if rule_id is None and others:
            return _api_error(500, "Addition failed : Name has already been used")
        if rule_id is not None and any(rule["id"] != _php_float(rule_id) for rule in others):
            return _api_error(500, "Update failed : Invalid rule id")
        save = {"name": name, "builder": builder, "query": query, "severity": data["severity"],
                "disabled": int(_loose_flag(data.get("disabled", 0))), "extra": extra,
                "notes": _strip_tags(_php_str(data.get("notes")))}  # fmt: skip
        if "alert_operation_id" in data:
            save["alert_operation_id"] = (
                None if data["alert_operation_id"] in (None, "") else _php_int(data["alert_operation_id"])
            )
        if "invert_map" in data:
            save["invert_map"] = int(_filter_bool(data["invert_map"]))
        if "proc" in data:
            save["proc"] = _strip_tags(_php_str(data["proc"]))[:80]  # varchar(80), truncated without strict mode
        if "notify_per_entity" in data:
            save["notify_per_entity"] = _filter_bool(data["notify_per_entity"])
        if "max_entities" in data:
            save["max_entities"] = (
                None if data["max_entities"] in (None, "") else max(1, _php_int(data["max_entities"]))
            )
        if _numeric(rule_id):
            rule = self.tables["rules"].get(_php_int(rule_id)) if _php_float(rule_id).is_integer() else None
            if rule is None:
                return _api_error(500, "Failed to update existing alert rule")
            rule.update(save)
        else:
            rule = self.seed("rules", save)
        if None in devices:  # an unknown hostname reaches sync() as null, after the rule was saved
            return _server_error()
        rule["devices"] = sorted(set(devices))
        rule["groups"] = sorted({_php_int(g) for g in _php_list(data.get("groups"))})
        rule["locations"] = sorted({_php_int(loc) for loc in _php_list(data.get("locations"))})
        return _api_success()

    def _delete_rule(self, r: _Req) -> FakeResponse:
        ref = r.args["id"]
        if not _numeric(ref):
            return _api_error(400, "Invalid rule id has been provided")
        rule = self.tables["rules"].get(int(ref)) if _digits(ref) else None
        if rule is None:
            return _api_success(message="No alert rule by that ID")
        del self.tables["rules"][rule["id"]]
        self._drop("faults", "rule_id", rule["id"])  # the model's deleting hook takes its alerts with it
        return _api_success(message="Alert rule has been removed")

    # -- faults -----------------------------------------------------------------------------------
    def _list_alerts(self, r: _Req) -> FakeResponse:
        states = {_php_float(s) for s in r.params.get("state", "1").split(",")}  # the default hides all but active
        ref, severity, rule_ref = r.args.get("id"), r.params.get("severity"), r.params.get("alert_rule")
        wanted = (int(ref) if _digits(ref) else 0) if _truthy(ref) else None
        rows = []
        for f in sorted(self.tables["faults"].values(), key=lambda f: (f["timestamp"], f["id"]), reverse=True):
            rule, d = self.tables["rules"].get(f["rule_id"]), self.tables["devices"].get(f["device_id"])
            if rule is None or d is None or f["state"] not in states:
                continue
            if wanted is not None and f["id"] != wanted:
                continue
            if severity in ("ok", "warning", "critical") and rule["severity"] != severity:
                continue
            if _numeric(rule_ref) and rule["id"] != _php_float(rule_ref):
                continue
            row = {"hostname": d["hostname"], **{k: copy.deepcopy(f[k]) for k in _FAULT_COLUMNS}}
            row["info"] = None if f["info"] is None else _php_json(f["info"])  # read with toBase(): the raw column
            row.update(severity=rule["severity"], name=rule["name"], proc=rule["proc"], notes=rule["notes"])
            rows.append(row)
        return _api_success(rows, "alerts", array=True)

    def _fault_targets(self, fault: Dict[str, Any]) -> List[Dict[str, Any]]:
        """``api_alert_fault_action_targets``: the fault alone while its rule notifies per entity and the open faults
        of its device and rule that are not recovered (state 0) number at most ``max_entities`` (at least 1;
        ``default_max_entities`` when null), as AlertUtil decides; else every open fault of that device and rule
        (whatever its state)."""
        rule = self.tables["rules"].get(fault["rule_id"])
        siblings = [
            f for f in self.tables["faults"].values()
            if f["device_id"] == fault["device_id"] and f["rule_id"] == fault["rule_id"] and f["open"] == 1
        ]  # fmt: skip
        if rule and rule["notify_per_entity"]:
            limit = self.default_max_entities if rule["max_entities"] is None else rule["max_entities"]
            if sum(f["state"] != 0 for f in siblings) <= max(1, limit):
                return [fault]
        return siblings

    def _note(self, target: Dict[str, Any], data: Dict[str, Any] | None) -> None:
        line = f"{_raw(self._tick())} - Ack ({self.username}) {_php_str((data or {}).get('note'))}"
        target["note"] = (target["note"] + "\n" if target["note"] else "") + line

    def _ack_alert(self, r: _Req) -> FakeResponse:
        ref, data = r.args["id"], r.array()
        if not _numeric(ref):
            return _api_error(400, "Invalid fault has been provided")
        fault = self.tables["faults"].get(int(ref)) if _digits(ref) else None
        targets = [] if fault is None else self._fault_targets(fault)
        for target in targets:
            self._note(target, data)
            target["info"] = {**(target["info"] or {}), "until_clear": (data or {}).get("until_clear")}
            target["state"] = 2
        return _api_success(message="Alert has been acknowledged" if targets else "No Alert by that ID")

    def _unmute_alert(self, r: _Req) -> FakeResponse:
        ref, data = r.args["id"], r.array()
        if not _numeric(ref):
            return _api_error(400, "Invalid fault has been provided")
        fault = self.tables["faults"].get(int(ref)) if _digits(ref) else None
        targets = [] if fault is None else self._fault_targets(fault)
        for target in targets:
            self._note(target, data)  # unmute writes its note as "Ack (...)" too, and leaves until_clear alone
            target["state"] = 1
        return _api_success(message="Alert has been unmuted" if targets else "No alert by that ID")

    # -- eventlog, ports ----------------------------------------------------------------------------
    def _list_logs(self, r: _Req) -> FakeResponse:
        """``list_logs`` behind eventlog, syslog and alertlog: a path hostname LibreNMS does not know filters
        nothing, ``from``/``to`` bound the id when numeric and the time otherwise, the order is ascending unless
        ``sortorder`` is exactly ``DESC``, and ``limit`` is cast with ``(int)`` (a negative one is no limit)."""
        table, timestamp, id_field = _LOGS[r.name]
        ref, p = r.args["hostname"], r.params
        device_id = self._device_ref(ref)
        rows = [e for e in self.tables[table].values() if device_id is None or e["device_id"] == device_id]
        for name, keep in (("from", lambda a, b: a >= b), ("to", lambda a, b: a <= b)):
            bound = p.get(name)
            if _truthy(bound):  # a number bounds the id, anything else the time text
                key = id_field if _numeric(bound) else timestamp
                rows = [e for e in rows if keep(e[key], _php_float(bound) if key == id_field else bound)]
        total = len(rows)
        rows.sort(key=lambda e: (e[timestamp], e[id_field]), reverse=p.get("sortorder") == "DESC")
        start, limit = max(0, _php_int(p.get("start", 0))), _php_int(p.get("limit", 50))
        rows = rows[start:] if limit < 0 else rows[start : start + limit]
        devices = self.tables["devices"]
        out = []
        for e in rows:
            d = devices.get(e["device_id"]) or {}
            row = {"hostname": d.get("hostname"), "sysName": d.get("sysName")}
            if table == "eventlog":  # "host" for backward compatibility
                row["host"] = e["device_id"]
            columns = {"eventlog": _EVENT_COLUMNS, "syslog": _SYSLOG_COLUMNS, "alert_log": _ALERT_LOG_COLUMNS}[table]
            out.append({**row, **{k: copy.deepcopy(e[k]) for k in columns}})  # alert_log details: decoded
        return _api_success(out, "logs", array=True, extra={"total": total})

    def _port(self, ref: str) -> Dict[str, Any] | None:
        """``Port::where('port_id', $id)``: MySQL reads a leading number from the text, so ``12abc`` is port 12."""
        match = re.match(r"\s*(\d+)", ref)
        return self.tables["ports"].get(int(match.group(1)) if match else 0)

    def _get_port_info(self, r: _Req) -> FakeResponse:
        """``get_port_info``: the port as a one-row list (none for an unknown id), deleted or not; ``with=statistics``
        adds its ports_statistics rows, ``with=vlans`` its ports_vlans rows, each that stores ``untagged`` 0 with the
        whole port under ``port``, which PortVlan's accessor loaded and nothing hides (``device``, which LibreNMS also
        allows, is not modelled)."""
        port = self._port(r.args["portid"])
        if port is None:
            return _api_success([], "port")
        row = {k: port[k] for k in _PORT_COLUMNS}
        if r.params.get("with") == "statistics":
            row["statistics"] = self._rows("ports_statistics", _PORT_STATISTICS_COLUMNS, port_id=port["port_id"])
        elif r.params.get("with") == "vlans":
            row["vlans"] = self._port_vlans(port, with_port=True)
        return _api_success([row], "port")

    def _get_port_transceiver(self, r: _Req) -> FakeResponse:
        """``Port::find($id)->transceivers()``: an unknown port is a null LibreNMS calls a method on, a 500."""
        port = self._port(r.args["portid"])
        if port is None:
            return _server_error()
        rows = self._rows("transceivers", _TRANSCEIVER_COLUMNS, port_id=port["port_id"])
        return _api_success(rows, "transceivers")

    def _get_port_description(self, r: _Req) -> FakeResponse:
        port = self._port(r.args["portid"])
        if port is None:
            return _api_error(400, "Invalid port ID.")
        return _api_success(port["ifAlias"], "port_description")  # a NULL ifAlias leaves the key out

    def _update_port_description(self, r: _Req) -> FakeResponse:
        port = self._port(r.args["portid"])
        if port is None:
            return _api_error(400, "Invalid port ID.")
        description = (r.array() or {}).get("description")
        if _empty(description):
            description = "repoll"  # also for a missing key or a body that is not JSON
        elif isinstance(description, (dict, list)):
            return _server_error()
        description = _php_str(description)
        port["ifAlias"] = description[:255]  # varchar(255), truncated without strict mode
        pins = self.attribs.setdefault(port["device_id"], {})
        if description == "repoll":
            pins.pop(f"ifName:{port['ifName']}", None)
            self._log(
                port["device_id"], f"{port['ifName']} Port ifAlias cleared via API", "interface", 3, port["port_id"]
            )
            return _api_success(message="Port description cleared.")
        pins[f"ifName:{port['ifName']}"] = 1
        self._log(
            port["device_id"],
            f"{port['ifName']} Port ifAlias set via API: {description}",
            "interface",
            3,
            port["port_id"],
        )
        return _api_success(message="Port description updated.")

    # -- report routes: read-only tables -----------------------------------------------------------
    def _device_ref(self, ref: str | None) -> int | None:
        """``ctype_digit($ref) ? $ref : getidbyname($ref)``: digits as an id (known or not), a hostname's id, else
        None, which the handlers read as no device filter at all."""
        if ref is None or ref == "":
            return None
        if _digits(ref):
            return int(ref)
        d = self._by_hostname(ref)
        return d["device_id"] if d else None

    def _rows(self, table: str, columns: Tuple[str, ...], **match: Any) -> List[Dict[str, Any]]:
        """*table*'s rows in id order as *columns*, those whose columns equal *match* (a None value matches all)."""
        rows = sorted(self.tables[table].values(), key=lambda row: row[_ID_KEYS.get(table, "id")])
        rows = [row for row in rows if all(row[key] == value for key, value in match.items() if value is not None)]
        return [{key: copy.deepcopy(row[key]) for key in columns} for row in rows]

    def _list_bgp(self, r: _Req) -> FakeResponse:
        """Sessions with a state; an unknown ``hostname`` filters nothing. Never a 404."""
        p = r.params
        rows = self._rows("bgp_peers", _BGP_COLUMNS, device_id=self._device_ref(p.get("hostname")))
        rows = [b for b in rows if b["bgpPeerState"] not in (None, "")]
        if _truthy(p.get("remote_asn")):
            asn = re.sub(r"[^0-9]", "", p["remote_asn"])
            rows = [b for b in rows if str(b["bgpPeerRemoteAs"]) == asn]
        if _truthy(p.get("bgp_descr")):
            rows = [b for b in rows if _like(b["bgpPeerDescr"], f"%{p['bgp_descr']}%")]
        for name, column in (("bgp_state", "bgpPeerState"), ("bgp_adminstate", "bgpPeerAdminStatus")):
            if _truthy(p.get(name)):
                rows = [b for b in rows if _same(b[column], p[name])]
        return _api_success(rows, "bgp_sessions", array=True)

    def _get_bgp(self, r: _Req) -> FakeResponse:
        ref = r.args["id"]
        if not _numeric(ref):
            return _api_error(400, "Invalid id has been provided")
        peer = self.tables["bgp_peers"].get(_php_int(ref)) if _php_float(ref).is_integer() else None
        if peer is None or peer["bgpPeerState"] in (None, ""):
            return _api_error(404, f"BGP peer {ref} does not exist")
        return _api_success([{k: peer[k] for k in _BGP_COLUMNS}], "bgp_session", array=True)

    def _list_ospf(self, r: _Req) -> FakeResponse:
        rows = self._rows("ospf_nbrs", _OSPF_COLUMNS, device_id=self._device_ref(r.params.get("hostname")))
        return _api_success([o for o in rows if o["ospfNbrState"] not in (None, "")], "ospf_neighbours", array=True)

    def _list_ospfv3(self, r: _Req) -> FakeResponse:
        """``DeviceCache::get($hostname)->device_id``: a device by id or hostname filters, one LibreNMS does not
        know (by id too) filters nothing; no neighbour with a state at all is LibreNMS's HTTP 500."""
        d = self._device(r.params.get("hostname"))
        rows = self._rows("ospfv3_nbrs", _OSPFV3_COLUMNS, device_id=d["device_id"] if d else None)
        rows = [o for o in rows if o["ospfv3NbrState"] not in (None, "")]
        if not rows:
            return _api_error(500, "Error retrieving ospfv3_nbrs")
        return _api_success(rows, "ospfv3_neighbours", array=True)

    def _list_health(self, r: _Req) -> FakeResponse:
        """``list_available_health_graphs``: without a type the device's sensor classes (of sensors not deleted, in
        sensor order) as ``device_<class>``, then processors, storage and memory pools when it has any; with a type
        (``device_`` stripped) the ``{sensor_id, desc}`` of each processor, storage volume, memory pool or sensor of
        that class not deleted; with a sensor_id that one's full row. An unknown device has none (no 404)."""
        d = self._device(r.args["hostname"]) or {"device_id": 0}
        kind = re.sub(r"^device_", "", r.args.get("type") or "") if r.args.get("type") is not None else None
        sensors = [row for row in self._rows("sensors", _SENSOR_COLUMNS, device_id=d["device_id"])
                   if not row["sensor_deleted"]]  # fmt: skip
        if kind is None:
            classes = list(dict.fromkeys(row["sensor_class"] for row in sensors))
            graphs = [{"desc": name[:1].upper() + name[1:], "name": f"device_{name}"} for name in classes]
            for name, label in (("processor", "Processors"), ("storage", "Storage"), ("mempool", "Memory Pools")):
                if self._rows(_HEALTH_KINDS[name][0], ("device_id",), device_id=d["device_id"]):
                    graphs.append({"desc": label, "name": f"device_{name}"})
            return _api_success(graphs, "graphs", array=True)
        if kind in _HEALTH_KINDS:
            table, columns, id_key, descr_key = _HEALTH_KINDS[kind]
            rows = self._rows(table, columns, device_id=d["device_id"])
        else:
            columns, id_key, descr_key = _SENSOR_COLUMNS, "sensor_id", "sensor_descr"
            rows = [row for row in sensors if row["sensor_class"] == kind]
        sensor_id = r.args.get("sensor_id")
        if sensor_id not in (None, "", "0"):  # PHP's truthiness
            return _api_success([row for row in rows if str(row[id_key]) == sensor_id], "graphs", array=True)
        return _api_success([{"sensor_id": row[id_key], "desc": row[descr_key]} for row in rows], "graphs", array=True)

    def _get_port_groups(self, r: _Req) -> FakeResponse:
        groups = sorted(self.tables["port_groups"].values(), key=lambda g: g["name"].lower())
        if not groups:
            return _api_error(404, "No port groups found")
        rows = [{k: g[k] for k in ("id", "name", "desc")} for g in groups]
        return _api_success(rows, "groups", f"Found {len(rows)} port groups", array=True)

    def _get_ports_by_group(self, r: _Req) -> FakeResponse:
        ref = r.args["name"]
        groups = self.tables["port_groups"]
        group = groups.get(int(ref)) if _digits(ref) else self._named("port_groups", "name", ref)
        if group is None:
            return _api_error(404, "Port group not found")
        ports = [self.tables["ports"][i] for i in sorted(group["ports"]) if i in self.tables["ports"]]
        if not ports:
            return _api_error(404, f"No ports found in group {ref}")
        columns = _PORT_COLUMNS if _truthy(r.params.get("full")) else ("port_id",)
        return _api_success([{k: port[k] for k in columns} for port in ports], "ports", array=True)

    def _device_availability(self, r: _Req) -> FakeResponse:
        """An Eloquent collection (no ``count``), shortest period first; an unknown device has none."""
        device_id = self._device_ref(r.args["hostname"])
        rows = sorted(self._rows("availability", ("duration", "availability_perc"), device_id=device_id or 0),
                      key=lambda a: a["duration"])  # fmt: skip
        return _api_success(rows, "availability")

    def _device_outages(self, r: _Req) -> FakeResponse:
        """An Eloquent collection (no ``count``), the latest outage first; ``going_down`` and ``up_again`` are unix
        seconds, ``up_again`` null while the device is down."""
        device_id = self._device_ref(r.args["hostname"])
        rows = sorted(self._rows("outages", ("going_down", "up_again"), device_id=device_id or 0),
                      key=lambda o: o["going_down"], reverse=True)  # fmt: skip
        return _api_success(rows, "outages")

    def _get_vlans(self, r: _Req) -> FakeResponse:
        d = self._device(r.args["hostname"])
        if d is None:
            return _api_error(404, f"Device {r.args['hostname']} not found")
        return _api_success(self._rows("vlans", _VLAN_COLUMNS[2:], device_id=d["device_id"]), "vlans", array=True)

    def _list_links(self, r: _Req) -> FakeResponse:
        """Both link routes; an unknown hostname filters nothing."""
        device_id = self._device_ref(r.args.get("hostname"))
        rows = self._rows("links", _LINK_COLUMNS, local_device_id=device_id)
        if not rows:
            return _api_error(404, "Links do not exist")
        return _api_success(rows, "links", array=True)

    def _get_link(self, r: _Req) -> FakeResponse:
        ref = r.args["id"]
        if not _numeric(ref):
            return _api_error(400, "Invalid id has been provided")
        link = self.tables["links"].get(_php_int(ref)) if _php_float(ref).is_integer() else None
        if link is None:
            return _api_error(404, f"Link {ref} does not exist")
        return _api_success([{k: link[k] for k in _LINK_COLUMNS}], "link", array=True)

    def _get_fdb(self, r: _Req) -> FakeResponse:
        d = self._device(r.args["hostname"])
        if d is None:
            return _api_error(404, f"Device {r.args['hostname']} not found")
        return _api_success(self._rows("ports_fdb", _FDB_COLUMNS, device_id=d["device_id"]), "ports_fdb")

    def _get_transceivers(self, r: _Req) -> FakeResponse:
        d = self._device(r.args["hostname"])  # DeviceCache hands an unknown device over empty: no rows, no 404
        rows = self._rows("transceivers", _TRANSCEIVER_COLUMNS, device_id=d["device_id"] if d else 0)
        return _api_success(rows, "transceivers")

    def _get_components(self, r: _Req) -> FakeResponse:
        """``getComponents($device_id)[$device_id]``: an object keyed by component id, each its type, label, status,
        ignore, disabled and error, then its preferences. Every query param is an equality filter (``label`` a
        LIKE). A device without components is a missing key, which PHP reads as null: no ``components`` at all."""
        device_id = self._device_ref(r.args["hostname"])
        found = {}
        for c in sorted(self.tables["components"].values(), key=lambda c: c["id"]):
            row = {**{k: c[k] for k in _COMPONENT_COLUMNS}, **c["prefs"]}
            wanted = all(
                _like(row.get(k), v) if k == "label" else _same(str(row.get(k)), v) for k, v in r.params.items()
            )
            if c["device_id"] == device_id and wanted:
                found[str(c["id"])] = row
        return _api_success(found or None, "components", array=bool(found))

    def _search_ports(self, r: _Req) -> FakeResponse:
        """``search_ports``: with only ``{field}`` given it is the search term over ifAlias, ifDescr and ifName; else a
        list of the columns to search. Both lists are checked trimmed and used as sent."""
        field, search = r.args["field"], r.args.get("search")
        if _empty(search):
            field, search = search, field
        columns = _columns(r.params.get("columns"), ("device_id", "port_id", "ifIndex", "ifName", "ifAlias"))
        fields = _columns(field, ("ifAlias", "ifDescr", "ifName"))
        for checked in (columns, fields):
            if isinstance(checked, FakeResponse):
                return checked
        ports = [p for p in self.tables["ports"].values() if not p["deleted"]]
        ports = [p for p in ports if any(_like(p[f], f"%{search}%") for f in fields)]
        if not ports:
            return _api_error(404, "No ports found")
        ports.sort(key=lambda p: _sort_key(p["ifName"]))
        return _api_success([{c: p[c] for c in columns} for p in ports], "ports")

    def _search_mac(self, r: _Req) -> FakeResponse:
        """``search_by_mac``: the ports that learned the MAC, fewest FDB entries first (the likely edge port);
        ``filter=first`` returns that port alone, as an object."""
        mac = _mac_hex(r.args["search"])
        if not re.fullmatch(r"[0-9a-f]{12}", mac):
            return _api_error(422, {"macAddress": ["The mac address field format is invalid."]})
        fdb = list(self.tables["ports_fdb"].values())
        ports = sorted({f["port_id"] for f in fdb if f["mac_address"] == mac} & set(self.tables["ports"]))
        rows = [
            {
                **{k: self.tables["ports"][i][k] for k in _PORT_COLUMNS},
                "fdb_entries_count": sum(f["port_id"] == i for f in fdb),
            }
            for i in ports
        ]
        if not rows:
            return _api_error(404, "mac not found")
        rows.sort(key=lambda row: row["fdb_entries_count"])
        if r.params.get("filter") == "first":
            return _api_success(rows[0], "ports")
        return _api_success(rows, "ports")

    def _get_all_ports(self, r: _Req) -> FakeResponse:
        columns = _columns(r.params.get("columns"), ("port_id", "ifName"))
        if isinstance(columns, FakeResponse):
            return columns
        ports = sorted((p for p in self.tables["ports"].values() if not p["deleted"]), key=lambda p: p["port_id"])
        return _api_success([{c: p[c] for c in columns} for p in ports], "ports")  # no 404 when empty

    def _list_bills(self, r: _Req) -> FakeResponse:
        """``list_bills`` behind ``bills`` and ``bills/{bill_id}``: ``custid``, then ``ref``, then a numeric id
        filter; a ``bill_id`` that is not a number filters nothing. CDR bills only, current period only."""
        ref, p = r.args.get("bill_id"), r.params
        bills = sorted(self.tables["bills"].values(), key=lambda b: b["bill_name"].lower())
        if _truthy(p.get("custid")):
            bills = [b for b in bills if _same(b["bill_custid"], p["custid"])]
        elif _truthy(p.get("ref")):
            bills = [b for b in bills if _same(b["bill_ref"], p["ref"])]
        elif _numeric(ref):
            bills = [b for b in bills if b["bill_id"] == _php_float(ref)]
        return _api_success([self._bill_out(b) for b in bills], "bills", array=True)

    def _bill_out(self, b: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: b[k] for k in _BILL_COLUMNS}
        cdr, rate = b["bill_cdr"] or 0, b["rate_95th"] or 0
        over = rate - cdr
        out.update(
            bill_allowed=cdr,
            allowed=_si(cdr) + "bps",
            used=_si(rate) + "bps",
            percent=round(rate / cdr * 100, 2) if cdr > 0 else "-",
            overuse="-" if over <= 0 else _si(over),
            ports=[
                {
                    "device_id": self.tables["ports"][i]["device_id"],
                    "port_id": i,
                    "ifName": self.tables["ports"][i]["ifName"],
                }
                for i in b["ports"]
                if i in self.tables["ports"]
            ],
        )
        return out

    def _list_fdb(self, r: _Req) -> FakeResponse:
        """``list_fdb``: ``{mac}`` is compared with the stored 12 hex digits as given, and an empty one (also
        ``0``) filters nothing."""
        mac = r.args.get("mac")
        rows = [f for f in self._rows("ports_fdb", _FDB_COLUMNS) if _empty(mac) or _same(f["mac_address"], mac)]
        if not rows:
            return _api_error(404, "Fdb entry does not exist")
        return _api_success(rows, "ports_fdb")

    def _list_fdb_detail(self, r: _Req) -> FakeResponse:
        """``list_fdb_detail``: the MAC parsed in any form, the newest entry first, and the MAC as LibreNMS writes it
        and its vendor as envelope extras."""
        mac = _mac_hex(r.args["mac"])
        if len(mac) != 12:
            return _api_error(422, "Invalid MAC address")
        entries = sorted(
            (f for f in self.tables["ports_fdb"].values() if f["mac_address"] == mac),
            key=lambda f: f["updated_at"],
            reverse=True,
        )
        if not entries:
            return _api_error(404, "Fdb entry does not exist")
        rows = []
        for f in entries:
            d, port = self.tables["devices"].get(f["device_id"]) or {}, self.tables["ports"].get(f["port_id"]) or {}
            seen = datetime.strptime(f["updated_at"], "%Y-%m-%dT%H:%M:%S.000000Z")
            rows.append({
                "hostname": d.get("hostname"), "sysName": d.get("sysName"), "ifName": port.get("ifName"),
                "ifAlias": port.get("ifAlias"), "ifDescr": port.get("ifDescr"), "updated_at": _raw(seen),
                "last_seen": _ago(self.now - seen),
            })  # fmt: skip
        readable = ":".join(mac[i : i + 2] for i in range(0, 12, 2))
        extra = {"mac": readable, "mac_oui": self.oui.get(mac[:6], "")}
        return _api_success(rows, "ports_fdb", array=True, extra=extra)

    def _list_nac(self, r: _Req) -> FakeResponse:
        mac = r.args.get("mac")
        rows = [n for n in self._rows("ports_nac", _NAC_COLUMNS) if _empty(mac) or _same(n["mac_address"], mac)]
        if not rows:
            return _api_error(404, " Nac entry does not exist")  # the leading blank is LibreNMS's
        return _api_success(rows, "ports_nac")

    def _list_arp(self, r: _Req) -> FakeResponse:
        """``list_arp``: ``all`` (``device`` narrows it; an unknown device is no rows), a network with ``{cidr}``, a
        MAC as ``FILTER_VALIDATE_MAC`` takes it, else one IPv4 address exactly."""
        query, cidr, p = r.args["query"], r.args.get("cidr"), r.params
        if _empty(query):
            return _api_error(400, "No valid IP/MAC provided")
        rows = self._rows("ipv4_mac", _ARP_COLUMNS)
        if query == "all":
            if "device" in p:
                d = self._device(p["device"])
                if d is None:
                    return _api_success([], "arp")
                rows = [a for a in rows if a["device_id"] == d["device_id"]]
        elif cidr:
            try:
                network = ipaddress.IPv4Network(f"{query}/{cidr}", strict=False)
            except ValueError:
                return _api_error(400, "Invalid Network Address")
            rows = [a for a in rows if ipaddress.IPv4Address(a["ipv4_address"]) in network]
        elif _FILTER_MAC.fullmatch(query):
            rows = [a for a in rows if a["mac_address"] == _mac_hex(query)]
        else:
            rows = [a for a in rows if a["ipv4_address"] == query]
        return _api_success(rows, "arp")

    def _list_sensors(self, r: _Req) -> FakeResponse:
        """Every sensor the token may see: LibreNMS reads no filter on this route."""
        rows = self._rows("sensors", _SENSOR_COLUMNS)
        if not rows:
            return _api_error(404, "Sensors do not exist")
        return _api_success(rows, "sensors")

    def _list_vlans(self, r: _Req) -> FakeResponse:
        rows = self._rows("vlans", _VLAN_COLUMNS, device_id=self._device_ref(r.params.get("hostname")))
        rows = [v for v in rows if v["vlan_vlan"] is not None]
        if not rows:
            return _api_error(404, "VLANs do not exist")
        return _api_success(rows, "vlans", array=True)


_STATE_FILTERS = {
    "active": lambda d: not d["ignore"] and not d["disabled"],
    "ignored": lambda d: d["ignore"] and not d["disabled"],
    "up": lambda d: d["status"] and not d["ignore"] and not d["disable_notify"] and not d["disabled"],
    "down": lambda d: not d["status"] and not d["ignore"] and not d["disabled"],
    "disabled": lambda d: d["disabled"],
}
_HOSTNAME = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9])?|[0-9A-Fa-f:.]+")
_NUMERIC = re.compile(r"\s*[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\s*")
# PHP's FILTER_VALIDATE_MAC: six pairs joined by - or :, or three groups of four joined by dots.
_FILTER_MAC = re.compile(
    r"(?:[0-9A-Fa-f]{2}([-:]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"
)
# list_logs per route: (table, time column, id column).
_LOGS = {
    "list_eventlog": ("eventlog", "datetime", "event_id"),
    "list_syslog": ("syslog", "timestamp", "seq"),
    "list_alertlog": ("alert_log", "time_logged", "id"),
}


def _compile(template: str, rest: str | None = None) -> re.Pattern[str]:
    """A Laravel route template as a regex over the decoded path: ``{x}`` is one segment, ``{x?}`` may be absent, and
    the parameter *rest* (``->where(x, '.*')``) takes the rest of the path, slashes included."""
    pattern = ""
    for segment in template.split("/"):
        param = re.fullmatch(r"\{(\w+)(\??)\}", segment)
        value = "" if param is None else f"(?P<{param.group(1)}>{'.+' if param.group(1) == rest else '[^/]+'})"
        if param and param.group(2):
            pattern += f"(?:/{value})?"
            continue
        pattern += ("/" if pattern else "") + (value if param else re.escape(segment))
    return re.compile(pattern)


def _columns(raw: str | None, default: Tuple[str, ...]) -> List[str] | FakeResponse:
    """``validate_column_list`` over the ports table, then the query that uses the list: the names are checked trimmed
    (an unknown one is a 400) but selected as sent, so a blank around one fails in SQL (a 500)."""
    if raw is None or raw == "":
        return list(default)
    names = raw.split(",")
    invalid = [name.strip() for name in names if name.strip() not in _PORT_COLUMNS]
    if invalid:
        return _api_error(400, "Invalid columns: " + ",".join(invalid))
    if any(name != name.strip() for name in names):
        return _server_error()
    return names


def _mac_hex(text: str) -> str:
    """``Mac::parse($text)->hex()``: the 12 lowercase hex digits of a MAC in any usual form (groups of one digit
    padded), or ``""``."""
    groups = re.split(r"[:-]", text.strip())
    if len(groups) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", g) for g in groups):
        return "".join(g.zfill(2) for g in groups).lower()
    bare = text.strip().replace(".", "")
    return bare.lower() if re.fullmatch(r"[0-9A-Fa-f]{12}", bare) else ""


def _si(value: float) -> str:
    """``Number::formatSi($value, 2, 0, '')``: the value in steps of 1000 with its prefix."""
    value, prefix = float(value), ""
    for unit in ("k", "M", "G", "T"):
        if value < 1000:
            break
        value, prefix = value / 1000, unit
    return f"{round(value, 2):g} {prefix}"


def _ago(delta: timedelta) -> str:
    """Carbon's ``diffForHumans`` for a time in the past."""
    seconds = int(delta.total_seconds())
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute"), (1, "second")):
        if seconds >= size:
            count = seconds // size
            return f"{count} {unit}{'s' if count != 1 else ''} ago"
    return "0 seconds ago"


def _token(headers: Headers) -> str | None:
    """``X-Auth-Token`` wins even when empty; ``Authorization: Bearer`` counts only without it."""
    if "X-Auth-Token" in headers:
        return headers["X-Auth-Token"]
    auth = headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else None


def _param(value: Any) -> str:
    """A query value as PHP receives it from ``requests``: a list repeats the key, and PHP keeps the last one."""
    if isinstance(value, (list, tuple)):
        value = value[-1] if value else ""
    return str(value)


def _maintenance_answer(subject: str, data: Dict[str, Any], duration: Any, start: Any) -> FakeResponse:
    when = f"will begin maintenance mode at {start}" if data.get("start") is not None else "moved into maintenance mode"
    suffix = f" for {_php_str(duration)}h" if _truthy(duration) else ""
    return _api_success(message=f"{subject} {when}{suffix}", code=201)


def _location_model(loc: Dict[str, Any]) -> Dict[str, Any]:
    """A Location serialised by Eloquent: float coordinates, a bool, an ISO-8601 UTC timestamp."""
    return {"id": loc["id"], "location": loc["location"], "lat": loc["lat"], "lng": loc["lng"],
            "timestamp": _iso(loc["timestamp"]), "fixed_coordinates": bool(loc["fixed_coordinates"])}  # fmt: skip


def _display(d: Dict[str, Any]) -> str:
    values = {"hostname": d["hostname"], "sysName": d["sysName"], "sysName_fallback": d["sysName"] or d["hostname"],
              "ip": d["ip"]}  # fmt: skip
    template = d["display_template"] or "{{ $sysName_fallback }}"
    return re.sub(r"\{\{\s*\$(\w+)\s*\}\}", lambda m: _php_str(values.get(m.group(1))), template)


def _rule_sql(builder: Any) -> str:
    """``QueryBuilderParser::fromJson($builder)->toSql()``: SQL for a builder with a condition and at least one rule,
    else ``""`` (which the handlers answer with "We couldn't parse your rule")."""
    if isinstance(builder, str):
        builder = _json_or_none(builder)
    where = _where(builder) if isinstance(builder, dict) and builder.get("condition") in ("AND", "OR") else ""
    return f"SELECT * FROM devices WHERE {where}" if where else ""


def _where(group: Dict[str, Any]) -> str:
    terms = []
    for rule in group.get("rules") or []:
        if isinstance(rule, dict) and "rules" in rule:
            terms.append(f"({_where(rule)})")
        elif isinstance(rule, dict) and rule.get("field"):
            terms.append(f"{rule['field']} {rule.get('operator', 'equal')} {json.dumps(rule.get('value'))}")
    return f" {group.get('condition', 'AND')} ".join(terms)


def _service_value(column: str, value: Any) -> Any:
    """A value as the ``services`` column stores it (no strict mode: a non-number in an int column is 0)."""
    if column in _SERVICE_INTS:
        return _tinyint(value)
    if value is None:
        return "" if column == "service_type" else None
    return _php_str(value)


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, str):
        return value.strip() or None
    return value


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def _raw(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _decimal(value: float | None) -> str | None:
    return None if value is None else f"{value:.8f}"


def _sort_key(value: Any) -> Tuple[bool, Any]:
    return (value is not None, value.lower() if isinstance(value, str) else value)


def _same(a: Any, b: Any) -> bool:
    """Equality under MySQL's case-insensitive ``utf8mb4_unicode_ci`` collation."""
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()


def _like(value: Any, pattern: str) -> bool:
    """SQL ``LIKE``: ``%`` and ``_`` are wildcards (LibreNMS never escapes them), case-insensitive."""
    if value is None:
        return False
    regex = "".join(".*" if c == "%" else "." if c == "_" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, str(value), re.I | re.S) is not None


def _digits(value: Any) -> bool:
    """PHP ``ctype_digit``: a non-empty string of ASCII digits."""
    return isinstance(value, str) and re.fullmatch(r"[0-9]+", value) is not None


def _numeric(value: Any) -> bool:
    """PHP ``is_numeric``."""
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float)) or (isinstance(value, str) and _NUMERIC.fullmatch(value) is not None)


def _empty(value: Any) -> bool:
    """PHP ``empty()``: null, false, 0, ``""``, ``"0"`` and empty arrays."""
    if isinstance(value, (dict, list)):
        return not value
    return value in (None, False, 0, "", "0")


def _truthy(value: Any) -> bool:
    return not _empty(value)


def _blank(value: Any) -> bool:
    """What Laravel's ``required`` rule rejects."""
    return value is None or (isinstance(value, str) and not value.strip()) or value == []


def _php_int(value: Any) -> int:
    """PHP ``(int)``: the leading number of a string, 0 for anything without one."""
    if isinstance(value, (bool, int, float)):
        return int(value)
    match = re.match(r"\s*[+-]?\d+", value) if isinstance(value, str) else None
    return int(match.group(0)) if match else 0


def _php_float(value: Any) -> float:
    if isinstance(value, (bool, int, float)):
        return float(value)
    match = re.match(r"\s*[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", value) if isinstance(value, str) else None
    return float(match.group(0)) if match else 0.0


def _elvis(value: Any) -> str:
    """PHP ``$value ?: ''``: every empty value, ``"0"`` and ``0`` included, becomes ``""``."""
    return "" if _empty(value) else _php_str(value)


def _php_str(value: Any) -> str:
    """PHP string interpolation: null is ``""``, true ``"1"``, false ``""``, an array ``"Array"``."""
    if value is None or value is False:
        return ""
    if value is True:
        return "1"
    if isinstance(value, (dict, list)):
        return "Array"
    return str(value)


def _php_list(value: Any) -> List[Any]:
    """PHP ``(array)``: null is empty, a scalar a one-element list, an object its values."""
    if value is None:
        return []
    if isinstance(value, dict):
        return list(value.values())
    return list(value) if isinstance(value, list) else [value]


def _php_json(value: Any) -> str:
    """``json_encode`` without flags: compact, with ``/`` escaped."""
    return json.dumps(value, separators=(",", ":")).replace("/", "\\/")


def _tinyint(value: Any) -> int:
    """How MySQL without strict mode stores a value in a tinyint: numbers as numbers, any other text as 0."""
    if isinstance(value, str):
        return _php_int(value) if _numeric(value) else 0
    return 0 if value is None or isinstance(value, (dict, list)) else int(value)


def _filter_bool(value: Any) -> bool:
    """``filter_var($v, FILTER_VALIDATE_BOOLEAN)``: true only for 1, ``"1"``, ``"true"``, ``"on"``, ``"yes"``."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return isinstance(value, str) and value.strip().lower() in ("1", "true", "on", "yes")


def _loose_flag(value: Any) -> bool:
    """``add_edit_rule``'s ``disabled``: kept when it equals ``'1'`` loosely, else 0."""
    if isinstance(value, bool):
        return value
    return (isinstance(value, (int, float)) and value == 1) or (
        isinstance(value, str) and _numeric(value) and float(value) == 1
    )


def _strip_tags(text: str) -> str:
    return re.sub(r"<[^>]*>?", "", text)


def _json_or_none(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _json_string(value: Any) -> bool:
    """Laravel's ``json`` rule: a string holding valid JSON."""
    if not isinstance(value, str):
        return False
    try:
        json.loads(value)
    except ValueError:
        return False
    return True


def _json_error(body: Any) -> str:
    """``json_last_error_msg()`` after the body was decoded: valid JSON that is not an array decoded without error."""
    return "Syntax error" if body is None else "No error"


def seeded() -> FakeLibreNMS:
    """A small, realistic LibreNMS: four devices (one SNMPv3, two that override sysLocation, one disabled without a
    location), three locations (one unused), a static and a dynamic device group, three services (one with a password
    in its parameters, one from a template), a global rule saved by the UI that does not notify per entity and a
    scoped one that does, their faults (two open siblings on one device, one cleared), ports with descriptions (one
    pinned, one deleted), a poller group, an alert operation and eventlog rows."""
    fake = FakeLibreNMS()
    for row in (
        {"id": 1, "location": "SFO-1", "lat": 37.6213, "lng": -122.379, "fixed_coordinates": 1},
        {"id": 2, "location": "NYC-2", "lat": 40.7128, "lng": -74.006, "fixed_coordinates": 0},
        {"id": 3, "location": "LON-3", "lat": 51.5074, "lng": -0.1278, "fixed_coordinates": 1},
    ):
        fake.seed("locations", row)
    fake.seed("poller_groups", {"id": 1, "group_name": "core-pollers", "descr": "Pollers in the core sites"})
    for row in (
        {"device_id": 1, "hostname": "core-sw1.example.net", "sysName": "core-sw1", "ip": "192.0.2.1",
         "community": "c0re-Community!", "location_id": 1, "override_sysLocation": 1, "os": "ios",
         "hardware": "WS-C3850-48T", "version": "16.12.4", "serial": "FOC1234X0AB", "purpose": "core",
         "notes": "", "sysDescr": "Cisco IOS Software, Catalyst L3 Switch", "uptime": 8640000,
         "last_polled": "2026-10-28T11:55:02.000000Z", "last_discovered": "2026-10-28T06:00:11.000000Z"},
        {"device_id": 2, "hostname": "edge-rtr1.example.net", "sysName": "edge-rtr1", "ip": "198.51.100.2",
         "overwrite_ip": "198.51.100.2", "snmpver": "v3", "authlevel": "authPriv", "authname": "nms-v3",
         "authpass": "Auth-S3cret-v3", "authalgo": "SHA-256", "cryptopass": "Priv-S3cret-v3", "cryptoalgo": "AES-256",
         "location_id": 1, "os": "iosxe", "hardware": "ISR4451-X/K9", "purpose": "edge", "poller_group": 1,
         "display_template": "{{ $sysName }}", "last_discovered": "2026-10-28T06:01:40.000000Z", "uptime": 4320000},
        {"device_id": 3, "hostname": "access-sw2.example.net", "sysName": "access-sw2", "ip": "192.0.2.12",
         "community": "acc3ss-Community", "location_id": 2, "override_sysLocation": 1, "os": "ios",
         "purpose": "access", "notes": "rack B4", "uptime": 1200000},
        {"device_id": 4, "hostname": "lab-fw1.example.net", "sysName": "lab-fw1", "ip": "203.0.113.4",
         "community": "lab-Community", "os": "asa", "type": "firewall", "disabled": 1, "status": 0,
         "purpose": "lab", "notes": "decommission after Q4"},
    ):  # fmt: skip
        fake.seed("devices", row)
    fake.seed(
        "device_groups",
        {"id": 1, "name": "core-switches", "desc": "Core layer switches", "type": "static", "devices": [1]},
    )
    edge = {"condition": "AND", "valid": True, "rules": [
        {"id": "devices.hostname", "field": "devices.hostname", "type": "string", "input": "text",
         "operator": "begins_with", "value": "edge-"}]}  # fmt: skip
    fake.seed(
        "device_groups",
        {"id": 2, "name": "edge-routers", "type": "dynamic", "rules": {**edge, "joins": []}, "devices": [2]},
    )
    for row in (
        {"service_id": 1, "device_id": 1, "service_ip": "192.0.2.1", "service_type": "http", "service_desc": "Web UI",
         "service_param": "-u /health -t 10", "service_status": 0, "service_changed": 1761600000,
         "service_message": "HTTP OK: HTTP/1.1 200 OK", "service_ds": '{"time":"s","size":"B"}',
         "service_name": "core-web"},
        {"service_id": 2, "device_id": 3, "service_ip": "access-sw2.example.net", "service_type": "http",
         "service_desc": "Intranet login", "service_param": "-H intranet.example.net -a monitor:Sup3rS3cret!",
         "service_status": 1, "service_message": "HTTP WARNING: slow response", "service_name": "intranet"},
        {"service_id": 3, "device_id": 1, "service_ip": "192.0.2.1", "service_type": "icmp", "service_status": 0,
         "service_message": "OK - 192.0.2.1 rta 0.4ms", "service_template_id": 2, "service_name": "ping"},
    ):  # fmt: skip
        fake.seed("services", row)
    fake.alert_operations[1] = {
        "id": 1, "name": "NOC on-call", "default_operation_step_duration_seconds": 300,
        "notifications_suppressed": False,
        "segments": [{"id": 1, "position": 0, "operation_phase": "problem", "escalation_step_from": 1,
                      "escalation_step_to": None, "start_in_seconds": 0, "step_duration_seconds": 0,
                      "transports": [{"id": "3", "text": "Mail: NOC"}]}],
    }  # fmt: skip
    port_down = {"condition": "AND", "valid": True, "rules": [
        {"id": "ports.ifOperStatus", "field": "ports.ifOperStatus", "type": "string", "input": "text",
         "operator": "equal", "value": "down"}]}  # fmt: skip
    high_cpu = {"condition": "AND", "valid": True, "rules": [
        {"id": "processors.processor_usage", "field": "processors.processor_usage", "type": "integer",
         "input": "number", "operator": "greater", "value": "90"}]}  # fmt: skip
    fake.seed("rules", {
        "id": 1, "name": "Port down", "severity": "warning", "builder": port_down, "alert_operation_id": 1,
        "extra": {"invert": False, "acknowledgement": True, "recovery": True, "mute": False,
                  "options": {"override_query": False}},  # as the UI saves it: mute is written true or false
        "proc": "https://wiki.example.net/runbooks/port-down", "notes": "Page the NOC for core links",
    })  # fmt: skip
    fake.seed("rules", {
        "id": 2, "name": "High CPU", "severity": "critical", "builder": high_cpu, "alert_operation_id": 1,
        "notify_per_entity": True, "devices": [1], "groups": [1],
    })  # fmt: skip
    # entity_type is the morph name AppServiceProvider gives the entity's model: "interface" for a Port
    for row in (
        {"id": 1, "rule_id": 1, "device_id": 2, "entity_type": "interface", "entity_id": 5, "entity_key": "port:5",
         "state": 1, "timestamp": "2026-10-28 10:02:00", "details": {"rule": [{"port_id": 5, "ifName": "Gi0/0/0"}]}},
        {"id": 2, "rule_id": 1, "device_id": 2, "entity_type": "interface", "entity_id": 6, "entity_key": "port:6",
         "state": 2, "timestamp": "2026-10-28 09:10:00", "info": {"until_clear": False},
         "note": "2026-10-28 09:15:00 - Ack (alice) carrier ticket 4411"},
        {"id": 3, "rule_id": 1, "device_id": 3, "entity_type": "interface", "entity_id": 9, "entity_key": "port:9",
         "state": 1, "timestamp": "2026-10-28 08:30:00"},
        {"id": 4, "rule_id": 2, "device_id": 1, "state": 1, "timestamp": "2026-10-28 11:40:00"},
        {"id": 5, "rule_id": 2, "device_id": 1, "state": 0, "open": 0, "timestamp": "2026-10-27 22:00:00"},
    ):  # fmt: skip
        fake.seed("faults", {**row, "first_seen": row["timestamp"], "last_seen": row["timestamp"]})
    for row in (
        {"port_id": 1, "device_id": 1, "ifIndex": 1, "ifName": "Gi1/0/1", "ifDescr": "GigabitEthernet1/0/1",
         "ifAlias": "uplink to edge-rtr1", "ifOperStatus": "up", "ifAdminStatus": "up"},
        {"port_id": 2, "device_id": 1, "ifIndex": 2, "ifName": "Gi1/0/2", "ifDescr": "GigabitEthernet1/0/2",
         "ifAlias": "", "ifOperStatus": "down", "ifAdminStatus": "up"},
        {"port_id": 3, "device_id": 1, "ifIndex": 3, "ifName": "Gi1/0/3", "ifDescr": "GigabitEthernet1/0/3",
         "ifAlias": None, "deleted": 1},
        {"port_id": 5, "device_id": 2, "ifIndex": 1, "ifName": "Gi0/0/0", "ifDescr": "GigabitEthernet0/0/0",
         "ifAlias": "WAN: transit-a", "ifOperStatus": "down", "ifAdminStatus": "up"},
        {"port_id": 6, "device_id": 2, "ifIndex": 2, "ifName": "Gi0/0/1", "ifDescr": "GigabitEthernet0/0/1",
         "ifAlias": "WAN: transit-b", "ifOperStatus": "down", "ifAdminStatus": "up"},
        {"port_id": 9, "device_id": 3, "ifIndex": 48, "ifName": "Gi1/0/48", "ifDescr": "GigabitEthernet1/0/48",
         "ifAlias": "to core-sw1", "ifOperStatus": "up", "ifAdminStatus": "up"},
    ):  # fmt: skip
        fake.seed("ports", {**row, "ifType": "ethernetCsmacd", "ifSpeed": 1000000000, "poll_time": 1761652500})
    fake.attribs = {1: {"ifName:Gi1/0/1": 1}, 2: {"ifName:Gi0/0/0": 1, "ifName:Gi0/0/1": 1}}
    for row in (
        {"device_id": 1, "datetime": "2026-10-01 09:00:00", "message": "Device core-sw1.example.net has been created"},
        {"device_id": 1, "datetime": "2026-10-02 10:30:00", "type": "interface", "reference": 1, "username": "admin",
         "severity": 3, "message": "Gi1/0/1 Port ifAlias set via API: uplink to edge-rtr1"},
        {"device_id": 2, "datetime": "2026-10-03 08:00:00", "message": "Device edge-rtr1.example.net has been created"},
        {"device_id": 3, "datetime": "2026-10-04 08:00:00",
         "message": "Device access-sw2.example.net has been created"},
        {"device_id": 2, "datetime": "2026-10-20 14:05:00", "message": "Interface went down: Gi0/0/0",
         "type": "interface", "reference": 5, "severity": 4},
        {"device_id": 2, "datetime": "2026-10-27 23:59:59", "message": "version: 17.9.3 -> 17.9.4a", "severity": 3},
    ):  # fmt: skip
        fake.seed("eventlog", row)
    _seed_reports(fake)
    return fake


def _seed_reports(fake: FakeLibreNMS) -> None:
    """What the read-only report routes show: interface addresses (IPv4 and IPv6, for ``devices?type=ipv4|ipv6``), a
    port group, the uplink's discards (ports_statistics), LLDP/CDP links (one to an unmonitored neighbour), sensors
    (one past its limit, an optic), a transceiver, processors (one past its warning limit), a memory pool and a flash
    volume, NTP components, BGP sessions (one idle, one without a state), OSPF neighbours (no OSPFv3 ones),
    alert-log rows whose details carry contacts, syslog, VLANs and the trunk that carries them, a MAC
    learned on an access port and on the uplink, a NAC session, ARP entries, outages and availability, and two CDR
    bills (one over its commit)."""
    seed = fake.seed
    seed("port_groups", {"id": 1, "name": "uplinks", "desc": "Core and WAN uplinks", "ports": [1, 5, 6]})
    seed("ports_statistics", {"port_id": 1, "ifInDiscards": 120, "ifInDiscards_prev": 120, "ifInDiscards_delta": 0,
                              "ifInDiscards_rate": 0, "ifOutDiscards": 9042, "ifOutDiscards_prev": 9000,
                              "ifOutDiscards_delta": 42, "ifOutDiscards_rate": 0})  # fmt: skip
    seed("port_groups", {"id": 2, "name": "spare"})
    for row in (
        {"id": 1, "local_device_id": 1, "local_port_id": 1, "remote_hostname": "edge-rtr1", "protocol": "cdp",
         "remote_port": "GigabitEthernet0/0/2", "remote_device_id": 2, "remote_platform": "cisco ISR4451-X/K9"},
        {"id": 2, "local_device_id": 1, "local_port_id": 2, "remote_hostname": "access-sw2.example.net",
         "remote_port": "Gi1/0/48", "remote_device_id": 3, "remote_port_id": 9, "remote_version": "IOS 15.2(7)E"},
        {"id": 3, "local_device_id": 3, "local_port_id": 9, "remote_hostname": "core-sw1.example.net",
         "remote_port": "Gi1/0/2", "remote_device_id": 1, "remote_port_id": 2},
        {"id": 4, "local_device_id": 2, "local_port_id": 5, "remote_hostname": "transit-a-pe1",
         "remote_port": "xe-0/0/1", "remote_port_id": 0, "remote_platform": "Juniper MX204"},
    ):  # fmt: skip
        seed("links", row)
    for row in (
        {"sensor_id": 1, "device_id": 1, "sensor_class": "temperature", "sensor_type": "cisco-entity-sensor",
         "sensor_oid": ".1.3.6.1.4.1.9.9.91.1.1.1.1.4.1006", "sensor_index": "1006",
         "sensor_descr": "Chassis Temperature", "sensor_current": 41, "sensor_limit": 60, "sensor_limit_warn": 55,
         "sensor_limit_low": 0, "sensor_prev": 40, "group": "", "lastupdate": "2026-10-28 11:55:02"},
        {"sensor_id": 2, "device_id": 1, "sensor_class": "dbm", "sensor_type": "cisco-entity-sensor",
         "sensor_oid": ".1.3.6.1.4.1.9.9.91.1.1.1.1.4.1011", "sensor_index": "1011",
         "sensor_descr": "Gi1/0/1 Receive Power Sensor", "sensor_current": -3.2, "sensor_limit": 1,
         "sensor_limit_low": -14.4, "entPhysicalIndex": 1011, "entPhysicalIndex_measured": "ports",
         "lastupdate": "2026-10-28 11:55:02"},
        {"sensor_id": 3, "device_id": 2, "sensor_class": "voltage", "sensor_type": "cisco-entity-sensor",
         "sensor_oid": ".1.3.6.1.4.1.9.9.91.1.1.1.1.4.2001", "sensor_index": "2001", "sensor_descr": "PSU 1 12V",
         "sensor_current": 12.1, "sensor_limit": 13.2, "sensor_limit_low": 10.8, "lastupdate": "2026-10-28 11:55:40"},
        {"sensor_id": 4, "device_id": 3, "sensor_class": "temperature", "sensor_type": "cisco-entity-sensor",
         "sensor_oid": ".1.3.6.1.4.1.9.9.91.1.1.1.1.4.1006", "sensor_index": "1006",
         "sensor_descr": "Chassis Temperature", "sensor_current": 71, "sensor_limit": 70, "sensor_limit_warn": 65,
         "lastupdate": "2026-10-28 11:54:10"},
    ):  # fmt: skip
        seed("sensors", row)
    seed("transceivers", {
        "id": 1, "device_id": 1, "port_id": 1, "index": "1011", "entity_physical_index": 1011,
        "type": "1000BASE-LX SFP", "vendor": "CISCO-FINISAR", "oui": "00:90:65", "model": "GLC-LH-SMD",
        "revision": "A", "serial": "FNS12345ABC", "date": "2021-03-04", "ddm": True, "encoding": "8B10B",
        "cable": "SM", "distance": 10000, "wavelength": 1310, "connector": "LC",
        "created_at": "2026-10-01T09:00:00.000000Z", "updated_at": "2026-10-28T06:00:11.000000Z",
    })  # fmt: skip
    for row in (
        {"processor_id": 1, "device_id": 1, "processor_index": "1", "processor_type": "cpm", "processor_usage": 97,
         "processor_descr": "CPU 0", "processor_oid": ".1.3.6.1.4.1.9.9.109.1.1.1.1.8.1", "entPhysicalIndex": 1000},
        {"processor_id": 2, "device_id": 2, "processor_index": "7000", "processor_type": "qfp", "processor_usage": 12,
         "processor_descr": "QFP 0", "processor_oid": ".1.3.6.1.4.1.9.9.715.1.1.6.1.14.7000"},
    ):  # fmt: skip
        seed("processors", row)
    seed("mempools", {
        "mempool_id": 1, "device_id": 1, "mempool_index": "1", "mempool_type": "cemp", "mempool_descr": "Processor",
        "mempool_perc": 41, "mempool_used": 1761607680, "mempool_free": 2533359616, "mempool_total": 4294967296,
    })  # fmt: skip
    seed("storage", {
        "storage_id": 1, "device_id": 1, "storage_index": "1", "storage_type": "flash", "storage_descr": "flash:",
        "storage_size": 1621966848, "storage_used": 908328960, "storage_free": 713637888, "storage_perc": 56,
    })  # fmt: skip
    seed("components", {"id": 7, "device_id": 1, "type": "ntp", "label": "192.0.2.123",
                        "prefs": {"peer": "192.0.2.123", "stratum": "2"}})  # fmt: skip
    seed("components", {"id": 8, "device_id": 1, "type": "ntp", "label": "192.0.2.124", "status": 2,
                        "error": "Peer unreachable", "prefs": {"peer": "192.0.2.124", "stratum": "16"}})  # fmt: skip
    for row in (
        {"bgpPeer_id": 1, "device_id": 2, "bgpPeerIdentifier": "203.0.113.1", "bgpPeerRemoteAs": 64500,
         "astext": "TRANSIT-A", "bgpPeerState": "established", "bgpLocalAddr": "203.0.113.2",
         "bgpPeerRemoteAddr": "203.0.113.1", "bgpPeerDescr": "transit-a", "bgpPeerFsmEstablishedTime": 864000,
         "bgpPeerInUpdates": 120332, "bgpPeerOutUpdates": 12, "bgpPeerInTotalMessages": 150201,
         "bgpPeerOutTotalMessages": 30215, "bgpPeerInUpdateElapsedTime": 3},
        {"bgpPeer_id": 2, "device_id": 2, "bgpPeerIdentifier": "198.51.100.9", "bgpPeerRemoteAs": 64501,
         "astext": "TRANSIT-B", "bgpPeerState": "idle", "bgpLocalAddr": "198.51.100.10",
         "bgpPeerRemoteAddr": "198.51.100.9", "bgpPeerDescr": "transit-b", "bgpPeerFsmEstablishedTime": 0,
         "bgpPeerLastErrorCode": 6, "bgpPeerLastErrorSubCode": 2, "bgpPeerLastErrorText": "Administrative Shutdown"},
        {"bgpPeer_id": 3, "device_id": 1, "bgpPeerIdentifier": "192.0.2.2", "bgpPeerRemoteAs": 65000},
    ):  # fmt: skip
        seed("bgp_peers", row)
    for row in (
        {"id": 1, "device_id": 1, "port_id": 1, "ospf_nbr_id": "198.51.100.2.0", "ospfNbrIpAddr": "198.51.100.2",
         "ospfNbrRtrId": "198.51.100.2", "ospfNbrOptions": 82, "ospfNbrPriority": 1, "ospfNbrState": "full",
         "ospfNbrEvents": 6, "ospfNbrLsRetransQLen": 0, "ospfNbmaNbrStatus": "active",
         "ospfNbmaNbrPermanence": "dynamic", "ospfNbrHelloSuppressed": "false"},
        {"id": 2, "device_id": 2, "port_id": 0, "ospf_nbr_id": "192.0.2.1.0", "ospfNbrIpAddr": "192.0.2.1",
         "ospfNbrRtrId": "192.0.2.1", "ospfNbrOptions": 82, "ospfNbrPriority": 1, "ospfNbrState": "full",
         "ospfNbrEvents": 6, "ospfNbrLsRetransQLen": 0, "ospfNbmaNbrStatus": "active",
         "ospfNbmaNbrPermanence": "dynamic", "ospfNbrHelloSuppressed": "false"},
    ):  # fmt: skip
        seed("ospf_nbrs", row)
    contacts = {"noc@example.net": "NOC", "jane.doe@example.net": "Jane Doe"}
    wan = {"device_id": 2, "port_id": 5, "ifName": "Gi0/0/0", "ifAlias": "WAN: transit-a", "ifOperStatus": "down",
           "hostname": "edge-rtr1.example.net", "sysContact": "noc@example.net"}  # fmt: skip
    for row in (
        {"id": 1, "rule_id": 1, "device_id": 2, "fault_id": 1, "state": 1, "time_logged": "2026-10-28 10:02:00",
         "details": {"contacts": contacts, "rule": [wan]}},
        {"id": 2, "rule_id": 1, "device_id": 2, "fault_id": 2, "state": 1, "time_logged": "2026-10-28 09:10:00",
         "details": {"contacts": contacts, "rule": [{**wan, "port_id": 6, "ifName": "Gi0/0/1",
                                                     "ifAlias": "WAN: transit-b"}]}},
        {"id": 3, "rule_id": 1, "device_id": 2, "fault_id": 2, "state": 2, "time_logged": "2026-10-28 09:15:00"},
        {"id": 4, "rule_id": 2, "device_id": 1, "fault_id": 5, "state": 1, "time_logged": "2026-10-27 21:00:00",
         "details": {"contacts": contacts, "rule": [{"device_id": 1, "processor_descr": "CPU 0",
                                                     "processor_usage": 97}]}},
        {"id": 5, "rule_id": 2, "device_id": 1, "fault_id": 5, "state": 0, "time_logged": "2026-10-27 22:00:00"},
    ):  # fmt: skip
        seed("alert_log", row)
    for row in (
        {"seq": 1, "device_id": 2, "priority": "err", "level": "err", "tag": "LINK-3-UPDOWN",
         "program": "LINK-3-UPDOWN", "timestamp": "2026-10-20 14:05:00",
         "msg": "Interface GigabitEthernet0/0/0, changed state to down"},
        {"seq": 2, "device_id": 1, "priority": "notice", "level": "notice", "tag": "SYS-5-CONFIG_I",
         "program": "SYS-5-CONFIG_I", "timestamp": "2026-10-28 11:00:00",
         "msg": "Configured from console by admin on vty0 (192.0.2.200)"},
        {"seq": 3, "device_id": 2, "priority": "notice", "level": "notice", "tag": "BGP-5-ADJCHANGE",
         "program": "BGP-5-ADJCHANGE", "timestamp": "2026-10-28 11:30:00",
         "msg": "neighbor 198.51.100.9 Down BGP Notification sent"},
    ):  # fmt: skip
        seed("syslog", row)
    for row in (
        {"vlan_id": 1, "device_id": 1, "vlan_vlan": 1, "vlan_name": "default"},
        {"vlan_id": 2, "device_id": 1, "vlan_vlan": 10, "vlan_name": "users"},
        {"vlan_id": 3, "device_id": 1, "vlan_vlan": 20, "vlan_name": "voice"},
        {"vlan_id": 4, "device_id": 3, "vlan_vlan": 10, "vlan_name": "users"},
    ):
        seed("vlans", row)
    # the trunk between core-sw1 Gi1/0/2 and access-sw2 Gi1/0/48: VLAN 1 native, 10 (and 20 on core-sw1) tagged; the
    # access side's VLAN 1 row says 0, which PortVlan reads as untagged because it is the port's ifVlan
    for port_id in (2, 9):
        fake.touch("ports", port_id, ifVlan="1", ifTrunk="dot1Q")
    for row in (
        {"port_vlan_id": 1, "device_id": 1, "port_id": 2, "vlan": 1, "baseport": 2, "untagged": 1},
        {"port_vlan_id": 2, "device_id": 1, "port_id": 2, "vlan": 10, "baseport": 2},
        {"port_vlan_id": 3, "device_id": 1, "port_id": 2, "vlan": 20, "baseport": 2},
        {"port_vlan_id": 4, "device_id": 3, "port_id": 9, "vlan": 1, "baseport": 48},
        {"port_vlan_id": 5, "device_id": 3, "port_id": 9, "vlan": 10, "baseport": 48},
    ):
        seed("ports_vlans", row)
    for row in (
        {"ports_fdb_id": 1, "device_id": 3, "port_id": 9, "mac_address": "001122334455", "vlan_id": 4,
         "created_at": "2026-10-27T08:00:00.000000Z", "updated_at": "2026-10-28T11:00:00.000000Z"},
        {"ports_fdb_id": 2, "device_id": 1, "port_id": 2, "mac_address": "001122334455", "vlan_id": 2,
         "created_at": "2026-10-27T08:00:05.000000Z", "updated_at": "2026-10-28T10:00:00.000000Z"},
        {"ports_fdb_id": 3, "device_id": 1, "port_id": 2, "mac_address": "00000c9ff001", "vlan_id": 2,
         "created_at": "2026-10-01T09:00:00.000000Z", "updated_at": "2026-10-28T11:50:00.000000Z"},
    ):  # fmt: skip
        seed("ports_fdb", row)
    seed("ports_nac", {
        "ports_nac_id": 1, "auth_id": "0A00000100000010", "device_id": 3, "port_id": 9, "domain": "data",
        "username": "00-11-22-33-44-55", "mac_address": "001122334455", "ip_address": "192.0.2.50",
        "host_mode": "multiAuth", "authz_status": "authorizationSuccess", "authz_by": "Authentication Server",
        "authc_status": "authcSuccess", "method": "mab", "timeout": 3600, "time_left": 1800, "vlan": 10,
        "time_elapsed": 1800, "created_at": "2026-10-28T11:00:00.000000Z", "updated_at": "2026-10-28T11:30:00.000000Z",
    })  # fmt: skip
    for row in (
        {"ipv4_address_id": 1, "ipv4_address": "192.0.2.1", "ipv4_prefixlen": 24, "port_id": 1},
        {"ipv4_address_id": 2, "ipv4_address": "203.0.113.2", "ipv4_prefixlen": 30, "port_id": 5},
    ):
        seed("ipv4_addresses", {**row, "ipv4_network_id": None, "context_name": ""})
    seed("ipv6_addresses", {
        "ipv6_address_id": 1, "ipv6_address": "2001:0db8:0000:0000:0000:0000:0000:0002", "ipv6_compressed": "2001:db8::2",
        "ipv6_prefixlen": 64, "ipv6_origin": "manual", "port_id": 5, "ipv6_network_id": None, "context_name": "",
    })  # fmt: skip
    for row in (
        {"id": 1, "port_id": 9, "device_id": 3, "mac_address": "001122334455", "ipv4_address": "192.0.2.50"},
        {"id": 2, "port_id": 2, "device_id": 1, "mac_address": "00000c9ff001", "ipv4_address": "192.0.2.254"},
        {"id": 3, "port_id": 5, "device_id": 2, "mac_address": "0050569a0001", "ipv4_address": "203.0.113.1"},
    ):
        seed("ipv4_mac", row)
    fake.oui = {"001122": "CIMSYS Inc", "00000c": "Cisco Systems, Inc"}
    seed("outages", {"id": 1, "device_id": 2, "going_down": 1761000000, "up_again": 1761003600})
    seed("outages", {"id": 2, "device_id": 4, "going_down": 1761600000})
    for device_id, percentages in ((1, (100.0, 99.98, 99.95, 99.9)), (2, (100.0, 99.4, 99.86, 99.98))):
        for duration, percent in zip((86400, 604800, 2592000, 31536000), percentages):
            seed("availability", {"device_id": device_id, "duration": duration, "availability_perc": percent})
    for row in (
        {"bill_id": 1, "bill_name": "Transit A", "bill_cdr": 1000000000, "rate_95th": 812000000,
         "rate_95th_in": 812000000, "rate_95th_out": 400000000, "bill_custid": "CUST-001", "bill_ref": "TRANSIT-A",
         "bill_last_calc": "2026-10-28 11:50:02", "ports": [5]},
        {"bill_id": 2, "bill_name": "Transit B", "bill_cdr": 500000000, "rate_95th": 620000000,
         "rate_95th_in": 620000000, "rate_95th_out": 210000000, "bill_custid": "CUST-002", "bill_ref": "TRANSIT-B",
         "bill_last_calc": "2026-10-28 11:50:02", "ports": [6]},
    ):  # fmt: skip
        seed("bills", row)
