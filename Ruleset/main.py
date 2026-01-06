import asyncio  # noqa: D100, INP001
import contextlib
import ipaddress
import itertools
import re
from typing import Any

import anyio
import httpx
import orjson
import polars as pl
import yaml

ASN_CACHE: dict[str, list[str]] = {}
POOL = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, pool=30.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
    http2=True,
)


SINGBOX_ALIAS = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-SET": "domain_suffix",
    "URL-REGEX": "domain_regex",
    "DOMAIN-WILDCARD": "domain_regex",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "IP6-CIDR": "ip_cidr",
    "SRC-IP": "source_ip_cidr",
    "SRC-IP-CIDR": "source_ip_cidr",
    "IP-ASN": "ip_asn",
    "DEST-PORT": "port",
    "DST-PORT": "port",
    "IN-PORT": "port",
    "SRC-PORT": "source_port",
    "SOURCE-PORT": "source_port",
    "PROCESS-NAME": "process_name",
    "PROCESS-PATH": "process_path",
    "PROCESS-PATH-REGEX": "process_path_regex",
    "PROCESS-NAME-REGEX": "process_name_regex",
    "PROTOCOL": "protocol",
    "NETWORK": "network",
    "HOST": "domain",
    "HOST-SUFFIX": "domain_suffix",
    "HOST-KEYWORD": "domain_keyword",
    "USER": "user",
    "USER-ID": "user_id",
    "PACKAGE-NAME": "package_name",
    "UID": "user_id",
    "CLASH-MODE": "clash_mode",
    "NETWORK-TYPE": "network_type",
    "NETWORK-IS-EXPENSIVE": "network_is_expensive",
    "NETWORK-IS-CONSTRAINED": "network_is_constrained",
    "WIFI-SSID": "wifi_ssid",
    "WIFI-BSSID": "wifi_bssid",
    "RULE-SET": "rule_set",
    "RULE-SET-IPCIDR-MATCH-SOURCE": "rule_set_ipcidr_match_source",
    "RULE-SET-IP-CIDR-MATCH-SOURCE": "rule_set_ip_cidr_match_source",
    "PREFERRED-BY": "preferred_by",
    "AUTH-USER": "auth_user",
    "CLIENT": "client",
    "IP-VERSION": "ip_version",
    "INBOUND": "inbound",
    "AND": "and",
    "OR": "or",
}


MIHOMO_ALIAS = {
    "DOMAIN": "DOMAIN",
    "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
    "DOMAIN-SET": "DOMAIN-SUFFIX",
    "URL-REGEX": "DOMAIN-REGEX",
    "DOMAIN-WILDCARD": "DOMAIN-WILDCARD",
    "DOMAIN-REGEX": "DOMAIN-REGEX",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR",
    "IP6-CIDR": "IP-CIDR",
    "IP-SUFFIX": "IP-SUFFIX",
    "SRC-IP": "SRC-IP-CIDR",
    "SRC-IP-CIDR": "SRC-IP-CIDR",
    "SRC-IP-SUFFIX": "SRC-IP-SUFFIX",
    "IP-ASN": "IP-ASN",
    "SRC-IP-ASN": "SRC-IP-ASN",
    "DEST-PORT": "DST-PORT",
    "DST-PORT": "DST-PORT",
    "IN-PORT": "IN-PORT",
    "IN-TYPE": "IN-TYPE",
    "IN-USER": "IN-USER",
    "IN-NAME": "IN-NAME",
    "SRC-PORT": "SRC-PORT",
    "SOURCE-PORT": "SRC-PORT",
    "PROCESS-NAME": "PROCESS-NAME",
    "PROCESS-PATH": "PROCESS-PATH",
    "PROCESS-PATH-REGEX": "PROCESS-PATH-REGEX",
    "PROCESS-NAME-REGEX": "PROCESS-NAME-REGEX",
    "PROTOCOL": "NETWORK",
    "NETWORK": "NETWORK",
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "GEOIP": "GEOIP",
    "GEOSITE": "GEOSITE",
    "SRC-GEOIP": "SRC-GEOIP",
    "UID": "UID",
    "DSCP": "DSCP",
    "RULE-SET": "RULE-SET",
    "AND": "AND",
    "OR": "OR",
    "NOT": "NOT",
    "SUB-RULE": "SUB-RULE",
    "MATCH": "MATCH",
}


SINGBOX_ORDER = [
    "inbound",
    "ip_version",
    "auth_user",
    "protocol",
    "client",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_geoip",
    "geoip",
    "source_ip_cidr",
    "source_ip_is_private",
    "ip_cidr",
    "ip_is_private",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "user",
    "user_id",
    "clash_mode",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "interface_address",
    "network_interface_address",
    "default_interface_address",
    "wifi_ssid",
    "wifi_bssid",
    "preferred_by",
    "rule_set",
    "rule_set_ipcidr_match_source",
    "rule_set_ip_cidr_match_source",
    "invert",
]


MIHOMO_ORDER = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN-WILDCARD",
    "GEOSITE",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "SRC-IP-ASN",
    "SRC-GEOIP",
    "IP-CIDR",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-PORT",
    "DST-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-NAME",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH",
    "PROCESS-PATH-REGEX",
    "NETWORK",
    "UID",
    "DSCP",
    "RULE-SET",
    "AND",
    "OR",
    "NOT",
    "SUB-RULE",
    "MATCH",
]


SINGBOX_DENY = frozenset(
    {
        "USER-AGENT",
        "CELLULAR-RADIO",
        "DEVICE-NAME",
        "MAC-ADDRESS",
        "FINAL",
        "GEOIP",
        "GEOSITE",
        "SOURCE-GEOIP",
        "NOT",
        "RULE-SET-IPCIDR-MATCH-SOURCE",
    },
)


MIHOMO_DENY = frozenset(
    {
        "USER-AGENT",
        "CELLULAR-RADIO",
        "DEVICE-NAME",
        "MAC-ADDRESS",
        "FINAL",
        "IP-IS-PRIVATE",
        "SOURCE-IP-IS-PRIVATE",
        "NETWORK-IS-EXPENSIVE",
        "NETWORK-IS-CONSTRAINED",
        "WIFI-SSID",
        "WIFI-BSSID",
        "PREFERRED-BY",
        "AUTH-USER",
        "CLIENT",
        "IP-VERSION",
        "INBOUND",
        "PACKAGE-NAME",
        "USER",
        "USER-ID",
        "CLASH-MODE",
        "NETWORK-TYPE",
        "INTERFACE-ADDRESS",
        "NETWORK-INTERFACE-ADDRESS",
        "DEFAULT-INTERFACE-ADDRESS",
        "RULE-SET-IPCIDR-MATCH-SOURCE",
        "RULE-SET-IP-CIDR-MATCH-SOURCE",
    },
)


SINGBOX_ALIASES = tuple(SINGBOX_ALIAS.keys())


MIHOMO_ALIASES = tuple(MIHOMO_ALIAS.keys())


async def prefix(asn: str) -> list[str]:  # noqa: D103
    cached = ASN_CACHE.get(asn)
    if cached is not None:
        return cached

    asn_id = asn.replace("AS", "").replace("as", "")

    apis = [
        (
            f"https://api.bgpview.io/asn/{asn_id}/prefixes",
            lambda body: [
                item["prefix"]
                for prefix_list in (
                    body.get("data", {}).get("ipv4_prefixes", ()),
                    body.get("data", {}).get("ipv6_prefixes", ()),
                )
                for item in prefix_list
            ],
        ),
        (
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_id}",
            lambda body: [
                item["prefix"]
                for item in body.get("data", {}).get("prefixes", ())
                if "prefix" in item
            ],
        ),
    ]

    for url_template, extractor in apis:
        with contextlib.suppress(httpx.HTTPError, orjson.JSONDecodeError, KeyError):
            resp = await POOL.get(url_template.format(asn_id=asn_id))
            if resp.status_code == 200:  # noqa: PLR2004
                body = orjson.loads(resp.content)
                if body.get("status") == "ok":
                    cidrs = extractor(body)
                    if cidrs:
                        ASN_CACHE[asn] = cidrs
                        return cidrs

    cidrs = []
    ASN_CACHE[asn] = cidrs
    return cidrs


async def fetch(url: str) -> str:  # noqa: D103
    if url.startswith("file://"):
        async with await anyio.Path(url[7:]).open("r", encoding="utf-8") as handle:
            return await handle.read()

    resp = await POOL.get(url)
    resp.raise_for_status()
    return resp.text


def decode_yaml(blob: str) -> list[dict[str, str]]:  # noqa: D103
    parsed = yaml.safe_load(blob)
    return [
        {
            "pattern": (
                "IP-CIDR"
                if is_net(entry := item.strip("'\""))
                else "DOMAIN-SUFFIX"
                if entry.startswith("+")
                else "DOMAIN"
            )
            if "," not in item
            else item.split(",", 2)[0].strip(),
            "address": (
                (entry := entry[1:].lstrip(".")) if entry.startswith("+") else entry
            )
            if "," not in item
            else item.split(",", 2)[1].strip(),
        }
        for item in parsed.get("payload", ())
    ]


def decode_list(blob: str) -> list[dict[str, str]]:  # noqa: D103
    lines = (
        line.strip()
        for line in blob.strip().split("\n")
        if line and not line.startswith("#")
    )

    return [
        (
            {
                "pattern": parts[0].strip(),
                "address": f"{parts[1].strip()},{parts[2].strip()}"
                if len(parts) > 2 and parts[2].strip()  # noqa: PLR2004
                else parts[1].strip()
                if len(parts) > 1
                else "",
            }
            if "," in line
            else {"pattern": "DOMAIN-SUFFIX", "address": line.removeprefix(".")}
        )
        for line in lines
        for parts in [line.split(",", 2)]
    ]


def is_net(address: str) -> bool:  # noqa: D103
    try:
        ipaddress.ip_network(address, strict=False)
    except ValueError:
        return False
    return True


async def ingest(url: str) -> pl.DataFrame:  # noqa: D103
    payload = await fetch(url)
    if url.endswith((".yaml", ".yml")):
        with contextlib.suppress(Exception):
            return pl.DataFrame(decode_yaml(payload))
    return pl.DataFrame(decode_list(payload))


async def merge(asn_list: list[str]) -> list[str]:  # noqa: D103
    bundles = await asyncio.gather(
        *(prefix(item) for item in asn_list),
        return_exceptions=True,
    )
    return list(
        itertools.chain.from_iterable(
            bundle for bundle in bundles if isinstance(bundle, list)
        ),
    )


def validate_regex(pattern: str) -> bool:  # noqa: D103
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def mask_regex(pattern: str) -> str:  # noqa: D103
    masked = pattern.lstrip(".")
    char_map = {".": r"\.", "*": r"[\w.-]*?", "?": r"[\w.-]"}
    return "^" + "".join(char_map.get(char, char) for char in masked) + "$"


def normalize_cidr(entry: str) -> str:  # noqa: D103
    if "/" in entry:
        return entry
    try:
        addr = ipaddress.ip_address(entry)
    except ValueError:
        return entry
    return f"{entry}/32" if addr.version == 4 else f"{entry}/128"  # noqa: PLR2004


def split_port(item: str) -> tuple[str | None, int | None]:  # noqa: D103
    if ":" in item or "-" in item:
        token = ":" if ":" in item else "-"
        parts = item.split(token)
        if len(parts) == 2:  # noqa: PLR2004
            with contextlib.suppress(ValueError):
                start, end = int(parts[0]), int(parts[1])
                return f"{start}:{end}", None
        return None, None
    with contextlib.suppress(ValueError):
        return None, int(item)
    return None, None


def compose_singbox_json(frame: pl.DataFrame, cidrs: list[str]) -> dict[str, Any]:  # noqa: C901, D103, PLR0912, PLR0915
    def _process_ports(addresses: list[str]) -> tuple[list[str], list[str]]:
        if not addresses:
            return [], []

        port_results = [
            (split_port(item)[0], split_port(item)[1]) for item in addresses
        ]
        filtered_results = [
            (None, span) if span is not None else (value, None)
            for span, value in port_results
            if span is not None or value is not None
        ]

        if not filtered_results:
            return [], []

        ports, ranges = zip(*filtered_results, strict=False)
        return [p for p in ports if p], [r for r in ranges if r]

    logical_rules: list[dict[str, Any]] = []
    regular_rule: dict[str, Any] = {}

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    for block in grouped.iter_rows(named=True):
        pattern, addresses = block["pattern"], block["address"]

        match pattern:
            case "domain":
                regular_rule.setdefault("domain", []).extend(addresses)
            case "domain_suffix":
                regular_rule.setdefault("domain_suffix", []).extend(
                    f".{item}" if not item.startswith(".") else item
                    for item in addresses
                )
            case "domain_keyword":
                regular_rule.setdefault("domain_keyword", []).extend(addresses)
            case "domain_regex":
                valid_regexes = list(filter(validate_regex, addresses))
                if valid_regexes:
                    regular_rule.setdefault("domain_regex", []).extend(valid_regexes)
            case "domain_wildcard":
                regex_patterns = [
                    mask_regex(item)
                    for item in addresses
                    if (regex := mask_regex(item)) and validate_regex(regex)
                ]
                if regex_patterns:
                    regular_rule.setdefault("domain_regex", []).extend(regex_patterns)
            case "ip_cidr":
                regular_rule.setdefault("ip_cidr", []).extend(
                    normalize_cidr(addr.rsplit(",", 1)[0])
                    if addr.endswith(",no-resolve")
                    else normalize_cidr(addr)
                    for addr in addresses
                )
            case "source_ip_cidr":
                regular_rule.setdefault("source_ip_cidr", []).extend(
                    normalize_cidr(item) for item in addresses
                )
            case "port" | "source_port":
                ports, ranges = _process_ports(addresses)
                field_prefix = "" if pattern == "port" else "source_"
                if ports:
                    regular_rule.setdefault(f"{field_prefix}port", []).extend(ports)
                if ranges:
                    regular_rule.setdefault(f"{field_prefix}port_range", []).extend(
                        ranges,
                    )
            case "process_name":
                regular_rule.setdefault("process_name", []).extend(addresses)
            case "process_path":
                regular_rule.setdefault("process_path", []).extend(addresses)
            case "network":
                proto = [
                    entry.lower()
                    for entry in addresses
                    if entry.upper() in {"TCP", "UDP", "ICMP"}
                ]
                if proto:
                    regular_rule.setdefault("network", []).extend(proto)
            case "protocol":
                supported_protocols = [
                    entry.lower()
                    for entry in addresses
                    if entry.upper() in {"TLS", "HTTP", "QUIC", "STUN"}
                ]
                if supported_protocols:
                    regular_rule.setdefault("protocol", []).extend(supported_protocols)
            case "client":
                supported_clients = [
                    entry.lower()
                    for entry in addresses
                    if entry.upper() in {"CHROMIUM", "SAFARI", "FIREFOX", "QUIC-GO"}
                ]
                if supported_clients:
                    regular_rule.setdefault("client", []).extend(supported_clients)
            case "auth_user":
                regular_rule.setdefault("auth_user", []).extend(addresses)
            case "user":
                regular_rule.setdefault("user", []).extend(addresses)
            case "user_id":
                user_ids = [
                    int(user_id_str)
                    for user_id_str in addresses
                    if user_id_str.isdigit()
                ]
                if user_ids:
                    regular_rule.setdefault("user_id", []).extend(user_ids)
            case "clash_mode":
                if addresses:
                    regular_rule["clash_mode"] = addresses[
                        0
                    ]  # Only one clash_mode allowed
            case "network_type":
                network_types = [
                    entry.lower()
                    for entry in addresses
                    if entry.lower() in {"wifi", "cellular", "ethernet", "other"}
                ]
                if network_types:
                    regular_rule.setdefault("network_type", []).extend(network_types)
            case "network_is_expensive":
                if addresses:
                    regular_rule["network_is_expensive"] = (
                        addresses[0].lower() == "true"
                    )
            case "network_is_constrained":
                if addresses:
                    regular_rule["network_is_constrained"] = (
                        addresses[0].lower() == "true"
                    )
            case "wifi_ssid":
                regular_rule.setdefault("wifi_ssid", []).extend(addresses)
            case "wifi_bssid":
                regular_rule.setdefault("wifi_bssid", []).extend(addresses)
            case "rule_set":
                regular_rule.setdefault("rule_set", []).extend(addresses)
            case "ip_version":
                ip_versions = [
                    int(version_str)
                    for version_str in addresses
                    if version_str.isdigit() and int(version_str) in {4, 6}
                ]
                if ip_versions:
                    regular_rule.setdefault("ip_version", []).extend(ip_versions)
            case "inbound":
                regular_rule.setdefault("inbound", []).extend(addresses)
            case "process_path_regex":
                valid_regexes = list(filter(validate_regex, addresses))
                if valid_regexes:
                    regular_rule.setdefault("process_path_regex", []).extend(
                        valid_regexes,
                    )
            case "process_name_regex":
                valid_regexes = list(filter(validate_regex, addresses))
                if valid_regexes:
                    regular_rule.setdefault("process_name_regex", []).extend(
                        valid_regexes,
                    )
            case "ip_is_private":
                if addresses:
                    regular_rule["ip_is_private"] = addresses[0].lower() == "true"
            case "source_ip_is_private":
                if addresses:
                    regular_rule["source_ip_is_private"] = (
                        addresses[0].lower() == "true"
                    )
            case "and" | "or":
                parsed_sub_rules = [
                    sub_rule
                    for addr in addresses
                    if addr.startswith("((") and addr.endswith("))")
                    for inner_content in [addr[2:-2].strip()]
                    for rule_parts in [
                        (
                            inner_content.split("), (")
                            if "), (" in inner_content
                            else [inner_content]
                        ),
                    ]
                    for processed_parts in [
                        (
                            (
                                [
                                    *rule_parts[:1],
                                    rule_parts[0][1:],
                                    *rule_parts[1:-1],
                                    rule_parts[-1][:-1],
                                ]
                                if rule_parts
                                and rule_parts[0].startswith("(")
                                and rule_parts[-1].endswith(")")
                                else rule_parts
                            )
                            if "), (" in inner_content
                            else rule_parts
                        ),
                    ]
                    for rule in processed_parts
                    if "," in (stripped_rule := rule.strip())
                    for parts in [stripped_rule.split(",", 1)]
                    if len(parts) == 2  # noqa: PLR2004
                    for sub_pattern, address in [(parts[0].strip(), parts[1].strip())]
                    for sub_rule in [
                        (
                            {
                                "domain": [address],
                            }
                            if sub_pattern == "DOMAIN"
                            else {
                                "domain_suffix": [address.lstrip(".")],
                            }
                            if sub_pattern == "DOMAIN-SUFFIX"
                            else {
                                "domain_keyword": [address],
                            }
                            if sub_pattern == "DOMAIN-KEYWORD"
                            else {
                                "network": [address.lower()],
                            }
                            if sub_pattern == "NETWORK"
                            else (
                                {"protocol": [address.lower()]}
                                if address.upper() in {"TLS", "HTTP", "QUIC", "STUN"}
                                else {}
                            )
                            if sub_pattern == "PROTOCOL"
                            else (
                                {"client": [address.lower()]}
                                if address.upper()
                                in {"CHROMIUM", "SAFARI", "FIREFOX", "QUIC-GO"}
                                else {}
                            )
                            if sub_pattern == "CLIENT"
                            else {
                                "process_name": [address],
                            }
                            if sub_pattern == "PROCESS-NAME"
                            else {
                                "process_path": [address],
                            }
                            if sub_pattern == "PROCESS-PATH"
                            else (
                                {"process_path_regex": [address]}
                                if validate_regex(address)
                                else {}
                            )
                            if sub_pattern == "PROCESS-PATH-REGEX"
                            else (
                                {"process_name_regex": [address]}
                                if validate_regex(address)
                                else {}
                            )
                            if sub_pattern == "PROCESS-NAME-REGEX"
                            else {
                                "source_ip_cidr": [normalize_cidr(address)],
                            }
                            if sub_pattern in {"SRC-IP", "SRC-IP-CIDR"}
                            else ({"port": [int(address)]} if address.isdigit() else {})
                            if sub_pattern in {"DEST-PORT", "DST-PORT", "PORT"}
                            else (
                                {"source_port": [int(address)]}
                                if address.isdigit()
                                else {}
                            )
                            if sub_pattern == "SRC-PORT"
                            else {
                                "ip_cidr": [normalize_cidr(address)],
                            }
                            if sub_pattern == "IP-CIDR"
                            else (
                                {"domain_regex": [address]}
                                if validate_regex(address)
                                else {}
                            )
                            if sub_pattern == "DOMAIN-REGEX"
                            else (
                                {"domain_regex": [mask_regex(address)]}
                                if validate_regex(mask_regex(address))
                                else {}
                            )
                            if sub_pattern == "DOMAIN-WILDCARD"
                            else {
                                "user": [address],
                            }
                            if sub_pattern == "USER"
                            else (
                                {"user_id": [int(address)]} if address.isdigit() else {}
                            )
                            if sub_pattern == "USER-ID"
                            else {
                                "package_name": [address],
                            }
                            if sub_pattern == "PACKAGE-NAME"
                            else {
                                "auth_user": [address],
                            }
                            if sub_pattern == "AUTH-USER"
                            else (
                                {"network_type": [address.lower()]}
                                if address.lower()
                                in {"wifi", "cellular", "ethernet", "other"}
                                else {}
                            )
                            if sub_pattern == "NETWORK-TYPE"
                            else {
                                "wifi_ssid": [address],
                            }
                            if sub_pattern == "WIFI-SSID"
                            else {
                                "wifi_bssid": [address],
                            }
                            if sub_pattern == "WIFI-BSSID"
                            else {
                                "rule_set": [address],
                            }
                            if sub_pattern == "RULE-SET"
                            else (
                                {"ip_version": [int(address)]}
                                if address.isdigit() and int(address) in {4, 6}
                                else {}
                            )
                            if sub_pattern == "IP-VERSION"
                            else {
                                "inbound": [address],
                            }
                            if sub_pattern == "INBOUND"
                            else {
                                "ip_is_private": address.lower() == "true",
                            }
                            if sub_pattern == "IP-IS-PRIVATE"
                            else {
                                "source_ip_is_private": address.lower() == "true",
                            }
                            if sub_pattern == "SOURCE-IP-IS-PRIVATE"
                            else {}
                        ),
                    ]
                    if sub_rule
                ]

                if parsed_sub_rules:
                    logical_rule = {
                        "type": "logical",
                        "mode": pattern,
                        "rules": parsed_sub_rules,
                        "invert": False,
                    }
                    logical_rules.append(logical_rule)

    if cidrs:
        regular_rule.setdefault("ip_cidr", []).extend(
            normalize_cidr(item) for item in cidrs
        )

    regular_rule = {
        key: (
            sorted(set(value))
            if key in {"port", "source_port"}
            else list(dict.fromkeys(value))
        )
        for key, value in regular_rule.items()
        if isinstance(value, list)
    }

    ordered_regular = {
        field: regular_rule[field] for field in SINGBOX_ORDER if regular_rule.get(field)
    }
    ordered_regular.update(
        {
            field: value
            for field, value in regular_rule.items()
            if field not in ordered_regular and value
        },
    )

    final_rules = logical_rules + ([ordered_regular] if ordered_regular else [])

    return {"version": 4, "rules": final_rules or []}


def compose_mihomo_yaml(  # noqa: C901, D103, PLR0912, PLR0915
    frame: pl.DataFrame,
    cidrs: list[str],
    category: str,
    filename: str = "",
) -> dict[str, Any] | None:
    def _process_ports(addresses: list[str]) -> tuple[list[str], list[str]]:
        if not addresses:
            return [], []

        port_results = [
            (split_port(item)[0], split_port(item)[1]) for item in addresses
        ]
        filtered_results = [
            (None, span) if span is not None else (value, None)
            for span, value in port_results
            if span is not None or value is not None
        ]

        if not filtered_results:
            return [], []

        ports, ranges = zip(*filtered_results, strict=False)
        return [p for p in ports if p], [r for r in ranges if r]

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    payload = []

    for block in grouped.iter_rows(named=True):
        pattern, addresses = block["pattern"], block["address"]

        match pattern:
            case "DOMAIN":
                payload.extend([f"DOMAIN,{addr}" for addr in addresses])
            case "DOMAIN-SUFFIX":
                payload.extend(
                    [f"DOMAIN-SUFFIX,{addr.lstrip('.')}" for addr in addresses],
                )
            case "DOMAIN-KEYWORD":
                payload.extend([f"DOMAIN-KEYWORD,{addr}" for addr in addresses])
            case "DOMAIN-REGEX":
                payload.extend(
                    [
                        f"DOMAIN-REGEX,{addr}"
                        for addr in addresses
                        if validate_regex(addr)
                    ],
                )
            case "DOMAIN-WILDCARD":
                payload.extend([f"DOMAIN-WILDCARD,{addr}" for addr in addresses])
            case "GEOSITE":
                payload.extend([f"GEOSITE,{addr}" for addr in addresses])
            case "IP-CIDR":
                if category == "ip" and (
                    "china-ip" in filename or "china-ip-ipv6" in filename
                ):
                    payload.extend(
                        normalize_cidr(
                            addr.removesuffix(",no-resolve")
                            if addr.endswith(",no-resolve")
                            else addr,
                        )
                        for addr in addresses
                    )
                else:
                    payload.extend(
                        f"IP-CIDR,{normalize_cidr(addr.removesuffix(',no-resolve'))},no-resolve"
                        if addr.endswith(",no-resolve")
                        else f"IP-CIDR,{normalize_cidr(addr)}"
                        for addr in addresses
                    )
            case "IP-SUFFIX":
                payload.extend([f"IP-SUFFIX,{addr}" for addr in addresses])
            case "IP-ASN":
                payload.extend(
                    f"IP-ASN,{addr.removesuffix(',no-resolve')},no-resolve"
                    if addr.endswith(",no-resolve")
                    else f"IP-ASN,{addr}"
                    for addr in addresses
                )
            case "GEOIP":
                payload.extend(
                    f"GEOIP,{addr.removesuffix(',no-resolve')},no-resolve"
                    if addr.endswith(",no-resolve")
                    else f"GEOIP,{addr}"
                    for addr in addresses
                )
            case "SRC-IP-CIDR":
                payload.extend(
                    [f"SRC-IP-CIDR,{normalize_cidr(addr)}" for addr in addresses],
                )
            case "SRC-IP-SUFFIX":
                payload.extend([f"SRC-IP-SUFFIX,{addr}" for addr in addresses])
            case "SRC-IP-ASN":
                payload.extend([f"SRC-IP-ASN,{addr}" for addr in addresses])
            case "SRC-GEOIP":
                payload.extend([f"SRC-GEOIP,{addr}" for addr in addresses])
            case "DST-PORT" | "SRC-PORT" | "IN-PORT":
                ports, ranges = _process_ports(addresses)
                if ports:
                    payload.extend([f"{pattern},{port}" for port in ports])
                if ranges:
                    payload.extend([f"{pattern},{range_val}" for range_val in ranges])
            case "PROCESS-NAME":
                payload.extend([f"PROCESS-NAME,{addr}" for addr in addresses])
            case "PROCESS-PATH":
                payload.extend([f"PROCESS-PATH,{addr}" for addr in addresses])
            case "NETWORK":
                proto = [
                    entry.upper()
                    for entry in addresses
                    if entry.upper() in {"TCP", "UDP", "ICMP"}
                ]
                if proto:
                    payload.extend([f"NETWORK,{p}" for p in proto])
            case "IN-TYPE":
                payload.extend([f"IN-TYPE,{addr}" for addr in addresses])
            case "IN-USER":
                payload.extend([f"IN-USER,{addr}" for addr in addresses])
            case "IN-NAME":
                payload.extend([f"IN-NAME,{addr}" for addr in addresses])
            case "PROCESS-NAME-REGEX":
                payload.extend(
                    [
                        f"PROCESS-NAME-REGEX,{addr}"
                        for addr in addresses
                        if validate_regex(addr)
                    ],
                )
            case "PROCESS-PATH-REGEX":
                payload.extend(
                    [
                        f"PROCESS-PATH-REGEX,{addr}"
                        for addr in addresses
                        if validate_regex(addr)
                    ],
                )
            case "UID":
                payload.extend([f"UID,{addr}" for addr in addresses])
            case "DSCP":
                payload.extend([f"DSCP,{addr}" for addr in addresses])
            case "RULE-SET":
                pass
            case "AND" | "OR" | "NOT" | "SUB-RULE":
                payload.extend(
                    [
                        f"{pattern},{addr.strip()}"
                        if addr and not addr.startswith("((")
                        else f"{pattern},{(addr.replace('), (', '),(').strip() if addr else '') or ''}"
                        for addr in addresses
                    ],
                )
            case "MATCH":
                payload.extend([f"MATCH,{addr}" for addr in addresses])

    if cidrs:
        payload.extend([f"IP-CIDR,{normalize_cidr(item)}" for item in cidrs])

    if category == "ip" and ("china-ip" in filename or "china-ip-ipv6" in filename):
        yaml_lines = ["payload:"]
        yaml_lines.extend(f'- "{item}"' for item in payload)
        return {"__custom_yaml__": "\n".join(yaml_lines)}

    return {"payload": payload} if payload else None


def compose_mihomo_text(  # noqa: C901, D103, PLR0912, PLR0915
    frame: pl.DataFrame,
    cidrs: list[str],
    category: str,
    filename: str = "",
) -> list[str] | None:
    def _process_ports(addresses: list[str]) -> tuple[list[str], list[str]]:
        if not addresses:
            return [], []

        port_results = [
            (split_port(item)[0], split_port(item)[1]) for item in addresses
        ]
        filtered_results = [
            (None, span) if span is not None else (value, None)
            for span, value in port_results
            if span is not None or value is not None
        ]

        if not filtered_results:
            return [], []

        ports, ranges = zip(*filtered_results, strict=False)
        return [p for p in ports if p], [r for r in ranges if r]

    if category == "domainset":
        grouped = frame.group_by("pattern").agg(pl.col("address"))
        domain_rules = [
            addr
            for block in grouped.iter_rows(named=True)
            if (pattern := block["pattern"]) == "DOMAIN"
            for addr in block["address"]
        ]

        suffix_rules = [
            f"+.{item}" if not item.startswith(".") else f"+{item}"
            for block in grouped.iter_rows(named=True)
            if (pattern := block["pattern"]) == "DOMAIN-SUFFIX"
            for item in block["address"]
        ]

        rules = domain_rules + suffix_rules
    else:
        grouped = frame.group_by("pattern").agg(pl.col("address"))
        rules = []

        for block in grouped.iter_rows(named=True):
            pattern, addresses = block["pattern"], block["address"]

            match pattern:
                case "DOMAIN":
                    rules.extend([f"DOMAIN,{addr}" for addr in addresses])
                case "DOMAIN-SUFFIX":
                    rules.extend(
                        [f"DOMAIN-SUFFIX,{addr.lstrip('.')}" for addr in addresses],
                    )
                case "DOMAIN-KEYWORD":
                    rules.extend([f"DOMAIN-KEYWORD,{addr}" for addr in addresses])
                case "DOMAIN-REGEX":
                    valid_regexes = list(filter(validate_regex, addresses))
                    if valid_regexes:
                        rules.extend(
                            [f"DOMAIN-REGEX,{regex}" for regex in valid_regexes],
                        )
                case "DOMAIN-WILDCARD":
                    rules.extend([f"DOMAIN-WILDCARD,{addr}" for addr in addresses])
                case "GEOSITE":
                    rules.extend([f"GEOSITE,{addr}" for addr in addresses])
                case "IP-CIDR":
                    if category == "ip" and (
                        "china-ip" in filename or "china-ip-ipv6" in filename
                    ):
                        rules.extend(
                            normalize_cidr(
                                addr.removesuffix(",no-resolve")
                                if addr.endswith(",no-resolve")
                                else addr,
                            )
                            for addr in addresses
                        )
                    else:
                        rules.extend(
                            f"IP-CIDR,{normalize_cidr(addr.removesuffix(',no-resolve'))},no-resolve"
                            if addr.endswith(",no-resolve")
                            else f"IP-CIDR,{normalize_cidr(addr)}"
                            for addr in addresses
                        )
                case "IP-SUFFIX":
                    rules.extend([f"IP-SUFFIX,{addr}" for addr in addresses])
                case "IP-ASN":
                    rules.extend(
                        f"IP-ASN,{addr.removesuffix(',no-resolve')},no-resolve"
                        if addr.endswith(",no-resolve")
                        else f"IP-ASN,{addr}{',no-resolve' if category == 'ip' else ''}"
                        for addr in addresses
                    )
                case "GEOIP":
                    rules.extend(
                        f"GEOIP,{addr.removesuffix(',no-resolve')},no-resolve"
                        if addr.endswith(",no-resolve")
                        else f"GEOIP,{addr}{',no-resolve' if category == 'ip' else ''}"
                        for addr in addresses
                    )
                case "SRC-IP-CIDR":
                    rules.extend(
                        [f"SRC-IP-CIDR,{normalize_cidr(addr)}" for addr in addresses],
                    )
                case "SRC-IP-SUFFIX":
                    rules.extend([f"SRC-IP-SUFFIX,{addr}" for addr in addresses])
                case "SRC-IP-ASN":
                    rules.extend([f"SRC-IP-ASN,{addr}" for addr in addresses])
                case "SRC-GEOIP":
                    rules.extend([f"SRC-GEOIP,{addr}" for addr in addresses])
                case "DST-PORT" | "SRC-PORT" | "IN-PORT":
                    ports, ranges = _process_ports(addresses)
                    if ports:
                        rules.extend([f"{pattern},{port}" for port in ports])
                    if ranges:
                        rules.extend([f"{pattern},{range_val}" for range_val in ranges])
                case "PROCESS-NAME":
                    rules.extend([f"PROCESS-NAME,{addr}" for addr in addresses])
                case "PROCESS-PATH":
                    rules.extend([f"PROCESS-PATH,{addr}" for addr in addresses])
                case "NETWORK":
                    proto = [
                        entry.upper()
                        for entry in addresses
                        if entry.upper() in {"TCP", "UDP", "ICMP"}
                    ]
                    if proto:
                        rules.extend([f"NETWORK,{p}" for p in proto])
                case "IN-TYPE":
                    rules.extend([f"IN-TYPE,{addr}" for addr in addresses])
                case "IN-USER":
                    rules.extend([f"IN-USER,{addr}" for addr in addresses])
                case "IN-NAME":
                    rules.extend([f"IN-NAME,{addr}" for addr in addresses])
                case "PROCESS-NAME-REGEX":
                    valid_regexes = list(filter(validate_regex, addresses))
                    if valid_regexes:
                        rules.extend(
                            [f"PROCESS-NAME-REGEX,{regex}" for regex in valid_regexes],
                        )
                case "PROCESS-PATH-REGEX":
                    valid_regexes = list(filter(validate_regex, addresses))
                    if valid_regexes:
                        rules.extend(
                            [f"PROCESS-PATH-REGEX,{regex}" for regex in valid_regexes],
                        )
                case "UID":
                    rules.extend([f"UID,{addr}" for addr in addresses])
                case "DSCP":
                    rules.extend([f"DSCP,{addr}" for addr in addresses])
                case "RULE-SET":
                    rules.extend([f"RULE-SET,{addr}" for addr in addresses])
                case "AND" | "OR" | "NOT" | "SUB-RULE":
                    rules.extend(
                        [
                            f"{pattern},{addr.strip()}"
                            if addr and not addr.startswith("((")
                            else f"{pattern},{(addr.replace('), (', '),(').strip() if addr else '') or ''}"
                            for addr in addresses
                        ],
                    )
                case "MATCH":
                    rules.extend([f"MATCH,{addr}" for addr in addresses])

        if cidrs:
            if category == "ip" and (
                "china-ip" in filename or "china-ip-ipv6" in filename
            ):
                rules.extend([normalize_cidr(addr) for addr in cidrs])
            else:
                ip_rules = [f"IP-CIDR,{normalize_cidr(addr)}" for addr in cidrs]
                rules.extend(ip_rules)

    return rules or None


async def emit_mihomo_yaml(  # noqa: D103
    url: str,
    directory: str,
    category: str,
) -> anyio.Path | None:
    frame = await ingest(url)
    if frame.height == 0 or not frame.columns:
        return None

    frame = frame.filter(
        ~pl.col("pattern").str.contains("#")
        & ~pl.col("address").is_in(
            [
                "th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
                "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
            ]
        )
        & pl.col("pattern").is_in(MIHOMO_ALIASES),
    )
    if frame.height == 0:
        return None

    invalid = frame.filter(pl.col("pattern").is_in(list(MIHOMO_DENY)))
    if invalid.height > 0:
        obsolete = list(set(invalid["pattern"].unique().to_list()) & set(MIHOMO_DENY))
        if obsolete:
            frame = frame.filter(~pl.col("pattern").is_in(obsolete))

    asn_view = frame.filter(pl.col("pattern") == "IP-ASN")
    cidrs: list[str] = []
    if asn_view.height > 0:
        cidrs = await merge(asn_view["address"].unique().to_list())

    frame = frame.with_columns(pl.col("pattern").replace(MIHOMO_ALIAS))

    await anyio.Path(directory).mkdir(exist_ok=True, parents=True)

    rules = compose_mihomo_yaml(
        frame,
        cidrs,
        category,
        anyio.Path(url).stem.replace("_", "-"),
    )
    if not rules:
        return None

    file_name = anyio.Path(
        directory,
        f"{anyio.Path(url).stem.replace('_', '-')}.{category}.yaml",
    )
    async with await anyio.Path(file_name).open("w", encoding="utf-8") as handle:
        if "__custom_yaml__" in rules:
            await handle.write(rules["__custom_yaml__"])
        else:
            await handle.write(
                yaml.dump(rules, default_flow_style=False, sort_keys=False),
            )

    return file_name


async def emit_mihomo_text(  # noqa: D103
    url: str,
    directory: str,
    category: str,
) -> anyio.Path | None:
    frame = await ingest(url)
    if frame.height == 0 or not frame.columns:
        return None

    frame = frame.filter(
        ~pl.col("pattern").str.contains("#")
        & ~pl.col("address").is_in(
            [
                "th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
                "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
            ]
        )
        & pl.col("pattern").is_in(MIHOMO_ALIASES),
    )
    if frame.height == 0:
        return None

    invalid = frame.filter(pl.col("pattern").is_in(list(MIHOMO_DENY)))
    if invalid.height > 0:
        obsolete = list(set(invalid["pattern"].unique().to_list()) & set(MIHOMO_DENY))
        if obsolete:
            frame = frame.filter(~pl.col("pattern").is_in(obsolete))

    asn_view = frame.filter(pl.col("pattern") == "IP-ASN")
    cidrs: list[str] = []
    if asn_view.height > 0:
        cidrs = await merge(asn_view["address"].unique().to_list())

    frame = frame.with_columns(pl.col("pattern").replace(MIHOMO_ALIAS))

    await anyio.Path(directory).mkdir(exist_ok=True, parents=True)

    rules = compose_mihomo_text(
        frame,
        cidrs,
        category,
        anyio.Path(url).stem.replace("_", "-"),
    )
    if not rules:
        return None

    file_name = anyio.Path(
        directory,
        f"{anyio.Path(url).stem.replace('_', '-')}.{category}.txt",
    )
    async with await anyio.Path(file_name).open("w", encoding="utf-8") as handle:
        await handle.write("\n".join(rules))

    return file_name


async def emit_singbox_json(  # noqa: D103
    url: str,
    directory: str,
    category: str,
) -> anyio.Path | None:
    frame = await ingest(url)
    if frame.height == 0 or not frame.columns:
        return None

    frame = frame.filter(
        ~pl.col("pattern").str.contains("#")
        & ~pl.col("address").is_in(
            [
                "th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
                "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
            ]
        )
        & pl.col("pattern").is_in(SINGBOX_ALIASES),
    )
    if frame.height == 0:
        return None

    invalid = frame.filter(pl.col("pattern").is_in(list(SINGBOX_DENY)))
    if invalid.height > 0:
        obsolete = list(set(invalid["pattern"].unique().to_list()) & set(SINGBOX_DENY))
        if obsolete:
            frame = frame.filter(~pl.col("pattern").is_in(obsolete))

    asn_view = frame.filter(pl.col("pattern") == "IP-ASN")
    cidrs: list[str] = []
    if asn_view.height > 0:
        cidrs = await merge(asn_view["address"].unique().to_list())

    frame = frame.with_columns(pl.col("pattern").replace(SINGBOX_ALIAS))

    await anyio.Path(directory).mkdir(exist_ok=True, parents=True)

    rules = compose_singbox_json(frame, cidrs)
    if not rules.get("rules"):
        return None

    file_name = anyio.Path(
        directory,
        f"{anyio.Path(url).stem.replace('_', '-')}.{category}.json",
    )
    async with await anyio.Path(file_name).open("wb") as handle:
        await handle.write(orjson.dumps(rules, option=orjson.OPT_INDENT_2))

    return file_name


async def main() -> None:  # noqa: D103
    list_dir = anyio.Path("dist/List")

    if not await list_dir.exists():
        list_dir = anyio.Path("../dist/List")

    if not await list_dir.exists():
        return

    singbox_json_base = anyio.Path("sing-box/json")
    singbox_srs_base = anyio.Path("sing-box/srs")
    mihomo_yaml_base = anyio.Path("mihomo/yaml")
    mihomo_text_base = anyio.Path("mihomo/text")
    mihomo_mrs_base = anyio.Path("mihomo/mrs")

    for base_dir in [singbox_json_base, singbox_srs_base]:
        await asyncio.gather(
            *(
                (base_dir / subdir).mkdir(exist_ok=True, parents=True)
                for subdir in ["domainset", "ip", "non_ip", "dns"]
            ),
        )

    for base_dir in [mihomo_yaml_base, mihomo_text_base, mihomo_mrs_base]:
        await asyncio.gather(
            *(
                (base_dir / subdir).mkdir(exist_ok=True, parents=True)
                for subdir in ["domainset", "ip", "non_ip", "dns"]
            ),
        )

    conf_files = []
    for subdir in ["domainset", "ip", "non_ip"]:
        subdir_path = list_dir / subdir
        if await subdir_path.exists():
            conf_files.extend(
                [(conf_file, subdir) async for conf_file in subdir_path.glob("*.conf")],
            )

    singbox_tasks = [
        asyncio.create_task(
            emit_singbox_json(
                f"file://{await conf_file.absolute()}",
                str(singbox_json_base / category),
                category,
            ),
        )
        for conf_file, category in conf_files
    ]

    mihomo_yaml_tasks = [
        asyncio.create_task(
            emit_mihomo_yaml(
                f"file://{await conf_file.absolute()}",
                str(mihomo_yaml_base / category),
                category,
            ),
        )
        for conf_file, category in conf_files
    ]

    mihomo_text_tasks = [
        asyncio.create_task(
            emit_mihomo_text(
                f"file://{await conf_file.absolute()}",
                str(mihomo_text_base / category),
                category,
            ),
        )
        for conf_file, category in conf_files
    ]

    modules_dir = anyio.Path("dist/Modules/Rules/sukka_local_dns_mapping")
    if not await modules_dir.exists():
        modules_dir = anyio.Path("../dist/Modules/Rules/sukka_local_dns_mapping")

    if await modules_dir.exists():
        dns_files = [f async for f in modules_dir.glob("*.conf")]

        singbox_tasks.extend(
            [
                asyncio.create_task(
                    emit_singbox_json(
                        f"file://{await conf_file.absolute()}",
                        str(singbox_json_base / "dns"),
                        "dns",
                    ),
                )
                for conf_file in dns_files
            ],
        )

        mihomo_yaml_tasks.extend(
            [
                asyncio.create_task(
                    emit_mihomo_yaml(
                        f"file://{await conf_file.absolute()}",
                        str(mihomo_yaml_base / "dns"),
                        "dns",
                    ),
                )
                for conf_file in dns_files
            ],
        )

        mihomo_text_tasks.extend(
            [
                asyncio.create_task(
                    emit_mihomo_text(
                        f"file://{await conf_file.absolute()}",
                        str(mihomo_text_base / "dns"),
                        "dns",
                    ),
                )
                for conf_file in dns_files
            ],
        )

    all_tasks = singbox_tasks + mihomo_yaml_tasks + mihomo_text_tasks
    if all_tasks:
        await asyncio.gather(*all_tasks, return_exceptions=False)

    await POOL.aclose()


if __name__ == "__main__":
    asyncio.run(main())
