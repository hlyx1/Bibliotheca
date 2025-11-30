import asyncio  # noqa: CPY001, D100, INP001
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


ALIAS = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-SET": "domain_suffix",
    "URL-REGEX": "domain_regex",
    "DOMAIN-WILDCARD": "domain_wildcard",
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
    "PROTOCOL": "network",
    "NETWORK": "network",
    "HOST": "domain",
    "HOST-SUFFIX": "domain_suffix",
    "HOST-KEYWORD": "domain_keyword",
    "host": "domain",
    "host-suffix": "domain_suffix",
    "host-keyword": "domain_keyword",
    "ip-cidr": "ip_cidr",
    "ip-cidr6": "ip_cidr",
}

ORDER = [
    "query_type",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "ip_cidr",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "network_interface_address",
    "default_interface_address",
    "wifi_ssid",
    "wifi_bssid",
    "invert",
]


DENY = frozenset({
    "USER-AGENT",
    "CELLULAR-RADIO",
    "DEVICE-NAME",
    "MAC-ADDRESS",
    "FINAL",
    "GEOIP",
    "GEOSITE",
    "SOURCE-GEOIP",
})

ALIASES = tuple(ALIAS.keys())


async def prefix(asn: str) -> list[str]:  # noqa: D103
    cached = ASN_CACHE.get(asn)
    if cached is not None:
        return cached

    asn_id = asn.replace("AS", "").replace("as", "")
    cidrs: list[str] = []

    with contextlib.suppress(httpx.HTTPError, orjson.JSONDecodeError, KeyError):
        resp = await POOL.get(f"https://api.bgpview.io/asn/{asn_id}/prefixes")
        if resp.status_code == 200:  # noqa: PLR2004
            body = orjson.loads(resp.content)
            if body.get("status") == "ok":
                blob = body.get("data", {})
                cidrs.extend(item["prefix"] for item in blob.get("ipv4_prefixes", ()))
                cidrs.extend(item["prefix"] for item in blob.get("ipv6_prefixes", ()))
                if cidrs:
                    ASN_CACHE[asn] = cidrs
                    return cidrs

    with contextlib.suppress(httpx.HTTPError, orjson.JSONDecodeError, KeyError):
        resp = await POOL.get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_id}",
        )
        if resp.status_code == 200:  # noqa: PLR2004
            body = orjson.loads(resp.content)
            if body.get("status") == "ok":
                cidrs.extend(item["prefix"] for item in body.get("data", {}).get("prefixes", ()) if "prefix" in item)
                if cidrs:
                    ASN_CACHE[asn] = cidrs
                    return cidrs

    ASN_CACHE[asn] = cidrs
    return cidrs


async def fetch(url: str) -> str:  # noqa: D103
    if url.startswith("file://"):
        path = url[7:]
        async with await anyio.Path(path).open("r", encoding="utf-8") as handle:
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
            "address": ((entry := entry[1:].lstrip(".")) if entry.startswith("+") else entry)
            if "," not in item
            else item.split(",", 2)[1].strip(),
        }
        for item in parsed.get("payload", ())
    ]


def decode_list(blob: str) -> list[dict[str, str]]:  # noqa: D103
    return [
        {"pattern": parts[0].strip(), "address": parts[1].strip()}
        if len(parts := line.split(",", 2)) >= 2  # noqa: PLR2004
        else {"pattern": "DOMAIN-SUFFIX", "address": parts[0].strip().removeprefix(".")}
        for line in blob.strip().split("\n")
        if line.strip() and not line.startswith("#")
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
    bundles = await asyncio.gather(*(prefix(item) for item in asn_list), return_exceptions=True)
    return list(itertools.chain.from_iterable(bundle for bundle in bundles if isinstance(bundle, list)))


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
    else:
        with contextlib.suppress(ValueError):
            return None, int(item)
    return None, None


def compose(frame: pl.DataFrame, cidrs: list[str]) -> dict[str, Any]:  # noqa: C901, D103, PLR0912, PLR0915
    rules: dict[str, Any] = {"version": 4, "rules": [{}]}
    payload: dict[str, Any] = rules["rules"][0]

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    for block in grouped.iter_rows(named=True):
        pattern, addresses = block["pattern"], block["address"]

        if pattern == "domain":
            payload.setdefault("domain", []).extend(addresses)
            continue

        if pattern == "domain_suffix":
            payload.setdefault("domain_suffix", []).extend(
                f".{item}" if not item.startswith(".") else item for item in addresses
            )
            continue

        if pattern == "domain_keyword":
            payload.setdefault("domain_keyword", []).extend(addresses)
            continue

        if pattern == "domain_regex":
            valid_regexes = [item for item in addresses if validate_regex(item)]
            if valid_regexes:
                payload.setdefault("domain_regex", []).extend(valid_regexes)
            continue

        if pattern == "domain_wildcard":
            regex_patterns = [regex for item in addresses if (regex := mask_regex(item)) and validate_regex(regex)]
            if regex_patterns:
                payload.setdefault("domain_regex", []).extend(regex_patterns)
            continue

        if pattern == "ip_cidr":
            payload.setdefault("ip_cidr", []).extend(normalize_cidr(item) for item in addresses)
            continue

        if pattern == "source_ip_cidr":
            payload.setdefault("source_ip_cidr", []).extend(normalize_cidr(item) for item in addresses)
            continue

        if pattern == "port":
            ports, ranges = (
                zip(
                    *[
                        (None, span) if (span := split_port(item)[0]) is not None else (value, None)
                        for item in addresses
                        if (span := split_port(item)[0]) is not None or (value := split_port(item)[1]) is not None
                    ],
                    strict=False,
                )
                if addresses
                else ([], [])
            )
            if ports := [p for p in ports if p is not None]:
                payload.setdefault("port", []).extend(ports)
            if ranges := [r for r in ranges if r is not None]:
                payload.setdefault("port_range", []).extend(ranges)
            continue

        if pattern == "source_port":
            ports, ranges = (
                zip(
                    *[
                        (None, span) if (span := split_port(item)[0]) is not None else (value, None)
                        for item in addresses
                        if (span := split_port(item)[0]) is not None or (value := split_port(item)[1]) is not None
                    ],
                    strict=False,
                )
                if addresses
                else ([], [])
            )
            if ports := [p for p in ports if p is not None]:
                payload.setdefault("source_port", []).extend(ports)
            if ranges := [r for r in ranges if r is not None]:
                payload.setdefault("source_port_range", []).extend(ranges)
            continue

        if pattern == "process_name":
            payload.setdefault("process_name", []).extend(addresses)
            continue

        if pattern == "process_path":
            payload.setdefault("process_path", []).extend(addresses)
            continue

        if pattern == "network":
            proto = [entry.lower() for entry in addresses if entry.upper() in {"TCP", "UDP", "ICMP"}]
            if proto:
                payload.setdefault("network", []).extend(proto)

    if cidrs:
        payload.setdefault("ip_cidr", []).extend(normalize_cidr(item) for item in cidrs)

    payload = {
        key: (sorted(set(value)) if key in {"port", "source_port"} else list(dict.fromkeys(value)))
        for key, value in payload.items()
        if isinstance(value, list)
    }

    ordered = {field: payload[field] for field in ORDER if payload.get(field)}
    ordered.update({field: value for field, value in payload.items() if field not in ordered and value})

    if not ordered:
        return {"version": 2, "rules": []}

    rules["rules"][0] = ordered
    return rules


async def emit(url: str, directory: str, category: str) -> anyio.Path | None:  # noqa: D103
    frame = await ingest(url)
    if frame.height == 0 or not frame.columns:
        return None

    frame = frame.filter(
        ~pl.col("pattern").str.contains("#")
        & ~pl.col("address").str.ends_with("-ruleset.skk.moe")
        & pl.col("pattern").is_in(ALIASES),
    )
    if frame.height == 0:
        return None

    invalid = frame.filter(pl.col("pattern").is_in(list(DENY)))
    if invalid.height > 0:
        obsolete = [item for item in invalid["pattern"].unique().to_list() if item in DENY]
        if obsolete:
            frame = frame.filter(~pl.col("pattern").is_in(obsolete))

    asn_view = frame.filter(pl.col("pattern") == "IP-ASN")
    cidrs: list[str] = []
    if asn_view.height > 0:
        cidrs = await merge(asn_view["address"].unique().to_list())

    frame = frame.with_columns(pl.col("pattern").replace(ALIAS))

    await anyio.Path(directory).mkdir(exist_ok=True, parents=True)

    rules = compose(frame, cidrs)
    if not rules.get("rules"):
        return None

    file_name = anyio.Path(directory, f"{anyio.Path(url).stem.replace('_', '-')}.{category}.json")
    async with await anyio.Path(file_name).open("wb") as handle:
        await handle.write(orjson.dumps(rules, option=orjson.OPT_INDENT_2))

    return file_name


async def main() -> None:  # noqa: D103
    list_dir = anyio.Path("dist/List")

    if not await list_dir.exists():
        list_dir = anyio.Path("../dist/List")

    if not await list_dir.exists():
        return

    json_base = anyio.Path("sing-box/json")
    srs_base = anyio.Path("sing-box/srs")

    for base_dir in [json_base, srs_base]:
        for subdir in ["domainset", "ip", "non_ip", "dns"]:
            await (base_dir / subdir).mkdir(exist_ok=True, parents=True)

    conf_files = [
        (conf_file, subdir)
        for subdir in ["domainset", "ip", "non_ip"]
        if await (subdir_path := list_dir / subdir).exists()
        for conf_file in [f async for f in subdir_path.glob("*.conf")]
    ]

    tasks = [
        asyncio.create_task(emit(f"file://{await conf_file.absolute()}", str(json_base / category), category))
        for conf_file, category in conf_files
    ]

    modules_dir = anyio.Path("dist/Modules/Rules/sukka_local_dns_mapping")
    if not await modules_dir.exists():
        modules_dir = anyio.Path("../dist/Modules/Rules/sukka_local_dns_mapping")

    if await modules_dir.exists():
        tasks.extend([
            asyncio.create_task(emit(f"file://{await conf_file.absolute()}", str(json_base / "dns"), "dns"))
            for conf_file in [f async for f in modules_dir.glob("*.conf")]
        ])

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=False)

    await POOL.aclose()


if __name__ == "__main__":
    asyncio.run(main())
