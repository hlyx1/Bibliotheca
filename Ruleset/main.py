import asyncio  # noqa: CPY001, D100, INP001
import contextlib
import ipaddress
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
    rows: list[dict[str, str]] = []
    for item in parsed.get("payload", ()):
        entry = item.strip("'\"")
        if "," not in item:
            if is_net(entry):
                kind = "IP-CIDR"
            elif entry.startswith("+"):
                kind = "DOMAIN-SUFFIX"
                entry = entry[1:].lstrip(".")
            else:
                kind = "DOMAIN"
        else:
            parts = item.split(",", 2)
            kind = parts[0].strip()
            entry = parts[1].strip()
        rows.append({"pattern": kind, "address": entry})
    return rows


def decode_list(blob: str) -> list[dict[str, str]]:  # noqa: D103
    entries: list[dict[str, str]] = []
    for raw in blob.strip().split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 2)
        if len(parts) >= 2:  # noqa: PLR2004
            entries.append({"pattern": parts[0].strip(), "address": parts[1].strip()})
        elif len(parts) == 1:
            address = parts[0].strip().removeprefix(".")
            entries.append({"pattern": "DOMAIN-SUFFIX", "address": address})
    return entries


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
    cidrs: list[str] = []
    for bundle in bundles:
        if isinstance(bundle, list):
            cidrs.extend(bundle)
    return cidrs


def mask_regex(pattern: str) -> str:  # noqa: D103
    masked = pattern.lstrip(".")
    escaped = masked.replace(".", r"\.").replace("*", "MASK")
    return f"^{escaped.replace('MASK', r'[^.]+')}$"


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
            payload.setdefault("domain_regex", []).extend(addresses)
            continue

        if pattern == "domain_wildcard":
            payload.setdefault("domain_regex", []).extend(mask_regex(item) for item in addresses)
            continue

        if pattern == "ip_cidr":
            payload.setdefault("ip_cidr", []).extend(normalize_cidr(item) for item in addresses)
            continue

        if pattern == "source_ip_cidr":
            payload.setdefault("source_ip_cidr", []).extend(normalize_cidr(item) for item in addresses)
            continue

        if pattern == "port":
            ports: list[int] = []
            ranges: list[str] = []
            for item in addresses:
                span, value = split_port(item)
                if span is not None:
                    ranges.append(span)
                elif value is not None:
                    ports.append(value)
            if ports:
                payload.setdefault("port", []).extend(ports)
            if ranges:
                payload.setdefault("port_range", []).extend(ranges)
            continue

        if pattern == "source_port":
            ports: list[int] = []
            ranges: list[str] = []
            for item in addresses:
                span, value = split_port(item)
                if span is not None:
                    ranges.append(span)
                elif value is not None:
                    ports.append(value)
            if ports:
                payload.setdefault("source_port", []).extend(ports)
            if ranges:
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

    for key, value in list(payload.items()):
        if isinstance(value, list):
            if key in {"port", "source_port"}:
                payload[key] = sorted(set(value))
            elif key in {"port_range", "source_port_range"}:
                payload[key] = list(dict.fromkeys(value))
            else:
                payload[key] = list(dict.fromkeys(value))

    ordered: dict[str, Any] = {}
    for field in ORDER:
        if payload.get(field):
            ordered[field] = payload[field]

    for field, value in payload.items():
        if field not in ordered and value:
            ordered[field] = value

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


async def main() -> None:  # noqa: C901, D103
    list_dir = anyio.Path("dist/List")

    if not await list_dir.exists():
        list_dir = anyio.Path("../dist/List")

    if not await list_dir.exists():
        return

    json_base = anyio.Path("sing-box/json")
    srs_base = anyio.Path("sing-box/srs")

    for base_dir in [json_base, srs_base]:
        for subdir in ["domainset", "ip", "non_ip", "local_dns"]:
            await (base_dir / subdir).mkdir(exist_ok=True, parents=True)

    conf_files = []
    for subdir in ["domainset", "ip", "non_ip"]:
        subdir_path = list_dir / subdir
        if await subdir_path.exists():
            conf_files.extend([(conf_file, subdir) async for conf_file in subdir_path.glob("*.conf")])

    tasks: list[asyncio.Task[Any]] = []
    for conf_file, category in conf_files:
        file_url = f"file://{await conf_file.absolute()}"
        output_dir = json_base / category
        tasks.append(asyncio.create_task(emit(file_url, str(output_dir), category)))

    modules_dir = anyio.Path("dist/Modules/Rules/sukka_local_dns_mapping")
    if not await modules_dir.exists():
        modules_dir = anyio.Path("../dist/Modules/Rules/sukka_local_dns_mapping")

    if await modules_dir.exists():
        local_dns_files = [f async for f in modules_dir.glob("*.conf")]
        for conf_file in local_dns_files:
            file_url = f"file://{await conf_file.absolute()}"
            output_dir = json_base / "local_dns"
            tasks.append(asyncio.create_task(emit(file_url, str(output_dir), "local_dns")))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=False)

    await POOL.aclose()


if __name__ == "__main__":
    asyncio.run(main())
