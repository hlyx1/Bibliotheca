from __future__ import annotations  # noqa: CPY001, D100, INP001

import asyncio
import datetime as dt
import functools
import pathlib
import re
import sys
import typing
import urllib.parse

import aiofiles
import httpx
import orjson
from bs4 import BeautifulSoup
from markdownify import markdownify as md

ROOT: typing.Final = pathlib.Path(__file__).resolve().parent
README_FILE: typing.Final = ROOT / "README.md"
CATALOG_FILE: typing.Final = ROOT / "catalogue.json"

BASE_HEADERS: typing.Final = {
    "accept": "text/html,*/*;q=0.01",
    "accept-language": "en-US,en;q=0.9",
    "cache-control": "no-cache",
    "sec-ch-ua": '"Edge";v="107","Chromium";v="107"',
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "x-requested-with": "XMLHttpRequest",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

UTC8: typing.Final = dt.timezone(dt.timedelta(hours=8))
CCTV_TAG: typing.Final = re.compile(
    rb"<strong>\xe5\xa4\xae\xe8\xa7\x86\xe7\xbd\x91\xe6\xb6\x88\xe6\x81\xaf</strong>\xef\xbc\x88\xe6\x96\xb0\xe9\x97\xbb\xe8\x81\x94\xe6\x92\xad\xef\xbc\x89\xef\xbc\x9a",
)
TITLE_SELECTOR: typing.Final = ".video18847 .playingVideo .tit,.tit"
BODY_SELECTOR: typing.Final = "#content_area"


class IndexEntry(typing.TypedDict):  # noqa: D101
    date: str


class ItemEntry(typing.TypedDict):  # noqa: D101
    title: str
    payload: bytes
    link: str


@functools.lru_cache(maxsize=1)
def datecode() -> str:  # noqa: D103
    return dt.datetime.now(UTC8).strftime("%Y%m%d")


@functools.lru_cache(maxsize=1)
def timetag() -> str:  # noqa: D103
    return dt.datetime.now(UTC8).strftime("%Y-%m-%d %H:%M")


async def pull_bytes(  # noqa: D103
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 3,
    pause: float = 0.5,
) -> bytes:
    delay = pause
    for attempt in range(1, retries + 1):
        try:
            response = await client.get(url, headers={"Referer": url})
            response.raise_for_status()
            return response.content  # noqa: TRY300
        except (
            httpx.TimeoutException,
            httpx.RequestError,
            httpx.HTTPStatusError,
        ) as exc:  # noqa: PERF203
            if attempt == retries:
                msg = f"Acquisition failure: {exc}"
                raise RuntimeError(msg) from exc
            await asyncio.sleep(delay)
            delay *= 1.5
    msg = f"Acquisition failure: exhausted retries for {url}"
    raise RuntimeError(msg)


async def pull_index(client: httpx.AsyncClient, day: str) -> list[str]:  # noqa: D103
    target = f"http://tv.cctv.com/lm/xwlb/day/{day}.shtml"
    try:
        payload = await pull_bytes(client, target)
    except Exception:  # noqa: BLE001
        return []

    soup = BeautifulSoup(payload, "lxml")
    links: list[str] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if "shtml" not in href:
            continue
        absolute = urllib.parse.urljoin(target, href)
        if absolute in seen:
            continue
        seen.add(absolute)
        links.append(absolute)
    return links


async def pull_item(client: httpx.AsyncClient, link: str) -> ItemEntry:  # noqa: D103
    try:
        payload = await pull_bytes(client, link)
    except Exception:  # noqa: BLE001
        return {"title": "", "payload": b"", "link": link}

    soup = BeautifulSoup(payload, "lxml")
    title_node = soup.select_one(TITLE_SELECTOR)
    title = title_node.text if title_node else ""
    title = title.replace("[视频]", "").replace("[Video]", "").strip()

    body_node = soup.select_one(BODY_SELECTOR)
    body_bytes = str(body_node).encode() if body_node else b""
    return {"title": title, "payload": body_bytes, "link": link}


async def pull_batch(client: httpx.AsyncClient, links: list[str]) -> list[ItemEntry]:  # noqa: D103
    if not links:
        return []

    limit = max(1, min(len(links), 64))
    gate = asyncio.Semaphore(limit)

    async def worker(link: str) -> ItemEntry:
        async with gate:
            return await pull_item(client, link)

    return await asyncio.gather(
        *(worker(link) for link in links), return_exceptions=False
    )


def render_markdown(items: list[ItemEntry]) -> str:  # noqa: D103
    stamp = timetag()
    blocks = [f"- 时间：{stamp}\n"]  # noqa: RUF001

    for item in items:
        title = item["title"].strip()
        if not title or "新闻联播" in title:
            continue

        payload = item["payload"]
        if payload:
            cleaned = CCTV_TAG.sub(b"", payload).decode(errors="ignore")
            body = md(cleaned, heading_style="ATX_CLOSED").strip()
        else:
            body = ""

        blocks.append(f"\n## {title}\n")
        if body:
            blocks.append(f"{body}\n\n")
        blocks.append(f"- [链接]({item['link']})\n")

    return "".join(blocks)


async def sync_catalog(day: str, doc_path: pathlib.Path) -> None:  # noqa: D103
    try:
        entries: list[IndexEntry] = []
        if CATALOG_FILE.exists():
            async with aiofiles.open(CATALOG_FILE, "rb") as handle:
                payload = await handle.read()
            if payload:
                entries = typing.cast("list[IndexEntry]", orjson.loads(payload))

        if not any(entry.get("date") == day for entry in entries):
            entries.insert(0, {"date": day})
            temp_catalog = CATALOG_FILE.with_suffix(".tmp")
            async with aiofiles.open(temp_catalog, "wb") as handle:
                await handle.write(orjson.dumps(entries))
            temp_catalog.replace(CATALOG_FILE)

        if README_FILE.exists():
            async with aiofiles.open(README_FILE, encoding="utf-8") as handle:
                readme = await handle.read()

            marker = "<!-- INSERT -->"
            record = f"- [{day}](./{doc_path.relative_to(ROOT).as_posix()})"
            if record not in readme:
                updated = readme.replace(marker, f"{marker}\n{record}")
                temp_readme = README_FILE.with_suffix(".tmp")
                async with aiofiles.open(temp_readme, "w", encoding="utf-8") as handle:
                    await handle.write(updated)
                temp_readme.replace(README_FILE)

    except Exception as exc:
        msg = f"Catalogue synchronization failure: {exc}"
        raise RuntimeError(msg) from exc


async def main() -> None:  # noqa: C901, D103, PLR0912
    today = datecode()

    try:
        days: list[str]
        if CATALOG_FILE.exists():
            async with aiofiles.open(CATALOG_FILE, "rb") as f:
                buf = await f.read()
            if buf:
                idx = typing.cast("list[IndexEntry]", orjson.loads(buf))
                seen = {e.get("date", "") for e in idx if e.get("date")}
            else:
                seen = set()
        else:
            seen = set()

        if not seen:
            days = [today]
        else:
            last = max(seen)
            s = dt.datetime.strptime(last, "%Y%m%d").replace(tzinfo=UTC8).date()
            t = dt.datetime.strptime(today, "%Y%m%d").replace(tzinfo=UTC8).date()
            if s > t:
                days = [today]
            else:
                span = (t - s).days
                if span <= 0:
                    days = [d for d in (today,) if d not in seen] or [today]
                else:
                    days = [
                        (s + dt.timedelta(days=i)).strftime("%Y%m%d")
                        for i in range(span + 1)
                        if (s + dt.timedelta(days=i)).strftime("%Y%m%d") not in seen
                    ]
                    if today not in days:
                        days.append(today)

        if not days:
            return

        async with httpx.AsyncClient(
            headers=BASE_HEADERS,
            timeout=5.0,
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=128, max_connections=256),
            http2=True,
            trust_env=False,
        ) as client:
            for day in days:
                year_dir = ROOT / day[:4]
                doc_path = year_dir / f"{day}.md"

                year_dir.mkdir(parents=True, exist_ok=True)

                links = await pull_index(client, day)
                if not links:
                    continue

                items = await pull_batch(client, links)
                if not items:
                    continue

                content = render_markdown(items)
                tmp = doc_path.with_suffix(".tmp")
                async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                    await f.write(content)
                tmp.replace(doc_path)

                await sync_catalog(day, doc_path)

    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)  # noqa: T201
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
