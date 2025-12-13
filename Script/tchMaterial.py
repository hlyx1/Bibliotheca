from __future__ import annotations  # noqa: CPY001, D100, INP001

import argparse
import contextlib
import operator
import os
import pathlib
import re
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


@dataclass(slots=True, frozen=True)
class Asset:  # noqa: D101
    url: str
    cid: str | None
    title: str | None


CLIENT = requests.Session()
CLIENT.proxies = {"http": None, "https": None}

RETRY = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=(500, 502, 503, 504, 429),
    allowed_methods=frozenset({"GET"}),
    raise_on_status=False,
    respect_retry_after_header=True,
)
ADAPTER = HTTPAdapter(max_retries=RETRY, pool_connections=32, pool_maxsize=64)
CLIENT.mount("https://", ADAPTER)
CLIENT.mount("http://", ADAPTER)

AUTH_HEADER = "X-ND-AUTH"
PDF_REWRITER = re.compile(
    r"^https?://(?:.+)\.ykt\.cbern\.com\.cn/(.+)/([\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12})\.pkg/(.+)\.pdf$",
).sub
SYNC_MATCH = re.compile(r"^https?://[^/]+/syncClassroom/basicWork/detail").match
HTTP_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 60
CHUNK_BYTES = 131072
PROGRESS_DELAY = 0.25

CLIENT.headers.update({
    AUTH_HEADER: 'MAC id="0",nonce="0",mac="0"',
    "Accept": "application/json",
    "Connection": "keep-alive",
})

TOKEN: str | None = None


def set_token(token: str) -> str:  # noqa: D103
    global TOKEN  # noqa: PLW0603
    TOKEN = token.strip() if token else None
    CLIENT.headers[AUTH_HEADER] = f'MAC id="{TOKEN or "0"}",nonce="0",mac="0"'
    return "Access token applied."


def resolve_asset(url: str) -> Asset | None:  # noqa: C901, D103
    try:  # noqa: PLR1702
        params = parse_qs(url.split("?", 1)[1]) if "?" in url else {}
        cid = (params.get("contentId") or [None])[-1]
        if not cid:
            return None
        ctype = (params.get("contentType") or ["assets_document"])[-1]
        endpoint = (
            f"https://s-file-1.ykt.cbern.com.cn/zxx/ndrs/special_edu/resources/details/{cid}.json"
            if SYNC_MATCH(url) or ctype == "thematic_course"
            else f"https://s-file-1.ykt.cbern.com.cn/zxx/ndrv2/resources/tch_material/details/{cid}.json"
        )
        payload = CLIENT.get(endpoint, timeout=HTTP_TIMEOUT).json()
        resource_url = None
        for item in payload.get("ti_items", ()):
            if item.get("lc_ti_format") == "pdf":
                resource_url = item["ti_storages"][0]
                break
        if not resource_url and ctype == "thematic_course":
            listing = CLIENT.get(
                f"https://s-file-1.ykt.cbern.com.cn/zxx/ndrs/special_edu/thematic_course/{cid}/resources/list.json",
                timeout=HTTP_TIMEOUT,
            ).json()
            for entry in listing:
                if entry.get("resource_type_code") == "assets_document":
                    for item in entry.get("ti_items", ()):
                        if item.get("lc_ti_format") == "pdf":
                            resource_url = item["ti_storages"][0]
                            break
                    if resource_url:
                        break
        if not resource_url:
            return None
        if not TOKEN:
            resource_url = PDF_REWRITER(r"https://c1.ykt.cbern.com.cn/\1/\2.pkg/\3.pdf", resource_url)
        return Asset(url=resource_url, cid=cid, title=payload.get("title"))
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None


def format_bytes(size: float) -> str:  # noqa: D103
    for u in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:  # noqa: PLR2004
            return f"{size:3.1f}{u}"
        size /= 1024.0
    return f"{size:3.1f}PB"


def clean_name(name: str) -> str:  # noqa: D103
    return re.sub(r'[\/:*?"<>|]', "_", name).strip() or "download"


def prepare_path(path: pathlib.Path, *, overwrite: bool) -> None:  # noqa: D103
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        msg = f"Destination exists: {path}. Use --overwrite to replace."
        raise FileExistsError(msg)


def download(url: str, dest: pathlib.Path, *, progress: bool = True) -> None:  # noqa: D103
    resp = CLIENT.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT)
    try:  # noqa: PLR1702
        if resp.status_code >= 400:  # noqa: PLR2004
            hint = " Access token might be invalid." if resp.status_code in {401, 403} else ""
            msg = f"HTTP {resp.status_code}.{hint}"
            raise requests.HTTPError(msg)

        total = int(resp.headers.get("Content-Length", 0) or 0)
        dl = 0
        prepare_path(dest, overwrite=True)
        resp.raw.decode_content = False
        tmp = None
        next_emit = time.monotonic()

        try:
            with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(dest.parent)) as f:
                tmp = pathlib.Path(f.name)
                buf = memoryview(bytearray(CHUNK_BYTES))
                write, readinto = f.write, resp.raw.readinto
                while True:
                    n = readinto(buf)
                    if not n:
                        break
                    write(buf[:n])
                    dl += n
                    if progress:
                        now = time.monotonic()
                        if total:
                            if dl == total or now >= next_emit:
                                sys.stdout.write(
                                    f"\r>> {dest.name}: {format_bytes(dl)}/{format_bytes(total)} ({dl / total * 100:5.1f}%)",  # noqa: E501
                                )
                                sys.stdout.flush()
                                next_emit = now + PROGRESS_DELAY
                        elif now >= next_emit:
                            sys.stdout.write(f"\r>> {dest.name}: {format_bytes(dl)} transferred")
                            sys.stdout.flush()
                            next_emit = now + PROGRESS_DELAY
            pathlib.Path(tmp).replace(dest)
            tmp = None
        finally:
            if tmp and tmp.exists():
                with contextlib.suppress(OSError):
                    tmp.unlink()

        if progress:
            sys.stdout.write(
                f"\r>> {dest.name}: {format_bytes(total or dl)}"
                + (f"/{format_bytes(total)} (100.0%)\n" if total else " transferred\n"),
            )
            sys.stdout.flush()
    finally:
        resp.close()


def collect_urls(pos: Iterable[str], source: str | None) -> list[str]:  # noqa: D103
    urls = [entry.strip() for entry in pos if entry.strip()]
    if source:
        if source == "-":
            urls.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            path = pathlib.Path(source)
            if not path.exists():
                msg = f"URL source unavailable: {source}"
                raise FileNotFoundError(msg)
            urls.extend(line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    return list(dict.fromkeys(urls))


def resolve_all(urls: Iterable[str]) -> tuple[list[Asset], list[str]]:  # noqa: D103
    ordered: list[str] = list(urls)
    total = len(ordered)
    if not total:
        return [], []
    if total == 1:
        asset = resolve_asset(ordered[0])
        return ([asset], []) if asset else ([], ordered)

    workers = min(32, max(4, (os.cpu_count() or 1) * 4))
    success = [None] * total
    failure = []

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="asset") as executor:
        future_map = {executor.submit(resolve_asset, url): (index, url) for index, url in enumerate(ordered)}
        for future in as_completed(future_map):
            index, url = future_map[future]
            try:
                asset = future.result()
            except (requests.RequestException, ValueError, KeyError, TypeError):
                asset = None
            if asset is None:
                failure.append((index, url))
            else:
                success[index] = asset

    return [item for item in success if item], [url for _, url in sorted(failure, key=operator.itemgetter(0))]


def make_name(asset: Asset) -> str:  # noqa: D103
    if asset.title:
        return clean_name(asset.title) + ".pdf"
    if asset.cid:
        return f"{asset.cid}.pdf"
    return "download.pdf"


def run_parse(args: argparse.Namespace) -> int:  # noqa: D103
    urls = collect_urls(args.urls, args.from_file)
    if not urls:
        print("No URL supplied.", file=sys.stderr)  # noqa: T201
        return 1

    assets, unresolved = resolve_all(urls)

    if args.output:
        path = pathlib.Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(asset.url for asset in assets), encoding="utf-8")
    else:
        for asset in assets:
            print(asset.url)  # noqa: T201

    if unresolved:
        print("Unresolved URLs:", file=sys.stderr)  # noqa: T201
        for url in unresolved:
            print(f"  - {url}", file=sys.stderr)  # noqa: T201
        return 1 if not assets else 0

    return 0


def run_download(args: argparse.Namespace) -> int:  # noqa: C901, D103, PLR0912
    urls = collect_urls(args.urls, args.from_file)
    if not urls:
        print("No URL supplied.", file=sys.stderr)  # noqa: T201
        return 1

    assets, unresolved = resolve_all(urls)
    if not assets:
        print("No downloadable resources resolved.", file=sys.stderr)  # noqa: T201
        if unresolved:
            for url in unresolved:
                print(f"  - {url}", file=sys.stderr)  # noqa: T201
        return 1

    multiple = len(assets) > 1
    target_dir = None
    if args.output_dir:
        target_dir = pathlib.Path(args.output_dir).expanduser()
        target_dir.mkdir(parents=True, exist_ok=True)

    if multiple and not target_dir:
        print("--output-dir is mandatory when downloading multiple files.", file=sys.stderr)  # noqa: T201
        return 1

    if args.output and multiple:
        print("--output only supports single download targets.", file=sys.stderr)  # noqa: T201
        return 1

    if args.output:
        destination = pathlib.Path(args.output).expanduser()
        try:
            prepare_path(destination, overwrite=args.overwrite)
        except FileExistsError as err:
            print(err, file=sys.stderr)  # noqa: T201
            return 1

    exit_code = 0

    for asset in assets:
        destination = (
            target_dir / make_name(asset)
            if target_dir
            else (pathlib.Path(args.output).expanduser() if args.output else pathlib.Path(make_name(asset)))
        )

        try:
            prepare_path(destination, overwrite=args.overwrite)
        except FileExistsError as err:
            print(err, file=sys.stderr)  # noqa: T201
            exit_code = 1
            continue

        try:
            print(f"Fetch: {asset.url}")  # noqa: T201
            download(asset.url, destination, progress=not args.quiet)
        except (requests.RequestException, OSError, ValueError) as err:
            print(f"Download failure: {asset.url}\n  Reason: {err}", file=sys.stderr)  # noqa: T201
            exit_code = 1

    if unresolved:
        print("Unresolved URLs:", file=sys.stderr)  # noqa: T201
        for url in unresolved:
            print(f"  - {url}", file=sys.stderr)  # noqa: T201
        exit_code = 1

    return exit_code


def run_token(args: argparse.Namespace) -> int:  # noqa: D103
    print(set_token(args.token))  # noqa: T201
    return 0


def build_cli() -> argparse.ArgumentParser:  # noqa: D103
    parser = argparse.ArgumentParser(
        description="SmartEdu resource parser and downloader (CLI)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--token", help="Access token applied before executing commands.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_parser = subparsers.add_parser("parse", help="Resolve resource URLs to downloadable endpoints.")
    parse_parser.add_argument("urls", nargs="*", help="Resource page URLs.")
    parse_parser.add_argument("-f", "--from-file", help="Read URLs from file or '-' for stdin.")
    parse_parser.add_argument("-o", "--output", help="Write resolved URLs to file.")
    parse_parser.set_defaults(func=run_parse)

    download_parser = subparsers.add_parser("download", help="Resolve and download PDF payloads.")
    download_parser.add_argument("urls", nargs="*", help="Resource page URLs.")
    download_parser.add_argument("-f", "--from-file", help="Read URLs from file or '-' for stdin.")
    download_parser.add_argument("-o", "--output", help="Target path (single download mode).")
    download_parser.add_argument("-d", "--output-dir", help="Target directory for batch downloads.")
    download_parser.add_argument("--overwrite", action="store_true", help="Allow overwriting outputs.")
    download_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output.")
    download_parser.set_defaults(func=run_download)

    token_parser = subparsers.add_parser("set-token", help="Apply access token for current session only.")
    token_parser.add_argument("token", help="Access token value.")
    token_parser.set_defaults(func=run_token)

    return parser


def main(argv: Sequence[str] | None = None) -> int:  # noqa: D103
    parser = build_cli()
    args = parser.parse_args(argv)
    if args.token:
        set_token(args.token)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
