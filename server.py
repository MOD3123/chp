import asyncio
import os
import re
import ssl
import urllib.parse
import urllib.request
from typing import Optional

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector
from aiohttp_socks import ProxyConnector


PORT = int(os.getenv("PORT", "10000"))

PROXY_SOURCE = (
    "https://api.proxyscrape.com/v4/free-proxy-list/get"
    "?request=display_proxies"
    "&proxy_format=protocolipport"
    "&format=text"
    "&country=ch"
)

PROXY_REFRESH_SECONDS = 300
REQUEST_TIMEOUT = 30

proxy_cache = []
proxy_cache_time = 0


async def fetch_proxy_list():
    global proxy_cache, proxy_cache_time

    now = asyncio.get_event_loop().time()

    if proxy_cache and now - proxy_cache_time < PROXY_REFRESH_SECONDS:
        return proxy_cache

    print("[PROXY] Downloading ProxyScrape list...", flush=True)

    try:
        req = urllib.request.Request(
            PROXY_SOURCE,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        with urllib.request.urlopen(req, timeout=15) as response:
            data = response.read().decode("utf-8", errors="ignore")

        proxies = []

        for line in data.splitlines():
            line = line.strip()

            if not line:
                continue

            if not re.match(
                r"^(https?|socks4|socks5)://[^:\s]+:\d+$",
                line,
                re.IGNORECASE,
            ):
                continue

            proxies.append(line)

        proxy_cache = proxies
        proxy_cache_time = now

        print(
            f"[PROXY] Loaded {len(proxies)} proxies",
            flush=True,
        )

        return proxies

    except Exception as exc:
        print(
            f"[PROXY] Failed to download proxy list: {exc}",
            flush=True,
        )

        return proxy_cache


def clean_headers(headers):
    """
    Forward request headers while removing hop-by-hop headers.
    Authorization is intentionally preserved.
    """

    hop_by_hop = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
        "host",
    }

    result = {}

    for key, value in headers.items():
        if key.lower() in hop_by_hop:
            continue

        result[key] = value

    return result


async def request_via_http_proxy(
    proxy: str,
    method: str,
    url: str,
    headers: dict,
    body: bytes,
):
    parsed = urllib.parse.urlparse(proxy)

    proxy_url = f"http://{parsed.hostname}:{parsed.port}"

    timeout = ClientTimeout(total=REQUEST_TIMEOUT)

    connector = TCPConnector(
        ssl=False,
        limit=20,
    )

    async with ClientSession(
        connector=connector,
        timeout=timeout,
    ) as session:

        async with session.request(
            method,
            url,
            headers=headers,
            data=body if body else None,
            proxy=proxy_url,
            allow_redirects=False,
        ) as response:

            response_body = await response.read()

            response_headers = {}

            for key, value in response.headers.items():

                if key.lower() in {
                    "transfer-encoding",
                    "connection",
                    "keep-alive",
                    "proxy-authenticate",
                    "proxy-authorization",
                }:
                    continue

                response_headers[key] = value

            return (
                response.status,
                response_headers,
                response_body,
            )


async def request_via_socks_proxy(
    proxy: str,
    method: str,
    url: str,
    headers: dict,
    body: bytes,
):
    timeout = ClientTimeout(total=REQUEST_TIMEOUT)

    connector = ProxyConnector.from_url(
        proxy,
        ssl=False,
        limit=20,
    )

    async with ClientSession(
        connector=connector,
        timeout=timeout,
    ) as session:

        async with session.request(
            method,
            url,
            headers=headers,
            data=body if body else None,
            allow_redirects=False,
        ) as response:

            response_body = await response.read()

            response_headers = {}

            for key, value in response.headers.items():

                if key.lower() in {
                    "transfer-encoding",
                    "connection",
                    "keep-alive",
                    "proxy-authenticate",
                    "proxy-authorization",
                }:
                    continue

                response_headers[key] = value

            return (
                response.status,
                response_headers,
                response_body,
            )


async def request_via_proxy(
    proxy: str,
    method: str,
    url: str,
    headers: dict,
    body: bytes,
):
    if proxy.lower().startswith("socks5://"):
        return await request_via_socks_proxy(
            proxy,
            method,
            url,
            headers,
            body,
        )

    if proxy.lower().startswith("socks4://"):
        return await request_via_socks_proxy(
            proxy,
            method,
            url,
            headers,
            body,
        )

    return await request_via_http_proxy(
        proxy,
        method,
        url,
        headers,
        body,
    )


async def handle(request: web.Request):

    url = request.query.get("url")

    if not url:
        return web.json_response(
            {
                "error": "Missing ?url=",
                "example": "/?url=https://example.com/",
            },
            status=400,
        )

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return web.json_response(
            {
                "error": "Only http:// and https:// URLs are supported"
            },
            status=400,
        )

    method = request.method

    body = await request.read()

    headers = clean_headers(request.headers)

    # Give the upstream destination the actual Host header.
    headers["Host"] = parsed.netloc

    print(
        f"[REQUEST] {method} {url}",
        flush=True,
    )

    proxies = await fetch_proxy_list()

    if not proxies:
        return web.json_response(
            {
                "error": "No upstream proxies available"
            },
            status=503,
        )

    last_error: Optional[str] = None

    # Randomize order so the same proxy isn't always selected.
    import random

    candidates = list(proxies)
    random.shuffle(candidates)

    # Avoid hammering an unlimited number of public proxies.
    candidates = candidates[:15]

    for proxy in candidates:

        print(
            f"[PROXY] Trying {proxy}",
            flush=True,
        )

        try:

            status, response_headers, response_body = (
                await request_via_proxy(
                    proxy,
                    method,
                    url,
                    headers,
                    body,
                )
            )

            print(
                f"[PROXY] {proxy} -> HTTP {status}",
                flush=True,
            )

            return web.Response(
                status=status,
                headers=response_headers,
                body=response_body,
            )

        except Exception as exc:

            last_error = str(exc)

            print(
                f"[PROXY] Failed {proxy}: {exc}",
                flush=True,
            )

    return web.json_response(
        {
            "error": "All upstream proxies failed",
            "detail": last_error,
        },
        status=502,
    )


async def health(request):
    return web.json_response(
        {
            "status": "ok",
            "proxy_source": "ProxyScrape",
        }
    )


def main():

    app = web.Application(
        client_max_size=50 * 1024 * 1024,
    )

    app.router.add_route(
        "*",
        "/",
        handle,
    )

    app.router.add_get(
        "/health",
        health,
    )

    print(
        f"Starting proxy on 0.0.0.0:{PORT}",
        flush=True,
    )

    web.run_app(
        app,
        host="0.0.0.0",
        port=PORT,
    )


if __name__ == "__main__":
    main()
