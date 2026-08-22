import os
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from urllib.parse import urlparse, parse_qs


PORT = int(os.environ.get("PORT", "10000"))
SOCKS5_PORT = int(os.environ.get("SOCKS5_PORT", "1080"))

CONFIG_FILE = "/app/wireproxy.conf"
RUNTIME_CONFIG = "/tmp/wireproxy.conf"

MAX_BODY_SIZE = 50 * 1024 * 1024

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def log(message):
    print(message, flush=True)


# ============================================================
# WIREPROXY
# ============================================================

def start_wireproxy():

    private_key = os.environ.get(
        "WG_PRIVATE_KEY",
        ""
    ).strip()

    if not private_key:
        raise RuntimeError(
            "WG_PRIVATE_KEY is missing from Render Environment Variables"
        )

    log("WG_PRIVATE_KEY detected")

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        config = f.read()

    if "[Interface]" not in config:
        raise RuntimeError(
            "wireproxy.conf does not contain [Interface]"
        )

    # Private key vložíme až do runtime configu.
    # Skutočný private key teda nie je v GitHube.
    config = config.replace(
        "[Interface]",
        "[Interface]\nPrivateKey = " + private_key,
        1
    )

    with open(
        RUNTIME_CONFIG,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(config)

    os.chmod(
        RUNTIME_CONFIG,
        0o600
    )

    log("Starting wireproxy...")

    process = subprocess.Popen(
        [
            "wireproxy",
            "-c",
            RUNTIME_CONFIG
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    def wireproxy_logger():

        if process.stdout:

            for line in process.stdout:

                log(
                    "[wireproxy] "
                    + line.rstrip()
                )

    threading.Thread(
        target=wireproxy_logger,
        daemon=True
    ).start()

    deadline = time.time() + 30

    while time.time() < deadline:

        if process.poll() is not None:

            raise RuntimeError(
                "wireproxy exited with code "
                f"{process.returncode}"
            )

        try:

            with socket.create_connection(
                (
                    "127.0.0.1",
                    SOCKS5_PORT
                ),
                timeout=1
            ):

                log(
                    "SOCKS5 ready on "
                    f"127.0.0.1:{SOCKS5_PORT}"
                )

                return process

        except OSError:

            time.sleep(0.5)

    try:
        process.terminate()
    except Exception:
        pass

    raise RuntimeError(
        "wireproxy SOCKS5 did not start "
        "within 30 seconds"
    )


# ============================================================
# SOCKS5
# ============================================================

def recv_exact(sock, length):

    data = b""

    while len(data) < length:

        chunk = sock.recv(
            length - len(data)
        )

        if not chunk:
            raise ConnectionError(
                "SOCKS5 connection closed"
            )

        data += chunk

    return data


def socks5_connect(host, port):

    log(
        f"[SOCKS5] connecting to "
        f"{host}:{port}"
    )

    sock = socket.create_connection(
        (
            "127.0.0.1",
            SOCKS5_PORT
        ),
        timeout=30
    )

    # --------------------------------------------------------
    # SOCKS5 greeting
    # --------------------------------------------------------

    sock.sendall(
        b"\x05\x01\x00"
    )

    response = recv_exact(
        sock,
        2
    )

    if response != b"\x05\x00":

        sock.close()

        raise RuntimeError(
            "SOCKS5 authentication negotiation failed"
        )

    # --------------------------------------------------------
    # SOCKS5 CONNECT
    #
    # Používame DOMAINNAME namiesto lokálneho DNS.
    # Tým zabránime tomu, aby Render riešil cieľový hostname.
    # --------------------------------------------------------

    hostname = host.encode(
        "idna"
    )

    if len(hostname) > 255:

        sock.close()

        raise RuntimeError(
            "Target hostname too long"
        )

    request = (
        b"\x05"          # version
        b"\x01"          # CONNECT
        b"\x00"          # reserved
        b"\x03"          # DOMAINNAME
        + bytes([len(hostname)])
        + hostname
        + int(port).to_bytes(
            2,
            "big"
        )
    )

    sock.sendall(request)

    response = recv_exact(
        sock,
        4
    )

    if response[0] != 5:

        sock.close()

        raise RuntimeError(
            "Invalid SOCKS5 response"
        )

    reply = response[1]

    if reply != 0:

        sock.close()

        messages = {
            1: "general SOCKS server failure",
            2: "connection not allowed",
            3: "network unreachable",
            4: "host unreachable",
            5: "connection refused",
            6: "TTL expired",
            7: "command not supported",
            8: "address type not supported",
        }

        raise RuntimeError(
            "SOCKS5 CONNECT failed: "
            f"{reply} - "
            f"{messages.get(reply, 'unknown error')}"
        )

    # --------------------------------------------------------
    # Consume BND.ADDR + BND.PORT
    # --------------------------------------------------------

    address_type = response[3]

    if address_type == 1:

        # IPv4
        recv_exact(sock, 4)

    elif address_type == 3:

        # Domain
        length = recv_exact(
            sock,
            1
        )[0]

        recv_exact(
            sock,
            length
        )

    elif address_type == 4:

        # IPv6
        recv_exact(
            sock,
            16
        )

    else:

        sock.close()

        raise RuntimeError(
            "Unknown SOCKS5 address type: "
            f"{address_type}"
        )

    recv_exact(
        sock,
        2
    )

    log(
        f"[SOCKS5] connected to "
        f"{host}:{port}"
    )

    return sock


# ============================================================
# HTTP HELPERS
# ============================================================

def get_header(headers, name):

    wanted = name.lower()

    for key, value in headers.items():

        if key.lower() == wanted:
            return value

    return None


def send_error(
    handler,
    status_code,
    message
):

    body = (
        message + "\n"
    ).encode(
        "utf-8"
    )

    response = (
        f"HTTP/1.1 {status_code} {message}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode(
        "iso-8859-1"
    )

    try:

        handler.wfile.write(
            response
        )

        handler.wfile.write(
            body
        )

        handler.wfile.flush()

    except Exception:
        pass


# ============================================================
# HTTP PROXY
# ============================================================

class ProxyHandler(
    socketserver.StreamRequestHandler
):

    def handle(self):

        upstream = None

        try:

            # ------------------------------------------------
            # Request line
            # ------------------------------------------------

            request_line = (
                self.rfile
                .readline()
                .decode(
                    "iso-8859-1"
                )
                .rstrip(
                    "\r\n"
                )
            )

            if not request_line:
                return

            parts = request_line.split(
                " ",
                2
            )

            if len(parts) != 3:

                send_error(
                    self,
                    400,
                    "Invalid HTTP request"
                )

                return

            method = parts[0]
            request_target = parts[1]
            http_version = parts[2]

            # ------------------------------------------------
            # Render health check
            # ------------------------------------------------

            if (
                method == "GET"
                and request_target == "/"
            ):

                body = b"OK\n"

                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    + (
                        f"Content-Length: "
                        f"{len(body)}\r\n"
                    ).encode()
                    + b"Connection: close\r\n"
                    b"\r\n"
                    + body
                )

                self.wfile.write(
                    response
                )

                self.wfile.flush()

                return

            # ------------------------------------------------
            # Headers
            # ------------------------------------------------

            headers = {}

            while True:

                line = (
                    self.rfile
                    .readline()
                    .decode(
                        "iso-8859-1"
                    )
                )

                if line in (
                    "",
                    "\r\n",
                    "\n"
                ):
                    break

                if ":" not in line:
                    continue

                key, value = line.split(
                    ":",
                    1
                )

                headers[
                    key.strip()
                ] = value.strip()

            # ------------------------------------------------
            # URL parameter
            #
            # https://server/?url=https://example.com/api
            # ------------------------------------------------

            parsed = urlparse(
                request_target
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            urls = query.get(
                "url"
            )

            if not urls:

                send_error(
                    self,
                    400,
                    "Missing ?url= parameter"
                )

                return

            target_url = urls[0]

            target = urlparse(
                target_url
            )

            if target.scheme not in (
                "http",
                "https"
            ):

                send_error(
                    self,
                    400,
                    "Only http and https URLs are supported"
                )

                return

            if not target.hostname:

                send_error(
                    self,
                    400,
                    "Target URL has no hostname"
                )

                return

            host = target.hostname

            # ------------------------------------------------
            # Port
            # ------------------------------------------------

            if target.port:

                port = target.port

            elif target.scheme == "https":

                port = 443

            else:

                port = 80

            # ------------------------------------------------
            # Path + query
            # ------------------------------------------------

            path = (
                target.path
                or "/"
            )

            if target.query:

                path += (
                    "?"
                    + target.query
                )

            log(
                f"[REQUEST] "
                f"{method} "
                f"{target.scheme}://"
                f"{host}:{port}"
                f"{path}"
            )

            log(
                f"[ROUTE] "
                f"{host}:{port} "
                f"-> SOCKS5 "
                f"127.0.0.1:{SOCKS5_PORT}"
            )

            # ------------------------------------------------
            # Request body
            # ------------------------------------------------

            body = b""

            content_length = get_header(
                headers,
                "Content-Length"
            )

            transfer_encoding = get_header(
                headers,
                "Transfer-Encoding"
            )

            if (
                transfer_encoding
                and
                "chunked"
                in transfer_encoding.lower()
            ):

                send_error(
                    self,
                    501,
                    "Chunked request bodies are not supported"
                )

                return

            if content_length:

                try:

                    length = int(
                        content_length
                    )

                except ValueError:

                    send_error(
                        self,
                        400,
                        "Invalid Content-Length"
                    )

                    return

                if length > MAX_BODY_SIZE:

                    send_error(
                        self,
                        413,
                        "Request body too large"
                    )

                    return

                body = self.rfile.read(
                    length
                )

                if len(body) != length:

                    send_error(
                        self,
                        400,
                        "Incomplete request body"
                    )

                    return

            # ------------------------------------------------
            # CONNECT THROUGH WIREPROXY
            # ------------------------------------------------

            upstream = socks5_connect(
                host,
                port
            )

            # ------------------------------------------------
            # HTTPS TLS
            #
            # TLS ide cez SOCKS5 connection.
            # SNI = pôvodný hostname.
            # ------------------------------------------------

            if target.scheme == "https":

                log(
                    f"[TLS] "
                    f"starting TLS "
                    f"SNI={host}"
                )

                context = (
                    ssl.create_default_context()
                )

                upstream = (
                    context.wrap_socket(
                        upstream,
                        server_hostname=host
                    )
                )

                log(
                    f"[TLS] established "
                    f"for {host}"
                )

            # ------------------------------------------------
            # Build upstream HTTP request
            # ------------------------------------------------

            outgoing = (
                f"{method} "
                f"{path} "
                f"{http_version}\r\n"
            ).encode(
                "iso-8859-1"
            )

            # ------------------------------------------------
            # Host header
            # ------------------------------------------------

            host_header = host

            if (
                target.scheme == "http"
                and port != 80
            ) or (
                target.scheme == "https"
                and port != 443
            ):

                host_header += (
                    f":{port}"
                )

            outgoing += (
                f"Host: "
                f"{host_header}\r\n"
            ).encode(
                "iso-8859-1"
            )

            # ------------------------------------------------
            # Forward original headers
            #
            # Authorization / Bearer is preserved.
            # ------------------------------------------------

            for key, value in headers.items():

                lower = key.lower()

                if lower == "host":
                    continue

                if lower in HOP_BY_HOP_HEADERS:
                    continue

                if lower == "content-length":
                    continue

                if lower == "expect":
                    continue

                outgoing += (
                    f"{key}: {value}\r\n"
                ).encode(
                    "iso-8859-1"
                )

            # ------------------------------------------------
            # Content-Length
            # ------------------------------------------------

            if (
                body
                or content_length is not None
            ):

                outgoing += (
                    f"Content-Length: "
                    f"{len(body)}\r\n"
                ).encode(
                    "iso-8859-1"
                )

            # ------------------------------------------------
            # Close upstream after response
            # ------------------------------------------------

            outgoing += (
                b"Connection: close\r\n"
                b"\r\n"
            )

            outgoing += body

            # ------------------------------------------------
            # Send
            # ------------------------------------------------

            log(
                f"[UPSTREAM] "
                f"sending {method} "
                f"to {host}"
            )

            upstream.sendall(
                outgoing
            )

            # ------------------------------------------------
            # Relay response
            # ------------------------------------------------

            total = 0

            while True:

                data = upstream.recv(
                    65536
                )

                if not data:
                    break

                total += len(
                    data
                )

                self.wfile.write(
                    data
                )

                self.wfile.flush()

            log(
                f"[UPSTREAM] "
                f"response={total} bytes"
            )

        except ssl.SSLError as exc:

            log(
                f"[TLS ERROR] {exc}"
            )

            send_error(
                self,
                502,
                "TLS connection failed"
            )

        except socket.timeout:

            log(
                "[ERROR] upstream timeout"
            )

            send_error(
                self,
                504,
                "Gateway Timeout"
            )

        except Exception as exc:

            log(
                f"[ERROR] "
                f"{type(exc).__name__}: "
                f"{exc}"
            )

            send_error(
                self,
                502,
                "Bad Gateway"
            )

        finally:

            if upstream:

                try:
                    upstream.close()
                except Exception:
                    pass


# ============================================================
# SERVER
# ============================================================

class ProxyServer(
    socketserver.ThreadingTCPServer
):

    allow_reuse_address = True
    daemon_threads = True


def main():

    log(
        "========================================"
    )

    log(
        "CHP proxy starting"
    )

    log(
        f"HTTP PORT={PORT}"
    )

    log(
        f"SOCKS5 PORT={SOCKS5_PORT}"
    )

    log(
        "========================================"
    )

    # --------------------------------------------------------
    # Start WireGuard userspace proxy
    # --------------------------------------------------------

    wireproxy = start_wireproxy()

    # --------------------------------------------------------
    # Start HTTP server
    # --------------------------------------------------------

    server = ProxyServer(
        (
            "0.0.0.0",
            PORT
        ),
        ProxyHandler
    )

    log(
        f"HTTP proxy listening on "
        f"0.0.0.0:{PORT}"
    )

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        pass

    finally:

        log(
            "Stopping HTTP proxy..."
        )

        try:
            server.server_close()
        except Exception:
            pass

        log(
            "Stopping wireproxy..."
        )

        try:

            wireproxy.terminate()

            wireproxy.wait(
                timeout=5
            )

        except Exception:

            try:
                wireproxy.kill()
            except Exception:
                pass


if __name__ == "__main__":
    main()
