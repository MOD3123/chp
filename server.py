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

WIREPROXY_CONFIG = "/app/wireproxy.conf"

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
    log("Starting wireproxy...")

    process = subprocess.Popen(
        [
            "wireproxy",
            "-c",
            WIREPROXY_CONFIG,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    def read_logs():
        if process.stdout:
            for line in process.stdout:
                log("[wireproxy] " + line.rstrip())

    threading.Thread(
        target=read_logs,
        daemon=True,
    ).start()

    deadline = time.time() + 30

    while time.time() < deadline:

        if process.poll() is not None:
            raise RuntimeError(
                f"wireproxy exited with code "
                f"{process.returncode}"
            )

        try:
            with socket.create_connection(
                ("127.0.0.1", SOCKS5_PORT),
                timeout=1,
            ):
                log(
                    f"SOCKS5 ready on "
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

def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Connection closed unexpectedly"
            )

        data += chunk

    return data


def socks5_connect(host, port):
    log(
        f"SOCKS5 connecting to "
        f"{host}:{port}"
    )

    sock = socket.create_connection(
        ("127.0.0.1", SOCKS5_PORT),
        timeout=30,
    )

    # SOCKS5 greeting
    sock.sendall(
        b"\x05\x01\x00"
    )

    response = recv_exact(sock, 2)

    if response != b"\x05\x00":
        sock.close()

        raise RuntimeError(
            "SOCKS5 authentication negotiation failed"
        )

    host_bytes = host.encode("idna")

    if len(host_bytes) > 255:
        sock.close()

        raise RuntimeError(
            "Hostname too long"
        )

    # SOCKS5 CONNECT using hostname.
    #
    # DNS resolution is therefore handled by
    # the SOCKS5/wireproxy side rather than locally.
    request = (
        b"\x05"
        b"\x01"
        b"\x00"
        b"\x03"
        + bytes([len(host_bytes)])
        + host_bytes
        + int(port).to_bytes(2, "big")
    )

    sock.sendall(request)

    response = recv_exact(sock, 4)

    if response[0] != 5:
        sock.close()

        raise RuntimeError(
            "Invalid SOCKS5 response"
        )

    reply = response[1]

    if reply != 0:
        sock.close()

        raise RuntimeError(
            f"SOCKS5 CONNECT failed "
            f"with code {reply}"
        )

    address_type = response[3]

    if address_type == 1:
        # IPv4
        recv_exact(sock, 4)

    elif address_type == 3:
        # Domain
        length = recv_exact(sock, 1)[0]
        recv_exact(sock, length)

    elif address_type == 4:
        # IPv6
        recv_exact(sock, 16)

    else:
        sock.close()

        raise RuntimeError(
            f"Unknown SOCKS5 address type "
            f"{address_type}"
        )

    # Destination port
    recv_exact(sock, 2)

    log(
        f"SOCKS5 connected to "
        f"{host}:{port}"
    )

    return sock


# ============================================================
# HTTP HELPERS
# ============================================================

def send_error(handler, code, message):
    body = message.encode("utf-8")

    response = (
        f"HTTP/1.1 {code} {message}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1")

    try:
        handler.wfile.write(response)
        handler.wfile.write(body)
        handler.wfile.flush()
    except Exception:
        pass


def get_header(headers, name):
    name = name.lower()

    for key, value in headers.items():
        if key.lower() == name:
            return value

    return None


def has_header(headers, name):
    return get_header(headers, name) is not None


# ============================================================
# PROXY HANDLER
# ============================================================

class ProxyHandler(socketserver.StreamRequestHandler):

    def handle(self):

        upstream = None

        try:

            # ------------------------------------------------
            # Request line
            # ------------------------------------------------

            request_line = (
                self.rfile
                .readline()
                .decode("iso-8859-1")
                .rstrip("\r\n")
            )

            if not request_line:
                return

            parts = request_line.split(" ", 2)

            if len(parts) != 3:

                send_error(
                    self,
                    400,
                    "Invalid HTTP request",
                )

                return

            method = parts[0]
            request_target = parts[1]
            http_version = parts[2]

            # ------------------------------------------------
            # Health check
            # ------------------------------------------------

            if request_target == "/" and method == "GET":

                body = b"OK\n"

                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n"
                    b"\r\n"
                    + body
                )

                self.wfile.write(response)
                self.wfile.flush()

                return

            # ------------------------------------------------
            # Request headers
            # ------------------------------------------------

            headers = {}

            while True:

                line = (
                    self.rfile
                    .readline()
                    .decode("iso-8859-1")
                )

                if line in ("", "\r\n", "\n"):
                    break

                if ":" not in line:
                    continue

                key, value = line.split(":", 1)

                key = key.strip()
                value = value.strip()

                headers[key] = value

            # ------------------------------------------------
            # ?url=
            # ------------------------------------------------

            parsed_request = urlparse(
                request_target
            )

            query = parse_qs(
                parsed_request.query,
                keep_blank_values=True,
            )

            target_values = query.get("url")

            if not target_values:

                send_error(
                    self,
                    400,
                    "Missing ?url= parameter",
                )

                return

            target_url = target_values[0]

            # ------------------------------------------------
            # Target URL
            # ------------------------------------------------

            target = urlparse(target_url)

            if target.scheme not in (
                "http",
                "https",
            ):

                send_error(
                    self,
                    400,
                    "Only http and https URLs are supported",
                )

                return

            if not target.hostname:

                send_error(
                    self,
                    400,
                    "Target URL has no hostname",
                )

                return

            target_host = target.hostname

            if target.port:

                target_port = target.port

            elif target.scheme == "https":

                target_port = 443

            else:

                target_port = 80

            # ------------------------------------------------
            # Target path
            # ------------------------------------------------

            target_path = target.path or "/"

            if target.query:

                target_path += "?" + target.query

            log(
                f"[request] "
                f"{method} "
                f"{target.scheme}://"
                f"{target_host}:"
                f"{target_port}"
                f"{target_path}"
            )

            # ------------------------------------------------
            # Authorization logging
            # ------------------------------------------------

            authorization = get_header(
                headers,
                "Authorization",
            )

            if authorization:

                if authorization.lower().startswith(
                    "bearer "
                ):

                    log(
                        "[request] "
                        "Authorization: "
                        "Bearer <present>"
                    )

                else:

                    log(
                        "[request] "
                        "Authorization: <present>"
                    )

            # ------------------------------------------------
            # Request body
            # ------------------------------------------------

            body = b""

            content_length = get_header(
                headers,
                "Content-Length",
            )

            transfer_encoding = get_header(
                headers,
                "Transfer-Encoding",
            )

            # We intentionally don't try to parse an inbound
            # chunked body manually here.
            if transfer_encoding:

                if "chunked" in transfer_encoding.lower():

                    send_error(
                        self,
                        501,
                        "Chunked request bodies are not supported",
                    )

                    return

            if content_length:

                try:
                    body_length = int(
                        content_length
                    )

                except ValueError:

                    send_error(
                        self,
                        400,
                        "Invalid Content-Length",
                    )

                    return

                if body_length < 0:

                    send_error(
                        self,
                        400,
                        "Invalid Content-Length",
                    )

                    return

                if body_length > MAX_BODY_SIZE:

                    send_error(
                        self,
                        413,
                        "Request body too large",
                    )

                    return

                body = self.rfile.read(
                    body_length
                )

                if len(body) != body_length:

                    send_error(
                        self,
                        400,
                        "Incomplete request body",
                    )

                    return

            # ------------------------------------------------
            # SOCKS5 -> WireGuard
            # ------------------------------------------------

            upstream = socks5_connect(
                target_host,
                target_port,
            )

            # ------------------------------------------------
            # HTTPS TLS
            # ------------------------------------------------

            if target.scheme == "https":

                log(
                    f"[tls] Starting TLS "
                    f"for {target_host}"
                )

                ssl_context = (
                    ssl.create_default_context()
                )

                upstream = (
                    ssl_context.wrap_socket(
                        upstream,
                        server_hostname=target_host,
                    )
                )

                log(
                    f"[tls] TLS established "
                    f"for {target_host}"
                )

            # ------------------------------------------------
            # Outgoing request
            # ------------------------------------------------

            outgoing = (
                f"{method} "
                f"{target_path} "
                f"{http_version}\r\n"
            ).encode("iso-8859-1")

            # Host must always be the real target.
            host_header = target_host

            if (
                (
                    target.scheme == "http"
                    and target_port != 80
                )
                or
                (
                    target.scheme == "https"
                    and target_port != 443
                )
            ):

                host_header += (
                    f":{target_port}"
                )

            outgoing += (
                f"Host: {host_header}\r\n"
            ).encode("iso-8859-1")

            # ------------------------------------------------
            # Copy headers
            # ------------------------------------------------

            for key, value in headers.items():

                lower_key = key.lower()

                # Host is replaced with target host.
                if lower_key == "host":
                    continue

                # Remove hop-by-hop headers.
                if lower_key in HOP_BY_HOP_HEADERS:
                    continue

                # We create Content-Length ourselves.
                if lower_key == "content-length":
                    continue

                # Expect: 100-continue would require additional
                # protocol handling, so don't forward it.
                if lower_key == "expect":
                    continue

                # Everything else passes through.
                #
                # This includes:
                #
                # Authorization: Bearer ...
                # Content-Type
                # Accept
                # User-Agent
                # X-Api-Key
                # X-Custom-Header
                # etc.
                #
                outgoing += (
                    f"{key}: {value}\r\n"
                ).encode("iso-8859-1")

            # ------------------------------------------------
            # Content-Length
            # ------------------------------------------------

            if body:

                outgoing += (
                    f"Content-Length: "
                    f"{len(body)}\r\n"
                ).encode("iso-8859-1")

            elif has_header(
                headers,
                "Content-Length",
            ):

                outgoing += (
                    b"Content-Length: 0\r\n"
                )

            # ------------------------------------------------
            # Connection
            # ------------------------------------------------

            outgoing += (
                b"Connection: close\r\n"
                b"\r\n"
            )

            outgoing += body

            # ------------------------------------------------
            # Send request
            # ------------------------------------------------

            log(
                f"[upstream] Sending "
                f"{method} request"
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

                total += len(data)

                self.wfile.write(
                    data
                )

                self.wfile.flush()

            log(
                f"[upstream] Response "
                f"received: {total} bytes"
            )

        except ssl.SSLError as exc:

            log(
                f"[TLS ERROR] {exc}"
            )

            try:
                send_error(
                    self,
                    502,
                    "TLS connection to target failed",
                )
            except Exception:
                pass

        except socket.timeout:

            log(
                "[ERROR] Upstream connection timeout"
            )

            try:
                send_error(
                    self,
                    504,
                    "Gateway Timeout",
                )
            except Exception:
                pass

        except Exception as exc:

            log(
                f"[ERROR] "
                f"{type(exc).__name__}: "
                f"{exc}"
            )

            try:
                send_error(
                    self,
                    502,
                    "Bad Gateway",
                )
            except Exception:
                pass

        finally:

            if upstream is not None:

                try:
                    upstream.shutdown(
                        socket.SHUT_RDWR
                    )
                except Exception:
                    pass

                try:
                    upstream.close()
                except Exception:
                    pass


# ============================================================
# SERVER
# ============================================================

class ThreadingProxyServer(
    socketserver.ThreadingTCPServer
):

    allow_reuse_address = True
    daemon_threads = True


def main():

    log(
        f"Starting proxy "
        f"on 0.0.0.0:{PORT}"
    )

    # Start exactly ONE wireproxy.
    wireproxy = start_wireproxy()

    server = ThreadingProxyServer(
        ("0.0.0.0", PORT),
        ProxyHandler,
    )

    log(
        f"HTTP proxy listening "
        f"on 0.0.0.0:{PORT}"
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
            server.shutdown()
        except Exception:
            pass

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
