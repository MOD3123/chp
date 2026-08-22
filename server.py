import os
import socket
import socketserver
import subprocess
import threading
import time
from urllib.parse import urlparse, parse_qs


PORT = int(os.environ.get("PORT", "10000"))
SOCKS5_PORT = int(os.environ.get("SOCKS5_PORT", "1080"))

WIREPROXY_CONFIG = "/tmp/wireproxy.conf"


# HTTP hop-by-hop headers.
# Authorization/Bearer sem NEPATRÍ, takže sa prenáša.
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


def start_wireproxy():
    print("Starting wireproxy...")

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

    def log_output():
        if process.stdout:
            for line in process.stdout:
                print("[wireproxy]", line.rstrip())

    threading.Thread(
        target=log_output,
        daemon=True,
    ).start()

    deadline = time.time() + 30

    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"wireproxy skončil s kódom {process.returncode}"
            )

        try:
            with socket.create_connection(
                ("127.0.0.1", SOCKS5_PORT),
                timeout=1,
            ):
                print(
                    f"SOCKS5 proxy ready on "
                    f"127.0.0.1:{SOCKS5_PORT}"
                )
                return process

        except OSError:
            time.sleep(0.5)

    process.terminate()

    raise RuntimeError(
        "wireproxy SOCKS5 proxy sa nespustil do 30 sekúnd"
    )


def recv_exact(sock, length):
    data = b""

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError(
                "SOCKS5 connection closed unexpectedly"
            )

        data += chunk

    return data


def socks5_connect(host, port):
    sock = socket.create_connection(
        ("127.0.0.1", SOCKS5_PORT),
        timeout=30,
    )

    # SOCKS5 greeting:
    #
    # VER  NMETHODS  METHOD
    #
    # 05     01       00
    #
    # 00 = no authentication
    sock.sendall(
        b"\x05\x01\x00"
    )

    response = recv_exact(sock, 2)

    if response != b"\x05\x00":
        sock.close()

        raise RuntimeError(
            "SOCKS5 authentication negotiation failed"
        )

    # Použijeme DOMAIN NAME, aby DNS lookup vykonal
    # SOCKS5/WireGuard server namiesto Renderu.
    host_bytes = host.encode("idna")

    if len(host_bytes) > 255:
        sock.close()

        raise ValueError(
            "Hostname je príliš dlhý"
        )

    request = (
        b"\x05"                  # SOCKS5
        b"\x01"                  # CONNECT
        b"\x00"                  # reserved
        b"\x03"                  # domain name
        + bytes([len(host_bytes)])
        + host_bytes
        + int(port).to_bytes(2, "big")
    )

    sock.sendall(request)

    # VER REP RSV ATYP
    response = recv_exact(sock, 4)

    if response[0] != 5:
        sock.close()

        raise RuntimeError(
            "Invalid SOCKS5 response"
        )

    if response[1] != 0:
        sock.close()

        raise RuntimeError(
            f"SOCKS5 CONNECT failed, code={response[1]}"
        )

    atyp = response[3]

    if atyp == 1:
        # IPv4
        recv_exact(sock, 4)

    elif atyp == 3:
        # DOMAIN
        length = recv_exact(sock, 1)[0]
        recv_exact(sock, length)

    elif atyp == 4:
        # IPv6
        recv_exact(sock, 16)

    else:
        sock.close()

        raise RuntimeError(
            f"Unknown SOCKS5 ATYP={atyp}"
        )

    # Port
    recv_exact(sock, 2)

    return sock


def send_error(handler, status_code, message):
    body = message.encode("utf-8")

    response = (
        f"HTTP/1.1 {status_code} {message}\r\n"
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


class ProxyHandler(socketserver.StreamRequestHandler):

    def handle(self):
        upstream = None

        try:
            # -------------------------------------------------
            # Request line
            # -------------------------------------------------

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

            method, request_target, http_version = parts

            # -------------------------------------------------
            # Headers
            # -------------------------------------------------

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

                # Zachovávame pôvodný názov headera.
                headers[key] = value

            # -------------------------------------------------
            # ?url=
            # -------------------------------------------------

            parsed = urlparse(request_target)

            query = parse_qs(
                parsed.query,
                keep_blank_values=True,
            )

            target_urls = query.get("url")

            if not target_urls:
                send_error(
                    self,
                    400,
                    "Missing ?url= parameter",
                )
                return

            target_url = target_urls[0]

            target = urlparse(target_url)

            # -------------------------------------------------
            # Validate target
            # -------------------------------------------------

            if target.scheme not in (
                "http",
                "https",
            ):
                send_error(
                    self,
                    400,
                    "Only http:// and https:// URLs are supported",
                )
                return

            if not target.hostname:
                send_error(
                    self,
                    400,
                    "Invalid target URL",
                )
                return

            target_host = target.hostname

            if target.port:
                target_port = target.port

            elif target.scheme == "https":
                target_port = 443

            else:
                target_port = 80

            # -------------------------------------------------
            # Target path
            # -------------------------------------------------

            target_path = target.path or "/"

            if target.query:
                target_path += "?" + target.query

            print(
                f"[request] "
                f"{method} "
                f"{target.scheme}://"
                f"{target_host}:"
                f"{target_port}"
                f"{target_path}"
            )

            # -------------------------------------------------
            # Debug Authorization header
            #
            # Token NEVYPISUJEME do logu.
            # -------------------------------------------------

            if "Authorization" in headers:
                auth = headers["Authorization"]

                if auth.lower().startswith("bearer "):
                    print(
                        "[request] "
                        "Authorization: Bearer <present>"
                    )
                else:
                    print(
                        "[request] "
                        "Authorization: <present>"
                    )

            # -------------------------------------------------
            # Connect through SOCKS5 / WireGuard
            # -------------------------------------------------

            upstream = socks5_connect(
                target_host,
                target_port,
            )

            # -------------------------------------------------
            # Build outgoing request
            # -------------------------------------------------

            outgoing = (
                f"{method} "
                f"{target_path} "
                f"{http_version}\r\n"
            ).encode("iso-8859-1")

            # Host musí byť cieľový server.
            host_header = target_host

            if (
                (target.scheme == "http" and target_port != 80)
                or
                (target.scheme == "https" and target_port != 443)
            ):
                host_header += f":{target_port}"

            outgoing += (
                f"Host: {host_header}\r\n"
            ).encode("iso-8859-1")

            # -------------------------------------------------
            # Preserve request headers
            # -------------------------------------------------

            for key, value in headers.items():

                lower_key = key.lower()

                # Host nastavujeme sami.
                if lower_key == "host":
                    continue

                # Hop-by-hop headers neposielame.
                if lower_key in HOP_BY_HOP_HEADERS:
                    continue

                # Content-Length nastavíme podľa reálneho body.
                if lower_key == "content-length":
                    continue

                # Authorization:
                #
                # TU SA PRENÁŠA AJ:
                #
                # Authorization: Bearer eyJ...
                #
                # ------------------------------------------------

                outgoing += (
                    f"{key}: {value}\r\n"
                ).encode("iso-8859-1")

            # -------------------------------------------------
            # Request body
            # -------------------------------------------------

            body = b""

            content_length = None

            for key, value in headers.items():
                if key.lower() == "content-length":
                    try:
                        content_length = int(value)
                    except ValueError:
                        send_error(
                            self,
                            400,
                            "Invalid Content-Length",
                        )
                        return

                    break

            if content_length is not None:

                if content_length < 0:
                    send_error(
                        self,
                        400,
                        "Invalid Content-Length",
                    )
                    return

                # Limit na ochranu pamäte.
                max_body = 50 * 1024 * 1024

                if content_length > max_body:
                    send_error(
                        self,
                        413,
                        "Request body too large",
                    )
                    return

                body = self.rfile.read(
                    content_length
                )

                if len(body) != content_length:
                    send_error(
                        self,
                        400,
                        "Incomplete request body",
                    )
                    return

                outgoing += (
                    f"Content-Length: "
                    f"{len(body)}\r\n"
                ).encode("iso-8859-1")

            # -------------------------------------------------
            # Finish request
            # -------------------------------------------------

            outgoing += (
                b"Connection: close\r\n"
                b"\r\n"
            )

            outgoing += body

            # -------------------------------------------------
            # Send request
            # -------------------------------------------------

            upstream.sendall(outgoing)

            # -------------------------------------------------
            # Return response
            # -------------------------------------------------

            while True:
                data = upstream.recv(65536)

                if not data:
                    break

                self.wfile.write(data)
                self.wfile.flush()

        except Exception as exc:

            print(
                "[proxy error]",
                type(exc).__name__,
                str(exc),
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


class ThreadingProxyServer(
    socketserver.ThreadingTCPServer
):

    allow_reuse_address = True

    daemon_threads = True


def main():

    print(
        f"Starting proxy on "
        f"0.0.0.0:{PORT}"
    )

    wireproxy = start_wireproxy()

    server = ThreadingProxyServer(
        ("0.0.0.0", PORT),
        ProxyHandler,
    )

    try:

        print(
            f"HTTP proxy listening on "
            f"0.0.0.0:{PORT}"
        )

        server.serve_forever()

    except KeyboardInterrupt:

        pass

    finally:

        print("Stopping HTTP proxy...")

        try:
            server.shutdown()
        except Exception:
            pass

        try:
            server.server_close()
        except Exception:
            pass

        print("Stopping wireproxy...")

        try:
            wireproxy.terminate()
            wireproxy.wait(timeout=5)
        except Exception:

            try:
                wireproxy.kill()
            except Exception:
                pass


if __name__ == "__main__":
    main()
