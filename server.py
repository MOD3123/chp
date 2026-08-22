import os
import shutil
import subprocess
import tempfile
import time
import socket


WIREPROXY_CONFIG = "/app/wireproxy.conf"
WIREPROXY_RUNTIME_CONFIG = "/tmp/wireproxy.conf"

SOCKS5_PORT = int(os.environ.get("SOCKS5_PORT", "1080"))


def start_wireproxy():
    private_key = os.environ.get("WG_PRIVATE_KEY")

    if not private_key:
        raise RuntimeError(
            "WG_PRIVATE_KEY is not set in Render environment"
        )

    private_key = private_key.strip()

    if not private_key:
        raise RuntimeError(
            "WG_PRIVATE_KEY is empty"
        )

    # Načítame verejný config z GitHubu.
    with open(WIREPROXY_CONFIG, "r", encoding="utf-8") as f:
        config = f.read()

    # PrivateKey pridáme až vo vnútri kontajnera.
    runtime_config = (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        + config
    )

    # wireproxy.conf už nesmie obsahovať [Interface],
    # pretože ho vytvárame tu.
    with open(
        WIREPROXY_RUNTIME_CONFIG,
        "w",
        encoding="utf-8",
    ) as f:
        f.write(runtime_config)

    os.chmod(
        WIREPROXY_RUNTIME_CONFIG,
        0o600,
    )

    print(
        "Starting wireproxy...",
        flush=True,
    )

    process = subprocess.Popen(
        [
            "wireproxy",
            "-c",
            WIREPROXY_RUNTIME_CONFIG,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    def read_logs():
        if process.stdout:
            for line in process.stdout:
                print(
                    "[wireproxy] " + line.rstrip(),
                    flush=True,
                )

    import threading

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
                print(
                    f"SOCKS5 ready on "
                    f"127.0.0.1:{SOCKS5_PORT}",
                    flush=True,
                )

                return process

        except OSError:
            time.sleep(0.5)

    process.terminate()

    raise RuntimeError(
        "wireproxy SOCKS5 did not start "
        "within 30 seconds"
    )
