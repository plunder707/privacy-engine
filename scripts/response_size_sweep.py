#!/usr/bin/env python3
"""Compare rewritten-response completion across binaries and body sizes.

The fixture is intentionally end-to-end: a local HTTPS origin advertises a
Content-Length and keeps the upstream connection alive after sending the body.
Each engine runs on an isolated proxy port with DNS filtering disabled.  Curl
must receive exactly the Content-Length emitted by the proxy before its hard
deadline.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from typing import Any, Iterable


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **kwargs)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_identity(repo: Path) -> dict[str, Any]:
    head = run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True).stdout.strip()
    status = run(
        ["git", "-C", str(repo), "status", "--porcelain=v1"],
        capture_output=True,
    ).stdout
    return {
        "head": head,
        "dirty": bool(status.strip()),
        "status_sha256": hashlib.sha256(status.encode()).hexdigest(),
    }


def source_ip() -> str:
    output = run(
        ["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True
    ).stdout.split()
    if "src" not in output:
        raise RuntimeError("could not determine a non-loopback WSL source address")
    address = output[output.index("src") + 1]
    if address.startswith("127."):
        raise RuntimeError(f"fixture address must not be loopback: {address}")
    return address


def body_for_size(size: int) -> bytes:
    prefix = b"<!doctype html><html><head><title>fixture</title></head><body>"
    suffix = b"</body></html>"
    if size < len(prefix) + len(suffix):
        raise ValueError(f"body size must be at least {len(prefix) + len(suffix)}")
    return prefix + (b"x" * (size - len(prefix) - len(suffix))) + suffix


class SizeHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        try:
            size = int(self.path.removeprefix("/size/").split("?", 1)[0])
            body = body_for_size(size)
        except (TypeError, ValueError):
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = False

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class ThreadedHttpServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def https_origin(address: str, port: int, cert: Path, key: Path) -> Iterable[None]:
    server = ThreadedHttpServer((address, port), SizeHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def create_origin_certificate(tmp: Path, address: str, ca_cert: Path, ca_key: Path) -> tuple[Path, Path]:
    key = tmp / "origin-key.pem"
    csr = tmp / "origin.csr"
    cert = tmp / "origin-cert.pem"
    extension = tmp / "origin.ext"
    serial = tmp / "origin-ca.srl"
    extension.write_text(
        f"subjectAltName=IP:{address}\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )
    run(["openssl", "genrsa", "-out", str(key), "2048"], capture_output=True)
    run(
        ["openssl", "req", "-new", "-key", str(key), "-out", str(csr), "-subj", "/CN=pe-size-fixture"],
        capture_output=True,
    )
    run(
        [
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-CAserial", str(serial), "-out", str(cert),
            "-days", "1", "-sha256", "-extfile", str(extension),
        ],
        capture_output=True,
    )
    return cert, key


def isolated_config(
    base: Path,
    destination: Path,
    *,
    repo: Path,
    proxy_port: int,
    ca_cert: Path,
    ca_key: Path,
) -> None:
    config = json.loads(base.read_text(encoding="utf-8"))
    config.update(
        {
            "listen_host": "127.0.0.1",
            "listen_port": proxy_port,
            "enable_dns_filter": False,
            "dashboard_port": None,
            "pinned_hosts_file": str(destination.parent / "pinned-hosts.json"),
            "receipts_file": str(destination.parent / "receipts.json"),
            "cert_log_file": str(destination.parent / "cert-log.jsonl"),
            "cert_pin_file": str(destination.parent / "cert-pins.json"),
            "mitm_ca_cert_file": str(ca_cert),
            "mitm_ca_key_file": str(ca_key),
            "mitm_ca_export_cert_file": str(destination.parent / "ca-export.pem"),
            "policy_config_file": str(repo / "docs" / "policy_full.json"),
            "filter_list_file": [str(repo / "state" / "easylist.txt")],
            "filter_list_cache_dir": str(destination.parent / "filter-cache"),
            "filter_list_url": [],
            "filter_list_refresh_secs": 0,
        }
    )
    # Candidate and deployed binaries both accept these fields, but keeping the
    # fixture independent of the host DNS configuration avoids port conflicts.
    destination.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def wait_for_port(port: int, process: subprocess.Popen[str], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"engine exited during startup with code {process.returncode}")
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"engine did not listen on 127.0.0.1:{port}")


def advertised_content_length(header_path: Path) -> int | None:
    value: int | None = None
    for line in header_path.read_text(encoding="latin-1").splitlines():
        if line.lower().startswith("content-length:"):
            value = int(line.split(":", 1)[1].strip())
    return value


def sweep_sizes() -> list[int]:
    sizes = set(range(1024, 2 * 1024 * 1024 + 1, 16 * 1024))
    # Exercise TLS/buffer boundaries and the originally observed body size.
    for boundary in [8192, 16384, 32768, 65536, 98304, 120361, 122088, 131072, 262144, 524288, 1048576, 2097152]:
        for delta in [-2, -1, 0, 1, 2]:
            if boundary + delta >= 1024:
                sizes.add(boundary + delta)
    return sorted(sizes)


def run_sweep(args: argparse.Namespace) -> int:
    binary = args.binary.resolve()
    repo = args.repo.resolve()
    base_config = args.config.resolve()
    ca_cert = args.ca_cert.resolve()
    ca_key = args.ca_key.resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)
    identity = git_identity(repo)
    identity.update({"binary": str(binary), "binary_sha256": sha256_file(binary)})
    address = source_ip()
    sizes = sweep_sizes() if not args.sizes else [int(value) for value in args.sizes.split(",")]
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="pe-response-size-") as raw_tmp:
        tmp = Path(raw_tmp)
        origin_cert, origin_key = create_origin_certificate(tmp, address, ca_cert, ca_key)
        config = tmp / "engine-config.json"
        isolated_config(
            base_config,
            config,
            repo=repo,
            proxy_port=args.proxy_port,
            ca_cert=ca_cert,
            ca_key=ca_key,
        )
        log_handle = (tmp / "engine.log").open("w", encoding="utf-8")
        engine = subprocess.Popen(
            [str(binary), "--engine-config", str(config)],
            cwd=repo,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "RUST_LOG": args.rust_log},
        )
        failures = 0
        try:
            wait_for_port(args.proxy_port, engine)
            with https_origin(address, args.origin_port, origin_cert, origin_key):
                with output.open("w", encoding="utf-8") as results:
                    for index, size in enumerate(sizes, start=1):
                        headers = tmp / "headers.txt"
                        body = tmp / "body.bin"
                        started = time.monotonic()
                        completed = subprocess.run(
                            [
                                "curl", "--silent", "--show-error", "--insecure", "--http1.1",
                                "--noproxy", "", "--proxy", f"http://127.0.0.1:{args.proxy_port}",
                                "--max-time", str(args.timeout), "--dump-header", str(headers),
                                "--output", str(body), f"https://{address}:{args.origin_port}/size/{size}",
                            ],
                            text=True,
                            capture_output=True,
                        )
                        duration = time.monotonic() - started
                        advertised = advertised_content_length(headers) if headers.exists() else None
                        received = body.stat().st_size if body.exists() else 0
                        passed = completed.returncode == 0 and advertised is not None and received == advertised
                        failures += int(not passed)
                        row = {
                            "format": "privacy_engine_response_size_sweep/v1",
                            "binary": identity,
                            "requested_body_bytes": size,
                            "advertised_body_bytes": advertised,
                            "received_body_bytes": received,
                            "curl_returncode": completed.returncode,
                            "curl_stderr": completed.stderr.strip()[:500],
                            "duration_seconds": round(duration, 6),
                            "passed": passed,
                        }
                        results.write(json.dumps(row, sort_keys=True) + "\n")
                        results.flush()
                        print(
                            f"[{index:03d}/{len(sizes):03d}] size={size} advertised={advertised} "
                            f"received={received} rc={completed.returncode} passed={int(passed)}"
                        )
        finally:
            engine.terminate()
            try:
                engine.wait(timeout=5)
            except subprocess.TimeoutExpired:
                engine.kill()
                engine.wait(timeout=2)
            log_handle.close()
            shutil.copyfile(tmp / "engine.log", output.with_suffix(output.suffix + ".engine.log"))

    manifest = {
        "format": "privacy_engine_response_size_sweep_manifest/v1",
        "binary": identity,
        "source_address": address,
        "proxy_port": args.proxy_port,
        "origin_port": args.origin_port,
        "timeout_seconds": args.timeout,
        "sizes": sizes,
        "rows": len(sizes),
        "failures": failures,
        "results": str(output),
        "results_sha256": sha256_file(output),
    }
    output.with_suffix(output.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if failures == 0 else 4


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ca-cert", type=Path, required=True)
    parser.add_argument("--ca-key", type=Path, required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--origin-port", type=int, default=18443)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--sizes", help="comma-separated pilot sizes; default is the full sweep")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rust-log", default="warn")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run_sweep(parse_args()))
