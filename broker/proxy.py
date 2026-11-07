"""Per-job target-side capture for decisive remote evidence.

The broker records the target VM's tap interface while the attacker runs the
PoC. The tap carries both directions of the target's traffic, so the parsed
target-to-attacker payload is the same target-side evidence a TCP proxy would
record, without changing the PoC's target URL. Production runs this in the
root broker; an unprivileged dev broker cannot open a capture socket.
"""

from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


class CaptureError(RuntimeError):
    """A capture could not start, stop, or parse."""


@dataclass
class ProxyCapture:
    interface: str
    target_ip: str
    target_port: int
    output_path: Path
    process: subprocess.Popen[str] | None = field(default=None, init=False)

    def start(self) -> None:
        if shutil.which("tshark") is None:
            raise CaptureError("tshark is not installed")
        self.output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        command = [
            "tshark",
            "-i",
            self.interface,
            "-f",
            f"tcp port {self.target_port}",
            "-w",
            str(self.output_path),
            "-q",
        ]
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            raise CaptureError(str(exc)) from exc
        # Give tshark time to open the capture socket and write the pcap header.
        time.sleep(0.5)
        if self.process.poll() is not None:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise CaptureError(stderr.strip() or "capture process exited")

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if not self.output_path.is_file():
            raise CaptureError("capture file is missing")

    def sha256(self) -> str:
        digest = hashlib.sha256()
        with self.output_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def parse_capture(
    path: Path,
    target_ip: str,
    *,
    attacker_ip: str | None = None,
    target_port: int | None = None,
    max_bytes: int = 1_000_000,
) -> str:
    """Return target-to-attacker TCP payload text from a pcap."""
    filters = [f"ip.src == {target_ip}", "tcp.len > 0"]
    if attacker_ip is not None:
        filters.append(f"ip.dst == {attacker_ip}")
    if target_port is not None:
        filters.append(f"tcp.srcport == {target_port}")
    command = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        " && ".join(filters),
        "-T",
        "fields",
        "-e",
        "tcp.payload",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError(str(exc)) from exc
    if result.returncode != 0:
        raise CaptureError(result.stderr.strip() or "tshark failed")
    hex_payload = "".join(line.strip() for line in result.stdout.splitlines())
    if len(hex_payload) % 2:
        hex_payload = hex_payload[:-1]
    try:
        raw = bytes.fromhex(hex_payload)[:max_bytes]
    except ValueError as exc:
        raise CaptureError("invalid tshark payload") from exc
    return raw.decode("utf-8", "replace")


class SerialCapture:
    """Read the target's QEMU TCP serial chardev into a broker-owned log."""

    def __init__(self, host: str, port: int, output_path: Path):
        self.host = host
        self.port = port
        self.output_path = output_path
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None

    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        self._thread = threading.Thread(
            target=self._run,
            name=f"xentry-serial-{self.port}",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._socket = socket.create_connection(
                    (self.host, self.port), timeout=1
                )
                self._socket.settimeout(None)
            except OSError:
                time.sleep(0.2)
                continue
            try:
                with self.output_path.open("ab") as handle:
                    while not self._stop.is_set():
                        try:
                            data = self._socket.recv(65536)
                        except OSError:
                            break
                        if not data:
                            break
                        handle.write(data)
                        handle.flush()
            finally:
                try:
                    self._socket.close()
                except OSError:
                    pass
                self._socket = None
            # A guest reboot can reset the chardev connection; reconnect and
            # append to the same log so post-boot evidence is retained.
            if not self._stop.is_set():
                time.sleep(0.2)

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
