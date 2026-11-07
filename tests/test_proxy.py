"""Target-side capture parser tests."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

from broker.proxy import CaptureError, ProxyCapture, SerialCapture, parse_capture

PAYLOAD = "HTTP/1.1 400 Bad Request\r\nContent-Length: 6\r\n\r\nabcdef"


def _hex_dump(raw: bytes) -> str:
    lines = []
    for offset in range(0, len(raw), 16):
        chunk = raw[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines) + "\n"


@pytest.mark.skipif(
    shutil.which("text2pcap") is None or shutil.which("tshark") is None,
    reason="wireshark tools are not installed",
)
def test_parse_capture_keeps_only_target_to_attacker_payload(tmp_path) -> None:
    pcap = tmp_path / "capture.pcap"
    dump = tmp_path / "payload.txt"
    dump.write_text(_hex_dump(PAYLOAD.encode()), encoding="utf-8")
    subprocess.run(
        [
            "text2pcap",
            "-q",
            "-4",
            "10.42.0.10,10.42.0.20",
            "-T",
            "80,34567",
            str(dump),
            str(pcap),
        ],
        check=True,
        capture_output=True,
    )
    assert parse_capture(pcap, "10.42.0.10") == PAYLOAD
    assert (
        parse_capture(
            pcap,
            "10.42.0.10",
            attacker_ip="10.42.0.20",
            target_port=80,
        )
        == PAYLOAD
    )
    assert (
        parse_capture(
            pcap,
            "10.42.0.10",
            attacker_ip="10.42.0.20",
            target_port=443,
        )
        == ""
    )
    assert parse_capture(pcap, "10.42.0.20") == ""


def test_capture_start_requires_tshark(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("broker.proxy.shutil.which", lambda _name: None)
    capture = ProxyCapture("vnet0", "10.42.0.10", 80, tmp_path / "capture.pcap")
    with pytest.raises(CaptureError, match="tshark"):
        capture.start()


def test_serial_capture_logs_tcp_output(tmp_path) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = int(server.getsockname()[1])
    output = tmp_path / "serial.log"
    capture = SerialCapture("127.0.0.1", port, output)
    capture.start()
    try:
        client, _ = server.accept()
        with client:
            client.sendall(b"boot log\nnonce-123\n")
        time.sleep(0.2)
    finally:
        capture.stop()
        server.close()
    assert "nonce-123" in output.read_text(encoding="utf-8")


def test_serial_capture_reconnects_after_eof(tmp_path) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    port = int(server.getsockname()[1])
    output = tmp_path / "serial.log"
    capture = SerialCapture("127.0.0.1", port, output)
    capture.start()
    try:
        first, _ = server.accept()
        with first:
            first.sendall(b"first\n")
        second, _ = server.accept()
        with second:
            second.sendall(b"second\n")
        time.sleep(0.2)
    finally:
        capture.stop()
        server.close()
    text = output.read_text(encoding="utf-8")
    assert "first" in text
    assert "second" in text
