"""Guest SSH transport owned by the broker."""

from __future__ import annotations

import asyncio
import hashlib
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

import asyncssh


class SSHError(RuntimeError):
    """A guest SSH operation failed."""


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


class SSHTransport:
    def __init__(
        self,
        key_path: Path,
        user: str,
        host: str,
        *,
        port: int = 22,
        connect_timeout: float = 20.0,
        command_timeout: float = 60.0,
    ) -> None:
        self.key_path = Path(key_path)
        self.user = user
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout

    async def _connect(self) -> asyncssh.SSHClientConnection:
        return await asyncssh.connect(
            self.host,
            port=self.port,
            username=self.user,
            client_keys=[str(self.key_path)],
            known_hosts=None,
            login_timeout=self.connect_timeout,
        )

    async def _run(self, command: str, input_text: str | None) -> CommandResult:
        started = time.monotonic()
        async with await self._connect() as conn:
            result = await conn.run(
                command,
                input=input_text,
                check=False,
                timeout=self.command_timeout,
            )
            return CommandResult(
                exit_code=result.exit_status if result.exit_status is not None else 255,
                stdout=str(result.stdout or ""),
                stderr=str(result.stderr or ""),
                duration_ms=int((time.monotonic() - started) * 1000),
            )

    def run(self, command: str, input_text: str | None = None) -> CommandResult:
        try:
            return asyncio.run(self._run(command, input_text))
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise SSHError(str(exc)) from exc

    def wait(self, timeout_s: float = 60.0) -> None:
        deadline = time.monotonic() + timeout_s
        last = ""
        while time.monotonic() < deadline:
            try:
                result = self.run("true")
                if result.exit_code == 0:
                    return
                last = result.stderr
            except SSHError as exc:
                last = str(exc)
            time.sleep(2)
        raise SSHError(f"guest SSH did not become ready: {last}")

    async def _run_tty(self, command: str, input_text: str | None) -> CommandResult:
        started = time.monotonic()
        async with await self._connect() as conn, conn.create_process(
            command,
            term_type="xterm",
            term_size=(120, 40),
        ) as process:
            if input_text:
                process.stdin.write(input_text)
                await process.stdin.drain()
            stdout = await process.stdout.read()
            await process.wait()
            return CommandResult(
                exit_code=process.exit_status if process.exit_status is not None else 255,
                stdout=str(stdout or ""),
                stderr="",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

    def run_tty(
        self,
        command: str,
        input_text: str | None = None,
        timeout_s: float | None = None,
    ) -> CommandResult:
        try:
            coroutine = self._run_tty(command, input_text)
            if timeout_s is not None:
                return asyncio.run(asyncio.wait_for(coroutine, timeout_s))
            return asyncio.run(coroutine)
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise SSHError(str(exc)) from exc

    async def _put(self, local_path: Path, remote_path: str) -> None:
        async with await self._connect() as conn, conn.start_sftp_client() as sftp:
            await sftp.put(str(local_path), remote_path)

    def put(self, local_path: Path, remote_path: str) -> None:
        try:
            asyncio.run(self._put(local_path, remote_path))
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise SSHError(str(exc)) from exc

    async def _get(self, remote_path: str, local_path: Path) -> None:
        async with await self._connect() as conn, conn.start_sftp_client() as sftp:
            await sftp.get(remote_path, str(local_path))

    def get(self, remote_path: str, local_path: Path) -> None:
        try:
            asyncio.run(self._get(remote_path, local_path))
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise SSHError(str(exc)) from exc

    async def _place_nonce(
        self,
        path: str,
        owner: str,
        mode: int,
        value: str,
    ) -> None:
        command = (
            "set -e; umask 077; "
            f"cat > {shlex.quote(path)}; "
            f"chmod {mode:o} {shlex.quote(path)}; "
            f"chown {shlex.quote(owner)} {shlex.quote(path)}"
        )
        async with await self._connect() as conn:
            result = await conn.run(
                command,
                input=value,
                check=False,
                timeout=self.command_timeout,
            )
            if result.exit_status != 0:
                raise SSHError(str(result.stderr or "place_nonce failed"))

    def place_nonce(self, path: str, owner: str, mode: int, value: str) -> str:
        try:
            asyncio.run(self._place_nonce(path, owner, mode, value))
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise SSHError(str(exc)) from exc
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
