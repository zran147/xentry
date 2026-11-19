"""Guest SSH transport owned by the broker."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

import asyncssh

# The mirror VM every guest command is tunnelled through (ADR 0002).
# XENTRY_SSH_JUMP="" disables it, which is how the smoke scripts reach a
# guest on a network this host still has an address on. The key path does
# not vary - the bring-up writes it - so it is a constant, not an override.
JUMP_HOST = "10.44.0.2"
JUMP_KEY = "/etc/xentry/proxy-vm.key"
# WHERE THE TUNNEL SAYS WHY IT FAILED. With a proxy command, a refused inner
# connection reaches asyncssh as "Connection lost" - the proxy just closed its
# pipe - so EHOSTUNREACH, a wrong key and an unreachable guest all arrive
# looking identical. ssh's own -E log keeps the real reason:
#     connect to host 10.43.1.10 port 22: Connection refused
# asyncssh discards the proxy's stderr, so without this the reason is gone.
# (the path is inline in the command below, to spend no line on a constant)
#
# -v as well, and not for taste: with -E alone the log came back EMPTY while
# the VM's neighbour table showed `10.43.1.10 dev ens3 FAILED` at the same
# moment. A -W forwarding failure is logged at VERBOSE level, so the single
# line worth having was the one being filtered out.


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
        # Read here rather than passed, because runtime.py builds an
        # SSHTransport in seven places and none of them should have to know.
        self.jump = os.environ.get("XENTRY_SSH_JUMP", JUMP_HOST)

    async def _connect(self) -> asyncssh.SSHClientConnection:
        # THROUGH the mirror VM, so this host needs no route to a job subnet.
        #
        # %h AND %p ARE NOT SUBSTITUTED HERE, so the host and port are
        # interpolated directly. asyncssh stores proxy_command as a token list
        # via split_args and execs it; nothing in the package touches %h at
        # all - that is an OpenSSH client feature. With the placeholders left
        # in, every attempt ran
        #
        #     ssh ... -W %h:%p root@10.44.0.2
        #
        # which is a bad forwarding specification, so ssh exited at once,
        # asyncssh saw EOF, and the readiness loop reported "Connection lost"
        # thirty times in sixty seconds. The usage error goes to STDERR, not
        # to the -E log, which is why that log stayed empty and made the
        # tunnel look like it had never run - while the identical command
        # worked by hand, because a hand-typed ProxyCommand goes through
        # OpenSSH, which does expand %h and %p.
        #
        # proxy_command rather than asyncssh's tunnel=: a STRING tunnel is
        # built with only passphrase and config, never client_keys, so it
        # would hunt for ~/.ssh/id_* and never find the proxy key; a tunnel
        # OBJECT is not closed by asyncssh, so every command would leak one.
        # asyncssh owns the proxy subprocess and reaps it.
        jump = (
            f"ssh -i {JUMP_KEY} -v -E /var/lib/xentry/jump.log"
            f" -W {self.host}:{self.port} -o StrictHostKeyChecking=no"
            f" -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 root@{self.jump}"
        )
        return await asyncssh.connect(
            self.host,
            port=self.port,
            username=self.user,
            client_keys=[str(self.key_path)],
            known_hosts=None,
            login_timeout=self.connect_timeout,
            proxy_command=jump if self.jump else (),
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
