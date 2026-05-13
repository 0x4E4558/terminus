from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import signal

import asyncssh

from .kernel import VirtualKernel
from .persistence import PersistenceEngine
from .session import SessionManager
from .shell import ShellEngine
from .terminal import TerminalRenderer


class TerminusSSHServer(asyncssh.SSHServer):
    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == self._username and password == self._password


class TerminusServer:
    def __init__(
        self,
        host: str,
        port: int,
        host_key: str | None,
        state_file: str,
        auth_user: str,
        auth_password: str,
    ) -> None:
        self.host = host
        self.port = port
        self.host_key = host_key
        self.auth_user = auth_user
        self.auth_password = auth_password
        self.persistence = PersistenceEngine(Path(state_file))
        self.kernel = VirtualKernel(self.persistence.load_vfs())
        self.renderer = TerminalRenderer()
        self.sessions = SessionManager()
        self._listener: asyncssh.SSHAcceptor | None = None

    def _ensure_host_key(self) -> str:
        if self.host_key:
            host_key_path = Path(self.host_key)
        else:
            host_key_path = Path(".terminus/ssh_host_key")
        host_key_path.parent.mkdir(parents=True, exist_ok=True)
        if not host_key_path.exists():
            key = asyncssh.generate_private_key("ssh-ed25519")
            key.write_private_key(str(host_key_path))
        return str(host_key_path)

    async def start(self) -> None:
        self._listener = await asyncssh.listen(
            self.host,
            self.port,
            server_factory=lambda: TerminusSSHServer(
                username=self.auth_user,
                password=self.auth_password,
            ),
            process_factory=self._handle_client,
            encoding="utf-8",
            server_host_keys=[self._ensure_host_key()],
        )

    async def _handle_client(self, process: asyncssh.SSHServerProcess) -> None:
        session = self.sessions.create()
        shell = ShellEngine(
            self.kernel,
            session,
            on_state_change=lambda: self.persistence.save_vfs(self.kernel.vfs),
        )
        process.stdout.write(self.renderer.banner())
        process.stdout.write(self.renderer.prompt(session))
        async for line in process.stdin:
            response = await shell.handle_line(line.rstrip("\n"))
            if response == "__TERMINATE__":
                process.stdout.write("session terminated\n")
                break
            if response:
                process.stdout.write(response)
                if not response.endswith("\n"):
                    process.stdout.write("\n")
            process.stdout.write(self.renderer.prompt(session))
        self.sessions.drop(session.session_id)

    async def stop(self) -> None:
        self.persistence.save_vfs(self.kernel.vfs)
        if self._listener:
            self._listener.close()
            await self._listener.wait_closed()


async def run_server(
    host: str,
    port: int,
    host_key: str | None,
    state_file: str,
    auth_user: str,
    auth_password: str,
) -> None:
    server = TerminusServer(
        host=host,
        port=port,
        host_key=host_key,
        state_file=state_file,
        auth_user=auth_user,
        auth_password=auth_password,
    )
    await server.start()
    stop_event = asyncio.Event()

    def _graceful_stop() -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _graceful_stop)
        except NotImplementedError:
            pass
    await stop_event.wait()
    await server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TERMINUS ENGINE SSH server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8022)
    parser.add_argument("--host-key", default=None, help="Path to SSH host key (optional)")
    parser.add_argument("--auth-user", default="operator", help="SSH login username")
    parser.add_argument("--auth-password", default="wreck", help="SSH login password")
    parser.add_argument(
        "--state-file",
        default=".terminus/state/world.json",
        help="Persistence file for virtual world state",
    )
    args = parser.parse_args()
    asyncio.run(
        run_server(
            args.host,
            args.port,
            args.host_key,
            args.state_file,
            args.auth_user,
            args.auth_password,
        )
    )


if __name__ == "__main__":
    main()
