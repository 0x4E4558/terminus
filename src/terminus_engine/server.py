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


class TerminusServer:
    def __init__(self, host: str, port: int, host_key: str | None, state_file: str) -> None:
        self.host = host
        self.port = port
        self.host_key = host_key
        self.persistence = PersistenceEngine(Path(state_file))
        self.kernel = VirtualKernel(self.persistence.load_vfs())
        self.renderer = TerminalRenderer()
        self.sessions = SessionManager()
        self._listener: asyncssh.SSHAcceptor | None = None

    async def start(self) -> None:
        options = {}
        if self.host_key:
            options["server_host_keys"] = [self.host_key]

        self._listener = await asyncssh.listen(
            self.host,
            self.port,
            process_factory=self._handle_client,
            encoding="utf-8",
            **options,
        )

    async def _handle_client(self, process: asyncssh.SSHServerProcess) -> None:
        session = self.sessions.create()
        shell = ShellEngine(self.kernel, session)
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


async def run_server(host: str, port: int, host_key: str | None, state_file: str) -> None:
    server = TerminusServer(host=host, port=port, host_key=host_key, state_file=state_file)
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
    parser.add_argument(
        "--state-file",
        default=".terminus/state/world.json",
        help="Persistence file for virtual world state",
    )
    args = parser.parse_args()
    asyncio.run(run_server(args.host, args.port, args.host_key, args.state_file))


if __name__ == "__main__":
    main()
