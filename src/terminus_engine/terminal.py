from __future__ import annotations

from .session import SessionState


class TerminalRenderer:
    BANNER = (
        "\x1b[38;5;39mTERMINUS ENGINE\x1b[0m\n"
        "\x1b[38;5;244mPersistent SSH-native simulation environment initialized.\x1b[0m\n"
    )

    def banner(self) -> str:
        return self.BANNER

    def prompt(self, session: SessionState) -> str:
        return f"\x1b[38;5;45m{session.env['USER']}@{session.env['HOST']}\x1b[0m:{session.cwd}$ "
