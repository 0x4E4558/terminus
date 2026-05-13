from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4


@dataclass(slots=True)
class SessionState:
    session_id: str = field(default_factory=lambda: str(uuid4()))
    cwd: str = "/home/operator"
    env: dict[str, str] = field(
        default_factory=lambda: {
            "USER": "operator",
            "HOST": "thewreck.net",
            "HOME": "/home/operator",
            "PWD": "/home/operator",
            "TERM": "xterm-256color",
        }
    )
    aliases: dict[str, str] = field(default_factory=dict)
    history: list[str] = field(default_factory=list)


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def create(self) -> SessionState:
        state = SessionState()
        self._sessions[state.session_id] = state
        return state

    def drop(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
