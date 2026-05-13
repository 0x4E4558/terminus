from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .vfs import VirtualFilesystem


@dataclass(slots=True)
class PersistenceEngine:
    state_file: Path

    def save_vfs(self, vfs: VirtualFilesystem) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(vfs.to_dict(), indent=2), encoding="utf-8")

    def load_vfs(self) -> VirtualFilesystem:
        if not self.state_file.exists():
            return VirtualFilesystem()
        data = json.loads(self.state_file.read_text(encoding="utf-8"))
        return VirtualFilesystem.from_dict(data)
