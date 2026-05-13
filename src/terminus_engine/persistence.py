from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .vfs import VirtualFilesystem
from .world import WorldSimulation


@dataclass(slots=True)
class PersistenceEngine:
    state_file: Path

    def save_state(self, vfs: VirtualFilesystem, world: WorldSimulation) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "terminus-state-v2",
            "vfs": vfs.to_dict(),
            "world": world.to_dict(),
        }
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load_state(self) -> tuple[VirtualFilesystem, WorldSimulation]:
        if not self.state_file.exists():
            return VirtualFilesystem(), WorldSimulation()
        data = json.loads(self.state_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "vfs" in data:
            vfs = VirtualFilesystem.from_dict(data["vfs"])
            world_raw = data.get("world", {})
            world = WorldSimulation.from_dict(world_raw) if world_raw else WorldSimulation()
            return vfs, world
        return VirtualFilesystem.from_dict(data), WorldSimulation()

    def save_vfs(self, vfs: VirtualFilesystem) -> None:
        self.save_state(vfs, WorldSimulation())

    def load_vfs(self) -> VirtualFilesystem:
        vfs, _ = self.load_state()
        return vfs
