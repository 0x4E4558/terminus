from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath
import copy


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class VFSNode:
    name: str
    node_type: str
    owner: str = "operator"
    group: str = "operators"
    mode: str = "755"
    hidden: bool = False
    created_at: str = field(default_factory=_now)
    modified_at: str = field(default_factory=_now)
    content: str = ""
    target: str | None = None
    children: dict[str, "VFSNode"] = field(default_factory=dict)

    def touch(self) -> None:
        self.modified_at = _now()


class VFSError(RuntimeError):
    pass


class VirtualFilesystem:
    def __init__(self) -> None:
        self.root = VFSNode(name="", node_type="dir", mode="755")
        self._seed_world()

    def _seed_world(self) -> None:
        self.mkdir("/home")
        self.mkdir("/home/operator")
        self.mkdir("/home/operator/logs")
        self.write_file(
            "/home/operator/README.term",
            "ANOMALY CONFIRMED: You are now inside THE WRECK.\n"
            "Investigate systems. Trust telemetry, not assumptions.\n",
        )
        self.write_file(
            "/home/operator/logs/bootstrap.log",
            "epoch=post-collapse host=crash-site status=unstable\n",
        )
        self.mkdir("/etc")
        self.write_file("/etc/hostname", "crash-site\n")
        self.mkdir("/var")
        self.mkdir("/var/log")
        self.write_file("/var/log/auth.log", "failed_login user=unknown src=10.0.9.7\n")

    def resolve_path(self, cwd: str, path: str) -> str:
        candidate = PurePosixPath(path)
        if not candidate.is_absolute():
            candidate = PurePosixPath(cwd) / candidate

        stack: list[str] = []
        for part in candidate.parts:
            if part in {"", "/", "."}:
                continue
            if part == "..":
                if stack:
                    stack.pop()
                continue
            stack.append(part)
        return "/" + "/".join(stack)

    def _walk(self, abs_path: str) -> tuple[VFSNode, str]:
        if not abs_path.startswith("/"):
            raise VFSError(f"path must be absolute: {abs_path}")
        if abs_path == "/":
            return self.root, ""
        parts = [p for p in PurePosixPath(abs_path).parts if p != "/"]
        node = self.root
        for part in parts:
            if node.node_type != "dir":
                raise VFSError(f"not a directory: {node.name}")
            child = node.children.get(part)
            if child is None:
                raise FileNotFoundError(abs_path)
            node = child
        return node, parts[-1]

    def _parent_of(self, abs_path: str) -> tuple[VFSNode, str]:
        p = PurePosixPath(abs_path)
        if str(p) == "/":
            raise VFSError("root has no parent")
        parent_path = str(p.parent) or "/"
        parent, _ = self._walk(parent_path)
        return parent, p.name

    def exists(self, abs_path: str) -> bool:
        try:
            self._walk(abs_path)
            return True
        except FileNotFoundError:
            return False

    def mkdir(self, abs_path: str, parents: bool = True) -> None:
        if abs_path == "/":
            return
        parts = [p for p in PurePosixPath(abs_path).parts if p != "/"]
        node = self.root
        for idx, part in enumerate(parts):
            last = idx == len(parts) - 1
            child = node.children.get(part)
            if child is None:
                if not parents and not last:
                    raise FileNotFoundError(abs_path)
                child = VFSNode(name=part, node_type="dir", mode="755", hidden=part.startswith("."))
                node.children[part] = child
                node.touch()
            elif child.node_type != "dir":
                raise VFSError(f"not a directory: {part}")
            node = child
        node.touch()

    def list_dir(self, abs_path: str, include_hidden: bool = False) -> list[VFSNode]:
        node, _ = self._walk(abs_path)
        if node.node_type != "dir":
            raise VFSError(f"not a directory: {abs_path}")
        children = list(node.children.values())
        if not include_hidden:
            children = [c for c in children if not c.hidden]
        return sorted(children, key=lambda n: n.name)

    def read_file(self, abs_path: str) -> str:
        node, _ = self._walk(abs_path)
        if node.node_type != "file":
            raise VFSError(f"not a file: {abs_path}")
        return node.content

    def write_file(self, abs_path: str, content: str, append: bool = False) -> None:
        parent, name = self._parent_of(abs_path)
        if parent.node_type != "dir":
            raise VFSError(f"not a directory: {str(PurePosixPath(abs_path).parent)}")
        node = parent.children.get(name)
        if node is None:
            node = VFSNode(name=name, node_type="file", mode="644", hidden=name.startswith("."))
            parent.children[name] = node
        if node.node_type != "file":
            raise VFSError(f"not a file: {abs_path}")
        node.content = node.content + content if append else content
        node.touch()
        parent.touch()

    def touch_file(self, abs_path: str) -> None:
        if self.exists(abs_path):
            node, _ = self._walk(abs_path)
            if node.node_type != "file":
                raise VFSError(f"not a file: {abs_path}")
            node.touch()
            return
        self.write_file(abs_path, "")

    def remove(self, abs_path: str, recursive: bool = False) -> None:
        if abs_path == "/":
            raise VFSError("cannot remove root")
        node, _ = self._walk(abs_path)
        if node.node_type == "dir" and node.children and not recursive:
            raise VFSError(f"directory not empty: {abs_path}")
        parent, name = self._parent_of(abs_path)
        del parent.children[name]
        parent.touch()

    def move(self, src: str, dst: str) -> None:
        src_parent, src_name = self._parent_of(src)
        node = src_parent.children.get(src_name)
        if node is None:
            raise FileNotFoundError(src)
        dst_parent_path = str(PurePosixPath(dst).parent) or "/"
        if not self.exists(dst_parent_path):
            raise FileNotFoundError(dst_parent_path)
        dst_parent, dst_name = self._parent_of(dst)
        node.name = dst_name
        dst_parent.children[dst_name] = node
        del src_parent.children[src_name]
        src_parent.touch()
        dst_parent.touch()

    def copy(self, src: str, dst: str) -> None:
        src_node, _ = self._walk(src)
        dst_parent, dst_name = self._parent_of(dst)
        node_copy = copy.deepcopy(src_node)
        node_copy.name = dst_name
        dst_parent.children[dst_name] = node_copy
        dst_parent.touch()

    def to_dict(self) -> dict:
        def pack(node: VFSNode) -> dict:
            return {
                "name": node.name,
                "node_type": node.node_type,
                "owner": node.owner,
                "group": node.group,
                "mode": node.mode,
                "hidden": node.hidden,
                "created_at": node.created_at,
                "modified_at": node.modified_at,
                "content": node.content,
                "target": node.target,
                "children": {k: pack(v) for k, v in node.children.items()},
            }

        return pack(self.root)

    @classmethod
    def from_dict(cls, data: dict) -> "VirtualFilesystem":
        def unpack(node_data: dict) -> VFSNode:
            node = VFSNode(
                name=node_data["name"],
                node_type=node_data["node_type"],
                owner=node_data.get("owner", "operator"),
                group=node_data.get("group", "operators"),
                mode=node_data.get("mode", "755"),
                hidden=node_data.get("hidden", False),
                created_at=node_data.get("created_at", _now()),
                modified_at=node_data.get("modified_at", _now()),
                content=node_data.get("content", ""),
                target=node_data.get("target"),
            )
            node.children = {k: unpack(v) for k, v in node_data.get("children", {}).items()}
            return node

        fs = cls.__new__(cls)
        fs.root = unpack(data)
        return fs
