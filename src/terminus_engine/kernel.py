from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import fnmatch

from .vfs import VFSNode, VirtualFilesystem, VFSError


@dataclass(slots=True)
class ExecResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


class VirtualKernel:
    """Routes shell command intent to virtualized subsystems."""

    def __init__(self, vfs: VirtualFilesystem | None = None) -> None:
        self.vfs = vfs or VirtualFilesystem()

    def run(
        self,
        command: str,
        args: list[str],
        flags: list[str],
        cwd: str,
        env: dict[str, str],
        stdin: str = "",
    ) -> ExecResult:
        dispatch = {
            "pwd": self._pwd,
            "ls": self._ls,
            "cd": self._cd,
            "cat": self._cat,
            "mkdir": self._mkdir,
            "touch": self._touch,
            "cp": self._cp,
            "mv": self._mv,
            "rm": self._rm,
            "grep": self._grep,
            "echo": self._echo,
            "help": self._help,
        }
        handler = dispatch.get(command)
        if handler is None:
            return ExecResult(stderr=f"{command}: command not found\n", exit_code=127)
        try:
            return handler(args=args, flags=flags, cwd=cwd, env=env, stdin=stdin)
        except (FileNotFoundError, VFSError, ValueError) as exc:
            return ExecResult(stderr=f"{command}: {exc}\n", exit_code=1)

    def _pwd(self, **kwargs) -> ExecResult:
        return ExecResult(stdout=f"{kwargs['cwd']}\n")

    def _ls(self, args: list[str], flags: list[str], cwd: str, **kwargs) -> ExecResult:
        target = args[0] if args else "."
        path = self.vfs.resolve_path(cwd, target)
        include_hidden = "-a" in flags or "--all" in flags
        long = "-l" in flags
        nodes = self.vfs.list_dir(path, include_hidden=include_hidden)
        if long:
            lines = [
                f"{n.node_type[0]}{self._mode_to_rwx(n.mode)} {n.owner} {n.group} {self._node_size(n)} {n.modified_at} {n.name}"
                for n in nodes
            ]
            return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "")
        return ExecResult(stdout=("  ".join(n.name for n in nodes) + "\n") if nodes else "")

    def _node_size(self, node: VFSNode) -> int:
        if node.node_type == "dir":
            return len(node.children)
        return len(node.content)

    def _mode_to_rwx(self, mode: str) -> str:
        mapping = {
            "0": "---",
            "1": "--x",
            "2": "-w-",
            "3": "-wx",
            "4": "r--",
            "5": "r-x",
            "6": "rw-",
            "7": "rwx",
        }
        if len(mode) != 3 or any(ch not in mapping for ch in mode):
            return "rw-r--r--"
        return "".join(mapping[ch] for ch in mode)

    def _cd(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        target = args[0] if args else "/home/operator"
        path = self.vfs.resolve_path(cwd, target)
        node, _ = self.vfs._walk(path)
        if node.node_type != "dir":
            raise VFSError(f"not a directory: {target}")
        return ExecResult(stdout=f"__CWD__:{path}\n")

    def _cat(self, args: list[str], cwd: str, stdin: str, **kwargs) -> ExecResult:
        if not args:
            return ExecResult(stdout=stdin)
        chunks: list[str] = []
        for item in args:
            path = self.vfs.resolve_path(cwd, item)
            chunks.append(self.vfs.read_file(path))
        text = "".join(chunks)
        if text and not text.endswith("\n"):
            text += "\n"
        return ExecResult(stdout=text)

    def _mkdir(self, args: list[str], flags: list[str], cwd: str, **kwargs) -> ExecResult:
        if not args:
            raise ValueError("missing operand")
        parents = "-p" in flags
        for item in args:
            path = self.vfs.resolve_path(cwd, item)
            self.vfs.mkdir(path, parents=parents)
        return ExecResult()

    def _touch(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        if not args:
            raise ValueError("missing file operand")
        for item in args:
            self.vfs.touch_file(self.vfs.resolve_path(cwd, item))
        return ExecResult()

    def _cp(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        if len(args) != 2:
            raise ValueError("usage: cp SRC DST")
        src = self.vfs.resolve_path(cwd, args[0])
        dst_raw = self.vfs.resolve_path(cwd, args[1])
        dst = self._coerce_dest(src, dst_raw)
        self.vfs.copy(src, dst)
        return ExecResult()

    def _mv(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        if len(args) != 2:
            raise ValueError("usage: mv SRC DST")
        src = self.vfs.resolve_path(cwd, args[0])
        dst_raw = self.vfs.resolve_path(cwd, args[1])
        dst = self._coerce_dest(src, dst_raw)
        self.vfs.move(src, dst)
        return ExecResult()

    def _coerce_dest(self, src: str, dst: str) -> str:
        if self.vfs.exists(dst):
            node, _ = self.vfs._walk(dst)
            if node.node_type == "dir":
                return str(PurePosixPath(dst) / PurePosixPath(src).name)
        return dst

    def _rm(self, args: list[str], flags: list[str], cwd: str, **kwargs) -> ExecResult:
        if not args:
            raise ValueError("missing operand")
        recursive = "-r" in flags or "-rf" in flags or "-fr" in flags
        force = "-f" in flags or "-rf" in flags or "-fr" in flags
        for item in args:
            path = self.vfs.resolve_path(cwd, item)
            try:
                self.vfs.remove(path, recursive=recursive)
            except FileNotFoundError:
                if not force:
                    raise
        return ExecResult()

    def _grep(self, args: list[str], cwd: str, stdin: str, **kwargs) -> ExecResult:
        if not args:
            raise ValueError("usage: grep PATTERN [FILE]")
        pattern = args[0]
        if len(args) > 1:
            content = self.vfs.read_file(self.vfs.resolve_path(cwd, args[1]))
        else:
            content = stdin
        lines = content.splitlines()
        matched = [ln for ln in lines if fnmatch.fnmatch(ln, f"*{pattern}*")]
        return ExecResult(stdout=("\n".join(matched) + "\n") if matched else "", exit_code=0 if matched else 1)

    def _echo(self, args: list[str], **kwargs) -> ExecResult:
        return ExecResult(stdout=(" ".join(args) + "\n"))

    def _help(self, **kwargs) -> ExecResult:
        return ExecResult(
            stdout=(
                "virtual commands: pwd ls cd cat mkdir touch cp mv rm grep echo help\n"
                "all operations run against TERMINUS virtual subsystems only.\n"
            )
        )
