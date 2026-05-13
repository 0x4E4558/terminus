from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
import fnmatch

from .vfs import VFSNode, VirtualFilesystem, VFSError
from .world import WorldSimulation


@dataclass(slots=True)
class ExecResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


class VirtualKernel:
    """Routes shell command intent to virtualized subsystems."""

    def __init__(self, vfs: VirtualFilesystem | None = None, world: WorldSimulation | None = None) -> None:
        self.vfs = vfs or VirtualFilesystem()
        self.world = world or WorldSimulation()

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
            "whoami": self._whoami,
            "uname": self._uname,
            "id": self._id,
            "date": self._date,
            "head": self._head,
            "tail": self._tail,
            "wc": self._wc,
            "find": self._find,
            "chmod": self._chmod,
            "chown": self._chown,
            "df": self._df,
            "du": self._du,
            "free": self._free,
            "help": self._help,
            "regions": self._regions,
            "hosts": self._hosts,
            "factions": self._factions,
            "npcs": self._npcs,
            "travel": self._travel,
            "ps": self._ps,
            "kill": self._kill,
            "systemctl": self._systemctl,
            "ss": self._ss,
            "authlog": self._authlog,
            "logs": self._logs,
            "telemetry": self._telemetry,
            "incidents": self._incidents,
            "malware": self._malware,
            "contain": self._contain,
            "teams": self._teams,
            "events": self._events,
            "siem": self._siem,
            "edr": self._edr,
            "brief": self._brief,
            "objectives": self._objectives,
            "metrics": self._metrics,
            "dialogue": self._dialogue,
            "state": self._state,
            "avatar": self._avatar,
            "advance": self._advance,
            "training": self._training,
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
        node = self.vfs.get_node(path)
        if node.node_type == "dir":
            nodes = self.vfs.list_dir(path, include_hidden=include_hidden)
        else:
            nodes = [node]
        if long:
            lines = []
            for n in nodes:
                permissions = f"{n.node_type[0]}{self._mode_to_rwx(n.mode)}"
                identity = f"{n.owner} {n.group}"
                size = str(self._node_size(n))
                lines.append(f"{permissions} {identity} {size} {n.modified_at} {n.name}")
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
        node = self.vfs.get_node(path)
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
            node = self.vfs.get_node(dst)
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

    def _whoami(self, env: dict[str, str], **kwargs) -> ExecResult:
        return ExecResult(stdout=f"{env.get('USER', 'operator')}\n")

    def _uname(self, args: list[str], **kwargs) -> ExecResult:
        if "-a" in args:
            return ExecResult(stdout="Linux crash-site 6.8.0-terminus #1 SMP x86_64 GNU/Linux\n")
        return ExecResult(stdout="Linux\n")

    def _id(self, env: dict[str, str], **kwargs) -> ExecResult:
        user = env.get("USER", "operator")
        return ExecResult(stdout=f"uid=1000({user}) gid=1000(operators) groups=1000(operators)\n")

    def _date(self, **kwargs) -> ExecResult:
        return ExecResult(stdout=f"{datetime.now(UTC).strftime('%a %b %d %H:%M:%S UTC %Y')}\n")

    def _head(self, args: list[str], flags: list[str], cwd: str, stdin: str, **kwargs) -> ExecResult:
        line_count = 10
        file_arg: str | None = None
        if "-n" in flags:
            if not args:
                raise ValueError("usage: head [-n N] [FILE]")
            line_count = int(args[0])
            if len(args) > 1:
                file_arg = args[1]
        elif args and args[0] == "-n":
            if len(args) < 2:
                raise ValueError("usage: head [-n N] [FILE]")
            line_count = int(args[1])
            if len(args) > 2:
                file_arg = args[2]
        elif args:
            file_arg = args[0]
        content = self.vfs.read_file(self.vfs.resolve_path(cwd, file_arg)) if file_arg else stdin
        lines = content.splitlines()
        output = "\n".join(lines[:line_count])
        return ExecResult(stdout=(output + "\n") if output else "")

    def _tail(self, args: list[str], flags: list[str], cwd: str, stdin: str, **kwargs) -> ExecResult:
        line_count = 10
        file_arg: str | None = None
        if "-n" in flags:
            if not args:
                raise ValueError("usage: tail [-n N] [FILE]")
            line_count = int(args[0])
            if len(args) > 1:
                file_arg = args[1]
        elif args and args[0] == "-n":
            if len(args) < 2:
                raise ValueError("usage: tail [-n N] [FILE]")
            line_count = int(args[1])
            if len(args) > 2:
                file_arg = args[2]
        elif args:
            file_arg = args[0]
        content = self.vfs.read_file(self.vfs.resolve_path(cwd, file_arg)) if file_arg else stdin
        lines = content.splitlines()
        output = "\n".join(lines[-line_count:])
        return ExecResult(stdout=(output + "\n") if output else "")

    def _wc(self, args: list[str], cwd: str, stdin: str, **kwargs) -> ExecResult:
        file_arg = args[0] if args else None
        content = self.vfs.read_file(self.vfs.resolve_path(cwd, file_arg)) if file_arg else stdin
        lines = content.splitlines()
        words = sum(len(line.split()) for line in lines)
        bytes_count = len(content.encode("utf-8"))
        label = file_arg or "-"
        return ExecResult(stdout=f"{len(lines)} {words} {bytes_count} {label}\n")

    def _find(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        if args and args[0] == "-name":
            start = "."
        else:
            start = args[0] if args else "."
        pattern = "*"
        if "-name" in args:
            idx = args.index("-name")
            if idx + 1 >= len(args):
                raise ValueError("usage: find PATH [-name PATTERN]")
            pattern = args[idx + 1]
        start_path = self.vfs.resolve_path(cwd, start)
        rows: list[str] = []
        self._collect_find_rows(start_path, pattern, rows)
        return ExecResult(stdout=("\n".join(rows) + "\n") if rows else "", exit_code=0 if rows else 1)

    def _collect_find_rows(self, abs_path: str, pattern: str, rows: list[str]) -> None:
        node = self.vfs.get_node(abs_path)
        name = PurePosixPath(abs_path).name or "/"
        if fnmatch.fnmatch(name, pattern):
            rows.append(abs_path)
        if node.node_type == "dir":
            for child_name in sorted(node.children.keys()):
                child_path = str(PurePosixPath(abs_path) / child_name) if abs_path != "/" else f"/{child_name}"
                self._collect_find_rows(child_path, pattern, rows)

    def _chmod(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        if len(args) < 2:
            raise ValueError("usage: chmod MODE FILE...")
        mode = args[0]
        if len(mode) != 3 or any(ch not in "01234567" for ch in mode):
            raise ValueError("mode must be octal, e.g., 644")
        for target in args[1:]:
            path = self.vfs.resolve_path(cwd, target)
            node = self.vfs.get_node(path)
            node.mode = mode
            node.touch()
        return ExecResult()

    def _chown(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        if len(args) < 2:
            raise ValueError("usage: chown OWNER[:GROUP] FILE...")
        owner_spec = args[0]
        owner, sep, group = owner_spec.partition(":")
        for target in args[1:]:
            path = self.vfs.resolve_path(cwd, target)
            node = self.vfs.get_node(path)
            node.owner = owner or node.owner
            if sep:
                node.group = group or node.group
            node.touch()
        return ExecResult()

    def _df(self, **kwargs) -> ExecResult:
        total = 10 * 1024 * 1024
        used = self._du_size("/")
        available = max(0, total - used)
        use_pct = int((used / total) * 100) if total else 0
        lines = [
            "Filesystem     1K-blocks  Used Available Use% Mounted on",
            f"terminus-vfs   {total // 1024:<9} {used // 1024:<5} {available // 1024:<9} {use_pct}% /",
        ]
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _du(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        target = args[0] if args else "."
        path = self.vfs.resolve_path(cwd, target)
        size = self._du_size(path)
        return ExecResult(stdout=f"{size}\t{path}\n")

    def _du_size(self, abs_path: str) -> int:
        node = self.vfs.get_node(abs_path)
        if node.node_type == "file":
            return len(node.content.encode("utf-8"))
        total = 0
        for name in node.children:
            child_path = str(PurePosixPath(abs_path) / name) if abs_path != "/" else f"/{name}"
            total += self._du_size(child_path)
        return total

    def _free(self, **kwargs) -> ExecResult:
        lines = [
            "              total        used        free      shared  buff/cache   available",
            "Mem:        2048000      884000      420000       64000      744000      980000",
            "Swap:       1024000      120000      904000",
        ]
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _help(self, **kwargs) -> ExecResult:
        return ExecResult(
            stdout=(
                "core admin commands: pwd ls cd cat mkdir touch cp mv rm grep echo whoami uname id date head tail wc find chmod chown df du free\n"
                "simulation commands: help regions hosts factions npcs travel ps kill systemctl ss authlog logs telemetry incidents malware contain teams events siem edr brief objectives metrics dialogue state avatar advance training\n"
                "all operations run against TERMINUS virtual subsystems only.\n"
            )
        )

    def _regions(self, **kwargs) -> ExecResult:
        lines = []
        for rid, region in sorted(self.world.regions.items()):
            marker = "*" if rid == self.world.current_region else " "
            lines.append(f"{marker} {rid}  {region['name']}  hosts={len(region['hosts'])}")
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _hosts(self, args: list[str], **kwargs) -> ExecResult:
        region = args[0] if args else None
        lines = []
        for host, info in sorted(self.world.hosts.items()):
            if region and info["region"] != region:
                continue
            marker = "*" if host == self.world.current_host else " "
            lines.append(
                f"{marker} {host}  region={info['region']} os={info.get('os', 'linux')} faction={info['faction']} transitions={','.join(info['transitions'])}"
            )
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "", exit_code=0 if lines else 1)

    def _factions(self, **kwargs) -> ExecResult:
        lines = [f"{key}  {item['name']}  doctrine=\"{item['doctrine']}\"" for key, item in sorted(self.world.factions.items())]
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _npcs(self, args: list[str], **kwargs) -> ExecResult:
        region = args[0] if args else None
        lines = []
        for name, npc in sorted(self.world.npcs.items()):
            if region and npc["region"] != region:
                continue
            lines.append(f"{name}  role={npc['role']} faction={npc['faction']} region={npc['region']}")
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "", exit_code=0 if lines else 1)

    def _travel(self, args: list[str], **kwargs) -> ExecResult:
        if len(args) != 1:
            raise ValueError("usage: travel HOST")
        destination = self.world.travel(args[0])
        return ExecResult(stdout=f"transition complete -> {destination}\n")

    def _ps(self, flags: list[str], **kwargs) -> ExecResult:
        show_all = "-A" in flags or "-ef" in flags
        lines = ["PID USER       CPU  MEM  STATE HOST         NAME"]
        for proc in sorted(self.world.processes, key=lambda p: p.pid):
            if proc.hidden and not show_all:
                continue
            lines.append(
                f"{proc.pid:<3} {proc.user:<10} {proc.cpu:>4.1f} {proc.mem:>4.1f} {proc.state:<5} {proc.host:<12} {proc.name}"
            )
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _kill(self, args: list[str], **kwargs) -> ExecResult:
        if len(args) != 1:
            raise ValueError("usage: kill PID")
        pid = int(args[0])
        if not self.world.kill(pid):
            raise ValueError(f"no such process: {pid}")
        return ExecResult()

    def _systemctl(self, args: list[str], **kwargs) -> ExecResult:
        if len(args) < 2:
            raise ValueError("usage: systemctl <status|start|stop|restart> SERVICE")
        action, service = args[0], args[1]
        self.world.set_service_state(service, action)
        svc = self.world.services[service]
        status_line = f"{service}.service - host={svc.host} status={svc.status}"
        if svc.pid is not None:
            status_line += f" pid={svc.pid}"
        return ExecResult(stdout=status_line + "\n")

    def _ss(self, flags: list[str], **kwargs) -> ExecResult:
        show_all = "-a" in flags or "-tulnp" in flags
        lines = ["Netid State  Local Address:Port  Peer Address:Port  Process"]
        for s in self.world.sockets:
            if s.state != "LISTEN" and not show_all:
                continue
            peer = s.remote or "*:*"
            process = f"pid={s.pid},{s.service}" if s.pid else (s.service or "-")
            lines.append(f"{s.proto:<5} {s.state:<6} {s.local}:{s.port:<5} {peer:<18} {process}")
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _authlog(self, args: list[str], **kwargs) -> ExecResult:
        host = args[0] if args else None
        rows = [e for e in self.world.auth_events if host is None or e["host"] == host]
        lines = [f"{e['ts']} host={e['host']} user={e['user']} src={e['src']} result={e['result']}" for e in rows]
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "", exit_code=0 if lines else 1)

    def _logs(self, args: list[str], **kwargs) -> ExecResult:
        host = args[0] if args else None
        rows = [e for e in self.world.log_events if host is None or e["host"] == host]
        lines = [f"{e['ts']} [{e['severity']}] {e['host']} {e['source']}: {e['message']}" for e in rows[-50:]]
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "", exit_code=0 if lines else 1)

    def _telemetry(self, args: list[str], **kwargs) -> ExecResult:
        host = args[0] if args else None
        rows = [e for e in self.world.telemetry if host is None or e["host"] == host]
        lines = [
            f"{e['ts']} host={e['host']} metric={e['metric']} value={e['value']} tags={','.join(e['tags'])}" for e in rows[-100:]
        ]
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "", exit_code=0 if lines else 1)

    def _incidents(self, args: list[str], **kwargs) -> ExecResult:
        mode = args[0] if args else "list"
        if mode == "list":
            lines = []
            for incident in self.world.incidents.values():
                lines.append(
                    f"{incident.incident_id} severity={incident.severity} status={incident.status} host={incident.host} indicators={','.join(incident.indicators)}"
                )
            return ExecResult(stdout="\n".join(lines) + "\n")
        if mode == "show":
            if len(args) < 2:
                raise ValueError("usage: incidents show INCIDENT_ID")
            incident = self.world.incidents.get(args[1])
            if incident is None:
                raise ValueError(f"unknown incident: {args[1]}")
            lines = [
                f"id={incident.incident_id}",
                f"title={incident.title}",
                f"host={incident.host}",
                f"severity={incident.severity}",
                f"status={incident.status}",
                f"malware={incident.malware}",
                f"persistence_chain={incident.persistence_chain}",
                f"anti_forensics={incident.anti_forensics}",
                f"rootkit={incident.rootkit}",
                f"exfiltration={incident.exfiltration}",
                f"indicators={','.join(incident.indicators)}",
            ]
            return ExecResult(stdout="\n".join(lines) + "\n")
        raise ValueError("usage: incidents [list|show INCIDENT_ID]")

    def _malware(self, args: list[str], **kwargs) -> ExecResult:
        mode = args[0] if args else "scan"
        if mode != "scan":
            raise ValueError("usage: malware scan")
        lines = []
        for incident in self.world.incidents.values():
            if incident.malware:
                lines.append(
                    f"{incident.incident_id} host={incident.host} rootkit={incident.rootkit} persistence={incident.persistence_chain} anti_forensics={incident.anti_forensics} exfiltration={incident.exfiltration}"
                )
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "no active malware signatures\n")

    def _contain(self, args: list[str], **kwargs) -> ExecResult:
        if len(args) != 1:
            raise ValueError("usage: contain INCIDENT_ID")
        self.world.contain_incident(args[0])
        return ExecResult(stdout=f"containment started for {args[0]}\n")

    def _teams(self, **kwargs) -> ExecResult:
        lines = []
        for team in self.world.teams.values():
            lines.append(
                f"{team.name} members={','.join(team.members)} sectors={','.join(team.sectors)} incidents={','.join(team.shared_incidents)}"
            )
        lines.append(f"online_sessions={','.join(self.world.online_sessions)}")
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _events(self, **kwargs) -> ExecResult:
        lines = []
        for event in self.world.events.values():
            lines.append(f"{event.event_id} status={event.status} regions={','.join(event.regions)} title={event.title}")
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "")

    def _siem(self, args: list[str], **kwargs) -> ExecResult:
        mode = args[0] if args else "hits"
        if mode == "hits":
            lines = [
                f"{d.ts} rule={d.rule_name} incident={d.incident_id} host={d.host} summary={d.summary}"
                for d in self.world.detections
            ]
            return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "no detections\n")
        if mode == "rules":
            lines = [
                f"{r.name} enabled={r.enabled} severity={r.severity} match_term={r.match_term}"
                for r in self.world.rules.values()
            ]
            return ExecResult(stdout="\n".join(lines) + "\n")
        raise ValueError("usage: siem [hits|rules]")

    def _edr(self, args: list[str], **kwargs) -> ExecResult:
        mode = args[0] if args else "status"
        if mode == "status":
            suspicious = [p for p in self.world.processes if p.malicious]
            hidden = [p for p in suspicious if p.hidden]
            return ExecResult(
                stdout=(
                    f"agent=edr-agent host={self.world.current_host} suspicious={len(suspicious)} hidden={len(hidden)}\n"
                )
            )
        if mode == "hunt":
            lines = [
                f"pid={p.pid} host={p.host} name={p.name} hidden={p.hidden} malicious={p.malicious}"
                for p in self.world.processes
                if p.malicious
            ]
            return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "no suspicious processes\n")
        raise ValueError("usage: edr [status|hunt]")

    def _brief(self, **kwargs) -> ExecResult:
        metrics = self.world.metrics()
        lines = [
            f"ANOMALY CONFIRMED: host={self.world.current_host} region={self.world.current_region}",
            f"open_incidents={metrics['open_incidents']} contained_incidents={metrics['contained_incidents']} detections={metrics['detections']}",
            f"hidden_malware={metrics['hidden_malware']} services={metrics['running_services']}/{metrics['total_services']} learning_index={metrics['learning_index']}",
            "Use objectives, incidents show <id>, logs, telemetry, and dialogue <channel> to plan response.",
        ]
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _objectives(self, **kwargs) -> ExecResult:
        lines = []
        for objective in self.world.objectives():
            marker = "[x]" if objective["status"] == "complete" else "[ ]"
            lines.append(f"{marker} {objective['id']} {objective['title']} :: {objective['hint']}")
        return ExecResult(stdout=("\n".join(lines) + "\n") if lines else "")

    def _metrics(self, **kwargs) -> ExecResult:
        metrics = self.world.metrics()
        skills = ", ".join(f"{name}={value}" for name, value in sorted(self.world.skills.items()))
        lines = [f"{key}={value}" for key, value in metrics.items()]
        lines.append(f"skills: {skills}")
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _dialogue(self, args: list[str], **kwargs) -> ExecResult:
        if not args:
            channels = ", ".join(sorted(self.world.dialogue_scripts.keys()))
            return ExecResult(stdout=f"available dialogue channels: {channels}\nusage: dialogue <channel>\n")
        speaker = args[0]
        lines = self.world.get_dialogue(speaker)
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _state(self, args: list[str], **kwargs) -> ExecResult:
        host = args[0] if args else None
        snapshot = self.world.state_snapshot(host=host)
        lines = [
            f"world_tick={snapshot['world_tick']}",
            f"current_region={snapshot['current_region']}",
            f"current_host={snapshot['current_host']}",
        ]
        for name, data in sorted(snapshot["hosts"].items()):
            lines.append(
                f"{name} os={data.get('os','linux')} stability={data.get('stability',0)} threat={data.get('threat_level','unknown')} updated={data.get('last_updated','')}"
            )
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _avatar(self, args: list[str], **kwargs) -> ExecResult:
        host = args[0] if args else None
        traces = self.world.get_avatar_traces(host=host)
        if not traces:
            return ExecResult(stdout="no avatar traces\n")
        lines = [
            f"{item['ts']} host={item['host']} confidence={item['confidence']} incident={item['linked_incident']} artifact={item['artifact']}"
            for item in traces
        ]
        return ExecResult(stdout="\n".join(lines) + "\n")

    def _advance(self, args: list[str], **kwargs) -> ExecResult:
        cycles = 1
        if args:
            cycles = int(args[0])
        self.world.advance_world(cycles=cycles)
        metrics = self.world.metrics()
        return ExecResult(
            stdout=(
                f"world advanced cycles={cycles} tick={metrics['world_tick']} open_incidents={metrics['open_incidents']} "
                f"contained_incidents={metrics['contained_incidents']}\n"
            )
        )

    def _training(self, args: list[str], cwd: str, **kwargs) -> ExecResult:
        mode = args[0] if args else "next"
        if mode == "list":
            rows = []
            for module in self.world.training_overview():
                marker = "[x]" if module["status"] == "complete" else "[ ]"
                rows.append(f"{marker} {module['id']} {module['title']} :: {module['focus']}")
            return ExecResult(stdout=("\n".join(rows) + "\n") if rows else "no training modules\n")
        if mode == "next":
            module = self.world.next_training_module()
            if module is None:
                return ExecResult(stdout="all foundational linux modules completed\n")
            seed_files = module.get("seed_files", [])
            if isinstance(seed_files, list):
                for item in seed_files:
                    if not isinstance(item, dict):
                        continue
                    seed_path = str(item.get("path", ""))
                    content = str(item.get("content", ""))
                    if seed_path and not self.vfs.exists(seed_path):
                        parent_path = str(PurePosixPath(seed_path).parent) or "/"
                        self.vfs.mkdir(parent_path, parents=True)
                        self.vfs.write_file(seed_path, content)
            return ExecResult(
                stdout=(
                    f"{module['id']} {module['title']}\n"
                    f"focus: {module['focus']}\n"
                    f"objective: {module['objective']}\n"
                    f"hint: {module['hint']}\n"
                    f"verify: training check {module['id']}\n"
                )
            )
        if mode == "check":
            if len(args) < 2:
                raise ValueError("usage: training check MODULE_ID")
            module_id = args[1]
            module_order = [str(module["id"]) for module in self.world.training_modules]
            if module_id not in module_order:
                raise ValueError(f"unknown training module: {module_id}")
            module_index = module_order.index(module_id)
            incomplete_before = [mid for mid in module_order[:module_index] if mid not in self.world.completed_training]
            if incomplete_before:
                return ExecResult(
                    stdout=f"{module_id} pending: complete prerequisites first -> {', '.join(incomplete_before)}\n",
                    exit_code=1,
                )
            complete, feedback = self._evaluate_training_module(module_id=module_id, cwd=cwd)
            if complete:
                self.world.complete_training_module(module_id)
                return ExecResult(stdout=f"{module_id} complete: {feedback}\n")
            return ExecResult(stdout=f"{module_id} pending: {feedback}\n", exit_code=1)
        raise ValueError("usage: training [list|next|check MODULE_ID]")

    def _evaluate_training_module(self, module_id: str, cwd: str) -> tuple[bool, str]:
        if module_id == "ANA-001":
            workspace = "/home/operator/training"
            if self.vfs.exists(workspace) and cwd == workspace:
                summary = self.vfs.resolve_path(workspace, "data-summary.txt")
                if not self.vfs.exists(summary):
                    return False, "create data-summary.txt using auth_sample.log"
                content = self.vfs.read_file(summary).lower()
                if "failed_login" in content:
                    return True, "data triage validated from log artifacts"
                return False, "data-summary.txt must contain 'failed_login'"
            return False, "create /home/operator/training and cd into it"
        if module_id == "ANA-002":
            summary = self.vfs.resolve_path("/home/operator/training", "system-summary.txt")
            if not self.vfs.exists(summary):
                return False, "system-summary.txt not found; capture systemctl status sshd output"
            content = self.vfs.read_file(summary).lower()
            if "sshd" in content and "running" in content:
                return True, "system service analysis validated"
            return False, "system-summary.txt must include 'sshd' and 'running'"
        if module_id == "ANA-003":
            summary = self.vfs.resolve_path("/home/operator/training", "network-summary.txt")
            if not self.vfs.exists(summary):
                return False, "network-summary.txt not found; capture ss output"
            content = self.vfs.read_file(summary)
            if "LISTEN" in content:
                return True, "network exposure analysis validated"
            return False, "network-summary.txt must include LISTEN sockets"
        if module_id == "ANA-004":
            report = self.vfs.resolve_path("/home/operator/training", "security-summary.txt")
            incident = self.world.incidents.get("INC-GLASS-VEIL")
            if incident is None or incident.status != "contained":
                return False, "contain INC-GLASS-VEIL first"
            if not self.vfs.exists(report):
                return False, "security-summary.txt not found"
            content = self.vfs.read_file(report).lower()
            if "contained" in content:
                return True, "security response and reporting validated"
            return False, "security-summary.txt must include 'contained'"
        raise ValueError(f"unknown training module: {module_id}")
