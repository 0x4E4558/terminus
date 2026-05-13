from __future__ import annotations

from dataclasses import dataclass
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
                "virtual commands: pwd ls cd cat mkdir touch cp mv rm grep echo help regions hosts factions npcs travel ps kill systemctl ss authlog logs telemetry incidents malware contain teams events siem edr\n"
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
                f"{marker} {host}  region={info['region']} faction={info['faction']} transitions={','.join(info['transitions'])}"
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
