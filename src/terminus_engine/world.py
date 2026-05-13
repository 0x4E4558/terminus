from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class ProcessEntry:
    pid: int
    name: str
    user: str
    host: str
    cpu: float = 0.0
    mem: float = 0.0
    state: str = "S"
    malicious: bool = False
    hidden: bool = False


@dataclass(slots=True)
class ServiceEntry:
    name: str
    host: str
    status: str = "running"
    pid: int | None = None


@dataclass(slots=True)
class SocketEntry:
    proto: str
    local: str
    port: int
    state: str
    pid: int | None
    service: str | None = None
    remote: str | None = None


@dataclass(slots=True)
class IncidentEntry:
    incident_id: str
    title: str
    host: str
    severity: str
    status: str = "open"
    indicators: list[str] = field(default_factory=list)
    malware: bool = False
    persistence_chain: bool = False
    anti_forensics: bool = False
    rootkit: bool = False
    exfiltration: bool = False


@dataclass(slots=True)
class TeamEntry:
    name: str
    members: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    shared_incidents: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EventEntry:
    event_id: str
    title: str
    status: str
    regions: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass(slots=True)
class DetectionRule:
    name: str
    match_term: str
    severity: str
    enabled: bool = True


@dataclass(slots=True)
class DetectionHit:
    rule_name: str
    incident_id: str
    host: str
    summary: str
    ts: str = field(default_factory=_now)


@dataclass(slots=True)
class WorldSimulation:
    current_region: str = "region0"
    current_host: str = "crash-site"
    regions: dict[str, dict] = field(default_factory=dict)
    hosts: dict[str, dict] = field(default_factory=dict)
    npcs: dict[str, dict] = field(default_factory=dict)
    factions: dict[str, dict] = field(default_factory=dict)
    processes: list[ProcessEntry] = field(default_factory=list)
    services: dict[str, ServiceEntry] = field(default_factory=dict)
    sockets: list[SocketEntry] = field(default_factory=list)
    auth_events: list[dict] = field(default_factory=list)
    log_events: list[dict] = field(default_factory=list)
    telemetry: list[dict] = field(default_factory=list)
    incidents: dict[str, IncidentEntry] = field(default_factory=dict)
    teams: dict[str, TeamEntry] = field(default_factory=dict)
    events: dict[str, EventEntry] = field(default_factory=dict)
    rules: dict[str, DetectionRule] = field(default_factory=dict)
    detections: list[DetectionHit] = field(default_factory=list)
    online_sessions: list[str] = field(default_factory=lambda: ["operator"])
    next_pid: int = 240

    def __post_init__(self) -> None:
        if not self.regions:
            self._seed()

    def _seed(self) -> None:
        self.factions = {
            "salvagers": {"name": "The Salvagers", "doctrine": "Knowledge survives longer than steel."},
            "mechanists": {"name": "The Mechanists", "doctrine": "Machines fail when operators stop listening."},
            "signal-choir": {"name": "The Signal Choir", "doctrine": "All systems speak."},
            "null-sect": {"name": "The Null Sect", "doctrine": "Visibility is vulnerability."},
        }
        self.regions = {
            "region0": {"name": "The Crash Site", "hosts": ["crash-site"], "factions": ["salvagers"]},
            "region1": {"name": "The Salvage District", "hosts": ["forge-hub"], "factions": ["mechanists"]},
            "region2": {"name": "The Mechanist Forge", "hosts": ["forge-core"], "factions": ["mechanists"]},
            "region3": {"name": "Club Neon", "hosts": ["neon-gateway"], "factions": ["signal-choir"]},
            "region4": {"name": "The Ghost Network", "hosts": ["ghost-node"], "factions": ["null-sect"]},
            "region5": {"name": "The Memory Palace", "hosts": ["archive-vault"], "factions": ["salvagers"]},
            "region6": {"name": "The Epoch Core", "hosts": ["epoch-core"], "factions": ["mechanists", "signal-choir"]},
        }
        self.hosts = {
            "crash-site": {"region": "region0", "transitions": ["forge-hub", "neon-gateway"], "faction": "salvagers"},
            "forge-hub": {"region": "region1", "transitions": ["crash-site", "forge-core"], "faction": "mechanists"},
            "forge-core": {"region": "region2", "transitions": ["forge-hub", "archive-vault"], "faction": "mechanists"},
            "neon-gateway": {"region": "region3", "transitions": ["crash-site", "ghost-node"], "faction": "signal-choir"},
            "ghost-node": {"region": "region4", "transitions": ["neon-gateway", "epoch-core"], "faction": "null-sect"},
            "archive-vault": {"region": "region5", "transitions": ["forge-core", "epoch-core"], "faction": "salvagers"},
            "epoch-core": {"region": "region6", "transitions": ["archive-vault", "ghost-node"], "faction": "mechanists"},
        }
        self.npcs = {
            "rust": {"role": "salvage handler", "faction": "salvagers", "region": "region0"},
            "cinder": {"role": "systems mechanic", "faction": "mechanists", "region": "region1"},
            "choirmaster": {"role": "traffic analyst", "faction": "signal-choir", "region": "region3"},
            "veil": {"role": "covert operator", "faction": "null-sect", "region": "region4"},
        }
        self.processes = [
            ProcessEntry(100, "init", "root", "crash-site", cpu=0.1, mem=0.2),
            ProcessEntry(131, "sshd", "root", "crash-site", cpu=0.3, mem=0.5),
            ProcessEntry(142, "chronyd", "root", "crash-site", cpu=0.2, mem=0.3),
            ProcessEntry(188, "relayd", "svc_relay", "neon-gateway", cpu=1.7, mem=2.9),
            ProcessEntry(201, "veilhook", "root", "ghost-node", cpu=4.2, mem=1.1, malicious=True, hidden=True),
        ]
        self.services = {
            "sshd": ServiceEntry("sshd", "crash-site", "running", pid=131),
            "relayd": ServiceEntry("relayd", "neon-gateway", "running", pid=188),
            "edr-agent": ServiceEntry("edr-agent", "crash-site", "running", pid=222),
            "backupd": ServiceEntry("backupd", "forge-hub", "degraded", pid=None),
        }
        self.sockets = [
            SocketEntry("tcp", "0.0.0.0", 22, "LISTEN", 131, service="sshd"),
            SocketEntry("tcp", "0.0.0.0", 443, "LISTEN", 188, service="relayd"),
            SocketEntry("udp", "0.0.0.0", 53, "LISTEN", None, service="dns-cache"),
            SocketEntry("tcp", "10.42.0.9", 4444, "ESTAB", 201, remote="198.51.100.7:9001"),
        ]
        self.auth_events = [
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "10.0.9.7", "result": "failed"},
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "10.0.9.7", "result": "failed"},
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "10.0.9.7", "result": "failed"},
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "127.0.0.1", "result": "success"},
        ]
        self.log_events = [
            {"ts": _now(), "host": "crash-site", "source": "kernel", "severity": "info", "message": "boot sequence restored"},
            {"ts": _now(), "host": "ghost-node", "source": "audit", "severity": "warning", "message": "tamper marks in auth journal"},
            {"ts": _now(), "host": "neon-gateway", "source": "netwatch", "severity": "warning", "message": "dns spike detected"},
        ]
        self.telemetry = [
            {"ts": _now(), "host": "crash-site", "metric": "cpu", "value": 39.2, "tags": ["host", "ops"]},
            {"ts": _now(), "host": "neon-gateway", "metric": "dns_qps", "value": 441.0, "tags": ["network", "anomaly"]},
            {"ts": _now(), "host": "ghost-node", "metric": "hidden_proc", "value": 1.0, "tags": ["edr", "stealth"]},
            {"ts": _now(), "host": "epoch-core", "metric": "correlation_gap", "value": 0.82, "tags": ["siem"]},
        ]
        self.incidents = {
            "INC-GLASS-VEIL": IncidentEntry(
                incident_id="INC-GLASS-VEIL",
                title="Glass Veil",
                host="ghost-node",
                severity="high",
                indicators=["dns_spike", "hidden_process", "cron_drift"],
                malware=True,
                persistence_chain=True,
                anti_forensics=True,
                rootkit=True,
                exfiltration=True,
            ),
            "INC-RELAY-BLEED": IncidentEntry(
                incident_id="INC-RELAY-BLEED",
                title="Relay Bleed",
                host="neon-gateway",
                severity="medium",
                indicators=["service_restart_loop", "socket_churn"],
            ),
        }
        self.teams = {
            "blue-alpha": TeamEntry(
                "blue-alpha",
                members=["operator", "rust"],
                sectors=["region0", "region3"],
                shared_incidents=["INC-GLASS-VEIL"],
            )
        }
        self.events = {
            "EVT-RESTORE-001": EventEntry(
                event_id="EVT-RESTORE-001",
                title="Sector Relay Restoration",
                status="active",
                regions=["region1", "region3"],
                summary="Analyst teams are restoring cross-region comms.",
            )
        }
        self.rules = {
            "detect-dns-spike": DetectionRule("detect-dns-spike", "dns_spike", "high"),
            "detect-hidden-proc": DetectionRule("detect-hidden-proc", "hidden_process", "critical"),
            "detect-auth-bruteforce": DetectionRule("detect-auth-bruteforce", "failed_login", "medium"),
        }
        self._refresh_detections()

    def _refresh_detections(self) -> None:
        self.detections = []
        for incident in self.incidents.values():
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                if any(rule.match_term in indicator for indicator in incident.indicators):
                    self.detections.append(
                        DetectionHit(
                            rule_name=rule.name,
                            incident_id=incident.incident_id,
                            host=incident.host,
                            summary=f"{rule.match_term} matched in {incident.incident_id}",
                        )
                    )
        failed = sum(1 for ev in self.auth_events if ev["result"] == "failed")
        if failed >= 3 and "detect-auth-bruteforce" in self.rules and self.rules["detect-auth-bruteforce"].enabled:
            self.detections.append(
                DetectionHit(
                    rule_name="detect-auth-bruteforce",
                    incident_id="INC-GLASS-VEIL",
                    host="crash-site",
                    summary="repeated failed logins detected",
                )
            )

    def travel(self, destination: str) -> str:
        if destination not in self.hosts:
            raise ValueError(f"unknown host: {destination}")
        allowed = self.hosts[self.current_host]["transitions"]
        if destination not in allowed and destination != self.current_host:
            raise ValueError(f"host transition blocked: {self.current_host} -> {destination}")
        self.current_host = destination
        self.current_region = self.hosts[destination]["region"]
        return destination

    def kill(self, pid: int) -> bool:
        for idx, proc in enumerate(self.processes):
            if proc.pid == pid:
                del self.processes[idx]
                for svc in self.services.values():
                    if svc.pid == pid:
                        svc.status = "stopped"
                        svc.pid = None
                self.log_events.append(
                    {"ts": _now(), "host": self.current_host, "source": "kernel", "severity": "info", "message": f"pid {pid} terminated"}
                )
                return True
        return False

    def set_service_state(self, name: str, action: str) -> None:
        svc = self.services.get(name)
        if svc is None:
            raise ValueError(f"unknown service: {name}")
        if action in {"status"}:
            return
        if action in {"start", "restart"}:
            if svc.pid is None:
                svc.pid = self.next_pid
                self.next_pid += 1
            svc.status = "running"
            if not any(p.pid == svc.pid for p in self.processes):
                self.processes.append(ProcessEntry(svc.pid, svc.name, "root", svc.host, cpu=0.5, mem=0.4))
        elif action == "stop":
            if svc.pid is not None:
                self.kill(svc.pid)
            svc.status = "stopped"
            svc.pid = None
        else:
            raise ValueError(f"unsupported action: {action}")
        self.log_events.append(
            {"ts": _now(), "host": svc.host, "source": "systemctl", "severity": "info", "message": f"{svc.name} {action}"}
        )

    def contain_incident(self, incident_id: str) -> None:
        incident = self.incidents.get(incident_id)
        if incident is None:
            raise ValueError(f"unknown incident: {incident_id}")
        incident.status = "contained"
        incident.exfiltration = False
        incident.rootkit = False
        incident.anti_forensics = False
        self.log_events.append(
            {"ts": _now(), "host": incident.host, "source": "response", "severity": "warning", "message": f"{incident_id} containment initiated"}
        )
        self.telemetry.append({"ts": _now(), "host": incident.host, "metric": "containment", "value": 1.0, "tags": ["incident", incident_id]})
        self._refresh_detections()

    def to_dict(self) -> dict:
        return {
            "current_region": self.current_region,
            "current_host": self.current_host,
            "regions": self.regions,
            "hosts": self.hosts,
            "npcs": self.npcs,
            "factions": self.factions,
            "processes": [asdict(p) for p in self.processes],
            "services": {k: asdict(v) for k, v in self.services.items()},
            "sockets": [asdict(s) for s in self.sockets],
            "auth_events": list(self.auth_events),
            "log_events": list(self.log_events),
            "telemetry": list(self.telemetry),
            "incidents": {k: asdict(v) for k, v in self.incidents.items()},
            "teams": {k: asdict(v) for k, v in self.teams.items()},
            "events": {k: asdict(v) for k, v in self.events.items()},
            "rules": {k: asdict(v) for k, v in self.rules.items()},
            "detections": [asdict(d) for d in self.detections],
            "online_sessions": list(self.online_sessions),
            "next_pid": self.next_pid,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WorldSimulation":
        world = cls.__new__(cls)
        world.current_region = data.get("current_region", "region0")
        world.current_host = data.get("current_host", "crash-site")
        world.regions = data.get("regions", {})
        world.hosts = data.get("hosts", {})
        world.npcs = data.get("npcs", {})
        world.factions = data.get("factions", {})
        world.processes = [ProcessEntry(**item) for item in data.get("processes", [])]
        world.services = {k: ServiceEntry(**v) for k, v in data.get("services", {}).items()}
        world.sockets = [SocketEntry(**item) for item in data.get("sockets", [])]
        world.auth_events = data.get("auth_events", [])
        world.log_events = data.get("log_events", [])
        world.telemetry = data.get("telemetry", [])
        world.incidents = {k: IncidentEntry(**v) for k, v in data.get("incidents", {}).items()}
        world.teams = {k: TeamEntry(**v) for k, v in data.get("teams", {}).items()}
        world.events = {k: EventEntry(**v) for k, v in data.get("events", {}).items()}
        world.rules = {k: DetectionRule(**v) for k, v in data.get("rules", {}).items()}
        world.detections = [DetectionHit(**item) for item in data.get("detections", [])]
        world.online_sessions = data.get("online_sessions", ["operator"])
        world.next_pid = data.get("next_pid", 240)
        if not world.regions:
            world._seed()
        world._refresh_detections()
        return world
