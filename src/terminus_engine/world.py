from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _default_skills() -> dict[str, int]:
    return {
        "shell_fluency": 1,
        "forensics": 1,
        "networking": 1,
        "incident_response": 1,
    }


LOW_THREAT_MIN_STABILITY = 85
MEDIUM_THREAT_MIN_STABILITY = 65
SEVERITY_STABILITY_PENALTY = {"low": 4, "medium": 8, "high": 14, "critical": 18}


def _threat_level_for_stability(stability: int) -> str:
    if stability >= LOW_THREAT_MIN_STABILITY:
        return "low"
    if stability >= MEDIUM_THREAT_MIN_STABILITY:
        return "medium"
    return "high"


def _max_threat(level_a: str, level_b: str) -> str:
    rank = {"low": 1, "medium": 2, "high": 3}
    return level_a if rank.get(level_a, 0) >= rank.get(level_b, 0) else level_b


def _default_dialogue_scripts() -> dict[str, list[str]]:
    """Seed dialogue channels used as in-world guidance from system and NPC voices."""
    return {
        "system": [
            "ANOMALY CONFIRMED: shell telemetry drift detected across relay sectors.",
            "SOC BRIEF: Investigate evidence before issuing containment orders.",
        ],
        "rust": [
            "Scrap logs never lie, operator. Start with authlog before touching services.",
            "If you contain too early, you bury the trail with your own noise.",
        ],
        "cinder": [
            "Forge-hub relays are unstable. Check sockets and service state together.",
            "Degraded backups usually follow process tampering, not hardware faults.",
        ],
        "choirmaster": [
            "Traffic harmonics broke in region3. DNS spikes are a chorus, not a solo.",
            "Correlate telemetry with incidents or you'll chase false positives all night.",
        ],
        "veil": [
            "Hidden processes survive where defenders only read the obvious dashboards.",
            "Every containment leaves residue. Logs will remember what operators miss.",
        ],
    }


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
    skills: dict[str, int] = field(default_factory=dict)
    dialogue_scripts: dict[str, list[str]] = field(default_factory=dict)
    training_modules: list[dict[str, str]] = field(default_factory=list)
    completed_training: list[str] = field(default_factory=list)
    host_states: dict[str, dict] = field(default_factory=dict)
    avatar_traces: list[dict] = field(default_factory=list)
    world_tick: int = 0
    next_pid: int = 240
    _state_revision: int = 0
    _objectives_cache: tuple[int, list[dict[str, str]]] | None = None
    _metrics_cache: tuple[int, dict[str, float | int]] | None = None

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
            "region7": {"name": "The Legacy Citadel", "hosts": ["citadel-ad", "ops-win10"], "factions": ["mechanists"]},
        }
        self.hosts = {
            "crash-site": {"region": "region0", "transitions": ["forge-hub", "neon-gateway"], "faction": "salvagers", "os": "linux"},
            "forge-hub": {"region": "region1", "transitions": ["crash-site", "forge-core"], "faction": "mechanists", "os": "linux"},
            "forge-core": {"region": "region2", "transitions": ["forge-hub", "archive-vault"], "faction": "mechanists", "os": "linux"},
            "neon-gateway": {"region": "region3", "transitions": ["crash-site", "ghost-node", "citadel-ad"], "faction": "signal-choir", "os": "linux"},
            "ghost-node": {"region": "region4", "transitions": ["neon-gateway", "epoch-core"], "faction": "null-sect", "os": "linux"},
            "archive-vault": {"region": "region5", "transitions": ["forge-core", "epoch-core", "citadel-ad"], "faction": "salvagers", "os": "linux"},
            "epoch-core": {"region": "region6", "transitions": ["archive-vault", "ghost-node"], "faction": "mechanists", "os": "linux"},
            "citadel-ad": {"region": "region7", "transitions": ["neon-gateway", "archive-vault", "ops-win10"], "faction": "mechanists", "os": "windows"},
            "ops-win10": {"region": "region7", "transitions": ["citadel-ad"], "faction": "mechanists", "os": "windows"},
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
            ProcessEntry(230, "lsass.exe", "SYSTEM", "citadel-ad", cpu=2.1, mem=3.4),
            ProcessEntry(231, "winlogon.exe", "SYSTEM", "citadel-ad", cpu=0.5, mem=0.8),
            ProcessEntry(232, "spoolsv.exe", "SYSTEM", "ops-win10", cpu=0.2, mem=0.6),
            ProcessEntry(233, "wmiprvse.exe", "SYSTEM", "ops-win10", cpu=1.4, mem=1.1, malicious=True, hidden=True),
        ]
        self.services = {
            "sshd": ServiceEntry("sshd", "crash-site", "running", pid=131),
            "relayd": ServiceEntry("relayd", "neon-gateway", "running", pid=188),
            "edr-agent": ServiceEntry("edr-agent", "crash-site", "running", pid=222),
            "backupd": ServiceEntry("backupd", "forge-hub", "degraded", pid=None),
            "winrm": ServiceEntry("winrm", "citadel-ad", "running", pid=230),
            "spooler": ServiceEntry("spooler", "ops-win10", "running", pid=232),
            "defender": ServiceEntry("defender", "ops-win10", "degraded", pid=None),
        }
        self.sockets = [
            SocketEntry("tcp", "0.0.0.0", 22, "LISTEN", 131, service="sshd"),
            SocketEntry("tcp", "0.0.0.0", 443, "LISTEN", 188, service="relayd"),
            SocketEntry("udp", "0.0.0.0", 53, "LISTEN", None, service="dns-cache"),
            SocketEntry("tcp", "10.42.0.9", 4444, "ESTAB", 201, remote="198.51.100.7:9001"),
            SocketEntry("tcp", "10.42.7.11", 5985, "LISTEN", 230, service="winrm"),
            SocketEntry("tcp", "10.42.7.25", 3389, "LISTEN", 232, service="spooler"),
        ]
        self.auth_events = [
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "10.0.9.7", "result": "failed"},
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "10.0.9.7", "result": "failed"},
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "10.0.9.7", "result": "failed"},
            {"ts": _now(), "host": "crash-site", "user": "operator", "src": "127.0.0.1", "result": "success"},
            {"ts": _now(), "host": "citadel-ad", "user": "svc-backup", "src": "10.42.7.99", "result": "failed"},
            {"ts": _now(), "host": "citadel-ad", "user": "svc-backup", "src": "10.42.7.99", "result": "success"},
        ]
        self.log_events = [
            {"ts": _now(), "host": "crash-site", "source": "kernel", "severity": "info", "message": "boot sequence restored"},
            {"ts": _now(), "host": "ghost-node", "source": "audit", "severity": "warning", "message": "tamper marks in auth journal"},
            {"ts": _now(), "host": "neon-gateway", "source": "netwatch", "severity": "warning", "message": "dns spike detected"},
            {"ts": _now(), "host": "citadel-ad", "source": "security", "severity": "warning", "message": "NTLM spray attempt rate exceeded baseline"},
            {"ts": _now(), "host": "ops-win10", "source": "defender", "severity": "warning", "message": "real-time protection restarted unexpectedly"},
        ]
        self.telemetry = [
            {"ts": _now(), "host": "crash-site", "metric": "cpu", "value": 39.2, "tags": ["host", "ops"]},
            {"ts": _now(), "host": "neon-gateway", "metric": "dns_qps", "value": 441.0, "tags": ["network", "anomaly"]},
            {"ts": _now(), "host": "ghost-node", "metric": "hidden_proc", "value": 1.0, "tags": ["edr", "stealth"]},
            {"ts": _now(), "host": "epoch-core", "metric": "correlation_gap", "value": 0.82, "tags": ["siem"]},
            {"ts": _now(), "host": "citadel-ad", "metric": "auth_fail_rate", "value": 17.0, "tags": ["windows", "identity"]},
            {"ts": _now(), "host": "ops-win10", "metric": "edr_gap", "value": 0.67, "tags": ["windows", "endpoint"]},
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
            "INC-CITADEL-DUSK": IncidentEntry(
                incident_id="INC-CITADEL-DUSK",
                title="Citadel Dusk",
                host="citadel-ad",
                severity="high",
                indicators=["failed_login", "wmiprvse_anomaly", "defender_restart"],
                malware=True,
                persistence_chain=True,
                anti_forensics=True,
                exfiltration=True,
            ),
        }
        self.teams = {
            "blue-alpha": TeamEntry(
                "blue-alpha",
                members=["operator", "rust"],
                sectors=["region0", "region3", "region7"],
                shared_incidents=["INC-GLASS-VEIL", "INC-CITADEL-DUSK"],
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
        self.skills = _default_skills()
        self.dialogue_scripts = _default_dialogue_scripts()
        self.training_modules = [
            {
                "id": "LNX-001",
                "title": "Navigation and workspace setup",
                "focus": "pwd, ls, cd, mkdir",
                "objective": "Create /home/operator/training and move into it.",
                "hint": "mkdir -p /home/operator/training && cd /home/operator/training",
            },
            {
                "id": "LNX-002",
                "title": "File creation and inspection",
                "focus": "touch, echo, cat",
                "objective": "Create notes.txt containing 'linux fundamentals'.",
                "hint": "echo linux fundamentals > notes.txt && cat notes.txt",
            },
            {
                "id": "LNX-003",
                "title": "Pipelines and filtering",
                "focus": "cat, grep, redirection",
                "objective": "Create evidence.txt containing a line with 'anomaly'.",
                "hint": "cat incidents.log | grep anomaly > evidence.txt",
            },
        ]
        self._initialize_host_states()
        self._seed_avatar_traces()
        self._refresh_detections()
        self._mark_dirty()

    def _mark_dirty(self) -> None:
        self._state_revision += 1
        self._objectives_cache = None
        self._metrics_cache = None

    def _initialize_host_states(self) -> None:
        self.host_states = {}
        for host, info in self.hosts.items():
            base_stability = 95 if info.get("os") == "windows" else 100
            self.host_states[host] = {
                "os": info.get("os", "linux"),
                "stability": base_stability,
                "threat_level": _threat_level_for_stability(base_stability),
                "last_updated": _now(),
            }
        for incident in self.incidents.values():
            state = self.host_states.get(incident.host)
            if state is None:
                continue
            penalty = SEVERITY_STABILITY_PENALTY.get(incident.severity, 8)
            state["stability"] = max(0, int(state["stability"]) - penalty)
            threat = _threat_level_for_stability(int(state["stability"]))
            if incident.status == "open":
                threat = _max_threat(threat, "high")
            state["threat_level"] = threat
            state["last_updated"] = _now()
        for process in self.processes:
            if process.malicious:
                state = self.host_states.get(process.host)
                if state is None:
                    continue
                state["stability"] = max(0, int(state["stability"]) - (4 if process.hidden else 2))
                base_threat = _threat_level_for_stability(int(state["stability"]))
                boost = "high" if process.hidden else "medium"
                state["threat_level"] = _max_threat(base_threat, boost)
                state["last_updated"] = _now()

    def _seed_avatar_traces(self) -> None:
        self.avatar_traces = [
            {
                "host": "citadel-ad",
                "artifact": "C:\\Users\\Operator\\AppData\\Roaming\\0x4E4558\\avatar.dat",
                "confidence": "high",
                "linked_incident": "INC-CITADEL-DUSK",
                "ts": _now(),
            },
            {
                "host": "ops-win10",
                "artifact": "HKCU\\Software\\0x4E4558\\AvatarHash",
                "confidence": "medium",
                "linked_incident": "INC-CITADEL-DUSK",
                "ts": _now(),
            },
            {
                "host": "archive-vault",
                "artifact": "/archives/avatars/0x4E4558.sig",
                "confidence": "medium",
                "linked_incident": "INC-GLASS-VEIL",
                "ts": _now(),
            },
        ]

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
        state = self.host_states.get(destination)
        if state is not None:
            state["last_updated"] = _now()
        self._mark_dirty()
        return destination

    def kill(self, pid: int) -> bool:
        for idx, proc in enumerate(self.processes):
            if proc.pid == pid:
                matched_malicious = proc.malicious
                matched_hidden = proc.hidden
                del self.processes[idx]
                for svc in self.services.values():
                    if svc.pid == pid:
                        svc.status = "stopped"
                        svc.pid = None
                if matched_malicious:
                    self.increment_skill("incident_response")
                if matched_hidden:
                    self.increment_skill("forensics")
                self.log_events.append(
                    {"ts": _now(), "host": self.current_host, "source": "kernel", "severity": "info", "message": f"pid {pid} terminated"}
                )
                state = self.host_states.get(proc.host)
                if state is not None:
                    state["stability"] = min(100, int(state["stability"]) + 3)
                    state["threat_level"] = _threat_level_for_stability(int(state["stability"]))
                    state["last_updated"] = _now()
                self._mark_dirty()
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
        state = self.host_states.get(svc.host)
        if state is not None:
            if action in {"stop"}:
                state["stability"] = max(0, int(state["stability"]) - 5)
                state["threat_level"] = _max_threat(_threat_level_for_stability(int(state["stability"])), "medium")
            else:
                state["stability"] = min(100, int(state["stability"]) + 2)
                state["threat_level"] = _threat_level_for_stability(int(state["stability"]))
            state["last_updated"] = _now()
        self._mark_dirty()

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
        self.increment_skill("incident_response")
        self.increment_skill("forensics")
        state = self.host_states.get(incident.host)
        if state is not None:
            state["stability"] = min(100, int(state["stability"]) + 8)
            state["threat_level"] = _threat_level_for_stability(int(state["stability"]))
            state["last_updated"] = _now()
        self._refresh_detections()
        self._mark_dirty()

    def get_dialogue(self, speaker: str) -> list[str]:
        speaker_key = speaker.lower()
        lines = self.dialogue_scripts.get(speaker_key)
        if lines is None:
            channels = ", ".join(sorted(self.dialogue_scripts.keys()))
            raise ValueError(f"unknown dialogue channel: {speaker}. available channels: {channels}")
        output = list(lines)
        open_incidents = sum(1 for incident in self.incidents.values() if incident.status == "open")
        if speaker_key == "system":
            output.append(f"ACTIVE HOST: {self.current_host} | OPEN INCIDENTS: {open_incidents} | DETECTIONS: {len(self.detections)}")
        if speaker_key != "system" and open_incidents > 0:
            output.append(f"{speaker_key}: {open_incidents} unresolved incidents still shaping the sector.")
        contained = [incident.incident_id for incident in self.incidents.values() if incident.status == "contained"]
        if contained:
            output.append(f"Contained incidents acknowledged: {', '.join(contained)}. Continue hunting for residual persistence.")
        return output

    def increment_skill(self, skill_name: str, amount: int = 1) -> None:
        self.skills[skill_name] = self.skills.get(skill_name, 0) + amount
        self._mark_dirty()

    def training_overview(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        completed = set(self.completed_training)
        for module in self.training_modules:
            row = dict(module)
            row["status"] = "complete" if module["id"] in completed else "open"
            rows.append(row)
        return rows

    def next_training_module(self) -> dict[str, str] | None:
        completed = set(self.completed_training)
        for module in self.training_modules:
            if module["id"] not in completed:
                return dict(module)
        return None

    def complete_training_module(self, module_id: str) -> bool:
        valid_ids = {module["id"] for module in self.training_modules}
        if module_id not in valid_ids:
            raise ValueError(f"unknown training module: {module_id}")
        if module_id in self.completed_training:
            return False
        self.completed_training.append(module_id)
        self.increment_skill("shell_fluency")
        if module_id == "LNX-003":
            self.increment_skill("forensics")
        self.log_events.append(
            {"ts": _now(), "host": self.current_host, "source": "training", "severity": "info", "message": f"{module_id} completed"}
        )
        self._mark_dirty()
        return True

    def average_skill_level(self) -> float:
        if not self.skills:
            return 1.0
        return sum(self.skills.values()) / len(self.skills)

    def objectives(self) -> list[dict[str, str]]:
        if self._objectives_cache and self._objectives_cache[0] == self._state_revision:
            return [dict(item) for item in self._objectives_cache[1]]
        hidden_malware = any(proc.malicious and proc.hidden for proc in self.processes)
        open_incidents = any(incident.status == "open" for incident in self.incidents.values())
        degraded_services = any(service.status != "running" for service in self.services.values())
        output = [
            {
                "id": "OBJ-RECON-001",
                "status": "open" if hidden_malware else "complete",
                "title": "Identify stealth malware process paths",
                "hint": "Use ps -A, edr hunt, and telemetry correlation.",
            },
            {
                "id": "OBJ-CONTAIN-002",
                "status": "open" if open_incidents else "complete",
                "title": "Contain active incidents without erasing evidence",
                "hint": "Review incidents show, authlog, and logs before contain.",
            },
            {
                "id": "OBJ-RESTORE-003",
                "status": "open" if degraded_services else "complete",
                "title": "Restore degraded services and verify sockets",
                "hint": "Correlate systemctl status with ss and telemetry.",
            },
        ]
        self._objectives_cache = (self._state_revision, output)
        return [dict(item) for item in output]

    def metrics(self) -> dict[str, float | int]:
        if self._metrics_cache and self._metrics_cache[0] == self._state_revision:
            return dict(self._metrics_cache[1])
        open_incidents = sum(1 for incident in self.incidents.values() if incident.status == "open")
        contained_incidents = sum(1 for incident in self.incidents.values() if incident.status == "contained")
        hidden_malware = sum(1 for proc in self.processes if proc.malicious and proc.hidden)
        running_services = sum(1 for service in self.services.values() if service.status == "running")
        avg_skill = self.average_skill_level()
        metrics_result: dict[str, float | int] = {
            "open_incidents": open_incidents,
            "contained_incidents": contained_incidents,
            "detections": len(self.detections),
            "hidden_malware": hidden_malware,
            "running_services": running_services,
            "total_services": len(self.services),
            "learning_index": round(avg_skill, 2),
            "world_tick": self.world_tick,
            "linux_training_completed": len(self.completed_training),
            "linux_training_total": len(self.training_modules),
        }
        self._metrics_cache = (self._state_revision, metrics_result)
        return dict(metrics_result)

    def get_avatar_traces(self, host: str | None = None) -> list[dict]:
        if host is None:
            return [dict(item) for item in self.avatar_traces]
        return [dict(item) for item in self.avatar_traces if item.get("host") == host]

    def state_snapshot(self, host: str | None = None) -> dict:
        hosts = self.host_states if host is None else {host: self.host_states.get(host, {})}
        hosts = {name: dict(data) for name, data in hosts.items() if data}
        return {
            "world_tick": self.world_tick,
            "current_region": self.current_region,
            "current_host": self.current_host,
            "hosts": hosts,
        }

    def advance_world(self, cycles: int = 1) -> None:
        if cycles < 1:
            raise ValueError("cycles must be >= 1")
        for _ in range(cycles):
            self.world_tick += 1
            for incident in self.incidents.values():
                state = self.host_states.get(incident.host)
                if state is None:
                    continue
                if incident.status == "open":
                    penalty = 4 if incident.severity == "high" else 2
                    state["stability"] = max(0, int(state["stability"]) - penalty)
                    state["threat_level"] = _max_threat(_threat_level_for_stability(int(state["stability"])), "medium")
                    if incident.exfiltration:
                        self.telemetry.append(
                            {
                                "ts": _now(),
                                "host": incident.host,
                                "metric": "data_egress_risk",
                                "value": 1.0,
                                "tags": ["incident", incident.incident_id],
                            }
                        )
                else:
                    state["stability"] = min(100, int(state["stability"]) + 1)
                    state["threat_level"] = _threat_level_for_stability(int(state["stability"]))
                state["last_updated"] = _now()
            if self.hosts.get(self.current_host, {}).get("os") == "windows":
                self.log_events.append(
                    {
                        "ts": _now(),
                        "host": self.current_host,
                        "source": "avatar",
                        "severity": "info",
                        "message": "0x4E4558 avatar continuity marker observed in host artifacts",
                    }
                )
        self._refresh_detections()
        self._mark_dirty()

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
            "skills": dict(self.skills),
            "dialogue_scripts": {k: list(v) for k, v in self.dialogue_scripts.items()},
            "training_modules": [dict(item) for item in self.training_modules],
            "completed_training": list(self.completed_training),
            "host_states": {k: dict(v) for k, v in self.host_states.items()},
            "avatar_traces": [dict(item) for item in self.avatar_traces],
            "world_tick": self.world_tick,
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
        world.skills = data.get(
            "skills",
            _default_skills(),
        )
        world.dialogue_scripts = data.get("dialogue_scripts", {})
        world.training_modules = data.get("training_modules", [])
        world.completed_training = data.get("completed_training", [])
        world.host_states = data.get("host_states", {})
        world.avatar_traces = data.get("avatar_traces", [])
        world.world_tick = data.get("world_tick", 0)
        world.next_pid = data.get("next_pid", 240)
        if not world.regions:
            world._seed()
        if not world.dialogue_scripts:
            world.dialogue_scripts = _default_dialogue_scripts()
        if not world.skills:
            world.skills = _default_skills()
        if not world.training_modules:
            world.training_modules = [
                {
                    "id": "LNX-001",
                    "title": "Navigation and workspace setup",
                    "focus": "pwd, ls, cd, mkdir",
                    "objective": "Create /home/operator/training and move into it.",
                    "hint": "mkdir -p /home/operator/training && cd /home/operator/training",
                },
                {
                    "id": "LNX-002",
                    "title": "File creation and inspection",
                    "focus": "touch, echo, cat",
                    "objective": "Create notes.txt containing 'linux fundamentals'.",
                    "hint": "echo linux fundamentals > notes.txt && cat notes.txt",
                },
                {
                    "id": "LNX-003",
                    "title": "Pipelines and filtering",
                    "focus": "cat, grep, redirection",
                    "objective": "Create evidence.txt containing a line with 'anomaly'.",
                    "hint": "cat incidents.log | grep anomaly > evidence.txt",
                },
            ]
        if not world.host_states:
            world._initialize_host_states()
        if not world.avatar_traces:
            world._seed_avatar_traces()
        world._state_revision = 0
        world._objectives_cache = None
        world._metrics_cache = None
        world._refresh_detections()
        world._mark_dirty()
        return world
