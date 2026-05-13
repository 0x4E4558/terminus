import unittest
import json
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from terminus_engine.kernel import VirtualKernel
from terminus_engine.persistence import PersistenceEngine
from terminus_engine.session import SessionState
from terminus_engine.shell import ShellEngine


class ShellAndVFSTests(unittest.IsolatedAsyncioTestCase):
    async def test_virtual_commands_execute_in_vfs_only(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        out = await shell.handle_line("pwd")
        self.assertIn("/home/operator", out)

        await shell.handle_line("mkdir -p incidents")
        await shell.handle_line("touch incidents/evidence.log")
        await shell.handle_line("echo anomaly_detected > incidents/evidence.log")
        cat_out = await shell.handle_line("cat incidents/evidence.log")
        self.assertIn("anomaly_detected", cat_out)

        grep_out = await shell.handle_line("cat incidents/evidence.log | grep anomaly")
        self.assertIn("anomaly_detected", grep_out)

    async def test_cd_updates_virtual_pwd(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())
        await shell.handle_line("mkdir -p /home/operator/sector0")
        await shell.handle_line("cd /home/operator/sector0")
        out = await shell.handle_line("pwd")
        self.assertIn("/home/operator/sector0", out)
        await shell.handle_line("cd ..")
        out2 = await shell.handle_line("pwd")
        self.assertIn("/home/operator", out2)

    async def test_alias_export_env_and_history(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())
        await shell.handle_line("alias ll='ls -l'")
        await shell.handle_line("mkdir -p logs")
        out = await shell.handle_line("ll")
        self.assertIsInstance(out, str)
        await shell.handle_line("export REGION=crash-site")
        env_out = await shell.handle_line("env")
        self.assertIn("REGION=crash-site", env_out)
        hist = await shell.handle_line("history")
        self.assertIn("alias ll='ls -l'", hist)

    async def test_world_foundation_operational_and_soc_commands(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        regions = await shell.handle_line("regions")
        self.assertIn("region0", regions)

        hosts = await shell.handle_line("hosts")
        self.assertIn("crash-site", hosts)
        self.assertIn("citadel-ad", hosts)
        self.assertIn("os=windows", hosts)

        travel = await shell.handle_line("travel forge-hub")
        self.assertIn("transition complete", travel)

        processes = await shell.handle_line("ps")
        self.assertIn("PID", processes)

        services = await shell.handle_line("systemctl status sshd")
        self.assertIn("sshd.service", services)

        sockets = await shell.handle_line("ss")
        self.assertIn("Netid", sockets)

        incidents = await shell.handle_line("incidents list")
        self.assertIn("INC-GLASS-VEIL", incidents)

        malware = await shell.handle_line("malware scan")
        self.assertIn("INC-GLASS-VEIL", malware)

        teams = await shell.handle_line("teams")
        self.assertIn("blue-alpha", teams)

        events = await shell.handle_line("events")
        self.assertIn("EVT-RESTORE-001", events)

        siem = await shell.handle_line("siem hits")
        self.assertIn("rule=", siem)

        edr = await shell.handle_line("edr hunt")
        self.assertIn("pid=", edr)

    async def test_containment_mutates_incident_state(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())
        before = await shell.handle_line("incidents show INC-GLASS-VEIL")
        self.assertIn("status=open", before)
        self.assertIn("exfiltration=True", before)

        out = await shell.handle_line("contain INC-GLASS-VEIL")
        self.assertIn("containment started", out)

        after = await shell.handle_line("incidents show INC-GLASS-VEIL")
        self.assertIn("status=contained", after)
        self.assertIn("exfiltration=False", after)

    async def test_dialogue_brief_objectives_and_metrics_commands(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        dialogue = await shell.handle_line("dialogue system")
        self.assertIn("ANOMALY CONFIRMED", dialogue)
        self.assertIn("OPEN INCIDENTS", dialogue)
        unknown_dialogue = await shell.handle_line("dialogue unknown-channel")
        self.assertIn("unknown dialogue channel", unknown_dialogue)
        self.assertIn("available channels", unknown_dialogue)

        brief = await shell.handle_line("brief")
        self.assertIn("open_incidents=", brief)
        self.assertIn("learning_index=", brief)

        objectives = await shell.handle_line("objectives")
        self.assertIn("OBJ-RECON-001", objectives)
        self.assertIn("[ ]", objectives)

        metrics_before = await shell.handle_line("metrics")
        self.assertIn("open_incidents=", metrics_before)
        self.assertIn("skills:", metrics_before)

        await shell.handle_line("contain INC-GLASS-VEIL")
        metrics_after = await shell.handle_line("metrics")
        self.assertIn("contained_incidents=1", metrics_after)
        self.assertIn("incident_response=", metrics_after)
        self.assertIn("world_tick=", metrics_after)

    async def test_state_avatar_and_advance_commands(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        state_before = await shell.handle_line("state")
        self.assertIn("world_tick=0", state_before)
        self.assertIn("citadel-ad os=windows", state_before)

        avatar = await shell.handle_line("avatar")
        self.assertIn("0x4E4558", avatar)
        self.assertIn("host=citadel-ad", avatar)

        advanced = await shell.handle_line("advance 2")
        self.assertIn("world advanced cycles=2", advanced)
        self.assertIn("tick=2", advanced)

        state_after = await shell.handle_line("state ghost-node")
        self.assertIn("world_tick=2", state_after)
        self.assertIn("ghost-node", state_after)

    async def test_linux_admin_command_surface_and_vfs_behavior(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        help_out = await shell.handle_line("help")
        required = [
            "pwd",
            "ls",
            "cd",
            "cat",
            "mkdir",
            "touch",
            "cp",
            "mv",
            "rm",
            "grep",
            "echo",
            "whoami",
            "uname",
            "id",
            "date",
            "head",
            "tail",
            "wc",
            "find",
            "chmod",
            "chown",
            "df",
            "du",
            "free",
        ]
        for cmd in required:
            self.assertIn(cmd, help_out)

        await shell.handle_line("mkdir -p /home/operator/training")
        await shell.handle_line("cd /home/operator/training")
        await shell.handle_line("echo linux fundamentals > notes.txt")
        await shell.handle_line("echo anomaly_detected >> notes.txt")

        head_out = await shell.handle_line("head -n 1 notes.txt")
        self.assertIn("linux fundamentals", head_out)
        tail_out = await shell.handle_line("tail -n 1 notes.txt")
        self.assertIn("anomaly_detected", tail_out)
        wc_out = await shell.handle_line("wc notes.txt")
        self.assertIn("notes.txt", wc_out)

        await shell.handle_line("chmod 600 notes.txt")
        ls_long = await shell.handle_line("ls -l notes.txt")
        self.assertIn("rw-------", ls_long)
        await shell.handle_line("chmod 0640 notes.txt")
        ls_long_zero_prefixed = await shell.handle_line("ls -l notes.txt")
        self.assertIn("rw-r-----", ls_long_zero_prefixed)

        await shell.handle_line("chown root:operators notes.txt")
        ls_long_after = await shell.handle_line("ls -l notes.txt")
        self.assertIn("root operators", ls_long_after)

        find_out = await shell.handle_line("find /home/operator -name notes.txt")
        self.assertIn("/home/operator/training/notes.txt", find_out)
        df_out = await shell.handle_line("df")
        self.assertIn("Filesystem", df_out)
        du_out = await shell.handle_line("du /home/operator/training")
        self.assertIn("/home/operator/training", du_out)
        free_out = await shell.handle_line("free")
        self.assertIn("Mem:", free_out)

    async def test_training_guides_linux_fundamentals(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        training_list = await shell.handle_line("training list")
        self.assertIn("ANA-001", training_list)
        self.assertIn("[ ]", training_list)

        training_next = await shell.handle_line("training next")
        self.assertIn("Data Analysis Foundations", training_next)
        self.assertIn("track: data", training_next)

        await shell.handle_line("mkdir -p /home/operator/training")
        await shell.handle_line("cd /home/operator/training")
        await shell.handle_line("grep failed_login auth_sample.log > data-summary.txt")
        stage1 = await shell.handle_line("training check ANA-001")
        self.assertIn("ANA-001 complete", stage1)

        await shell.handle_line("systemctl status sshd > system-summary.txt")
        await shell.handle_line("chmod 640 system-summary.txt")
        await shell.handle_line("chown root:operators system-summary.txt")
        stage2 = await shell.handle_line("training check ANA-002")
        self.assertIn("ANA-002 complete", stage2)

        await shell.handle_line("ss > network-summary.txt")
        stage3 = await shell.handle_line("training check ANA-003")
        self.assertIn("ANA-003 complete", stage3)

        await shell.handle_line("contain INC-GLASS-VEIL")
        await shell.handle_line("incidents show INC-GLASS-VEIL > security-summary.txt")
        stage4 = await shell.handle_line("training check ANA-004")
        self.assertIn("ANA-004 complete", stage4)

        await shell.handle_line("forensics record INC-GLASS-VEIL logs chain_of_custody")
        await shell.handle_line("forensics export /home/operator/training/forensics-ledger.txt")
        stage5 = await shell.handle_line("training check ANA-005")
        self.assertIn("ANA-005 complete", stage5)

        forensic_log = await shell.handle_line("forensics log")
        self.assertIn("INC-GLASS-VEIL", forensic_log)
        done = await shell.handle_line("training next")
        self.assertIn("all foundational linux modules completed", done)

    async def test_date_uses_simulated_world_time(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        before = await shell.handle_line("date")
        await shell.handle_line("advance 2")
        after = await shell.handle_line("date")

        before_dt = datetime.strptime(before.strip(), "%a %b %d %H:%M:%S UTC %Y")
        after_dt = datetime.strptime(after.strip(), "%a %b %d %H:%M:%S UTC %Y")
        self.assertEqual(int((after_dt - before_dt).total_seconds()), 120)

    def test_persistence_load_state_supports_legacy_and_v2(self) -> None:
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state.json"
            persistence = PersistenceEngine(state_file)
            kernel = VirtualKernel()
            persistence.save_state(kernel.vfs, kernel.world)

            vfs2, world2 = persistence.load_state()
            self.assertTrue(vfs2.exists("/home/operator"))
            self.assertIn("region0", world2.regions)

            legacy_file = Path(tmp) / "legacy.json"
            legacy = PersistenceEngine(legacy_file)
            legacy_file.write_text(
                json.dumps({"name": "", "node_type": "dir", "children": {}}),
                encoding="utf-8",
            )
            vfs3, world3 = legacy.load_state()
            self.assertEqual(vfs3.root.node_type, "dir")
            self.assertIn("region0", world3.regions)


if __name__ == "__main__":
    unittest.main()
