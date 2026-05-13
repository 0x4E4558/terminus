import unittest
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
            legacy_file.write_text('{"name":"","node_type":"dir","children":{}}', encoding="utf-8")
            vfs3, world3 = legacy.load_state()
            self.assertEqual(vfs3.root.node_type, "dir")
            self.assertIn("region0", world3.regions)


if __name__ == "__main__":
    unittest.main()
