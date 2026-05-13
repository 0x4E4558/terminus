import unittest

from terminus_engine.kernel import VirtualKernel
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


if __name__ == "__main__":
    unittest.main()
