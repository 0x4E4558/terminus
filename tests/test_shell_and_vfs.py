import asyncio
import unittest

from terminus_engine.kernel import VirtualKernel
from terminus_engine.session import SessionState
from terminus_engine.shell import ShellEngine


def run(shell: ShellEngine, line: str) -> str:
    return asyncio.run(shell.handle_line(line))


class ShellAndVFSTests(unittest.TestCase):
    def test_virtual_commands_execute_in_vfs_only(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())

        out = run(shell, "pwd")
        self.assertIn("/home/operator", out)

        run(shell, "mkdir -p incidents")
        run(shell, "touch incidents/evidence.log")
        run(shell, "echo anomaly_detected > incidents/evidence.log")
        cat_out = run(shell, "cat incidents/evidence.log")
        self.assertIn("anomaly_detected", cat_out)

        grep_out = run(shell, "cat incidents/evidence.log | grep anomaly")
        self.assertIn("anomaly_detected", grep_out)

    def test_cd_updates_virtual_pwd(self) -> None:
        kernel = VirtualKernel()
        shell = ShellEngine(kernel=kernel, session=SessionState())
        run(shell, "mkdir -p /home/operator/sector0")
        run(shell, "cd /home/operator/sector0")
        out = run(shell, "pwd")
        self.assertIn("/home/operator/sector0", out)


if __name__ == "__main__":
    unittest.main()
