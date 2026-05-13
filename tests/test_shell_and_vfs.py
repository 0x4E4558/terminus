import asyncio

from terminus_engine.kernel import VirtualKernel
from terminus_engine.session import SessionState
from terminus_engine.shell import ShellEngine


def run(shell: ShellEngine, line: str) -> str:
    return asyncio.run(shell.handle_line(line))


def test_virtual_commands_execute_in_vfs_only():
    kernel = VirtualKernel()
    shell = ShellEngine(kernel=kernel, session=SessionState())

    out = run(shell, "pwd")
    assert "/home/operator" in out

    run(shell, "mkdir -p incidents")
    run(shell, "touch incidents/evidence.log")
    run(shell, "echo anomaly_detected > incidents/evidence.log")
    cat_out = run(shell, "cat incidents/evidence.log")
    assert "anomaly_detected" in cat_out

    grep_out = run(shell, "cat incidents/evidence.log | grep anomaly")
    assert "anomaly_detected" in grep_out


def test_cd_updates_virtual_pwd():
    kernel = VirtualKernel()
    shell = ShellEngine(kernel=kernel, session=SessionState())
    run(shell, "mkdir -p /home/operator/sector0")
    run(shell, "cd /home/operator/sector0")
    out = run(shell, "pwd")
    assert "/home/operator/sector0" in out
