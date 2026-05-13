from __future__ import annotations

from dataclasses import dataclass

from .kernel import ExecResult, VirtualKernel
from .parser import ChainNode, CommandNode, ParserEngine
from .session import SessionState


@dataclass(slots=True)
class ShellSession:
    state: SessionState


class ShellEngine:
    def __init__(self, kernel: VirtualKernel, session: SessionState) -> None:
        self.kernel = kernel
        self.parser = ParserEngine()
        self.session = ShellSession(state=session)

    async def handle_line(self, line: str) -> str:
        stripped = line.strip()
        if not stripped:
            return ""
        self.session.state.history.append(stripped)
        if stripped in {"exit", "logout"}:
            return "__TERMINATE__"
        ast = self.parser.parse(stripped)
        result = self._execute_chain(ast)
        return result.stderr + result.stdout

    def _execute_chain(self, chain: ChainNode) -> ExecResult:
        final = ExecResult()
        previous_code = 0
        for idx, pipeline in enumerate(chain.pipelines):
            if idx > 0:
                op = chain.operators[idx - 1]
                if op == "&&" and previous_code != 0:
                    continue
                if op == "||" and previous_code == 0:
                    continue
            current = self._execute_pipeline(pipeline.commands)
            final.stdout += current.stdout
            final.stderr += current.stderr
            final.exit_code = current.exit_code
            previous_code = current.exit_code
        return final

    def _execute_pipeline(self, commands: list[CommandNode]) -> ExecResult:
        stdin = ""
        stderr = ""
        exit_code = 0
        output = ""
        for cmd in commands:
            env = {**self.session.state.env, **cmd.env}
            args = [self._expand(a, env) for a in cmd.args]
            flags = [self._expand(f, env) for f in cmd.flags]
            res = self.kernel.run(
                command=self._expand(cmd.command, env),
                args=args,
                flags=flags,
                cwd=self.session.state.cwd,
                env=env,
                stdin=stdin,
            )
            if res.stdout.startswith("__CWD__:"):
                new_cwd = res.stdout.split(":", 1)[1].strip()
                self.session.state.cwd = new_cwd
                self.session.state.env["PWD"] = new_cwd
                res.stdout = ""

            stdout = res.stdout
            for redir in cmd.redirects:
                target = self.kernel.vfs.resolve_path(self.session.state.cwd, self._expand(redir.target, env))
                if redir.operator == ">":
                    self.kernel.vfs.write_file(target, stdout, append=False)
                    stdout = ""
                elif redir.operator == ">>":
                    self.kernel.vfs.write_file(target, stdout, append=True)
                    stdout = ""
                elif redir.operator == "<":
                    stdin = self.kernel.vfs.read_file(target)

            stdin = stdout
            output = stdout
            stderr += res.stderr
            exit_code = res.exit_code
            if res.exit_code != 0:
                break
        return ExecResult(stdout=output, stderr=stderr, exit_code=exit_code)

    def _expand(self, token: str, env: dict[str, str]) -> str:
        result = token
        for key, value in env.items():
            result = result.replace(f"${key}", value)
        return result
