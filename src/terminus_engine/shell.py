from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Callable

from .kernel import ExecResult, VirtualKernel
from .parser import ChainNode, CommandNode, ParserEngine
from .session import SessionState


@dataclass(slots=True)
class ShellSession:
    state: SessionState


class ShellEngine:
    _MUTATING_COMMANDS = {"mkdir", "touch", "cp", "mv", "rm", "travel", "kill", "systemctl", "contain", "advance"}
    # Matches $VARNAME where names start with letter/underscore and continue
    # with alphanumeric/underscore characters.
    _VAR_PATTERN = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

    def __init__(
        self,
        kernel: VirtualKernel,
        session: SessionState,
        on_state_change: Callable[[], None] | None = None,
    ) -> None:
        self.kernel = kernel
        self.parser = ParserEngine()
        self.session = ShellSession(state=session)
        self.on_state_change = on_state_change

    async def handle_line(self, line: str) -> str:
        stripped = line.strip()
        if not stripped:
            return ""
        self.session.state.history.append(stripped)
        if stripped in {"exit", "logout"}:
            return "__TERMINATE__"
        if stripped == "history":
            return self._history_output()
        if stripped == "env":
            return "".join(f"{k}={v}\n" for k, v in sorted(self.session.state.env.items()))
        if stripped.startswith("alias"):
            return self._handle_alias(stripped)
        if stripped.startswith("export "):
            return self._handle_export(stripped)
        ast = self.parser.parse(stripped)
        result = self._execute_chain(ast)
        if result.exit_code == 0 and self.on_state_change and self._should_persist(ast):
            self.on_state_change()
        return result.stderr + result.stdout

    def _history_output(self) -> str:
        lines = [f"{idx + 1}  {cmd}" for idx, cmd in enumerate(self.session.state.history)]
        return ("\n".join(lines) + "\n") if lines else ""

    def _handle_alias(self, line: str) -> str:
        if line == "alias":
            if not self.session.state.aliases:
                return ""
            return "".join(f"alias {k}='{v}'\n" for k, v in sorted(self.session.state.aliases.items()))
        _, value = line.split("alias", 1)
        value = value.strip()
        if "=" not in value:
            return "alias: usage: alias name='value'\n"
        name, body = value.split("=", 1)
        name = name.strip()
        body = body.strip().strip("'").strip('"')
        if not name:
            return "alias: invalid alias name\n"
        self.session.state.aliases[name] = body
        return ""

    def _handle_export(self, line: str) -> str:
        tokens = shlex.split(line)
        if len(tokens) < 2:
            return "export: usage: export KEY=VALUE\n"
        for tok in tokens[1:]:
            if "=" not in tok:
                return f"export: invalid assignment: {tok}\n"
            key, value = tok.split("=", 1)
            if not key:
                return "export: invalid variable name\n"
            self.session.state.env[key] = value
        return ""

    def _should_persist(self, chain: ChainNode) -> bool:
        for pipeline in chain.pipelines:
            for cmd in pipeline.commands:
                if cmd.command in self._MUTATING_COMMANDS:
                    return True
                if any(r.operator in {">", ">>"} for r in cmd.redirects):
                    return True
        return False

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
            if cmd.command in self.session.state.aliases:
                alias_expanded = shlex.split(self.session.state.aliases[cmd.command])
                if alias_expanded:
                    cmd_command = alias_expanded[0]
                    cmd_args = alias_expanded[1:] + cmd.args
                else:
                    cmd_command = cmd.command
                    cmd_args = cmd.args
            else:
                cmd_command = cmd.command
                cmd_args = cmd.args
            flags = [self._expand(f, env) for f in cmd.flags]
            res = self.kernel.run(
                command=self._expand(cmd_command, env),
                args=[self._expand(a, env) for a in cmd_args],
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
        return self._VAR_PATTERN.sub(lambda m: env.get(m.group(1), m.group(0)), token)
