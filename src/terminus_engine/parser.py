from __future__ import annotations

from dataclasses import dataclass, field
import shlex


@dataclass(slots=True)
class RedirectionNode:
    operator: str
    target: str


@dataclass(slots=True)
class CommandNode:
    command: str
    args: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    redirects: list[RedirectionNode] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PipelineNode:
    commands: list[CommandNode] = field(default_factory=list)


@dataclass(slots=True)
class ChainNode:
    pipelines: list[PipelineNode] = field(default_factory=list)
    operators: list[str] = field(default_factory=list)


class ParseError(ValueError):
    pass


class ParserEngine:
    """Tokenizer -> parser -> AST for shell-like command lines."""

    _CHAIN_OPS = {";", "&&", "||"}
    _REDIRECTS = {">", ">>", "<"}

    def parse(self, line: str) -> ChainNode:
        tokens = self._tokenize(line)
        if not tokens:
            return ChainNode()
        return self._parse_chain(tokens)

    def _tokenize(self, line: str) -> list[str]:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)

    def _parse_chain(self, tokens: list[str]) -> ChainNode:
        chunks: list[list[str]] = []
        ops: list[str] = []
        current: list[str] = []

        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok in {"&", "|"} and i + 1 < len(tokens) and tokens[i + 1] == tok:
                tok = tok + tok
                i += 1
            elif tok == "&":
                raise ParseError("background execution '&' is not supported")
            if tok in self._CHAIN_OPS:
                if not current:
                    raise ParseError(f"unexpected chain operator: {tok}")
                chunks.append(current)
                current = []
                ops.append(tok)
            else:
                current.append(tok)
            i += 1
        if not current:
            raise ParseError("line ends with chain operator")
        chunks.append(current)

        return ChainNode(
            pipelines=[self._parse_pipeline(chunk) for chunk in chunks],
            operators=ops,
        )

    def _parse_pipeline(self, tokens: list[str]) -> PipelineNode:
        parts: list[list[str]] = []
        current: list[str] = []
        for tok in tokens:
            if tok == "|":
                if not current:
                    raise ParseError("empty pipe segment")
                parts.append(current)
                current = []
            else:
                current.append(tok)
        if not current:
            raise ParseError("line ends with pipe")
        parts.append(current)
        return PipelineNode(commands=[self._parse_command(p) for p in parts])

    def _parse_command(self, tokens: list[str]) -> CommandNode:
        env: dict[str, str] = {}
        i = 0
        while i < len(tokens):
            if "=" in tokens[i] and not tokens[i].startswith("-") and not tokens[i].startswith("="):
                k, v = tokens[i].split("=", 1)
                env[k] = v
                i += 1
                continue
            break

        if i >= len(tokens):
            raise ParseError("missing command")

        command = tokens[i]
        i += 1

        args: list[str] = []
        flags: list[str] = []
        redirects: list[RedirectionNode] = []

        while i < len(tokens):
            tok = tokens[i]
            if tok in self._REDIRECTS:
                i += 1
                if i >= len(tokens):
                    raise ParseError(f"redirect missing target: {tok}")
                redirects.append(RedirectionNode(operator=tok, target=tokens[i]))
            elif tok.startswith("-"):
                flags.append(tok)
            else:
                args.append(tok)
            i += 1

        return CommandNode(
            command=command,
            args=args,
            flags=flags,
            redirects=redirects,
            env=env,
        )
