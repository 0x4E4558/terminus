from terminus_engine.parser import ParserEngine


def test_parse_pipeline_and_redirect():
    parser = ParserEngine()
    chain = parser.parse('echo "signal choir" | grep signal > /tmp/out')
    assert len(chain.pipelines) == 1
    commands = chain.pipelines[0].commands
    assert len(commands) == 2
    assert commands[0].command == "echo"
    assert commands[0].args == ["signal choir"]
    assert commands[1].command == "grep"
    assert commands[1].args == ["signal"]
    assert commands[1].redirects[0].operator == ">"
    assert commands[1].redirects[0].target == "/tmp/out"
