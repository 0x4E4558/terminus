import unittest

from terminus_engine.parser import ParserEngine


class ParserTests(unittest.TestCase):
    def test_parse_pipeline_and_redirect(self) -> None:
        parser = ParserEngine()
        chain = parser.parse('echo "signal choir" | grep signal > /tmp/out')
        self.assertEqual(len(chain.pipelines), 1)
        commands = chain.pipelines[0].commands
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0].command, "echo")
        self.assertEqual(commands[0].args, ["signal choir"])
        self.assertEqual(commands[1].command, "grep")
        self.assertEqual(commands[1].args, ["signal"])
        self.assertEqual(commands[1].redirects[0].operator, ">")
        self.assertEqual(commands[1].redirects[0].target, "/tmp/out")


if __name__ == "__main__":
    unittest.main()
