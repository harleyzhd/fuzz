from .base_fuzzer import BaseFuzzer


class XmlFuzzer(BaseFuzzer):
    def generate(self):
        """Generate mutated XML inputs."""
        while True:
            # TODO: Implement XML-specific mutations
            # - Tag mutations
            # - Attribute fuzzing
            # - Nesting attacks (deeply nested tags)
            # - Entity expansion attacks
            # - CDATA injection
            yield self.mutate_bytes(self.example_input)
