from .base_fuzzer import BaseFuzzer


class PlaintextFuzzer(BaseFuzzer):
    def generate(self):
        """Generate mutated plaintext inputs."""
        while True:
            # TODO: Implement plaintext-specific mutations
            # - Line insertions/deletions
            # - Word boundary mutations
            # - Newline/whitespace fuzzing
            yield self.mutate_bytes(self.example_input)
