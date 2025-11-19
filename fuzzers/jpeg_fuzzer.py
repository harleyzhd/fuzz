from .base_fuzzer import BaseFuzzer


class JpegFuzzer(BaseFuzzer):
    def generate(self):
        """Generate mutated JPEG inputs."""
        while True:
            # TODO: Implement JPEG-specific mutations
            # - Header corruption
            # - Marker manipulation
            # - EXIF data fuzzing
            # - Huffman table corruption
            yield self.mutate_bytes(self.example_input)
