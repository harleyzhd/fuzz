import random


class BaseFuzzer:
    def __init__(self, example_input):
        """Initialize the fuzzer with example input data."""
        self.example_input = example_input
        try:
            self.parsed_data = self.parse_input(example_input)
        except Exception as exc:
            print(f"[!] Error parsing input: {exc}")
            self.parsed_data = None
    
    def parse_input(self, data):
        """Parse the input data. Override in subclasses."""
        return data
    
    def generate(self):
        """Generator that yields mutated inputs. Override in subclasses."""
        # Default: yield byte-level mutations
        while True:
            yield self.mutate_bytes(self.example_input)
    
    def mutate_bytes(self, data):
        """Apply generic byte-level mutations."""
        if not data:
            return data
        
        mutation_type = random.randint(0, 5)
        data = bytearray(data)
        
        if mutation_type == 0:  # Bit flip
            if len(data) > 0:
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= (1 << random.randint(0, 7))
        elif mutation_type == 1:  # Byte flip
            if len(data) > 0:
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
        elif mutation_type == 2:  # Insert random byte
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))
        elif mutation_type == 3:  # Delete byte
            if len(data) > 1:
                pos = random.randint(0, len(data) - 1)
                del data[pos]
        elif mutation_type == 4:  # Duplicate chunk
            if len(data) > 0:
                chunk_len = min(random.randint(1, 10), len(data))
                pos = random.randint(0, len(data) - chunk_len)
                chunk = data[pos:pos + chunk_len]
                data.extend(chunk * random.randint(2, 10))
        elif mutation_type == 5:  # Insert special values
            special_values = [0, 255, 127, 128, b'\x00', b'\xff', b'\n', b'\r']
            pos = random.randint(0, len(data))
            val = random.choice(special_values)
            if isinstance(val, bytes):
                data[pos:pos] = val
            else:
                data.insert(pos, val)
        
        return bytes(data)
