import json
import copy
import random
from .base_fuzzer import BaseFuzzer


class JsonFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        """Initialize the JSON fuzzer."""
        super().__init__(example_input)
        self._json = self.parsed_data
    
    def parse_input(self, data):
        """Parse JSON data."""
        return json.loads(data.decode('utf-8'))
    
    def mutate_json_structure(self, json_obj):
        """Apply structural mutations to JSON object."""
        mutated = copy.deepcopy(json_obj)
        
        if isinstance(mutated, dict):
            mutation = random.randint(0, 4)
            
            if mutation == 0 and len(mutated) > 0:  # Remove a key
                key = random.choice(list(mutated.keys()))
                del mutated[key]
            elif mutation == 1:  # Add a random key
                mutated[f"fuzz_{random.randint(0, 1000)}"] = "A" * random.randint(1, 100)
            elif mutation == 2 and len(mutated) > 0:  # Modify a value
                key = random.choice(list(mutated.keys()))
                value_type = random.randint(0, 5)
                if value_type == 0:
                    mutated[key] = "A" * random.randint(1, 1000)
                elif value_type == 1:
                    mutated[key] = random.randint(-2147483648, 2147483647)
                elif value_type == 2:
                    mutated[key] = random.choice([True, False, None])
                elif value_type == 3:
                    mutated[key] = []
                elif value_type == 4:
                    mutated[key] = {}
                elif value_type == 5:
                    mutated[key] = "%s" * 10  # Format string
            elif mutation == 3:  # Create deeply nested structure
                nested = mutated
                for _ in range(random.randint(10, 100)):
                    nested["nested"] = {}
                    nested = nested["nested"]
            elif mutation == 4 and len(mutated) > 0:  # Duplicate a key (invalid JSON)
                # This creates invalid JSON by string manipulation
                return mutated
                
        elif isinstance(mutated, list):
            mutation = random.randint(0, 2)
            if mutation == 0:  # Add items
                for _ in range(random.randint(1, 50)):
                    mutated.append("A" * random.randint(1, 100))
            elif mutation == 1 and len(mutated) > 0:  # Remove items
                for _ in range(min(len(mutated), random.randint(1, 5))):
                    mutated.pop(random.randint(0, len(mutated) - 1))
            elif mutation == 2:  # Modify items
                for i in range(len(mutated)):
                    if random.randint(0, 2) == 0:
                        mutated[i] = random.choice([None, True, False, 999999, "FUZZ"])
        
        return mutated
    
    def generate_invalid_json(self):
        """Generate syntactically invalid JSON."""
        invalid_patterns = [
            b'{"key": }',  # Missing value
            b'{"key" "value"}',  # Missing colon
            b'{key: "value"}',  # Unquoted key
            b'{"key": "value",}',  # Trailing comma
            b'{"key": "value"',  # Missing closing brace
            b'{"key": undefined}',  # Invalid keyword
            b'{"key": NaN}',  # Invalid number
            b'{"key": Infinity}',  # Invalid number
            b'{"key": \'value\'}',  # Single quotes
            b'{"key": "value" "key2": "value2"}',  # Missing comma
            b'[1, 2, 3,]',  # Trailing comma in array
            b'{"key": 0x123}',  # Hex number
            b'{{{{{',  # Multiple opening braces
            b'}}}}}',  # Multiple closing braces
        ]
        return random.choice(invalid_patterns)
    
    def generate(self):
        """Generate mutated JSON inputs."""
        # First, try sending empty file
        yield b""
        
        # Send very large input
        yield b"A" * 10000
        
        # Send invalid JSON patterns
        for _ in range(20):
            yield self.generate_invalid_json()
        
        # Send format string attack
        if self.parsed_data:
            format_obj = copy.deepcopy(self.parsed_data)
            if isinstance(format_obj, dict):
                for key in format_obj:
                    format_obj[key] = "%s%s%s%s%s%s%s%s%s%s"
            yield json.dumps(format_obj).encode('utf-8')
        
        # Send deeply nested structure (billion laughs style)
        nested = {"a": {}}
        current = nested["a"]
        for _ in range(990):
            current["a"] = {}
            current = current["a"]
        yield json.dumps(nested).encode('utf-8')
        
        # Send extremely large numbers
        if self.parsed_data and isinstance(self.parsed_data, dict):
            big_num = copy.deepcopy(self.parsed_data)
            for key in big_num:
                if random.randint(0, 1) == 0:
                    big_num[key] = 999999999999999999999999999999
            yield json.dumps(big_num).encode('utf-8')
        
        # Send very long strings
        if self.parsed_data and isinstance(self.parsed_data, dict):
            long_str = copy.deepcopy(self.parsed_data)
            for key in long_str:
                if random.randint(0, 1) == 0:
                    long_str[key] = "A" * 10000
            yield json.dumps(long_str).encode('utf-8')
        
        # Now do random structural mutations
        while True:
            if self.parsed_data:
                mutated_obj = self.mutate_json_structure(self.parsed_data)
                try:
                    yield json.dumps(mutated_obj).encode('utf-8')
                except (TypeError, ValueError, RecursionError):
                    # If json.dumps fails, yield random bytes
                    yield self.mutate_bytes(self.example_input)
            else:
                yield self.mutate_bytes(self.example_input)
