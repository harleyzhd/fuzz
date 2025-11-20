import random
from .base_fuzzer import BaseFuzzer


class PlaintextFuzzer(BaseFuzzer):
    def _mutate_line_boundaries(self, data):
        if not data:
            return data
        
        data = bytearray(data)
        mutation_type = random.randint(0, 2)

        if mutation_type == 0:
            return bytes(data).replace(b'\n', b'').replace(b'\r', b'')
        
        elif mutation_type == 1:
            result = bytes(data).replace(b'\n', b'\n\x00')
            return result
        
        # insert random newlines
        else:
            positions = random.sample(range(len(data)), min(random.randint(5, 20), len(data)))
            for pos in sorted(positions, reverse=True):
                data.insert(pos, ord('\n'))
            return bytes(data)
    
    def _mutate_whitespace(self, data):
        if not data:
            return data
        
        data = bytearray(data)
        mutation_type = random.randint(0, 2)
        
        # remove all whitespace
        if mutation_type == 0:
            result = bytearray()
            for byte in data:
                if byte not in [ord(' '), ord('\t'), ord('\n'), ord('\r')]:
                    result.append(byte)
            return bytes(result)
        
        # leading/trailing whitespace explosion
        elif mutation_type == 1:
            prefix = b' ' * random.randint(100, 1000)
            suffix = b'\t' * random.randint(100, 1000)
            return prefix + bytes(data) + suffix
        
        # whitespace to null bytes
        else:
            result = bytearray()
            for byte in data:
                if byte in [ord(' '), ord('\t')]:
                    result.append(0)
                else:
                    result.append(byte)
            return bytes(result)
    
    def _mutate_word_boundaries(self, data):
        if not data:
            return data
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = str(data, errors='ignore')
        
        mutation_type = random.randint(0, 2)
        
        # remove separators
        if mutation_type == 0:
            text = text.replace(' ', '').replace('\t', '').replace('\n', '')

        elif mutation_type == 1:
            words = text.split()
            if words:
                long_word = 'A' * random.choice([500, 1000, 5000, 10000])
                words.insert(random.randint(0, len(words)), long_word)
                text = ' '.join(words)

        else:
            words = text.split()
            text = '\x00'.join(words)
        
        return text.encode('utf-8', errors='ignore')
    
    def _insert_special_sequences(self, data):
        if not data:
            return data
        
        data = bytearray(data)
        
        special_sequences = [
            b'\x00',                          # null byte
            b'\x00' * random.randint(10, 100),  # null byte run
            b'\xff' * random.randint(10, 100),  # 0xFF run
            b'%s' * 10,                       # format string
            b'%n' * 10,                       # format string write
            b'%x' * 10,                       # format string hex
            b'A' * 10000,                     # very long string (buffer overflow)
            b'\x7f' * 100,                    # DEL character
        ]
        
        mutation_type = random.randint(0, 2)

        if mutation_type == 0:
            seq = random.choice(special_sequences)
            pos = random.randint(0, len(data))
            data[pos:pos] = seq

        elif mutation_type == 1:
            seq = random.choice(special_sequences)
            data = data + bytearray(seq)

        # replace chunk
        else:
            if len(data) > 0:
                seq = random.choice(special_sequences)
                start = random.randint(0, len(data) - 1)
                end = min(start + len(seq), len(data))
                data[start:end] = seq[:end - start]
        
        return bytes(data)
    
    def _mutate_encoding(self, data):
        if not data:
            return data
        
        data = bytearray(data)
        mutation_type = random.randint(0, 2)
        
        # non-printable characters
        if mutation_type == 0:
            non_printable = list(range(0, 32)) + list(range(127, 256))
            for _ in range(random.randint(5, 20)):
                pos = random.randint(0, len(data))
                data.insert(pos, random.choice(non_printable))
            return bytes(data)
        
        # high-byte values
        elif mutation_type == 1:
            for _ in range(random.randint(5, 30)):
                if len(data) > 0:
                    pos = random.randint(0, len(data) - 1)
                    data[pos] = random.randint(128, 255)
            return bytes(data)
        
        # mix ASCII and binary
        else:
            result = bytearray()
            for i, byte in enumerate(data):
                result.append(byte)
                if i % random.randint(2, 10) == 0:
                    result.append(random.randint(0, 255))
            return bytes(result)
    
    def _create_pathological_inputs(self):
        pattern_type = random.randint(0, 7)
        
        if pattern_type == 0:
            return b'A' * random.choice([1000, 5000, 10000, 50000])
        
        # repeating pattern
        elif pattern_type == 1:
            pattern = random.choice([b'AB', b'XYZ', b'0123', b'\x00\xff'])
            return pattern * random.choice([500, 1000, 5000])
        
        elif pattern_type == 2:
            return b'\x00' * random.choice([100, 500, 1000])
        
        elif pattern_type == 3:
            return b'\xff' * random.choice([100, 500, 1000])
        
        elif pattern_type == 4:
            return b'%s%n%x%p%d' * random.choice([10, 50, 100])
        
        # numbers
        elif pattern_type == 5:
            numbers = []
            for _ in range(random.randint(1, 10)):
                num = random.choice([
                    b'0', b'-1', b'2147483647', b'-2147483648',  # int32 boundaries
                    b'4294967295', b'9223372036854775807',        # max values
                    b'-9223372036854775808', b'18446744073709551615',
                    b'999999999999999999999999999999',            # overflow
                ])
                numbers.append(num)
            return b'\n'.join(numbers) + b'\n'
        
        # text + control characters
        elif pattern_type == 6:
            text = random.choice([b'trivial', b'test', b'admin', b'root'])
            for _ in range(random.randint(1, 5)):
                text += bytes([random.randint(0, 31)])
            return text + b'\n'

        else:
            size = random.choice([100, 500, 1000])
            return random.randbytes(size)
    
    def _mutate_length(self, data):
        if not data:
            return data
        
        mutation_type = random.randint(0, 2)
        
        # truncate
        if mutation_type == 0:
            if len(data) > 1:
                new_len = random.choice([
                    1, 2, 4, 8, 16, 32, 64, 128, 256,
                    len(data) // 2, len(data) - 1
                ])
                return data[:min(new_len, len(data))]

        elif mutation_type == 1:
            repeat_count = random.choice([8, 16, 32, 64, 128])
            return data * repeat_count
        
        # massive padding
        else:
            padding_size = random.choice([10000, 100000])
            padding_byte = random.choice([0, 0x41, 0xff])
            return data + bytes([padding_byte] * padding_size)
    
    def _mutate_numbers(self, data):
        if not data:
            return data
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            return data
        
        mutation_type = random.randint(0, 3)
        
        # boundary values
        if mutation_type == 0:
            import re
            boundary_values = [
                '0', '-1', '2147483647', '-2147483648',  # int32
                '4294967295', '9223372036854775807',     # int64/uint32
                '-9223372036854775808',                   # int64 min
                '18446744073709551615',                   # uint64 max
                '999999999999999999999999',               # overflow
            ]
            result = re.sub(r'\d+', lambda m: random.choice(boundary_values), text)
            return result.encode('utf-8', errors='ignore')
        
        # negative numbers
        elif mutation_type == 1:
            import re
            result = re.sub(r'\b(\d+)\b', lambda m: '-' + m.group(1), text)
            return result.encode('utf-8', errors='ignore')
        
        # format strings
        elif mutation_type == 2:
            import re
            result = re.sub(r'\d+', '%d%n%s%x', text)
            return result.encode('utf-8', errors='ignore')
        
        # very large numbers
        else:
            lines = text.split('\n')
            lines.insert(random.randint(0, len(lines)), str(2**63))
            return '\n'.join(lines).encode('utf-8', errors='ignore')
    
    def _mutate_structured_fields(self, data):
        if not data:
            return data
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            return data
        
        lines = text.split('\n')
        if len(lines) < 2:
            return data
        
        mutation_type = random.randint(0, 9)
        
        # mutate only numeric fields
        if mutation_type == 0:
            import re
            for i in range(len(lines)):
                if re.match(r'^\s*-?\d+\s*$', lines[i]):
                    boundary_values = [
                        '0', '-1', '2147483647', '-2147483648',
                        '4294967295', '9223372036854775807',
                        '-9223372036854775808', '18446744073709551615',
                        '999999999999999999999999',
                    ]
                    lines[i] = random.choice(boundary_values)
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # mutate only last field
        elif mutation_type == 1:
            if len(lines) > 1 and lines[-1].strip():
                import re
                if re.match(r'^\s*-?\d+\s*$', lines[-1]):
                    lines[-1] = random.choice([
                        '0', '-1', '2147483647', '-2147483648',
                        '4294967295', '-9223372036854775808',
                    ])
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # mutate only second field
        elif mutation_type == 2:
            if len(lines) > 1:
                import re
                if re.match(r'^\s*-?\d+\s*$', lines[1]):
                    lines[1] = random.choice([
                        '0', '-1', '2147483647', '-2147483648',
                        '4294967295', '-9223372036854775808',
                        '999999999999999999999999',
                    ])
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # keep first field, mutate rest
        elif mutation_type == 3:
            if len(lines) > 1:
                for i in range(1, len(lines)):
                    import re
                    if re.match(r'^\s*-?\d+\s*$', lines[i]):
                        lines[i] = random.choice([
                            str(random.randint(-2147483648, 2147483647)),
                            '2147483647', '-2147483648', '0', '-1',
                            '4294967295', '-9223372036854775808',
                        ])
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # add extra numeric fields
        elif mutation_type == 4:
            lines.append(random.choice([
                '0', '-1', '2147483647', '-2147483648',
                '4294967295', '999999999999999999',
            ]))
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # mutate each field independently
        elif mutation_type == 5:
            import re
            for i in range(len(lines)):
                if re.match(r'^\s*-?\d+\s*$', lines[i]):
                    num = int(lines[i].strip())
                    lines[i] = str(random.choice([
                        num + 1, num - 1, num * 2, num * -1,
                        -2147483648, 2147483647, 0
                    ]))
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # integer overflow/underflow on numeric fields
        elif mutation_type == 6:
            import re
            for i in range(len(lines)):
                if re.match(r'^\s*-?\d+\s*$', lines[i]):
                    lines[i] = random.choice([
                        '-2147483649',  # int32 underflow
                        '2147483648',   # int32 overflow
                        '-9223372036854775809',  # int64 underflow
                        '9223372036854775808',   # int64 overflow
                    ])
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # keep structure, mutate non-numeric to overflow strings
        elif mutation_type == 7:
            import re
            for i in range(len(lines)):
                if not re.match(r'^\s*-?\d+\s*$', lines[i]) and lines[i].strip():
                    if random.random() < 0.5:
                        lines[i] = 'A' * random.choice([100, 500, 1000, 5000])
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # format string on numeric fields
        elif mutation_type == 8:
            import re
            for i in range(len(lines)):
                if re.match(r'^\s*-?\d+\s*$', lines[i]):
                    lines[i] = random.choice(['%d', '%s', '%n', '%x', '%p'])
            return '\n'.join(lines).encode('utf-8', errors='ignore')
        
        # negative values on all numeric fields
        else:
            import re
            for i in range(len(lines)):
                if re.match(r'^\s*-?\d+\s*$', lines[i]):
                    num = abs(int(lines[i].strip()))
                    lines[i] = str(-num)
            return '\n'.join(lines).encode('utf-8', errors='ignore')

    
    def generate(self):
        # basic edge cases
        yield b""
        yield b"\x00"
        yield b"\xff"
        yield b"\n"
        
        # small truncations
        for size in [1, 2, 4, 8, 16, 32]:
            if len(self.example_input) >= size:
                yield self.example_input[:size]
        
        # PRIORITY: structure-aware mutations (preserves format, mutates values)
        for _ in range(50):
            yield self._mutate_structured_fields(self.example_input)
        
        # integer overflow/underflow
        for _ in range(30):
            yield self._mutate_numbers(self.example_input)
        
        # buffer overflow patterns
        for _ in range(20):
            yield self._create_pathological_inputs()
        
        # buffer overflow via length
        for _ in range(20):
            yield self._mutate_length(self.example_input)
        
        # format strings and special sequences
        for _ in range(20):
            yield self._insert_special_sequences(self.example_input)
        
        # null bytes and encoding issues
        for _ in range(15):
            yield self._mutate_encoding(self.example_input)
        
        # line boundary issues
        for _ in range(10):
            yield self._mutate_line_boundaries(self.example_input)
        
        # whitespace issues
        for _ in range(10):
            yield self._mutate_whitespace(self.example_input)
        
        # word boundary issues
        for _ in range(10):
            yield self._mutate_word_boundaries(self.example_input)
        
        # combined: structure-aware + encoding/injection
        for _ in range(30):
            mutated = self.example_input
            mutated = self._mutate_structured_fields(mutated)
            mutation_func = random.choice([
                self._mutate_encoding,
                self._insert_special_sequences,
            ])
            mutated = mutation_func(mutated)
            yield mutated
        
        # combined: structure-aware + overflow
        for _ in range(20):
            mutated = self.example_input
            mutated = self._mutate_structured_fields(mutated)
            mutation_func = random.choice([
                self._mutate_length,
                self._mutate_word_boundaries,
            ])
            mutated = mutation_func(mutated)
            yield mutated
        
        # random combinations
        for _ in range(30):
            mutated = self.example_input
            num_mutations = random.randint(2, 3)
            
            for _ in range(num_mutations):
                mutation_func = random.choice([
                    self._mutate_structured_fields,
                    self._mutate_numbers,
                    self._mutate_encoding,
                    self._insert_special_sequences,
                    self._mutate_length,
                ])
                mutated = mutation_func(mutated)
            
            yield mutated

        while True:
            mutated = self.example_input
            num_mutations = random.randint(3, 5)
            
            for _ in range(num_mutations):
                mutation_func = random.choice([
                    self._mutate_structured_fields,
                    self._mutate_numbers,
                    self._mutate_encoding,
                    self._insert_special_sequences,
                    self._mutate_length,
                ])
                mutated = mutation_func(mutated)
            
            yield mutated
