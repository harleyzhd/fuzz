import subprocess
import sys
import os
import random
import time
import json
from pathlib import Path
from pwn import process, remote, gdb, args, context, u64, asm

context.log_level = 'error'  # Reduce pwn noise
context.update(arch='amd64', os='linux')

# Debug flag - set to True to print every iteration's payload
DEBUG_PRINT_PAYLOADS = False

BINARIES_PATH = (Path(__file__).parent / "binaries").resolve()
INPUTS_PATH = (Path(__file__).parent / "example_inputs").resolve()
OUTPUT_PATH = (Path(__file__).parent / "fuzzer_output").resolve()

BIN_SH = u64(b'/bin/sh\x00')
BIN_SH_SC = asm(f'''
                mov rbx, {BIN_SH}
                xor rsi, rsi
                xor rdx, rdx
                mov rax, 0x3b
                push rbx
                mov rdi, rsp
                syscall
            ''')

# placeholder for now
gdb_script = """

"""

def start(binary_name, argv=[], *a, **kwargs):
    """Start a process for the given binary."""
    binary_path = BINARIES_PATH / binary_name
    if args.GDB:
        return gdb.debug([str(binary_path)] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        # probably dont need this lol
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([str(binary_path)] + argv, *a, **kwargs)


# Base Fuzzer Class
class BaseFuzzer:
    """Base class for all format-specific fuzzers."""
    
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
    
    # claude generated
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


class PlaintextFuzzer(BaseFuzzer):
    """Fuzzer for plaintext inputs."""
    
    def generate(self):
        """Generate mutated plaintext inputs."""
        while True:
            # TODO: Implement plaintext-specific mutations
            # - Line insertions/deletions
            # - Word boundary mutations
            # - Newline/whitespace fuzzing
            yield self.mutate_bytes(self.example_input)


class JsonFuzzer(BaseFuzzer):
    """Fuzzer for JSON inputs."""
    
    def __init__(self, example_input):
        """Initialize the JSON fuzzer."""
        super().__init__(example_input)
        self._json = self.parsed_data
    
    def parse_input(self, data):
        """Parse JSON data."""
        return json.loads(data.decode('utf-8'))
    
    def mutate_json_structure(self, json_obj):
        """Apply structural mutations to JSON object."""
        import copy
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
        import copy
        
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


class XmlFuzzer(BaseFuzzer):
    """Fuzzer for XML inputs."""
    
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


class CsvFuzzer(BaseFuzzer):

    def parse_input(self, data):
        try:
            txt = data.decode('utf-8', errors='ignore')
            lines = txt.splitlines()
            return [ln for ln in lines]
        except Exception:
            return None

    def _seed_text(self):
        return (self.example_input.decode('utf-8', errors='ignore')
                if isinstance(self.example_input, (bytes, bytearray))
                else str(self.example_input))

    def _rows_to_bytes(self, rows, delim=','):
        s = "\n".join(delim.join(r) for r in rows) + "\n"
        return s.encode('utf-8', errors='ignore')

    def _append_after_seed_text(self, suffix_text):
        seed = self._seed_text()
        if not seed.endswith("\n"):
            seed += "\n"
        return (seed + suffix_text).encode('utf-8', errors='ignore')

    def _pick_template_row(self, lines):
        # choose the line with most commas (most fields) as template
        if not lines:
            return ["a","b","c"]
        best = max(lines, key=lambda l: l.count(','))
        return best.split(',')

    def _mutate_field(self, s):
        s = s or ""
        r = random.randint(0, 6)
        if r == 0:
            return ""
        if r == 1:
            return (s[:3] or "x")
        if r == 2:
            return "A" * random.choice([8, 16, 64, 200, 500])
        if r == 3:
            return str(random.randint(0, 2**31-1))
        if r == 4:
            return f'"{s or "A"}"'
        if r == 5:
            return (s or "Z") + "\\n" + "Z"
        return (s.replace(",", ";") if s else ";")

    def _mutate_row_fields(self, base_row):
        row = []
        for f in base_row:
            row.append(self._mutate_field(f))
        # small chance to add/delete columns
        if random.random() < 0.10:
            for _ in range(random.randint(1, 2)):
                row.append(self._mutate_field(""))
        if random.random() < 0.03 and len(row) > 1:
            del row[random.randrange(len(row))]
        return row

    def _make_block_vary_each_field(self, base_row, nrows):
        return [self._mutate_row_fields(base_row) for _ in range(nrows)]

    
    def mutation_in_row(self, data, times):
        
        import copy
        if not data or not data[0]:
            return data
        data = copy.deepcopy(data)

        
        pool = ["!", "@", "#", "$", "%", "^", "&", "*", "?", ";", "|"]

        row_mutators = [
            lambda row: row + [random.choice(pool)],                     
            lambda row: (row[::-1] if len(row) > 1 else row),           
            lambda row: (row[:-1] if len(row) > 1 else row),            
            lambda row: (row[1:] if len(row) > 1 else row),             
            lambda row: [],                                             
            lambda row: row * random.randint(250, 500),                 
        ]

        counter = 0
        while counter < times:
            op = random.choice(row_mutators)
            r = random.randrange(len(data))
            try:
                data[r] = op(data[r])
                counter += 1
            except (IndexError, ValueError, TypeError):
                continue
        return data

    def _repeat_last_line_block(self, lines, counts):
        if not lines:
            return []
        last = lines[-1] if lines[-1].strip() else (lines[-2] if len(lines) >= 2 else lines[-1])
        if last.strip() == "":
            last = "a,b,c,A"
        payloads = []
        for n in counts:
            block = ("\n".join([last for _ in range(n)]) + "\n")
            payloads.append(self._append_after_seed_text(block))
        return payloads

    def _append_growing_last_field(self, template_line, steps=12):
        parts = template_line.split(",")
        if len(parts) == 0:
            parts = ["A"]
        if len(parts) == 1:
            parts.append("A")
        lines = []
        for i in range(steps):
            p = parts[:]
            p[-1] = "A" * max(1, i * 10)
            lines.append(",".join(p))
        block = "\n".join(lines) + "\n"
        return self._append_after_seed_text(block)

    def generate(self):
        yield b""                                 # empty
        yield self.example_input                  # seed unchanged
        yield (b"A" * 2000)                       # size stress single-field appended

        seed_lines = self.parse_input(self.example_input) or []

        # Detect if this is a numeric CSV (like csv2) by checking first line
        is_numeric_csv = False
        if seed_lines and len(seed_lines) > 0:
            first_line = seed_lines[0].strip()
            if ',' in first_line:
                fields = first_line.split(',')
                # Check if first line contains only numbers
                try:
                    [int(f.strip()) for f in fields if f.strip()]
                    is_numeric_csv = True
                except (ValueError, AttributeError):
                    pass

        # Special handling for numeric CSV (csv2 type)
        if is_numeric_csv:
            # csv2 has divide-by-zero bug when first field = 0
            yield b"0,1\r\n"
            yield b"0,2\r\n"
            yield b"0,0\r\n"
            yield b"0,10\r\n"
            yield b"0,100\r\n"
            yield b"0,-1\r\n"
            yield b"0,-10\r\n"

            # Multiple rows with 0 in first position
            yield b"0,1\r\n0,2\r\n"
            yield b"0,0\r\n0,0\r\n"

            # Various numeric combinations
            for n1 in [0, 1, -1, 10, 100, -100, 2147483647, -2147483648]:
                for n2 in [0, 1, -1, 10, 100]:
                    yield f"{n1},{n2}\r\n".encode('utf-8')

        # Continue with existing CSV fuzzing strategies
        template = self._pick_template_row(seed_lines)
        block = self._make_block_vary_each_field(template, nrows=random.randint(6, 18))
        yield self._append_after_seed_text("\n".join([",".join(r) for r in block]) + "\n")

        block_sc = self._make_block_vary_each_field(template, nrows=random.randint(4, 12))
        yield self._append_after_seed_text("\n".join([(";".join(r)) for r in block_sc]) + "\n")

        if seed_lines:
            template_line = seed_lines[-1] if seed_lines[-1].strip() else (seed_lines[0] if seed_lines else "a,b,c,A")
            yield self._append_growing_last_field(template_line, steps=12)

        for p in self._repeat_last_line_block(seed_lines, counts=[5, 10, 50, 100, 150]):
            yield p

        if seed_lines:
            last = seed_lines[-1] if seed_lines[-1].strip() else (seed_lines[0] if seed_lines else "a,b,c,A")
            semi_block = "\n".join([last.replace(",", ";") for _ in range(20)]) + "\n"
            yield self._append_after_seed_text(semi_block)

        if seed_lines:
            seed_rows = [ln.split(",") for ln in seed_lines if ln.strip()]
        else:
            seed_rows = [["a","b","c","A"]]
        mutated_rows = self.mutation_in_row(seed_rows, times=random.randint(3, 10))
        try:
            yield self._append_after_seed_text(self._rows_to_bytes(mutated_rows).decode('utf-8', errors='ignore'))
        except Exception:
            pass

        for rate in (20, 40):
            b = bytearray(self.example_input)
            for i in range(len(b)):
                if random.randint(0, rate) == 1:
                    b[i] ^= random.getrandbits(7)
            yield bytes(b)

        for _ in range(25):
            yield self.mutate_bytes(self.example_input)

        while True:
            yield self.mutate_bytes(self.example_input)


class JpegFuzzer(BaseFuzzer):
    """Fuzzer for JPEG inputs."""
    
    def generate(self):
        """Generate mutated JPEG inputs."""
        while True:
            # TODO: Implement JPEG-specific mutations
            # - Header corruption
            # - Marker manipulation
            # - EXIF data fuzzing
            # - Huffman table corruption
            yield self.mutate_bytes(self.example_input)


class ElfFuzzer(BaseFuzzer):
    """Fuzzer for ELF inputs."""
    
    def generate(self):
        """Generate mutated ELF inputs."""
        while True:
            # TODO: Implement ELF-specific mutations
            # - Header field mutations
            # - Section header fuzzing
            # - Program header fuzzing
            # - Symbol table corruption
            yield self.mutate_bytes(self.example_input)


class PdfFuzzer(BaseFuzzer):
    """Fuzzer for PDF inputs."""
    
    def generate(self):
        """Generate mutated PDF inputs."""
        while True:
            # TODO: Implement PDF-specific mutations
            # - Object stream corruption
            # - Cross-reference table fuzzing
            # - JavaScript injection
            # - Embedded file fuzzing
            yield self.mutate_bytes(self.example_input)


def detect_input_type(data):
    """Detect the input format type from the data."""
    # Check for ELF
    if data.startswith(b'\x7fELF'):
        return 'ELF'
    
    # Check for JPEG
    if data.startswith(b'\xff\xd8\xff'):
        return 'JPEG'
    
    # Check for PDF
    if data.startswith(b'%PDF'):
        return 'PDF'
    
    # Try to parse as JSON
    try:
        json.loads(data.decode('utf-8', errors='ignore'))
        return 'JSON'
    except:
        pass
    
    # Check for XML
    try:
        data_str = data.decode('utf-8', errors='ignore').strip()
        if data_str.startswith('<?xml') or data_str.startswith('<'):
            return 'XML'
    except:
        pass
    
    # Check for CSV (look for comma-separated values)
    try:
        data_str = data.decode('utf-8', errors='ignore')
        lines = data_str.strip().split('\n')
        if len(lines) > 0:
            # Check if first line has commas and consistent column count
            first_line_cols = len(lines[0].split(','))
            if first_line_cols > 1:
                # Check if other lines have similar structure
                consistent = all(len(line.split(',')) == first_line_cols for line in lines[:3])
                if consistent:
                    return 'CSV'
    except:
        pass
    
    # Default to plaintext
    return 'PLAINTEXT'


def get_fuzzer_class(input_type):
    """Return the appropriate fuzzer class for the given input type."""
    fuzzer_map = {
        'PLAINTEXT': PlaintextFuzzer,
        'JSON': JsonFuzzer,
        'XML': XmlFuzzer,
        'CSV': CsvFuzzer,
        'JPEG': JpegFuzzer,
        'ELF': ElfFuzzer,
        'PDF': PdfFuzzer,
    }
    return fuzzer_map.get(input_type, BaseFuzzer)


def fuzz_binary(binary_name, max_time=60):
    """Fuzz a single binary and return results."""
    print(f"\n[*] Fuzzing binary: {binary_name}")
    
    # Load the valid input
    input_file = INPUTS_PATH / f"{binary_name}.txt"
    if not input_file.exists():
        print(f"[!] No example input found for {binary_name}")
        return []
    
    with open(input_file, 'rb') as f:
        valid_input = f.read()
    
    print(f"[*] Loaded valid input ({len(valid_input)} bytes)")
    
    # Detect input type
    input_type = detect_input_type(valid_input)
    print(f"[*] Detected input type: {input_type}")
    
    # Get appropriate fuzzer class and instantiate it
    fuzzer_class = get_fuzzer_class(input_type)
    print(f"[*] Using fuzzer: {fuzzer_class.__name__}")
    
    try:
        fuzzer = fuzzer_class(valid_input)
    except Exception as e:
        print(f"[!] Error initializing fuzzer: {e}")
        return []
    
    crashes = []
    iterations = 0
    start_time = time.time()
    
    # Use the fuzzer's generator to get mutated inputs
    for mutated in fuzzer.generate():
        if (time.time() - start_time) >= max_time:
            break
        
        iterations += 1
        
        if DEBUG_PRINT_PAYLOADS:
            print(f"[DEBUG] Iteration {iterations}: Sending {len(mutated)} bytes")
            if len(mutated) <= 100:
                print(f"[DEBUG] Payload: {mutated}")
            else:
                print(f"[DEBUG] Payload (first 100 bytes): {mutated[:100]}...")
        
        try:
            # Run the binary with mutated input
            p = start(binary_name)
            p.send(mutated)
            p.shutdown('send')
            
            # Wait briefly for crash
            try:
                if hasattr(p, 'poll'):
                    result = p.poll(block=False)  # type: ignore
                    if result is None:
                        # Still running, wait a bit
                        time.sleep(0.1)
                        result = p.poll(block=False)  # type: ignore
                    
                    # Check if it crashed (non-zero exit)
                    # Exit code -6 is SIGABRT (abort()), which doesn't count as a crash
                    if result is not None and result != 0 and result != -6:
                        crashes.append({
                            'input': mutated,
                            'exit_code': result,
                            'iteration': iterations
                        })
                        print(f"[+] Crash found! Exit code: {result}, Iteration: {iterations}")
            except Exception:
                pass
            
            p.close()
            
        except Exception as e:
            # Binary might have crashed before we could interact
            if "SIGSEGV" in str(e) or "SIGABRT" in str(e) or "SIGILL" in str(e):
                crashes.append({
                    'input': mutated,
                    'error': str(e),
                    'iteration': iterations
                })
                print(f"[+] Crash found! Error: {str(e)[:50]}, Iteration: {iterations}")
        
        if iterations % 100 == 0:
            print(f"[*] Iterations: {iterations}, Time: {int(time.time() - start_time)}s")
    
    print(f"[*] Finished fuzzing {binary_name}: {iterations} iterations, {len(crashes)} crashes")
    return crashes


def save_results(binary_name, crashes):
    """Save fuzzing results to output file."""
    OUTPUT_PATH.mkdir(exist_ok=True)
    output_file = OUTPUT_PATH / f"{binary_name}.txt"
    
    with open(output_file, 'w') as f:
        f.write(f"Fuzzing results for {binary_name}\n")
        f.write(f"="*50 + "\n\n")
        f.write(f"Total crashes found: {len(crashes)}\n\n")
        
        for i, crash in enumerate(crashes, 1):
            f.write(f"Crash #{i}:\n")
            f.write(f"  Iteration: {crash['iteration']}\n")
            if 'exit_code' in crash:
                f.write(f"  Exit code: {crash['exit_code']}\n")
            if 'error' in crash:
                f.write(f"  Error: {crash['error']}\n")
            f.write(f"  Input (hex): {crash['input'].hex()}\n")
            f.write(f"  Input (repr): {repr(crash['input'][:100])}\n")
            f.write("\n")
    
    print(f"[*] Results saved to {output_file}")


def main() -> int:
    print("="*60)
    print("Starting Fuzzer")
    print("="*60)
    
    # Check if specific binary was requested
    target_binary = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
        target_binary = sys.argv[1]
    
    # Get list of binaries to fuzz
    binaries = []
    if target_binary:
        binary_path = BINARIES_PATH / target_binary
        if binary_path.exists():
            binaries = [target_binary]
            print(f"[*] Fuzzing single binary: {target_binary}")
        else:
            print(f"[!] Binary not found: {target_binary}")
            return 1
    else:
        # Fuzz all binaries
        binaries = [f.name for f in BINARIES_PATH.iterdir() if f.is_file()]
        binaries.sort()
        print(f"[*] Fuzzing all binaries ({len(binaries)} total)")
    
    # Fuzz each binary
    for binary_name in binaries:
        try:
            crashes = fuzz_binary(binary_name, max_time=60)
            save_results(binary_name, crashes)
        except Exception as e:
            print(f"[!] Error fuzzing {binary_name}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print("Fuzzing completed successfully")
    print("="*60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
