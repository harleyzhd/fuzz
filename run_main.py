import subprocess
import sys
import os
import random
import time
import json
import copy
import struct
import io
from pathlib import Path
from pwn import process, remote, gdb, args, context, u64, asm
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.constants import SH_FLAGS

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
    
    def __init__(self, example_input):
        super().__init__(example_input)
        self.elf_data = None
        self.elf_obj = None
        try:
            self.elf_obj = ELFFile(io.BytesIO(self.example_input))
            self.elf_data = bytearray(self.example_input)
        except Exception as e:
            print(f"[!] Warning: Could not parse ELF file: {e}")
            self.elf_data = bytearray(self.example_input)
    
    def _get_elf_header_offsets(self):
        return {
            'e_type': (0x10, 2),        # Object file type
            'e_machine': (0x12, 2),     # Architecture
            'e_version': (0x14, 4),     # Object file version
            'e_entry': (0x18, 8),       # Entry point virtual address
            'e_phoff': (0x20, 8),       # Program header table offset
            'e_shoff': (0x28, 8),       # Section header table offset
            'e_flags': (0x30, 4),       # Processor-specific flags
            'e_ehsize': (0x34, 2),      # ELF header size
            'e_phentsize': (0x36, 2),   # Program header entry size
            'e_phnum': (0x38, 2),       # Program header count
            'e_shentsize': (0x3a, 2),   # Section header entry size
            'e_shnum': (0x3c, 2),       # Section header count
            'e_shstrndx': (0x3e, 2),    # Section header string table index
        }
    
    def _mutate_elf_header(self, data):
        data = bytearray(data)
        offsets = self._get_elf_header_offsets()
        
        # random header to mutate
        field = random.choice(list(offsets.keys()))
        offset, size = offsets[field]
        
        mutation_type = random.randint(0, 5)
        
        if mutation_type == 0:  # max value
            data[offset:offset+size] = b'\xff' * size
        elif mutation_type == 1:  # zero
            data[offset:offset+size] = b'\x00' * size
        elif mutation_type == 2:  # bits flips
            for i in range(offset, offset + size):
                data[i] ^= random.randint(1, 255)
        elif mutation_type == 3:  # edge case power of 2
            val = 1 << random.randint(0, size * 8 - 1)
            data[offset:offset+size] = val.to_bytes(size, byteorder='little')
        elif mutation_type == 4:  # slight offsets (off by one)
            current = int.from_bytes(data[offset:offset+size], byteorder='little')
            new_val = current + random.choice([-1, 1, -2, 2])
            if new_val < 0:
                new_val = 0
            data[offset:offset+size] = new_val.to_bytes(size, byteorder='little')
        else:  # Random value
            data[offset:offset+size] = random.randbytes(size)
        
        return bytes(data)
    
    def _mutate_section_headers(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
            e_shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
            e_shentsize = struct.unpack('<H', data[0x3a:0x3c])[0]
            
            if e_shoff == 0 or e_shnum == 0:
                return bytes(data)
            
            section_idx = random.randint(0, e_shnum - 1)
            sh_offset = e_shoff + (section_idx * e_shentsize)
            
            if sh_offset + e_shentsize > len(data):
                return bytes(data)
            
            mutation_type = random.randint(0, 7)
            
            # flip section flags (SHF_WRITE, SHF_EXECINSTR)
            if mutation_type == 0:
                # sh_flags offset in section header
                flags_offset = sh_offset + 0x08
                current_flags = struct.unpack('<Q', data[flags_offset:flags_offset+8])[0]
                # Toggle write/exec flags
                new_flags = current_flags ^ random.choice([0x1, 0x2, 0x4]) # SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR
                data[flags_offset:flags_offset+8] = struct.pack('<Q', new_flags)
            
            # change section alignment
            elif mutation_type == 1:
                # sh_addralign offset
                align_offset = sh_offset + 0x30
                new_align = random.choice([1, 2, 4, 8, 16, 32, 64, 0x10000, 0x100000])
                data[align_offset:align_offset+8] = struct.pack('<Q', new_align)
            
            # modify section size
            elif mutation_type == 2:
                # sh_size offset
                size_offset = sh_offset + 0x20
                current_size = struct.unpack('<Q', data[size_offset:size_offset+8])[0]
                new_size = current_size + random.choice([-1, 1, -16, 16, 100, -100, 0x1000])
                if new_size < 0:
                    new_size = 0
                data[size_offset:size_offset+8] = struct.pack('<Q', new_size)
            
            # modify section offset
            elif mutation_type == 3:
                # sh_offset offset
                offset_offset = sh_offset + 0x18
                current_off = struct.unpack('<Q', data[offset_offset:offset_offset+8])[0]
                new_off = current_off + random.choice([-1, 1, -8, 8, 0x100])
                if new_off < 0:
                    new_off = 0
                data[offset_offset:offset_offset+8] = struct.pack('<Q', new_off)
            
            # change section type
            elif mutation_type == 4:
                # sh_type offset
                type_offset = sh_offset + 0x04
                # various SHT_types
                new_type = random.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11])
                data[type_offset:type_offset+4] = struct.pack('<I', new_type)
            
            # reorder sections by swapping two section headers
            elif mutation_type == 5:
                if e_shnum > 1:
                    other_idx = random.randint(0, e_shnum - 1)
                    other_offset = e_shoff + (other_idx * e_shentsize)
                    if other_offset + e_shentsize <= len(data):
                        # swapping two section headers
                        temp = data[sh_offset:sh_offset+e_shentsize]
                        data[sh_offset:sh_offset+e_shentsize] = data[other_offset:other_offset+e_shentsize]
                        data[other_offset:other_offset+e_shentsize] = temp
            
            # create overlapping sections
            elif mutation_type == 6:
                size_offset = sh_offset + 0x20 # sh_size offset
                offset_offset = sh_offset + 0x18 # sh_offset offset
                # make section extend into next section
                if section_idx < e_shnum - 1:
                    next_sh_offset = e_shoff + ((section_idx + 1) * e_shentsize)
                    next_offset = struct.unpack('<Q', data[next_sh_offset+0x18:next_sh_offset+0x20])[0]
                    current_offset = struct.unpack('<Q', data[offset_offset:offset_offset+8])[0]
                    overlap_size = next_offset - current_offset + random.randint(1, 100)
                    data[size_offset:size_offset+8] = struct.pack('<Q', overlap_size)
            
            else: # corrupt the entire section header entry
                data[sh_offset:sh_offset+e_shentsize] = random.randbytes(e_shentsize)
        
        except Exception as e:
            pass
        
        return bytes(data)
    
    def _mutate_program_headers(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            e_phoff = struct.unpack('<Q', data[0x20:0x28])[0]
            e_phnum = struct.unpack('<H', data[0x38:0x3a])[0]
            e_phentsize = struct.unpack('<H', data[0x36:0x38])[0]
            
            if e_phoff == 0 or e_phnum == 0:
                return bytes(data)
            
            # pick a random program header to mutate
            ph_idx = random.randint(0, e_phnum - 1)
            ph_offset = e_phoff + (ph_idx * e_phentsize)
            
            if ph_offset + e_phentsize > len(data):
                return bytes(data)
            
            mutation_type = random.randint(0, 6)
            
            # modify permission flags
            if mutation_type == 0:
                flags_offset = ph_offset + 0x04
                current_flags = struct.unpack('<I', data[flags_offset:flags_offset+4])[0]
                # Toggle RWX bits (PF_X=1, PF_W=2, PF_R=4)
                new_flags = current_flags ^ random.choice([1, 2, 4, 7])
                data[flags_offset:flags_offset+4] = struct.pack('<I', new_flags)
            
            # mismatch p_memsz and p_filesz
            elif mutation_type == 1:
                filesz_offset = ph_offset + 0x20
                memsz_offset = ph_offset + 0x28
                
                filesz = struct.unpack('<Q', data[filesz_offset:filesz_offset+8])[0]
                new_memsz = filesz + random.choice([0x1000, 0x10000, 0x100000, 0x1000000])
                data[memsz_offset:memsz_offset+8] = struct.pack('<Q', new_memsz)
            
            # p_filesz larger than p_memsz
            elif mutation_type == 2:
                filesz_offset = ph_offset + 0x20
                memsz_offset = ph_offset + 0x28
                
                memsz = struct.unpack('<Q', data[memsz_offset:memsz_offset+8])[0]
                new_filesz = memsz + random.randint(1, 1000)
                data[filesz_offset:filesz_offset+8] = struct.pack('<Q', new_filesz)
            # modify segment offset
            elif mutation_type == 3:
                offset_offset = ph_offset + 0x08
                current_offset = struct.unpack('<Q', data[offset_offset:offset_offset+8])[0]
                new_offset = current_offset + random.choice([-1, 1, -8, 8, 0x100, -0x100])
                if new_offset < 0:
                    new_offset = 0
                data[offset_offset:offset_offset+8] = struct.pack('<Q', new_offset)
            
            # change segment type
            elif mutation_type == 4:
                type_offset = ph_offset
                new_type = random.choice([0, 1, 2, 3, 4, 5, 6, 7])
                data[type_offset:type_offset+4] = struct.pack('<I', new_type)
            
            # mutate virtual address
            elif mutation_type == 5:
                vaddr_offset = ph_offset + 0x10
                current_vaddr = struct.unpack('<Q', data[vaddr_offset:vaddr_offset+8])[0]
                # try various virtual address mutations
                mutation_choice = random.randint(0, 5)
                if mutation_choice == 0:  # unaligned address
                    new_vaddr = current_vaddr + random.choice([1, 3, 5, 7])
                elif mutation_choice == 1:  # very high address
                    new_vaddr = random.choice([0x7fffffffffff, 0xffffffffffffffff, 0x8000000000000000])
                elif mutation_choice == 2:  # very low address
                    new_vaddr = random.choice([0, 1, 2, 4, 8, 16])
                elif mutation_choice == 3:  # off-by-one from page boundary
                    new_vaddr = (current_vaddr & ~0xfff) + random.choice([0xfff, 0x1000, 0x1001, -1])
                elif mutation_choice == 4:  # random offset from current
                    new_vaddr = current_vaddr + random.choice([-0x1000, 0x1000, -0x100, 0x100, -1, 1])
                else:
                    new_vaddr = random.randint(0, 0xffffffffffffffff)
                
                if new_vaddr < 0:
                    new_vaddr = 0
                data[vaddr_offset:vaddr_offset+8] = struct.pack('<Q', new_vaddr)
            
            # mutate alignment requirements
            else:
                align_offset = ph_offset + 0x30
                # mutate with invalid or problematic alignments
                mutation_choice = random.randint(0, 5)
                if mutation_choice == 0:  # non-power-of-2 alignment
                    new_align = random.choice([3, 5, 6, 7, 9, 10, 100, 1000])
                elif mutation_choice == 1:  # very large alignment
                    new_align = random.choice([0x100000, 0x1000000, 0x10000000, 0x100000000])
                elif mutation_choice == 2:  # zero or one
                    new_align = random.choice([0, 1])
                elif mutation_choice == 3:  # common but possibly problematic
                    new_align = random.choice([2, 4, 8, 16, 32, 64, 128, 256, 512])
                elif mutation_choice == 4:  # maximum value
                    new_align = 0xffffffffffffffff
                else: # negative values (which will wrap around)
                    new_align = random.choice([0xfffffffffffffffe, 0xffffffffffffffff])
                
                data[align_offset:align_offset+8] = struct.pack('<Q', new_align)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_symbol_table(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            symbol_tables = []
            for section in self.elf_obj.iter_sections():
                if isinstance(section, SymbolTableSection):
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    entsize = section['sh_entsize']
                    
                    if sh_offset + sh_size > len(data):
                        continue
                    
                    num_symbols = sh_size // entsize if entsize > 0 else 0
                    if num_symbols == 0:
                        continue
                    
                    symbol_tables.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'entsize': entsize,
                        'num_symbols': num_symbols,
                        'name': section.name
                    })

            if not symbol_tables:
                return bytes(data)

            chosen_table = random.choice(symbol_tables)
            sym_idx = random.randint(0, chosen_table['num_symbols'] - 1)
            sym_offset = chosen_table['offset'] + (sym_idx * chosen_table['entsize'])
            
            mutation_type = random.randint(0, 3)
            
            # change symbol type/binding
            if mutation_type == 0:
                info_offset = sym_offset + 0x04
                current_info = data[info_offset]
                # change binding (bits 4-7) or type (bits 0-3)
                new_binding = random.choice([0, 1, 2, 10, 13]) << 4  # STB_*
                new_type = random.choice([0, 1, 2, 3, 4, 5, 6])      # STT_*
                data[info_offset] = new_binding | new_type
            
            # change symbol value
            elif mutation_type == 1:
                value_offset = sym_offset + 0x08
                current_value = struct.unpack('<Q', data[value_offset:value_offset+8])[0]
                new_value = current_value ^ random.randint(1, 0xFFFFFFFF)
                data[value_offset:value_offset+8] = struct.pack('<Q', new_value)
            
            # change symbol size
            elif mutation_type == 2:
                size_offset = sym_offset + 0x10
                new_size = random.choice([0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF])
                data[size_offset:size_offset+8] = struct.pack('<Q', new_size)
            
            else:
                data[sym_offset:sym_offset+chosen_table['entsize']] = random.randbytes(chosen_table['entsize'])
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_string_table(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            # First, collect all string tables
            string_tables = []
            for section in self.elf_obj.iter_sections():
                if section.name in ['.strtab', '.shstrtab', '.dynstr']:
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    
                    if sh_offset + sh_size > len(data):
                        continue
                    
                    if sh_size == 0:
                        continue
                    
                    string_tables.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'name': section.name
                    })

            if not string_tables:
                return bytes(data)
            
            chosen_table = random.choice(string_tables)
            sh_offset = chosen_table['offset']
            sh_size = chosen_table['size']
            
            mutation_type = random.randint(0, 3)
            
            # insert very long string
            if mutation_type == 0:
                insert_pos = sh_offset + random.randint(0, min(sh_size - 1, 100))
                long_string = b'A' * random.choice([100, 500, 1000, 5000]) + b'\x00'
                end_pos = min(insert_pos + len(long_string), sh_offset + sh_size)
                data[insert_pos:end_pos] = long_string[:end_pos - insert_pos]
            
            # remove null terminators
            elif mutation_type == 1:
                for i in range(sh_offset, min(sh_offset + sh_size, len(data))):
                    if data[i] == 0 and random.random() < 0.3:
                        data[i] = ord('X')
            
            # add weird characters
            elif mutation_type == 2:
                pos = sh_offset + random.randint(0, sh_size - 1)
                if pos < len(data):
                    data[pos] = random.choice([0xFF, 0x00, ord('%'), ord('$'), 0x7F])
            
            # corrupt part of string table
            else:
                corrupt_start = sh_offset + random.randint(0, sh_size // 2)
                corrupt_len = random.randint(1, min(100, sh_size // 4))
                corrupt_end = min(corrupt_start + corrupt_len, sh_offset + sh_size)
                data[corrupt_start:corrupt_end] = random.randbytes(corrupt_end - corrupt_start)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _insert_dummy_section(self, data):
        if not self.elf_obj:
            return data

        data = bytearray(data)

        try:
            e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
            e_shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
            e_shentsize = struct.unpack('<H', data[0x3a:0x3c])[0]
            e_shstrndx = struct.unpack('<H', data[0x3e:0x40])[0]

            if e_shoff == 0 or e_shnum == 0:
                return bytes(data)

            insert_idx = random.randint(0, e_shnum)
            
            dummy_sh = bytearray(e_shentsize)
            struct.pack_into('<I', dummy_sh, 0x00, 0)                               # sh_name (invalid index)
            struct.pack_into('<I', dummy_sh, 0x04, random.choice([1, 2, 3, 8]))     # sh_type (various types)
            struct.pack_into('<Q', dummy_sh, 0x08, random.choice([0x3, 0x6, 0x7]))  # sh_flags (various combos)
            struct.pack_into('<Q', dummy_sh, 0x10, 0)                               # sh_addr
            struct.pack_into('<Q', dummy_sh, 0x18, random.choice([0, len(data), len(data) + 0x1000]))   # sh_offset
            struct.pack_into('<Q', dummy_sh, 0x20, random.choice([0, 0x100, 0x1000, 0x10000]))          # sh_size
            struct.pack_into('<I', dummy_sh, 0x28, 0)                               # sh_link
            struct.pack_into('<I', dummy_sh, 0x2c, 0)                               # sh_info
            struct.pack_into('<Q', dummy_sh, 0x30, random.choice([1, 0x1000, 0x10000]))                 # sh_addralign
            struct.pack_into('<Q', dummy_sh, 0x38, 0)                               # sh_entsize

            insert_pos = e_shoff + (insert_idx * e_shentsize)
            data[insert_pos:insert_pos] = dummy_sh

            data[0x3c:0x3e] = struct.pack('<H', e_shnum + 1)
            
            # If we inserted before or at e_shstrndx we need to increment e_shstrndx
            # because all section indices after insertion point are now shifted by 1
            if insert_idx <= e_shstrndx and e_shstrndx != 0xFFFF:  # SHN_UNDEF check
                new_shstrndx = e_shstrndx + 1
                data[0x3e:0x40] = struct.pack('<H', new_shstrndx)

        except Exception:
            pass

        return bytes(data)

    def _corrupt_magic_bytes(self, data):
        data = bytearray(data)
        data[0:4] = random.choice([
            b'\x7fELF',
            b'\x7fELE',  # last byte off
            b'\x00ELF',  # wrong magic
            b'ELF\x7f',  # reversed
            b'\xFF\xFF\xFF\xFF',
            b'\x00\x00\x00\x00',
        ])
        return bytes(data)
    
    def _mutate_section_contents(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            # PROGBITS sections with ALLOC flag (loadable sections)
            candidates = []
            for section in self.elf_obj.iter_sections():
                if section['sh_type'] == 'SHT_PROGBITS' and (section['sh_flags'] & 0x2):
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    
                    if sh_offset + sh_size <= len(data) and sh_size > 0:
                        candidates.append({
                            'offset': sh_offset,
                            'size': sh_size,
                            'name': section.name
                        })
            
            if not candidates:
                return bytes(data)
            
            # random mutations
            chosen = random.choice(candidates)
            off = chosen['offset']
            size = chosen['size']
            
            start = off + random.randint(0, max(0, size - 1))
            length = random.randint(1, min(64, size - (start - off)))
            
            for i in range(start, min(start + length, off + size)):
                data[i] ^= random.randint(1, 255)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_relocations(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            # relocation sections
            reloc_sections = []
            for section in self.elf_obj.iter_sections():
                if section['sh_type'] in ['SHT_REL', 'SHT_RELA']:
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    sh_entsize = section['sh_entsize']
                    
                    if sh_offset + sh_size > len(data) or sh_entsize == 0:
                        continue
                    
                    num_entries = sh_size // sh_entsize
                    if num_entries == 0:
                        continue
                    
                    reloc_sections.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'entsize': sh_entsize,
                        'num_entries': num_entries,
                        'type': section['sh_type'],
                        'name': section.name
                    })
            
            if not reloc_sections:
                return bytes(data)
            
            # random mutations
            chosen = random.choice(reloc_sections)
            entry_idx = random.randint(0, chosen['num_entries'] - 1)
            entry_offset = chosen['offset'] + (entry_idx * chosen['entsize'])
            
            mutation_type = random.randint(0, 2)
            
            if mutation_type == 0:
                r_offset_pos = entry_offset + 0x00
                current = struct.unpack('<Q', data[r_offset_pos:r_offset_pos+8])[0]
                new_offset = current + random.choice([-1, 1, -8, 8, 0x100, -0x100, 0x1000])
                if new_offset < 0:
                    new_offset = 0
                data[r_offset_pos:r_offset_pos+8] = struct.pack('<Q', new_offset)
            
            # mutate symbol index and relocation type
            elif mutation_type == 1:
                r_info_pos = entry_offset + 0x08
                current = struct.unpack('<Q', data[r_info_pos:r_info_pos+8])[0]
                # Flip some bits
                new_info = current ^ random.choice([1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0x100000000])
                data[r_info_pos:r_info_pos+8] = struct.pack('<Q', new_info)
            
            # mutate r_addend (only for RELA entries)
            else:
                if chosen['type'] == 'SHT_RELA' and chosen['entsize'] >= 24:
                    r_addend_pos = entry_offset + 0x10
                    if r_addend_pos + 8 <= len(data):
                        current = struct.unpack('<q', data[r_addend_pos:r_addend_pos+8])[0]  # signed
                        new_addend = current + random.choice([-1, 1, -8, 8, -100, 100, -0x1000, 0x1000])
                        data[r_addend_pos:r_addend_pos+8] = struct.pack('<q', new_addend)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_dynamic_section(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            dynamic_sections = []
            for section in self.elf_obj.iter_sections():
                if section['sh_type'] == 'SHT_DYNAMIC':
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    sh_entsize = section['sh_entsize']
                    
                    if sh_offset + sh_size > len(data) or sh_entsize == 0:
                        continue
                    
                    num_entries = sh_size // sh_entsize
                    if num_entries == 0:
                        continue
                    
                    dynamic_sections.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'entsize': sh_entsize,
                        'num_entries': num_entries,
                        'name': section.name
                    })
            
            if not dynamic_sections:
                return bytes(data)
            
            # usually only one dynamic section
            chosen = dynamic_sections[0]

            entry_idx = random.randint(0, chosen['num_entries'] - 1)
            entry_offset = chosen['offset'] + (entry_idx * chosen['entsize'])
            
            mutation_type = random.randint(0, 2)
            
            # mutate type of dynamic entry
            if mutation_type == 0:
                d_tag_pos = entry_offset
                # common DT_* tags: DT_NULL(0), DT_NEEDED(1), DT_STRTAB(5), DT_SYMTAB(6), etc.
                new_tag = random.choice([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                    0x6ffffef5,  # DT_GNU_HASH
                    0x6ffffffe,  # DT_VERNEED
                    0x6fffffff,  # DT_VERNEEDNUM
                    0xffffffff,  # Invalid tag
                    random.randint(0, 0xffffffffffffffff)
                ])
                data[d_tag_pos:d_tag_pos+8] = struct.pack('<Q', new_tag)
            
            # mutate value/pointer/address
            elif mutation_type == 1:
                d_un_pos = entry_offset + 8
                current = struct.unpack('<Q', data[d_un_pos:d_un_pos+8])[0]
                new_val = current + random.choice([-1, 1, -8, 8, 0x100, -0x100, 0x1000, -0x1000])
                if new_val < 0:
                    new_val = 0
                data[d_un_pos:d_un_pos+8] = struct.pack('<Q', new_val)
            
            else:
                data[entry_offset:entry_offset+chosen['entsize']] = random.randbytes(chosen['entsize'])
        
        except Exception:
            pass
        
        return bytes(data)
    
    def generate(self):
        yield b""
        yield b"\x7fELF"                    # just magic bytes
        yield b"\x7fELF" + b"\x00" * 100    # magic + padding
        yield self.example_input[:4]        # just header start
        yield self.example_input[:64]       # just ELF header

        for size in [1, 2, 4, 8, 16, 32, 63, 64, 100, 200]:
            if len(self.example_input) > size:
                yield self.example_input[:size]
        
        
        # corrupted magic bytes
        for _ in range(6):
            yield self._corrupt_magic_bytes(self.example_input)
        
        # append/prepend garbage
        for size in [100, 1000, 10000, 100000]:
            yield self.example_input + random.randbytes(size)
        
        for size in [100, 1000, 10000]:
            yield random.randbytes(size) + self.example_input
        
        
        # insert dummy sections
        for _ in range(10):
            yield self._insert_dummy_section(self.example_input)
        
        # random large files with ELF magic
        for _ in range(5):
            size = random.choice([1000, 5000, 10000, 50000])
            random_data = bytearray(random.randbytes(size))
            random_data[0:4] = b'\x7fELF'
            yield bytes(random_data)
        
        # ELF header mutations
        for _ in range(40):
            yield self._mutate_elf_header(self.example_input)
        
        # program header mutations
        for _ in range(30):
            yield self._mutate_program_headers(self.example_input)
        
        # symbol table mutations
        for _ in range(30):
            yield self._mutate_symbol_table(self.example_input)

        # section header mutations
        for _ in range(60):
            yield self._mutate_section_headers(self.example_input)
        
        # string table mutations
        for _ in range(40):
            yield self._mutate_string_table(self.example_input)
        
        # section contents mutations
        for _ in range(30):
            yield self._mutate_section_contents(self.example_input)
        
        # relocation table mutations
        for _ in range(25):
            yield self._mutate_relocations(self.example_input)
        
        # dynamic section mutations
        for _ in range(20):
            yield self._mutate_dynamic_section(self.example_input)

        # combined mutations
        for _ in range(100):
            mutated = self.example_input
            num_mutations = random.randint(2, 4)
            
            for _ in range(num_mutations):
                mutation_func = random.choice([
                    self._mutate_elf_header,
                    self._mutate_section_headers,
                    self._mutate_program_headers,
                    self._mutate_symbol_table,
                    self._mutate_string_table,
                    self._mutate_section_contents,
                    self._mutate_relocations,
                    self._mutate_dynamic_section,
                ])
                mutated = mutation_func(mutated)
            
            yield mutated

        while True:
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
