import random
import re
import string

from .base_fuzzer import BaseFuzzer


class PdfFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        try:
            self.text = example_input.decode("latin-1", errors="ignore")
        except Exception:
            self.text = ""

        self.objects = self._collect_objects()
        self.streams = self._collect_streams()
        self.startxref = self._find_startxref()
        self.version = self._find_version()

    def _collect_objects(self):
        pattern = re.compile(r"(\d+\s+\d+\s+obj)(.*?endobj)", re.S)
        return pattern.findall(self.text)

    def _collect_streams(self):
        pattern = re.compile(r"stream(.*?)endstream", re.S)
        return pattern.findall(self.text)

    def _find_startxref(self):
        match = re.search(r"startxref\s+(\d+)", self.text)
        if match:
            return int(match.group(1))
        return None

    def _find_version(self):
        match = re.search(r"%PDF-(\d\.\d)", self.text)
        if match:
            return match.group(1)
        return "1.3"

    # Helpers -----------------------------------------------------------------

    def _encode(self, text):
        if isinstance(text, bytes):
            return text
        return text.encode("latin-1", errors="ignore")

    def _random_ascii(self, length):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.choice(alphabet) for _ in range(length))

    # Deterministic seeds -----------------------------------------------------

    def _seed_linearized(self):
        prefix = f"%PDF-1.{random.randint(0,7)}\n"
        lin = "1 0 obj\n<< /Linearized 1 /O 1 /E 999999 /N 1 >>\nendobj\n"
        return self._encode(prefix + lin + self.text)

    def _seed_duplicate_xref(self):
        payload = self.text + "\nxref\n0 1\n0000000000 65535 f\ntrailer\n<< /Size 1 >>\nstartxref\n0\n%%EOF\n"
        return self._encode(payload)

    def _seed_javascript(self):
        js = random.choice([
            "app.alert('fuzz');",
            "this.getURL('file:///etc/passwd');",
            "util.printf('%s', 'AAAAAAA');"
        ])
        payload = "1 0 obj\n<< /OpenAction << /S /JavaScript /JS ({}) >> >>\nendobj\n".format(js)
        return self._encode(payload + self.text)
    
    def _seed_title_format(self):
        if "/Title" not in self.text:
            return self.example_input
        mutated = re.sub(r"/Title\s*\(.*?\)", "/Title (%p%p%p%n)", self.text, count=1)
        return self._encode(mutated)

    # Mutation strategies -----------------------------------------------------

    def _mutate_lengths(self):
        text = self.text
        for match in re.finditer(r"/Length\s+(\d+)", text):
            value = match.group(1)
            fuzzed = random.choice([
                "0",
                str(random.randint(1, 32)),
                str(random.randint(1000, 200000)),
                str(2 ** 31 - 1),
            ])
            text = text.replace(f"/Length {value}", f"/Length {fuzzed}", 1)
        return self._encode(text)

    def _mutate_stream_bytes(self):
        if not self.streams:
            return self.example_input
        choice = random.choice(self.streams)
        data = bytearray(choice.encode("latin-1", errors="ignore"))
        for _ in range(min(len(data), random.randint(4, 64))):
            idx = random.randrange(len(data))
            data[idx] ^= random.randint(1, 255)
        mutated = self.text.replace("stream" + choice + "endstream",
                                    "stream" + data.decode("latin-1", errors="ignore") + "endstream", 1)
        return self._encode(mutated)

    def _mutate_xref(self):
        if "xref" not in self.text:
            return self.example_input
        mutated = re.sub(r"startxref\s+\d+", f"startxref {random.randint(0, 128)}", self.text)
        mutated = mutated.replace("xref", "xref\n9999999999 00000 n", 1)
        return self._encode(mutated)

    def _mutate_trailer(self):
        trailer = re.search(r"trailer\s*<<(.*?)>>", self.text, re.S)
        if not trailer:
            return self.example_input
        body = trailer.group(1)
        tweaks = [
            "/Prev 0",
            "/Size 0",
            "/Encrypt << /R 5 /V 5 /Length 256 >>",
            "/Info 999 0 R",
        ]
        for tweak in tweaks:
            if random.random() < 0.5:
                body += f"\n{tweak}"
        mutated = self.text.replace(trailer.group(0), f"trailer\n<<{body}>>", 1)
        return self._encode(mutated)

    def _inject_fake_object(self):
        obj_id = random.randint(20, 500)
        payload = f"""{obj_id} 0 obj
<< /Type /Annot /Subtype /Widget /Rect [0 0 200 200]
   /AA << /E << /S /JavaScript /JS (app.alert('FUZZ');) >> >> >>
endobj
"""
        pos = random.randint(0, len(self.text))
        mutated = self.text[:pos] + payload + self.text[pos:]
        return self._encode(mutated)

    def _append_incremental_update(self):
        base = self.text
        new_obj_id = random.randint(100, 200)
        new_obj = f"{new_obj_id} 0 obj\n<< /Length 4 >>\nstream\nXOXO\nendstream\nendobj\n"
        update = f"""
xref
{new_obj_id} 1
0000000001 00000 n
trailer
<< /Size {new_obj_id+1} /Prev {self.startxref or 0} >>
startxref
0
%%EOF
"""
        return self._encode(base + "\n" + new_obj + update)

    def _filter_mutation(self):
        patterns = [
            "/Filter /FlateDecode",
            "/Filter [/FlateDecode /ASCIIHexDecode]",
            "/Filter [/LZWDecode /RunLengthDecode]"
        ]
        replacement = random.choice(patterns)
        mutated = re.sub(r"/Filter\s+\S+", replacement, self.text)
        if random.random() < 0.5:
            mutated = mutated.replace("/DecodeParms", "/DecodeParms << /Columns 0 /Predictor 15 >>", 1)
        return self._encode(mutated)

    def _rotate_objects(self):
        if not self.objects:
            return self.example_input
        objs = [f"{hdr}{body}" for hdr, body in self.objects]
        random.shuffle(objs)
        return self._encode("\n".join(objs) + "\n%%EOF")

    def _header_mutation(self):
        prefix = f"%PDF-{random.randint(0,9)}.{random.randint(0,9)}\n"
        garbage = "".join("%" + self._random_ascii(20) for _ in range(random.randint(1, 5)))
        return self._encode(prefix + garbage + "\n" + self.text)

    # Generator ---------------------------------------------------------------

    def generate(self):
        """Generate mutated PDF inputs."""
        yield b""
        yield self.example_input
        yield self._seed_linearized()
        yield self._seed_duplicate_xref()
        yield self._seed_javascript()
        yield self._seed_title_format()

        strategies = [
            self._mutate_lengths,
            self._mutate_stream_bytes,
            self._mutate_xref,
            self._mutate_trailer,
            self._inject_fake_object,
            self._append_incremental_update,
            self._filter_mutation,
            self._rotate_objects,
            self._header_mutation,
            lambda: self.mutate_bytes(self.example_input),
        ]

        while True:
            strategy = random.choice(strategies)
            try:
                yield strategy()
            except Exception:
                yield self.mutate_bytes(self.example_input)
