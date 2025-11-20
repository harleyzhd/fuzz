from .base_fuzzer import BaseFuzzer
import random
import copy
import re
import os
import xml.etree.ElementTree as ET


class XmlFuzzer(BaseFuzzer):
    #I cannot get any of these binaries to crash, i've spent like 15 hours on this and nothing is working
    def __init__(self, example_input):
        super().__init__(example_input)

        # Store raw seed bytes without losing invalid UTF-8
        if isinstance(example_input, (bytes, bytearray)):
            self._seed_bytes = bytes(example_input)
        else:
            self._seed_bytes = example_input.encode("utf-8", errors="surrogateescape")

        # Parse XML only if valid UTF-8
        try:
            self._xml = ET.fromstring(self._seed_bytes.decode("utf-8"))
        except Exception:
            self._xml = None

    # Basic byte-level mutators
    def byteflip(self, xml_bytes, flip_prob=0.05):
        b = bytearray(xml_bytes)
        for i in range(len(b)):
            if random.random() < flip_prob:
                b[i] ^= random.getrandbits(8)
        return bytes(b)

    def inject_invalid_utf8(self, xml_bytes, count=10):
        b = bytearray(xml_bytes)
        for _ in range(count):
            pos = random.randint(0, len(b) - 1 if len(b) else 0)
            b.insert(pos, random.choice([0xC0, 0xC1, 0xF5, 0xFF]))
        return bytes(b)

    # XML structural mutations
    def mutate_tag_names(self, xml_bytes, max_len=50):
        s = xml_bytes.decode("latin-1")

        def repl(m):
            slash = m.group("slash") or ""
            nlen = random.randint(1, max_len)
            newname = "".join(
                random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:")
                for _ in range(nlen)
            )
            return f"<{slash}{newname}"

        s = re.sub(
            r"<(?P<slash>/?)(?P<name>[A-Za-z_:][A-Za-z0-9_.:-]*)", repl, s
        )
        return s.encode("latin-1")

    def mutate_attributes(self, xml_bytes, add_long_attrs=True):
        s = xml_bytes.decode("latin-1")

        # Expand existing attributes
        s = re.sub(
            r'(?P<name>[A-Za-z_:][A-Za-z0-9_.:-]*)=("|\')(?P<val>.*?)(\2)',
            lambda m: f'{m.group("name")}={m.group(2)}{m.group("val")}' +
            ("A" * random.randint(200, 2000)) +
            f'{m.group(2)}',
            s
        )

        # Add massive attribute lists
        if add_long_attrs:
            def add_attrs(m):
                extras = " ".join(
                    f'attr{i}="{ "A"*random.randint(200,2000) }"'
                    for i in range(random.randint(0, 20))
                )
                return m.group(0) + " " + extras

            s = re.sub(
                r"<([A-Za-z_:][A-Za-z0-9_.:-]*)(\s|>)",
                add_attrs,
                s,
                count=1
            )

        return s.encode("latin-1")

    # Deep structural expansions
    def generate_deep_nesting(self, depth=1000):
        depth = min(depth, 20000)
        xml = []
        for i in range(depth):
            xml.append(f"<a{i}>")
        xml.append("X")
        for i in reversed(range(depth)):
            xml.append(f"</a{i}>")
        return "".join(xml).encode("utf-8")

    def generate_entity_bomb(self):
        xml = """<!DOCTYPE lolz [
<!ENTITY a "AAAAAAAAAA">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
]>"""
        xml += "<root>&e;</root>"
        return xml.encode("utf-8")

    def generate_external_entity(self, uri="file:///etc/passwd"):
        xml = f"""<!DOCTYPE root [
<!ENTITY ext SYSTEM "{uri}">
]>
<root>&ext;</root>"""
        return xml.encode("utf-8")

    def random_long_tag(self, length=10000):
        return (
            "<" + ("T" * length) + ">X</" + ("T" * length) + ">"
        ).encode("utf-8")

    # CDATA, comments, headers
    def inject_cdata(self, xml_bytes):
        s = xml_bytes.decode("latin-1")
        cdata = "<![CDATA[" + ("A" * random.randint(50, 200)) + "]]>"
        pos = random.randint(0, len(s))
        return (s[:pos] + cdata + s[pos:]).encode("latin-1")

    def inject_comments(self, xml_bytes):
        s = xml_bytes.decode("latin-1")
        comment = "<!-- " + ("X" * random.randint(50, 200)) + " -->"
        pos = random.randint(0, len(s))
        return (s[:pos] + comment + s[pos:]).encode("latin-1")

    def mangled_xml_header(self, xml_bytes):
        headers = [
            '<?xml version="1.0" encoding="????">',
            '<?xml version="9.9" encoding="UTF-16">',
            '<?xml version="1.0" encoding="UTF-8" standalone="maybe">',
            '<?xml\x00version="1.0">',
        ]
        return random.choice(headers).encode() + xml_bytes

    # Mismatches, illegal entities
    def generate_mismatched_tags(self, xml_bytes):
        s = xml_bytes.decode("latin-1")
        s = re.sub(r"</(\w+)>", r"<\1>", s)
        return s.encode("latin-1")

    def inject_illegal_entities(self, xml_bytes):
        s = xml_bytes.decode("latin-1")
        illegal = ["&lt", "&gt", "&amp", "&", "<![CDATA[", "<!--", "<!ENTITY"]
        endings = [">", ";", "\"", "'"]
        for ent in illegal:
            s = s.replace(ent, f"{ent}{random.choice(endings)}")
        return s.encode("latin-1")

    def generate(self):
        # Base seed
        if self._xml is not None:
            seed = ET.tostring(self._xml, encoding="utf-8")
        else:
            seed = self._seed_bytes or b"<root>seed</root>"

        # Basic inputs
        yield b"" + b"\x00" 
        yield b"<" * 10000 + b"\x00" 

        while True:
            r = random.random()

            if r < 0.10:
                yield self.byteflip(seed) + b"\x00" 

            elif r < 0.20:
                yield self.inject_invalid_utf8(seed) + b"\x00" 

            elif r < 0.30:
                yield self.mutate_tag_names(seed) + b"\x00" 

            elif r < 0.40:
                yield self.mutate_attributes(seed) + b"\x00" 

            elif r < 0.45:
                yield self.generate_deep_nesting(random.randint(50, 5000)) + b"\x00" 

            elif r < 0.50:
                yield self.generate_entity_bomb() + b"\x00" 

            elif r < 0.55:
                yield self.generate_external_entity() + b"\x00" 

            elif r < 0.60:
                yield self.inject_cdata(seed) + b"\x00" 

            elif r < 0.65:
                yield self.inject_comments(seed) + b"\x00" 

            elif r < 0.70:
                yield self.mangled_xml_header(seed) + b"\x00" 

            elif r < 0.75:
                yield self.generate_mismatched_tags(seed) + b"\x00" 

            elif r < 0.80:
                yield self.inject_illegal_entities(seed) + b"\x00" 

            elif r < 0.85:
                yield self.random_long_tag(random.choice([512, 2048, 65536])) + b"\x00" 

            else:
                # Mutation chain for more chaos
                b = seed
                funcs = [
                    self.byteflip,
                    self.inject_invalid_utf8,
                    self.mutate_tag_names,
                    self.mutate_attributes,
                    self.inject_cdata,
                    self.inject_comments,
                ]
                for _ in range(random.randint(2, 5)):
                    b = random.choice(funcs)(b)
                yield b + b"\x00" 
