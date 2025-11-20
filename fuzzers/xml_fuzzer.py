import random
import re
from .base_fuzzer import BaseFuzzer


class XmlFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        self.depth_targets = [128, 256, 512, 1024, 2048, 4096]

    def _deep_nesting(self, depth):
        open_tags = b"".join([f"<d{i}>".encode() for i in range(depth)])
        close_tags = b"".join([f"</d{i}>".encode() for i in reversed(range(depth))])
        return open_tags + close_tags

    def _entity_bomb(self, repeat):
        entity = b"<!DOCTYPE lolz [<!ENTITY lol \""
        entity += b"a" * repeat
        entity += b"\">]><root>&lol;</root>"
        return entity

    def _format_bomb(self, repetitions):
        fmt = b"%p%s%n%x%d"
        return b"<fmt>" + fmt * repetitions + b"</fmt>"

    def _attribute_bomb(self, count, attr_len):
        attrs = b" ".join([f"a{i}=\"{'A' * attr_len}\"".encode() for i in range(count)])
        return b"<tag " + attrs + b">value</tag>"

    def _format_attr_bomb(self, repetitions, attr_name="href"):
        fmt = b"%s%s%s%n"
        return b"<elem " + attr_name.encode() + b"=\"" + (fmt * repetitions) + b"\">"

    def _format_href_bomb(self, repetitions):
        chunk = b"%s%s%s%n"
        return b"<a href=\"" + chunk * repetitions + b"\"></a>"

    def _link_stress(self, count):
        return b"<html>" + (b'<a href="x">y</a>' * count) + b"</html>"

    def generate(self):
        yield b""
        yield self.example_input

        # Structured seeds based on generic XML stress patterns
        seed_payloads = []
        numeric_attrs = ("count", "repeat", "size", "length")
        for val in (8, 16, 24, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384):
            for attr in numeric_attrs:
                seed_payloads.append(f"<stress {attr}=\"{val}\"></stress>".encode())
                seed_payloads.append(f"<stress><node {attr}=\"{val}\"/></stress>".encode())
                seed_payloads.append(f"<items {attr}=\"{val}\"><item>{'A'*8}</item></items>".encode())
        seed_payloads.append(b'<attrs><entry payload="' + b'A' * 600 + b'"/></attrs>')
        seed_payloads.append(b'<attrs><entry data="' + b'B' * 1200 + b'"/></attrs>')
        for depth in (128, 256, 512, 1024, 2048):
            seed_payloads.append(self._deep_nesting(depth))
        for repeat in (256, 512, 1024):
            seed_payloads.append(self._format_bomb(repeat))
            seed_payloads.append(self._format_attr_bomb(repeat // 8 + 1, "href"))
            seed_payloads.append(self._format_attr_bomb(repeat // 8 + 1, "src"))
            seed_payloads.append(self._format_href_bomb(repeat // 16 + 4))
        for count in (128, 256, 512):
            seed_payloads.append(self._link_stress(count))
        for attr_count in (200, 400, 800, 1200):
            seed_payloads.append(self._attribute_bomb(attr_count, 64))
            seed_payloads.append(self._attribute_bomb(attr_count, 256))
            seed_payloads.append(self._attribute_bomb(attr_count, 512))
            seed_payloads.append(self._attribute_bomb(attr_count, 1024))
        for repeat in (1000, 5000, 20000):
            seed_payloads.append(b"<![CDATA[" + b"A" * repeat + b"]]>")
            seed_payloads.append(self._entity_bomb(repeat))
        seed_payloads.append(
            b"<overflow " + b" ".join([f'a{i}=\"VALUE{i}\"'.encode() for i in range(1500)]) + b">X</overflow>"
        )
        seed_payloads.append(
            b"<fmt>" + b"%p%s%d%x" * 1500 + b"</fmt>"
        )

        for payload in seed_payloads:
            yield payload

        # Oversized tags / attributes
        yield b"<" + b"a>" * 20000
        yield b"<" + b"A" * 20000 + b">"
        yield b"<tag " + b"x" * 50000 + b"=\"y\">"
        yield b"<tag attr=\"" + b"c" * 50000 + b"\">"
        yield b"<data>" + b"X" * 200000 + b"</data>"
        yield b"<empty/>" * 20000
        yield b"<!--" + b"A" * 50000 + b"-->"
        yield b"<![CDATA[" + b"A" * 200000 + b"]]>"

        # Format-string style payloads
        fmt = b"%p%p%p%p%p%p%p%p%n"
        yield fmt
        yield b"<a>" + fmt * 1000 + b"</a>"
        yield b"<a attr=\"" + fmt * 1000 + b"\">"

        # Deep nesting
        for depth in self.depth_targets:
            yield self._deep_nesting(depth)

        try:
            text = self.example_input.decode('utf-8', errors='ignore')
            tags = re.findall(r'<(\w+)', text)
            if tags:
                for _ in range(20):
                    tag = random.choice(tags)
                    fuzzed = text.replace(f"<{tag}", f"<{tag}{'A' * random.randint(100, 5000)}")
                    yield fuzzed.encode('utf-8', errors='ignore')
        except:
            pass

        specials = [
            b"\x00" * 1000,
            b"\xff" * 1000,
            b"\x0a" * 1000,
            b"\x0d" * 1000,
            b"&" * 1000,
            b"<" * 1000,
            b">" * 1000,
        ]
        for s in specials:
            yield b"<a>" + s + b"</a>"
            yield b"<a b=\"" + s + b"\">"

        entities = [
            self._entity_bomb(1000),
            self._entity_bomb(10000),
            self._entity_bomb(50000),
            b"<!DOCTYPE a [<!ENTITY x \"&x;\">]><a>&x;</a>",
            b"<!ENTITY % p \"" + b"A" * 50000 + b"\">",
        ]
        for e in entities:
            yield e
        yield self._format_bomb(1000)
        yield self._format_bomb(5000)

        while True:
            mutation = random.randint(0, 9)

            if mutation == 0:
                yield self.mutate_bytes(self.example_input)
            elif mutation == 1:
                depth = random.randint(100, 2000)
                yield self._deep_nesting(depth)
            elif mutation == 2:
                size = random.randint(10, 2000)
                yield b"<" + bytes([random.randint(0, 255) for _ in range(size)]) + b">"
            elif mutation == 3:
                try:
                    text = self.example_input.decode('utf-8', errors='ignore')
                    pos = random.randint(0, len(text) - 1)
                    insert = random.choice(["<", ">", "&", '"', "'", "\x00"]) * random.randint(1, 1000)
                    text = text[:pos] + insert + text[pos:]
                    yield text.encode('utf-8', errors='ignore')
                except:
                    yield self.mutate_bytes(self.example_input)
            elif mutation == 4:
                yield b"<a>" + bytes([random.randint(0, 255) for _ in range(random.randint(100, 50000))]) + b"</a>"
            elif mutation == 5:
                attrs = b" ".join([f"a{i}=\"{'A' * random.randint(1, 1000)}\"".encode() for i in range(random.randint(100, 1000))])
                yield b"<x " + attrs + b"/>"
            elif mutation == 6:
                yield b"<a b=\"" + bytes([random.randint(32, 126) for _ in range(random.randint(100, 20000))]) + b"\">"
            elif mutation == 7:
                fmt = random.choice([b"%s", b"%n", b"%x", b"%p", b"%d"])
                yield b"<a>" + fmt * random.randint(100, 1000) + b"</a>"
            elif mutation == 8:
                data = bytearray(self.example_input)
                for _ in range(random.randint(5, 50)):
                    pos = random.randint(0, len(data) - 1)
                    data[pos] = random.randint(0, 255)
                yield bytes(data)
            else:
                size = random.randint(1000, 50000)
                yield b"<a>" + b"B" * size + b"</a>"
