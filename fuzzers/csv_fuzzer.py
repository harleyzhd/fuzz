import random
import copy
from .base_fuzzer import BaseFuzzer


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
            return ["a", "b", "c"]
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
        if not data or not data[0]:
            return data
        data = copy.deepcopy(data)

        pool = ["!", "@", "#", "$", "%", "^", "&", "*", "?", ";", "|", "+", "-", "="]

        row_mutators = [
            lambda row: row + [random.choice(pool)],          # add one field
            lambda row: (row[::-1] if len(row) > 1 else row), # reverse row
            lambda row: (row[:-1] if len(row) > 1 else row),  # drop last field
            lambda row: (row[1:] if len(row) > 1 else row),   # drop first field
            lambda row: [],                                   # empty row
            lambda row: row * random.randint(50, 150),        # repeat row many times (reduced)
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

    def _append_growing_last_field(self, template_line, steps=8):
        # keep this but make it lighter
        parts = template_line.split(",")
        if len(parts) == 0:
            parts = ["A"]
        if len(parts) == 1:
            parts.append("A")
        lines = []
        for i in range(steps):
            p = parts[:]
            p[-1] = "A" * max(1, i * 15)
            lines.append(",".join(p))
        block = "\n".join(lines) + "\n"
        return self._append_after_seed_text(block)

    # Targeted overflow for first/last line
    def _overflow_variants_from_seed(self, lines, target_len=200, repeat_lines=500):
    
        payloads = []
        non_empty = [ln for ln in lines if ln.strip()]
        if not non_empty:
            return payloads

        header = non_empty[0]
        candidates = [non_empty[0]]
        if len(non_empty) > 1:
            candidates.append(non_empty[-1])

        def grow_to(s, n):
            s = s or "A"
            out = s
            while len(out) < n:
                out += s
            return out[:n]

        for line in candidates:
            fields = line.split(",")
            if not fields:
                continue

            # each field added individually
            for idx in range(len(fields)):
                grown_fields = fields[:]
                grown_fields[idx] = grow_to(grown_fields[idx], target_len)
                mutated_line = ",".join(grown_fields)

                # multi-line form
                block = "\n".join([mutated_line for _ in range(repeat_lines)]) + "\n"
                payloads.append(self._append_after_seed_text(block))

                # single-line concatenated
                concat_line = "".join([mutated_line for _ in range(repeat_lines)]) + "\n"
                payload_text = header + "\n" + concat_line
                payloads.append(payload_text.encode('utf-8', errors='ignore'))

            # all fields grown at once
            all_grown = [grow_to(f, target_len) for f in fields]
            big_line = ",".join(all_grown)

            block_all = "\n".join([big_line for _ in range(repeat_lines)]) + "\n"
            payloads.append(self._append_after_seed_text(block_all))

            concat_all = "".join([big_line for _ in range(repeat_lines)]) + "\n"
            payload_text2 = header + "\n" + concat_all
            payloads.append(payload_text2.encode('utf-8', errors='ignore'))

        return payloads

    def _zero_blocks(self, seed_lines):
        payloads = []

        # Single-line rows: 0, 0,0, 0,0,0, ..., up to 5 fields
        for cols in range(1, 6):
            row = ",".join(["0"] * cols) + "\n"
            payloads.append(row.encode("utf-8", errors="ignore"))

        # Square zero blocks: 1x1 up to 5x5
        for size in range(1, 6):
            row = ",".join(["0"] * size)
            block = "\n".join([row for _ in range(size)]) + "\n"
            payloads.append(block.encode("utf-8", errors="ignore"))

        return payloads

    def _format_string_payloads(self, seed_lines):
        payloads = []
        formats = ["%s", "%n", "%x", "%p", "%d"]

        for fmt in formats:
            # 1-field
            payloads.append(f"{fmt}\n".encode("utf-8"))
            # 2-field
            payloads.append(f"{fmt},0\n".encode("utf-8"))
            payloads.append(f"0,{fmt}\n".encode("utf-8"))
            # 3-field
            payloads.append(f"{fmt},0,0\n".encode("utf-8"))
            payloads.append(f"0,{fmt},0\n".encode("utf-8"))
            payloads.append(f"0,0,{fmt}\n".encode("utf-8"))
            # 4-field
            payloads.append(f"{fmt},0,0,0\n".encode("utf-8"))
            payloads.append(f"0,{fmt},0,0\n".encode("utf-8"))
            payloads.append(f"0,0,{fmt},0\n".encode("utf-8"))
            payloads.append(f"0,0,0,{fmt}\n".encode("utf-8"))

        # couple rows with format strings
        for fmt in ["%s", "%n"]:
            block = "\n".join([f"{fmt},0,0,0" for _ in range(3)]) + "\n"
            payloads.append(block.encode("utf-8"))

        return payloads


    def _null_and_control_payloads(self, seed_lines):
        payloads = []
        # Null bytes
        payloads += [
            b"\x00\n",
            b"\x00,0\n", b"0,\x00\n",
            b"\x00,0,0\n", b"0,\x00,0\n", b"0,0,\x00\n",
            b"\x00,0,0,0\n", b"0,\x00,0,0\n", b"0,0,\x00,0\n", b"0,0,0,\x00\n",
        ]

        # Control characters
        for ctrl in ["\x01", "\x02", "\x03", "\x04", "\x08", "\x7f"]:
            payloads.append(f"{ctrl}\n".encode("utf-8"))
            payloads.append(f"{ctrl},0\n".encode("utf-8"))
            payloads.append(f"0,{ctrl}\n".encode("utf-8"))
            payloads.append(f"{ctrl},0,0\n".encode("utf-8"))
            payloads.append(f"0,{ctrl},0\n".encode("utf-8"))
            payloads.append(f"0,0,{ctrl}\n".encode("utf-8"))
            payloads.append(f"{ctrl},0,0,0\n".encode("utf-8"))
            payloads.append(f"0,{ctrl},0,0\n".encode("utf-8"))
            payloads.append(f"0,0,{ctrl},0\n".encode("utf-8"))
            payloads.append(f"0,0,0,{ctrl}\n".encode("utf-8"))

        # Escaped sequences
        payloads += [
            b"\\n,0\n", b"\\r,0\n", b"\\t,0\n", b"0,\\n,0\n",
            b"\\n,0,0\n", b"0,\\r,0,0\n", b"0,0,\\t,0\n"
        ]
        return payloads


    def _extreme_numeric_payloads(self, seed_lines):
        payloads = []
        extremes = [
            "2147483647", "-2147483648",
            "9223372036854775807", "-9223372036854775808",
            "18446744073709551615", "999999999999999999999",
        ]

        for val in extremes:
            # 1-field
            payloads.append(f"{val}\n".encode("utf-8"))
            # 2-field
            payloads.append(f"{val},0\n".encode("utf-8"))
            payloads.append(f"0,{val}\n".encode("utf-8"))
            # 3-field
            payloads.append(f"{val},0,0\n".encode("utf-8"))
            payloads.append(f"0,{val},0\n".encode("utf-8"))
            payloads.append(f"0,0,{val}\n".encode("utf-8"))
            # 4-field
            payloads.append(f"{val},0,0,0\n".encode("utf-8"))
            payloads.append(f"0,{val},0,0\n".encode("utf-8"))
            payloads.append(f"0,0,{val},0\n".encode("utf-8"))
            payloads.append(f"0,0,0,{val}\n".encode("utf-8"))

        # Multi-column extremes
        payloads.append(b"2147483647,-2147483648,0,0\n")
        payloads.append(b"0,9223372036854775807,0,0\n")

        # Floating point extremes
        floats = ["inf", "-inf", "nan", "1e308", "-1e308"]
        for val in floats:
            payloads.append(f"{val},1,0,0\n".encode("utf-8"))
            payloads.append(f"0,{val},0,0\n".encode("utf-8"))

        return payloads


    def _empty_field_payloads(self, seed_lines):
        payloads = []
        payloads += [
            b"\n", b",\n", b",,\n", b",,,\n", b",,,,\n",
            b",\n,\n,\n,\n"
        ]
        return payloads


    def _whitespace_payloads(self, seed_lines):
        payloads = []
        # Spaces
        payloads += [
            b" \n", b" , \n", b"  ,  \n",
            b" , , \n", b" , , , \n"
        ]
        # Tabs
        payloads += [
            b"\t\n", b"\t,1\n", b"1,\t\n",
            b"\t,1,0\n", b"0,\t,1,0\n", b"0,0,\t,1\n"
        ]
        return payloads



    def generate(self):
        seed_lines = self.parse_input(self.example_input) or []
        template = self._pick_template_row(seed_lines)

        # trivial cases
        yield b""                    # empty
        yield self.example_input     # original valid input
        yield (b"A" * 2000)           # overflow test

        # targeted overflow variants based on the seed
        for p in self._overflow_variants_from_seed(
            seed_lines,
            target_len=200,
            repeat_lines=500,
        ):
            yield p

        # zero-only CSV structures 
        for p in self._zero_blocks(seed_lines):
            yield p

        # block varying each field (normal CSV line-per-row)
        block = self._make_block_vary_each_field(template, nrows=random.randint(4, 10))
        yield self._append_after_seed_text("\n".join([",".join(r) for r in block]) + "\n")

        # same but with semicolon delimiters
        block_sc = self._make_block_vary_each_field(template, nrows=random.randint(3, 8))
        yield self._append_after_seed_text("\n".join([(";".join(r)) for r in block_sc]) + "\n")
        print("1")
        # append line(s) with growing last field size
        if seed_lines:
            template_line = seed_lines[-1] if seed_lines[-1].strip() else (
                seed_lines[0] if seed_lines else "a,b,c,A"
            )
            yield self._append_growing_last_field(template_line, steps=6)

        # repeat the last line many times as separate rows
        for p in self._repeat_last_line_block(seed_lines, counts=[10, 50, 100]):
            yield p
        print("1")
        # Format string payloads
        for p in self._format_string_payloads(seed_lines):
            yield p
        print("1")
        # Null and control payloads
        for p in self._null_and_control_payloads(seed_lines):
            yield p
        print("1")
        # Max/min numeric payloads
        for p in self._extreme_numeric_payloads(seed_lines):
            yield p
        print("1")
        # Empty field payloads
        for p in self._empty_field_payloads(seed_lines):
            yield p
        print("1")
        # Whitespace payloads
        for p in self._whitespace_payloads(seed_lines):
            yield p
        print("1")
        # semi-colon version of last line as 20 rows
        if seed_lines:
            last = seed_lines[-1] if seed_lines[-1].strip() else (
                seed_lines[0] if seed_lines else "a,b,c,A"
            )
            semi_block = "\n".join([last.replace(",", ";") for _ in range(20)]) + "\n"
            yield self._append_after_seed_text(semi_block)

        # row-structure mutation 
        if seed_lines:
            seed_rows = [ln.split(",") for ln in seed_lines if ln.strip()]
        else:
            seed_rows = [["a", "b", "c", "A"]]
        mutated_rows = self.mutation_in_row(seed_rows, times=random.randint(2, 5))
        try:
            yield self._append_after_seed_text(
                self._rows_to_bytes(mutated_rows).decode('utf-8', errors='ignore')
            )
        except Exception:
            pass

        # a couple of light byte-flip variants of whole input
        for rate in (30, 60):
            b = bytearray(self.example_input)
            for i in range(len(b)):
                if random.randint(0, rate) == 1:
                    b[i] ^= random.getrandbits(7)
            yield bytes(b)
        print("1")
        # Keep mutating indefinitely
        while True:
            yield self.mutate_bytes(self.example_input)
