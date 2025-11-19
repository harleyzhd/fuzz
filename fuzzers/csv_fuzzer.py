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
