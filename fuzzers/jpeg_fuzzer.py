import random
import struct
from .base_fuzzer import BaseFuzzer


class JpegFuzzer(BaseFuzzer):

    MARKERS = {
        'SOI': b'\xff\xd8',
        'EOI': b'\xff\xd9',
        'APP0': b'\xff\xe0',
        'APP1': b'\xff\xe1',
        'DQT': b'\xff\xdb',
        'SOF0': b'\xff\xc0',
        'SOF1': b'\xff\xc1',
        'SOF2': b'\xff\xc2',
        'DHT': b'\xff\xc4',
        'DRI': b'\xff\xdd',
        'SOS': b'\xff\xda',
        'COM': b'\xff\xfe',
    }

    INTERESTING_VALUES = [
        0, 1, 2, 4, 8, 16, 32, 64, 127, 128, 255,
        256, 512, 1024, 2048, 4096, 8192, 16384, 32767, 32768, 65535,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
    ]

    def _find_markers(self, data):
        markers = []
        i = 0
        while i < len(data) - 1:
            if data[i] == 0xFF and data[i+1] != 0x00 and data[i+1] != 0xFF:
                marker_type = data[i:i+2]
                markers.append((i, marker_type))
            i += 1
        return markers

    def _corrupt_marker(self, data, marker_pos):
        data = bytearray(data)
        corruption_type = random.randint(0, 4)

        if corruption_type == 0:
            data[marker_pos + 1] = random.randint(0, 255)
        elif corruption_type == 1:
            data[marker_pos] = random.randint(0, 255)
        elif corruption_type == 2:
            if marker_pos + 2 < len(data):
                data[marker_pos:marker_pos+2] = b'\x00\x00'
        elif corruption_type == 3:
            if marker_pos + 2 < len(data):
                data.insert(marker_pos, 0xFF)
        elif corruption_type == 4:
            if marker_pos > 0:
                del data[marker_pos]

        return bytes(data)

    def _corrupt_segment_length(self, data):
        data = bytearray(data)
        markers = self._find_markers(data)

        for pos, marker in markers:
            if marker not in [self.MARKERS['SOI'], self.MARKERS['EOI'], b'\xff\xd0',
                             b'\xff\xd1', b'\xff\xd2', b'\xff\xd3', b'\xff\xd4',
                             b'\xff\xd5', b'\xff\xd6', b'\xff\xd7']:
                if pos + 4 <= len(data):
                    length_pos = pos + 2
                    corrupt_type = random.randint(0, 3)

                    if corrupt_type == 0:
                        data[length_pos:length_pos+2] = b'\xff\xff'
                    elif corrupt_type == 1:
                        data[length_pos:length_pos+2] = b'\x00\x00'
                    elif corrupt_type == 2:
                        data[length_pos:length_pos+2] = b'\x00\x01'
                    elif corrupt_type == 3:
                        new_len = random.choice(self.INTERESTING_VALUES) & 0xFFFF
                        data[length_pos:length_pos+2] = struct.pack('>H', new_len)

                    return bytes(data)

        return bytes(data)

    def _corrupt_quantization_table(self, data):
        data = bytearray(data)
        dqt_pos = data.find(b'\xff\xdb')

        if dqt_pos != -1 and dqt_pos + 4 < len(data):
            table_start = dqt_pos + 4
            table_len = min(64, len(data) - table_start)

            for i in range(table_len):
                if random.random() < 0.3:
                    data[table_start + i] = random.choice([0, 1, 255, 128])

        return bytes(data)

    def _corrupt_huffman_table(self, data):
        data = bytearray(data)
        dht_pos = data.find(b'\xff\xc4')

        if dht_pos != -1 and dht_pos + 20 < len(data):
            table_start = dht_pos + 5
            for i in range(min(16, len(data) - table_start)):
                if random.random() < 0.3:
                    data[table_start + i] = random.randint(0, 255)

        return bytes(data)

    def _seed_huffman_overflow(self, source=None, min_total=0x120):
        blob = bytearray(source if source is not None else self.example_input)
        if not blob:
            return None
        dht_pos = blob.find(b'\xff\xc4')
        if dht_pos == -1 or dht_pos + 4 >= len(blob):
            return None
        length = struct.unpack('>H', blob[dht_pos + 2:dht_pos + 4])[0]
        body_end = dht_pos + 2 + length
        if body_end > len(blob):
            return None
        info = blob[dht_pos + 4]
        counts = list(blob[dht_pos + 5:dht_pos + 21])
        if len(counts) != 16:
            return None
        total = sum(counts)
        extra_needed = max(0, min_total - total)
        new_counts = counts[:]
        idx = 0
        while extra_needed > 0 and idx < len(new_counts):
            add = min(0xFF - new_counts[idx], extra_needed)
            new_counts[idx] += add
            extra_needed -= add
            idx += 1
        if sum(new_counts) == total:
            return None
        symbols = bytes((i & 0xff) for i in range(sum(new_counts)))
        new_body = bytes([info]) + bytes(new_counts) + symbols
        new_length = len(new_body)
        mutated = (
            blob[:dht_pos + 2]
            + struct.pack('>H', new_length)
            + new_body
            + blob[body_end:]
        )
        return bytes(mutated)

    def _seed_dqt_overflow(self, source=None, extra_len=0x100):
        blob = bytearray(source if source is not None else self.example_input)
        if not blob:
            return None
        dqt_pos = blob.find(b'\xff\xdb')
        if dqt_pos == -1 or dqt_pos + 4 >= len(blob):
            return None
        length = struct.unpack('>H', blob[dqt_pos + 2:dqt_pos + 4])[0]
        body_end = dqt_pos + 2 + length
        if body_end > len(blob):
            return None
        info = blob[dqt_pos + 4]
        payload = bytes([info]) + bytes([random.randint(0, 255) for _ in range(length - 1 + extra_len)])
        new_length = len(payload)
        mutated = (
            blob[:dqt_pos + 2]
            + struct.pack('>H', new_length)
            + payload
            + blob[body_end:]
        )
        return bytes(mutated)

    def _seed_sos_component_mismatch(self, source=None):
        blob = bytearray(source if source is not None else self.example_input)
        if not blob:
            return None
        sos_pos = blob.find(b'\xff\xda')
        if sos_pos == -1 or sos_pos + 5 >= len(blob):
            return None
        length = struct.unpack('>H', blob[sos_pos + 2:sos_pos + 4])[0]
        end = sos_pos + 2 + length
        if end > len(blob):
            return None
        ns = blob[sos_pos + 4]
        comp_bytes = bytearray(blob[sos_pos + 5:sos_pos + 5 + 2 * ns])
        tail = blob[sos_pos + 5 + 2 * ns:end]
        comp_bytes.extend([0x0A, 0xFF])
        comp_bytes.extend([0x0B, 0xEE])
        new_ns = ns + 2 if ns <= 4 else ns + 1
        comp_bytes = comp_bytes[:2 * new_ns]
        new_length = 6 + 2 * new_ns
        mutated = (
            blob[:sos_pos + 2]
            + struct.pack('>H', new_length)
            + bytes([new_ns])
            + bytes(comp_bytes)
            + tail
            + blob[end:]
        )
        return bytes(mutated)

    def _corrupt_sof(self, data):
        data = bytearray(data)
        sof_markers = [b'\xff\xc0', b'\xff\xc1', b'\xff\xc2']

        for marker in sof_markers:
            sof_pos = data.find(marker)
            if sof_pos != -1 and sof_pos + 10 < len(data):
                field = random.randint(0, 3)

                if field == 0:
                    data[sof_pos + 4] = random.choice([0, 1, 16, 24, 32, 255])
                elif field == 1:
                    height = random.choice(self.INTERESTING_VALUES) & 0xFFFF
                    data[sof_pos + 5:sof_pos + 7] = struct.pack('>H', height)
                elif field == 2:
                    width = random.choice(self.INTERESTING_VALUES) & 0xFFFF
                    data[sof_pos + 7:sof_pos + 9] = struct.pack('>H', width)
                elif field == 3:
                    data[sof_pos + 9] = random.choice([0, 1, 2, 3, 4, 5, 255])

                return bytes(data)

        return bytes(data)

    def _corrupt_sos(self, data):
        data = bytearray(data)
        sos_pos = data.find(b'\xff\xda')

        if sos_pos != -1 and sos_pos + 10 < len(data):
            corrupt_type = random.randint(0, 2)

            if corrupt_type == 0:
                data[sos_pos + 4] = random.choice([0, 1, 2, 3, 4, 5, 255])
            elif corrupt_type == 1:
                for i in range(5, min(10, len(data) - sos_pos)):
                    data[sos_pos + i] = random.randint(0, 255)
            elif corrupt_type == 2:
                scan_start = sos_pos + 12
                if scan_start < len(data):
                    for i in range(min(100, len(data) - scan_start)):
                        if random.random() < 0.1:
                            data[scan_start + i] = random.randint(0, 255)

        return bytes(data)

    def _insert_fake_marker(self, data):
        data = bytearray(data)
        pos = random.randint(2, max(2, len(data) - 2))
        fake_marker = bytes([0xFF, random.randint(0xC0, 0xFE)])
        fake_length = struct.pack('>H', random.randint(2, 100))
        fake_data = bytes([random.randint(0, 255) for _ in range(random.randint(0, 50))])
        data[pos:pos] = fake_marker + fake_length + fake_data
        return bytes(data)

    def _remove_marker(self, data):
        data = bytearray(data)
        markers = self._find_markers(data)

        removable = [(p, m) for p, m in markers
                     if m not in [self.MARKERS['SOI'], self.MARKERS['EOI']]]

        if removable:
            pos, marker = random.choice(removable)
            if pos + 4 <= len(data):
                length = struct.unpack('>H', data[pos+2:pos+4])[0] if pos + 4 <= len(data) else 2
                end_pos = min(pos + 2 + length, len(data))
                del data[pos:end_pos]

        return bytes(data)

    def _duplicate_marker(self, data):
        data = bytearray(data)
        markers = self._find_markers(data)

        if markers:
            pos, marker = random.choice(markers)
            if pos + 4 <= len(data):
                try:
                    length = struct.unpack('>H', data[pos+2:pos+4])[0]
                    segment = data[pos:pos+2+length]
                    insert_pos = random.randint(2, len(data) - 2)
                    data[insert_pos:insert_pos] = segment
                except:
                    pass

        return bytes(data)

    def _truncate_at_marker(self, data):
        markers = self._find_markers(data)
        if len(markers) > 2:
            pos, _ = random.choice(markers[1:-1])
            return data[:pos]
        return data

    def _corrupt_image_data(self, data):
        data = bytearray(data)
        sos_pos = data.find(b'\xff\xda')

        if sos_pos != -1:
            scan_data_start = sos_pos + 12
            eoi_pos = data.rfind(b'\xff\xd9')

            if eoi_pos > scan_data_start:
                num_corruptions = random.randint(1, 20)
                for _ in range(num_corruptions):
                    pos = random.randint(scan_data_start, eoi_pos - 1)
                    data[pos] = random.randint(0, 255)

        return bytes(data)

    def _generate_minimal_jpeg(self, width=8, height=8):
        jpeg = bytearray()
        jpeg += b'\xff\xd8'
        jpeg += b'\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'

        jpeg += b'\xff\xdb\x00\x43\x00'
        jpeg += bytes([16] * 64)

        jpeg += b'\xff\xc0\x00\x0b'
        jpeg += bytes([8])
        jpeg += struct.pack('>H', height)
        jpeg += struct.pack('>H', width)
        jpeg += bytes([1, 1, 0x11, 0])

        jpeg += b'\xff\xc4\x00\x1f\x00'
        jpeg += bytes([0] * 16)
        jpeg += bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])

        jpeg += b'\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00'
        jpeg += bytes([0] * 100)

        jpeg += b'\xff\xd9'

        return bytes(jpeg)

    def _generate_extreme_dimensions(self):
        payloads = []

        dimensions = [
            (0, 0), (1, 1), (0, 100), (100, 0),
            (65535, 65535), (65535, 1), (1, 65535),
            (32767, 32767), (32768, 32768),
            (0xFFFF, 0xFFFF), (0x7FFF, 0x7FFF),
        ]

        for w, h in dimensions:
            jpeg = self._generate_minimal_jpeg(8, 8)
            jpeg = bytearray(jpeg)
            sof_pos = jpeg.find(b'\xff\xc0')
            if sof_pos != -1:
                jpeg[sof_pos + 5:sof_pos + 7] = struct.pack('>H', h)
                jpeg[sof_pos + 7:sof_pos + 9] = struct.pack('>H', w)
            payloads.append(bytes(jpeg))

        return payloads

    def _generate_malformed_headers(self):
        payloads = []

        payloads.append(b'\xff\xd8\xff\xd9')
        payloads.append(b'\xff\xd8')
        payloads.append(b'\xff\xd9')
        payloads.append(b'\x00' * 100)
        payloads.append(b'\xff' * 100)
        payloads.append(b'\xff\xd8' + b'\xff' * 100)
        payloads.append(b'\xff\xd8\xff\xe0\x00\x02')
        payloads.append(b'\xff\xd8\xff\xe0\xff\xff')
        payloads.append(b'\xff\xd8\xff\xc0\x00\x02')
        payloads.append(b'\xff\xd8\xff\xdb\x00\x02')

        return payloads

    def _generate_nested_markers(self):
        payloads = []

        base = b'\xff\xd8'
        for _ in range(50):
            base += b'\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        base += b'\xff\xd9'
        payloads.append(base)

        base = b'\xff\xd8'
        for _ in range(50):
            base += b'\xff\xdb\x00\x43\x00' + bytes([16] * 64)
        base += b'\xff\xd9'
        payloads.append(base)

        base = b'\xff\xd8'
        for _ in range(50):
            base += b'\xff\xc4\x00\x1f\x00' + bytes([0] * 28)
        base += b'\xff\xd9'
        payloads.append(base)

        return payloads

    def _generate_overflow_payloads(self):
        payloads = []

        jpeg = bytearray(b'\xff\xd8\xff\xe0')
        jpeg += struct.pack('>H', 0xFFFF)
        jpeg += b'JFIF\x00' + b'A' * 65527
        jpeg += b'\xff\xd9'
        payloads.append(bytes(jpeg))

        jpeg = bytearray(b'\xff\xd8\xff\xdb')
        jpeg += struct.pack('>H', 0xFFFF)
        jpeg += b'\x00' + b'A' * 65532
        jpeg += b'\xff\xd9'
        payloads.append(bytes(jpeg))

        return payloads

    def _corrupt_sampling_factors(self, data):
        data = bytearray(data)
        sof_markers = [b'\xff\xc0', b'\xff\xc1', b'\xff\xc2']

        for marker in sof_markers:
            sof_pos = data.find(marker)
            if sof_pos != -1 and sof_pos + 18 < len(data):
                samplings = [0x11, 0x12, 0x21, 0x22, 0x14, 0x41, 0x24, 0x42, 0x44]
                data[sof_pos + 11] = random.choice(samplings)
                if random.random() < 0.3:
                    data[sof_pos + 14] = random.choice(samplings)
                if random.random() < 0.3:
                    data[sof_pos + 17] = random.choice(samplings)
                return bytes(data)
        return bytes(data)

    def _add_dri_marker(self, data):
        data = bytearray(data)
        sos_pos = data.find(b'\xff\xda')

        if sos_pos != -1:
            dri_vals = [0, 1, 2, 8, 16, 100, 256, 1000, 32767, 32768, 65535]
            dri_val = random.choice(dri_vals)
            dri_marker = b'\xff\xdd\x00\x04' + struct.pack('>H', dri_val)
            data = data[:sos_pos] + dri_marker + data[sos_pos:]

        return bytes(data)

    def _corrupt_huffman_counts(self, data):
        data = bytearray(data)
        dht_pos = data.find(b'\xff\xc4')

        if dht_pos != -1 and dht_pos + 21 < len(data):
            count_patterns = [
                [0]*16,
                [255]*16,
                [16]*16,
                [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125],
                [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            ]
            pattern = random.choice(count_patterns)
            for i, c in enumerate(pattern):
                data[dht_pos + 5 + i] = c

        return bytes(data)

    def _valid_dims_with_corruption(self, data):
        data = bytearray(data)
        sof_markers = [b'\xff\xc0', b'\xff\xc1', b'\xff\xc2']

        for marker in sof_markers:
            sof_pos = data.find(marker)
            if sof_pos != -1 and sof_pos + 10 < len(data):
                dims = [(64, 64), (128, 128), (256, 256)]
                w, h = random.choice(dims)
                data[sof_pos + 5:sof_pos + 7] = struct.pack('>H', h)
                data[sof_pos + 7:sof_pos + 9] = struct.pack('>H', w)

                for _ in range(random.randint(5, 20)):
                    pos = random.randint(0, len(data) - 1)
                    data[pos] = random.randint(0, 255)

                return bytes(data)
        return bytes(data)

    def _corrupt_component_ids(self, data):
        data = bytearray(data)
        sof_pos = data.find(b'\xff\xc0')
        if sof_pos == -1:
            sof_pos = data.find(b'\xff\xc2')

        if sof_pos != -1 and sof_pos + 18 < len(data):
            ids = [[0,0,0], [1,1,1], [4,5,6], [0,1,2], [1,2,3], [255,254,253]]
            comp_ids = random.choice(ids)
            data[sof_pos + 10] = comp_ids[0]
            data[sof_pos + 13] = comp_ids[1]
            data[sof_pos + 16] = comp_ids[2]

        return bytes(data)

    def generate(self):
        yield b""
        yield self.example_input

        seeds = [
            self._seed_huffman_overflow(),
            self._seed_dqt_overflow(),
            self._seed_sos_component_mismatch(),
        ]
        for seed in seeds:
            if seed:
                yield seed
        for _ in range(4):
            overflow = self._seed_huffman_overflow(min_total=0x160 + random.randint(0, 0x100))
            if overflow:
                yield overflow

        for p in self._generate_malformed_headers():
            yield p

        for p in self._generate_extreme_dimensions():
            yield p

        for p in self._generate_nested_markers():
            yield p

        for p in self._generate_overflow_payloads():
            yield p

        for _ in range(20):
            markers = self._find_markers(self.example_input)
            if markers:
                pos, _ = random.choice(markers)
                yield self._corrupt_marker(self.example_input, pos)

        for _ in range(20):
            yield self._corrupt_segment_length(self.example_input)

        for _ in range(10):
            yield self._corrupt_quantization_table(self.example_input)

        for _ in range(10):
            yield self._corrupt_huffman_table(self.example_input)
        for _ in range(5):
            overflow = self._seed_huffman_overflow(min_total=0x1A0 + random.randint(0, 0x80))
            if overflow:
                yield overflow

        for _ in range(20):
            yield self._corrupt_sof(self.example_input)

        for _ in range(10):
            yield self._corrupt_sos(self.example_input)

        for _ in range(10):
            yield self._insert_fake_marker(self.example_input)

        for _ in range(10):
            yield self._remove_marker(self.example_input)

        for _ in range(10):
            yield self._duplicate_marker(self.example_input)

        for _ in range(5):
            yield self._truncate_at_marker(self.example_input)

        for _ in range(20):
            yield self._corrupt_image_data(self.example_input)

        for _ in range(20):
            yield self._corrupt_sampling_factors(self.example_input)

        for _ in range(20):
            yield self._add_dri_marker(self.example_input)

        for _ in range(20):
            yield self._corrupt_huffman_counts(self.example_input)

        for _ in range(20):
            yield self._valid_dims_with_corruption(self.example_input)

        for _ in range(20):
            yield self._corrupt_component_ids(self.example_input)
        dqt_seed = self._seed_dqt_overflow(extra_len=0x80)
        if dqt_seed:
            yield dqt_seed
        sos_seed = self._seed_sos_component_mismatch()
        if sos_seed:
            yield sos_seed

        while True:
            mutation_type = random.randint(0, 18)

            if mutation_type == 0:
                yield self.mutate_bytes(self.example_input)
            elif mutation_type == 1:
                markers = self._find_markers(self.example_input)
                if markers:
                    pos, _ = random.choice(markers)
                    yield self._corrupt_marker(self.example_input, pos)
                else:
                    yield self.mutate_bytes(self.example_input)
            elif mutation_type == 2:
                yield self._corrupt_segment_length(self.example_input)
            elif mutation_type == 3:
                yield self._corrupt_quantization_table(self.example_input)
            elif mutation_type == 4:
                overflow = self._seed_huffman_overflow(min_total=0x200 + random.randint(0, 0x200))
                if overflow:
                    yield overflow
                else:
                    yield self._corrupt_huffman_table(self.example_input)
            elif mutation_type == 5:
                yield self._corrupt_sof(self.example_input)
            elif mutation_type == 6:
                yield self._corrupt_sos(self.example_input)
            elif mutation_type == 7:
                yield self._insert_fake_marker(self.example_input)
            elif mutation_type == 8:
                yield self._remove_marker(self.example_input)
            elif mutation_type == 9:
                yield self._duplicate_marker(self.example_input)
            elif mutation_type == 10:
                yield self._truncate_at_marker(self.example_input)
            elif mutation_type == 11:
                yield self._corrupt_image_data(self.example_input)
            elif mutation_type == 12:
                yield self._corrupt_sampling_factors(self.example_input)
            elif mutation_type == 13:
                yield self._add_dri_marker(self.example_input)
            elif mutation_type == 14:
                yield self._corrupt_huffman_counts(self.example_input)
            elif mutation_type == 15:
                yield self._valid_dims_with_corruption(self.example_input)
            elif mutation_type == 16:
                yield self._corrupt_component_ids(self.example_input)
            elif mutation_type == 17:
                dqt_over = self._seed_dqt_overflow(extra_len=0x120)
                if dqt_over:
                    yield dqt_over
                else:
                    yield self._corrupt_quantization_table(self.example_input)
            elif mutation_type == 18:
                sos_over = self._seed_sos_component_mismatch()
                if sos_over:
                    yield sos_over
                else:
                    yield self._corrupt_sos(self.example_input)
