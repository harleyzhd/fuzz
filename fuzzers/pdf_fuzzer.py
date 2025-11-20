import random
import io
import struct
import pikepdf
from .base_fuzzer import BaseFuzzer


class PdfFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        self.pdf_data = None
        self.pdf_obj = None
        try:
            self.pdf_obj = pikepdf.open(io.BytesIO(self.example_input))
            self.pdf_data = bytearray(self.example_input)
        except Exception as e:
            print(f"[!] Warning: Could not parse PDF file: {e}")
            self.pdf_data = bytearray(self.example_input)
    
    def _corrupt_header(self, data):
        data = bytearray(data)
        if data.startswith(b'%PDF-'):
            mutation_type = random.randint(0, 4)
            
            if mutation_type == 0:
                data[5:8] = b'9.9'
            elif mutation_type == 1:
                data[0:5] = b'%XXX-'
            elif mutation_type == 2:
                data[5:8] = b'\x00\x00\x00'
            elif mutation_type == 3:
                data = data[5:]
            else:
                data[0] = random.randint(0, 255)
        return bytes(data)
    
    def _mutate_xref_table(self, data):
        data = bytearray(data)
        
        if b'xref' in data:
            xref_pos = data.find(b'xref')
            if xref_pos != -1:
                mutation_type = random.randint(0, 5)
                
                if mutation_type == 0:
                    data[xref_pos:xref_pos+4] = b'XXXX'
                elif mutation_type == 1:
                    data.insert(xref_pos + 4, 0)

                # bloat xref table with excessive entries
                elif mutation_type == 2:
                    end_pos = data.find(b'trailer', xref_pos)
                    if end_pos != -1:
                        data[xref_pos:end_pos] = b'xref\n' + b'0' * random.choice([100, 1000, 10000])
                elif mutation_type == 3:
                    data[xref_pos:xref_pos+4] = b'\x00\x00\x00\x00'

                # delete entire xref table
                elif mutation_type == 4:
                    trailer_pos = data.find(b'trailer', xref_pos)
                    if trailer_pos != -1:
                        del data[xref_pos:trailer_pos]
                else:
                    for i in range(min(100, len(data) - xref_pos)):
                        if random.random() < 0.1:
                            data[xref_pos + i] = random.randint(0, 255)
        
        return bytes(data)
    
    def _mutate_objects(self, data):
        data = bytearray(data)
        
        obj_pattern = b'obj'
        endobj_pattern = b'endobj'
        
        if obj_pattern in data:
            positions = []
            start = 0
            while True:
                pos = data.find(obj_pattern, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            
            if positions:
                mutation_type = random.randint(0, 6)
                target_pos = random.choice(positions)
                
                if mutation_type == 0:
                    data[target_pos:target_pos+3] = b'XXX'

                # bloat object with large data to trigger buffer overflow
                elif mutation_type == 1:
                    end_pos = data.find(endobj_pattern, target_pos)
                    if end_pos != -1:
                        data[target_pos:end_pos] = b'obj\n' + b'A' * random.choice([1000, 5000, 10000])
                elif mutation_type == 2:
                    data.insert(target_pos, 0)

                # delete entire object
                elif mutation_type == 3:
                    end_pos = data.find(endobj_pattern, target_pos)
                    if end_pos != -1:
                        del data[target_pos:end_pos + len(endobj_pattern)]

                # format string injection
                elif mutation_type == 4:
                    data[target_pos:target_pos+3] = b'%s%n%x'
                elif mutation_type == 5:
                    data[target_pos:target_pos+3] = b'\x00\x00\x00'
                else:
                    end_pos = data.find(endobj_pattern, target_pos)
                    if end_pos != -1:
                        for _ in range(random.randint(5, 20)):
                            pos = random.randint(target_pos, end_pos)
                            data[pos] = random.randint(0, 255)
        
        return bytes(data)
    
    def _mutate_streams(self, data):
        data = bytearray(data)
        
        stream_start = b'stream'
        stream_end = b'endstream'
        
        if stream_start in data:
            start_pos = data.find(stream_start)
            if start_pos != -1:
                end_pos = data.find(stream_end, start_pos)
                if end_pos != -1:
                    mutation_type = random.randint(0, 7)
                    
                    # fill stream with null bytes
                    if mutation_type == 0:
                        data[start_pos + 6:end_pos] = b'\x00' * random.choice([100, 1000, 10000])
                    
                    # bloat stream data
                    elif mutation_type == 1:
                        data[start_pos + 6:end_pos] = b'A' * random.choice([1000, 5000, 10000])
                    elif mutation_type == 2:
                        data[start_pos:start_pos + 6] = b'XXXXXX'

                    # delete entire stream
                    elif mutation_type == 3:
                        del data[start_pos:end_pos + len(stream_end)]
                    elif mutation_type == 4:
                        for _ in range(random.randint(10, 50)):
                            pos = random.randint(start_pos + 6, end_pos)
                            data[pos] = random.randint(0, 255)

                    # corrupt stream end marker
                    elif mutation_type == 5:
                        data[end_pos:end_pos + 9] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'

                    # format string injection in stream
                    elif mutation_type == 6:
                        data[start_pos + 6:end_pos] = b'%s%n%x%p%d' * 100
                    else:
                        data[start_pos + 6:end_pos] = random.randbytes(random.choice([100, 500, 1000]))
        
        return bytes(data)
    
    def _inject_javascript(self, data):
        js_payloads = [
            b'/JavaScript <</S /JavaScript /JS (' + b'A' * 10000 + b')>>',
            b'/JavaScript <</S /JavaScript /JS (app.alert("XSS");)>>',
            b'/JavaScript <</S /JavaScript /JS (%s%n%x%p%d)>>',
            b'/JavaScript <</S /JavaScript /JS (while(1){})>>',
            b'/OpenAction <</S /JavaScript /JS (app.alert(1);)>>',
            b'/AA <</O <</S /JavaScript /JS (app.alert(1);)>>>>',
        ]
        
        data = bytearray(data)
        if b'endobj' in data:
            pos = data.find(b'endobj')
            payload = random.choice(js_payloads)
            data[pos:pos] = payload + b'\n'
        
        return bytes(data)
    
    def _mutate_trailer(self, data):
        data = bytearray(data)
        
        if b'trailer' in data:
            trailer_pos = data.find(b'trailer')
            mutation_type = random.randint(0, 5)
            
            if mutation_type == 0:
                data[trailer_pos:trailer_pos + 7] = b'XXXXXXX'

            # set huge /Size value to trigger integer overflow
            elif mutation_type == 1:
                eof_pos = data.find(b'%%EOF', trailer_pos)
                if eof_pos != -1:
                    data[trailer_pos:eof_pos] = b'trailer\n<< /Size 999999999 >>\n'
            elif mutation_type == 2:
                data[trailer_pos:trailer_pos + 7] = b'\x00\x00\x00\x00\x00\x00\x00'

            # delete entire trailer
            elif mutation_type == 3:
                eof_pos = data.find(b'%%EOF', trailer_pos)
                if eof_pos != -1:
                    del data[trailer_pos:eof_pos]
            elif mutation_type == 4:
                data.insert(trailer_pos, 0)
            else:
                eof_pos = data.find(b'%%EOF', trailer_pos)
                if eof_pos != -1:
                    for _ in range(random.randint(5, 20)):
                        pos = random.randint(trailer_pos, eof_pos)
                        data[pos] = random.randint(0, 255)
        
        return bytes(data)
    
    def _mutate_integers(self, data):
        data = bytearray(data)
        
        boundary_values = [
            b'0', b'-1', b'2147483647', b'-2147483648',
            b'4294967295', b'9223372036854775807',
            b'-9223372036854775808', b'999999999999999999',
        ]
        
        import re
        text = data.decode('latin-1', errors='ignore')
        result = re.sub(r'\b\d+\b', lambda m: random.choice(boundary_values).decode('latin-1'), text)
        return result.encode('latin-1', errors='ignore')
    
    def _create_malformed_pdfs(self):
        patterns = [
            b'%PDF-1.4\n%%EOF',
            b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n',
            b'%PDF-9.9\n' + b'A' * 1000 + b'\n%%EOF',
            b'%PDF-1.4\n' + b'\x00' * 1000 + b'\n%%EOF',
            b'%PDF-1.4\nxref\n0 0\ntrailer\n<< >>\n%%EOF',
            b'%PDF-1.4\n' + b'%s%n%x' * 100 + b'\n%%EOF',
            b'%PDF-1.4\n1 0 obj\n' + b'<' * 1000 + b'\nendobj\n%%EOF',
            b'%PDF-1.4\n1 0 obj\nstream\n' + b'A' * 10000 + b'\nendstream\nendobj\n%%EOF',
            b'%PDF-1.4\n' + random.randbytes(1000) + b'\n%%EOF',
            b'%PDF-1.4\nxref\n0 999999\ntrailer\n%%EOF',
        ]
        return random.choice(patterns)
    
    def _mutate_structure(self):
        """Mutate PDF structure using pikepdf (fast C++ library)"""
        if not self.pdf_obj:
            return self.example_input
        
        try:
            # Create a copy to avoid modifying cached pdf_obj
            pdf_copy = pikepdf.open(io.BytesIO(self.example_input))
            
            mutation_type = random.randint(0, 4)
            
            # duplicate pages to bloat file
            if mutation_type == 0:
                pages = list(pdf_copy.pages)
                for _ in range(random.choice([5, 10, 20])):
                    if pages:
                        pdf_copy.pages.append(random.choice(pages))

            # remove pages to create broken references
            elif mutation_type == 1:
                if len(pdf_copy.pages) > 1:
                    del pdf_copy.pages[random.randint(0, len(pdf_copy.pages) - 1)]

            # corrupt MediaBox with extreme values
            elif mutation_type == 2:
                for page in pdf_copy.pages:
                    page.MediaBox = [0, 0, 999999, 999999]

            # corrupt page tree with invalid type
            elif mutation_type == 3:
                if len(pdf_copy.pages) > 0:
                    page = pdf_copy.pages[0]
                    page.Type = pikepdf.Name('/InvalidType')
                    
            # massively duplicate all pages
            else:
                pages = list(pdf_copy.pages)
                for page in pages:
                    for _ in range(random.choice([10, 50])):
                        pdf_copy.pages.append(page)
            
            output = io.BytesIO()
            pdf_copy.save(output)
            pdf_copy.close()
            return output.getvalue()
        except:
            return self.mutate_bytes(self.example_input)
    
    def _mutate_metadata(self):
        if not self.pdf_obj:
            return self.example_input
        
        try:
            # create a copy to avoid modifying cached pdf_obj
            pdf_copy = pikepdf.open(io.BytesIO(self.example_input))
            
            attack_strings = [
                'A' * 10000,
                '%s%n%x%p%d',
                '\x00' * 1000,
                '../../../etc/passwd',
                '<script>alert(1)</script>',
            ]
            
            with pdf_copy.open_metadata() as meta:
                meta['dc:title'] = random.choice(attack_strings)
                meta['dc:creator'] = random.choice(attack_strings)
                meta['dc:subject'] = random.choice(attack_strings)
                meta['pdf:Producer'] = random.choice(attack_strings)
            
            output = io.BytesIO()
            pdf_copy.save(output)
            pdf_copy.close()
            return output.getvalue()
        except:
            return self.mutate_bytes(self.example_input)
    
    def _mutate_byte_level(self):
        data = bytearray(self.example_input)
        mutation_type = random.randint(0, 6)
        
        if mutation_type == 0:
            for _ in range(random.randint(5, 20)):
                if len(data) > 0:
                    pos = random.randint(0, len(data) - 1)
                    data[pos] = random.randint(0, 255)
        elif mutation_type == 1:
            for _ in range(random.randint(5, 20)):
                if len(data) > 0:
                    pos = random.randint(0, len(data) - 1)
                    data[pos] ^= (1 << random.randint(0, 7))
        elif mutation_type == 2:
            pos = random.randint(0, len(data))
            data[pos:pos] = b'\x00' * random.randint(10, 100)
        elif mutation_type == 3:
            if len(data) > 10:
                start = random.randint(0, len(data) - 10)
                end = start + random.randint(10, min(100, len(data) - start))
                chunk = data[start:end]
                data.extend(chunk * random.randint(2, 10))
        elif mutation_type == 4:
            if len(data) > 1:
                data = data[:random.randint(1, len(data))]
        elif mutation_type == 5:
            pos = random.randint(0, len(data))
            data[pos:pos] = b'%s%n%x' * random.randint(10, 50)
        else:
            for _ in range(random.randint(10, 50)):
                pos = random.randint(0, len(data))
                data.insert(pos, random.randint(0, 255))
        
        return bytes(data)
    
    def generate(self):
        yield b""
        yield b"%PDF-1.4"
        yield b"%PDF-"
        yield b"%%EOF"
        
        if len(self.example_input) >= 4:
            for size in [1, 2, 4, 8, 16, 32]:
                if len(self.example_input) >= size:
                    yield self.example_input[:size]
        
        # Use cached parsed PDF object (parsed once in __init__)
        if self.pdf_obj:
            for _ in range(30):
                yield self._mutate_structure()
            
            for _ in range(20):
                yield self._mutate_metadata()
        
        for _ in range(20):
            yield self._create_malformed_pdfs()
        
        for _ in range(20):
            yield self._corrupt_header(self.example_input)
        
        for _ in range(20):
            yield self._mutate_xref_table(self.example_input)
        
        for _ in range(20):
            yield self._mutate_objects(self.example_input)
        
        for _ in range(20):
            yield self._mutate_streams(self.example_input)
        
        for _ in range(15):
            yield self._mutate_trailer(self.example_input)
        
        for _ in range(15):
            yield self._inject_javascript(self.example_input)
        
        for _ in range(15):
            yield self._mutate_integers(self.example_input)
        
        for _ in range(15):
            yield self._mutate_byte_level()
        
        for _ in range(30):
            mutated = self.example_input
            for _ in range(random.randint(2, 3)):
                mutation_func = random.choice([
                    self._corrupt_header,
                    self._mutate_xref_table,
                    self._mutate_objects,
                    self._mutate_streams,
                    self._mutate_trailer,
                ])
                mutated = mutation_func(mutated)
            yield mutated
        
        for _ in range(30):
            mutated = self.example_input
            for _ in range(random.randint(3, 5)):
                mutation_func = random.choice([
                    self._corrupt_header,
                    self._mutate_xref_table,
                    self._mutate_objects,
                    self._mutate_streams,
                    self._mutate_trailer,
                    self._inject_javascript,
                    self._mutate_integers,
                ])
                mutated = mutation_func(mutated)
            
            if random.random() < 0.5:
                mutated = bytearray(mutated)
                for _ in range(random.randint(1, 5)):
                    if len(mutated) > 0:
                        pos = random.randint(0, len(mutated) - 1)
                        mutated[pos] = random.randint(0, 255)
                mutated = bytes(mutated)
            yield mutated
        
        while True:
            # use cached parsed PDF object for structure mutations
            if self.pdf_obj and random.random() < 0.3:
                yield random.choice([
                    self._mutate_structure,
                    self._mutate_metadata,
                ])()
            else:
                mutated = self.example_input
                mutation_func = random.choice([
                    self._corrupt_header,
                    self._mutate_xref_table,
                    self._mutate_objects,
                    self._mutate_streams,
                    self._mutate_trailer,
                    self._inject_javascript,
                    self._mutate_integers,
                ])
                mutated = mutation_func(mutated)
                
                if random.random() < 0.5:
                    mutated = self._mutate_byte_level()
                
                yield mutated
