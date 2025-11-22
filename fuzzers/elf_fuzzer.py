import random
import struct
import io
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from .base_fuzzer import BaseFuzzer


class ElfFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        self.elf_data = None
        self.elf_obj = None
        try:
            self.elf_obj = ELFFile(io.BytesIO(self.example_input))
            self.elf_data = bytearray(self.example_input)
        except Exception as e:
            print(f"[!] Warning: Could not parse ELF file: {e}")
            self.elf_data = bytearray(self.example_input)
    
    def _get_elf_header_offsets(self):
        return {
            'e_type': (0x10, 2),        # Object file type
            'e_machine': (0x12, 2),     # Architecture
            'e_version': (0x14, 4),     # Object file version
            'e_entry': (0x18, 8),       # Entry point virtual address
            'e_phoff': (0x20, 8),       # Program header table offset
            'e_shoff': (0x28, 8),       # Section header table offset
            'e_flags': (0x30, 4),       # Processor-specific flags
            'e_ehsize': (0x34, 2),      # ELF header size
            'e_phentsize': (0x36, 2),   # Program header entry size
            'e_phnum': (0x38, 2),       # Program header count
            'e_shentsize': (0x3a, 2),   # Section header entry size
            'e_shnum': (0x3c, 2),       # Section header count
            'e_shstrndx': (0x3e, 2),    # Section header string table index
        }
    
    def _mutate_elf_header(self, data):
        data = bytearray(data)
        offsets = self._get_elf_header_offsets()
        
        # random header to mutate
        field = random.choice(list(offsets.keys()))
        offset, size = offsets[field]
        
        mutation_type = random.randint(0, 5)
        
        if mutation_type == 0:  # max value
            data[offset:offset+size] = b'\xff' * size
        elif mutation_type == 1:  # zero
            data[offset:offset+size] = b'\x00' * size
        elif mutation_type == 2:  # bits flips
            for i in range(offset, offset + size):
                data[i] ^= random.randint(1, 255)
        elif mutation_type == 3:  # edge case power of 2
            val = 1 << random.randint(0, size * 8 - 1)
            data[offset:offset+size] = val.to_bytes(size, byteorder='little')
        elif mutation_type == 4:  # slight offsets (off by one)
            current = int.from_bytes(data[offset:offset+size], byteorder='little')
            new_val = current + random.choice([-1, 1, -2, 2])
            if new_val < 0:
                new_val = 0
            data[offset:offset+size] = new_val.to_bytes(size, byteorder='little')
        else:  # Random value
            data[offset:offset+size] = random.randbytes(size)
        
        return bytes(data)
    
    def _mutate_section_headers(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
            e_shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
            e_shentsize = struct.unpack('<H', data[0x3a:0x3c])[0]
            
            if e_shoff == 0 or e_shnum == 0:
                return bytes(data)
            
            section_idx = random.randint(0, e_shnum - 1)
            sh_offset = e_shoff + (section_idx * e_shentsize)
            
            if sh_offset + e_shentsize > len(data):
                return bytes(data)
            
            mutation_type = random.randint(0, 7)
            
            # flip section flags (SHF_WRITE, SHF_EXECINSTR)
            if mutation_type == 0:
                # sh_flags offset in section header
                flags_offset = sh_offset + 0x08
                current_flags = struct.unpack('<Q', data[flags_offset:flags_offset+8])[0]
                # Toggle write/exec flags
                new_flags = current_flags ^ random.choice([0x1, 0x2, 0x4]) # SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR
                data[flags_offset:flags_offset+8] = struct.pack('<Q', new_flags)
            
            # change section alignment
            elif mutation_type == 1:
                # sh_addralign offset
                align_offset = sh_offset + 0x30
                new_align = random.choice([1, 2, 4, 8, 16, 32, 64, 0x10000, 0x100000])
                data[align_offset:align_offset+8] = struct.pack('<Q', new_align)
            
            # modify section size
            elif mutation_type == 2:
                # sh_size offset
                size_offset = sh_offset + 0x20
                current_size = struct.unpack('<Q', data[size_offset:size_offset+8])[0]
                new_size = current_size + random.choice([-1, 1, -16, 16, 100, -100, 0x1000])
                if new_size < 0:
                    new_size = 0
                data[size_offset:size_offset+8] = struct.pack('<Q', new_size)
            
            # modify section offset
            elif mutation_type == 3:
                # sh_offset offset
                offset_offset = sh_offset + 0x18
                current_off = struct.unpack('<Q', data[offset_offset:offset_offset+8])[0]
                new_off = current_off + random.choice([-1, 1, -8, 8, 0x100])
                if new_off < 0:
                    new_off = 0
                data[offset_offset:offset_offset+8] = struct.pack('<Q', new_off)
            
            # change section type
            elif mutation_type == 4:
                # sh_type offset
                type_offset = sh_offset + 0x04
                # various SHT_types
                new_type = random.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11])
                data[type_offset:type_offset+4] = struct.pack('<I', new_type)
            
            # reorder sections by swapping two section headers
            elif mutation_type == 5:
                if e_shnum > 1:
                    other_idx = random.randint(0, e_shnum - 1)
                    other_offset = e_shoff + (other_idx * e_shentsize)
                    if other_offset + e_shentsize <= len(data):
                        # swapping two section headers
                        temp = data[sh_offset:sh_offset+e_shentsize]
                        data[sh_offset:sh_offset+e_shentsize] = data[other_offset:other_offset+e_shentsize]
                        data[other_offset:other_offset+e_shentsize] = temp
            
            # create overlapping sections
            elif mutation_type == 6:
                size_offset = sh_offset + 0x20 # sh_size offset
                offset_offset = sh_offset + 0x18 # sh_offset offset
                # make section extend into next section
                if section_idx < e_shnum - 1:
                    next_sh_offset = e_shoff + ((section_idx + 1) * e_shentsize)
                    next_offset = struct.unpack('<Q', data[next_sh_offset+0x18:next_sh_offset+0x20])[0]
                    current_offset = struct.unpack('<Q', data[offset_offset:offset_offset+8])[0]
                    overlap_size = next_offset - current_offset + random.randint(1, 100)
                    data[size_offset:size_offset+8] = struct.pack('<Q', overlap_size)
            
            else: # corrupt the entire section header entry
                data[sh_offset:sh_offset+e_shentsize] = random.randbytes(e_shentsize)
        
        except Exception as e:
            pass
        
        return bytes(data)
    
    def _mutate_program_headers(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            e_phoff = struct.unpack('<Q', data[0x20:0x28])[0]
            e_phnum = struct.unpack('<H', data[0x38:0x3a])[0]
            e_phentsize = struct.unpack('<H', data[0x36:0x38])[0]
            
            if e_phoff == 0 or e_phnum == 0:
                return bytes(data)
            
            # pick a random program header to mutate
            ph_idx = random.randint(0, e_phnum - 1)
            ph_offset = e_phoff + (ph_idx * e_phentsize)
            
            if ph_offset + e_phentsize > len(data):
                return bytes(data)
            
            mutation_type = random.randint(0, 6)
            
            # modify permission flags
            if mutation_type == 0:
                flags_offset = ph_offset + 0x04
                current_flags = struct.unpack('<I', data[flags_offset:flags_offset+4])[0]
                # Toggle RWX bits (PF_X=1, PF_W=2, PF_R=4)
                new_flags = current_flags ^ random.choice([1, 2, 4, 7])
                data[flags_offset:flags_offset+4] = struct.pack('<I', new_flags)
            
            # mismatch p_memsz and p_filesz
            elif mutation_type == 1:
                filesz_offset = ph_offset + 0x20
                memsz_offset = ph_offset + 0x28
                
                filesz = struct.unpack('<Q', data[filesz_offset:filesz_offset+8])[0]
                new_memsz = filesz + random.choice([0x1000, 0x10000, 0x100000, 0x1000000])
                data[memsz_offset:memsz_offset+8] = struct.pack('<Q', new_memsz)
            
            # p_filesz larger than p_memsz
            elif mutation_type == 2:
                filesz_offset = ph_offset + 0x20
                memsz_offset = ph_offset + 0x28
                
                memsz = struct.unpack('<Q', data[memsz_offset:memsz_offset+8])[0]
                new_filesz = memsz + random.randint(1, 1000)
                data[filesz_offset:filesz_offset+8] = struct.pack('<Q', new_filesz)
            # modify segment offset
            elif mutation_type == 3:
                offset_offset = ph_offset + 0x08
                current_offset = struct.unpack('<Q', data[offset_offset:offset_offset+8])[0]
                new_offset = current_offset + random.choice([-1, 1, -8, 8, 0x100, -0x100])
                if new_offset < 0:
                    new_offset = 0
                data[offset_offset:offset_offset+8] = struct.pack('<Q', new_offset)
            
            # change segment type
            elif mutation_type == 4:
                type_offset = ph_offset
                new_type = random.choice([0, 1, 2, 3, 4, 5, 6, 7])
                data[type_offset:type_offset+4] = struct.pack('<I', new_type)
            
            # mutate virtual address
            elif mutation_type == 5:
                vaddr_offset = ph_offset + 0x10
                current_vaddr = struct.unpack('<Q', data[vaddr_offset:vaddr_offset+8])[0]
                # try various virtual address mutations
                mutation_choice = random.randint(0, 5)
                if mutation_choice == 0:  # unaligned address
                    new_vaddr = current_vaddr + random.choice([1, 3, 5, 7])
                elif mutation_choice == 1:  # very high address
                    new_vaddr = random.choice([0x7fffffffffff, 0xffffffffffffffff, 0x8000000000000000])
                elif mutation_choice == 2:  # very low address
                    new_vaddr = random.choice([0, 1, 2, 4, 8, 16])
                elif mutation_choice == 3:  # off-by-one from page boundary
                    new_vaddr = (current_vaddr & ~0xfff) + random.choice([0xfff, 0x1000, 0x1001, -1])
                elif mutation_choice == 4:  # random offset from current
                    new_vaddr = current_vaddr + random.choice([-0x1000, 0x1000, -0x100, 0x100, -1, 1])
                else:
                    new_vaddr = random.randint(0, 0xffffffffffffffff)
                
                if new_vaddr < 0:
                    new_vaddr = 0
                data[vaddr_offset:vaddr_offset+8] = struct.pack('<Q', new_vaddr)
            
            # mutate alignment requirements
            else:
                align_offset = ph_offset + 0x30
                # mutate with invalid or problematic alignments
                mutation_choice = random.randint(0, 5)
                if mutation_choice == 0:  # non-power-of-2 alignment
                    new_align = random.choice([3, 5, 6, 7, 9, 10, 100, 1000])
                elif mutation_choice == 1:  # very large alignment
                    new_align = random.choice([0x100000, 0x1000000, 0x10000000, 0x100000000])
                elif mutation_choice == 2:  # zero or one
                    new_align = random.choice([0, 1])
                elif mutation_choice == 3:  # common but possibly problematic
                    new_align = random.choice([2, 4, 8, 16, 32, 64, 128, 256, 512])
                elif mutation_choice == 4:  # maximum value
                    new_align = 0xffffffffffffffff
                else: # negative values (which will wrap around)
                    new_align = random.choice([0xfffffffffffffffe, 0xffffffffffffffff])
                
                data[align_offset:align_offset+8] = struct.pack('<Q', new_align)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_symbol_table(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            symbol_tables = []
            for section in self.elf_obj.iter_sections():
                if isinstance(section, SymbolTableSection):
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    entsize = section['sh_entsize']
                    
                    if sh_offset + sh_size > len(data):
                        continue
                    
                    num_symbols = sh_size // entsize if entsize > 0 else 0
                    if num_symbols == 0:
                        continue
                    
                    symbol_tables.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'entsize': entsize,
                        'num_symbols': num_symbols,
                        'name': section.name
                    })

            if not symbol_tables:
                return bytes(data)

            chosen_table = random.choice(symbol_tables)
            sym_idx = random.randint(0, chosen_table['num_symbols'] - 1)
            sym_offset = chosen_table['offset'] + (sym_idx * chosen_table['entsize'])
            
            mutation_type = random.randint(0, 3)
            
            # change symbol type/binding
            if mutation_type == 0:
                info_offset = sym_offset + 0x04
                current_info = data[info_offset]
                # change binding (bits 4-7) or type (bits 0-3)
                new_binding = random.choice([0, 1, 2, 10, 13]) << 4  # STB_*
                new_type = random.choice([0, 1, 2, 3, 4, 5, 6])      # STT_*
                data[info_offset] = new_binding | new_type
            
            # change symbol value
            elif mutation_type == 1:
                value_offset = sym_offset + 0x08
                current_value = struct.unpack('<Q', data[value_offset:value_offset+8])[0]
                new_value = current_value ^ random.randint(1, 0xFFFFFFFF)
                data[value_offset:value_offset+8] = struct.pack('<Q', new_value)
            
            # change symbol size
            elif mutation_type == 2:
                size_offset = sym_offset + 0x10
                new_size = random.choice([0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF])
                data[size_offset:size_offset+8] = struct.pack('<Q', new_size)
            
            else:
                data[sym_offset:sym_offset+chosen_table['entsize']] = random.randbytes(chosen_table['entsize'])
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_string_table(self, data):
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            # First, collect all string tables
            string_tables = []
            for section in self.elf_obj.iter_sections():
                if section.name in ['.strtab', '.shstrtab', '.dynstr']:
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    
                    if sh_offset + sh_size > len(data):
                        continue
                    
                    if sh_size == 0:
                        continue
                    
                    string_tables.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'name': section.name
                    })

            if not string_tables:
                return bytes(data)
            
            chosen_table = random.choice(string_tables)
            sh_offset = chosen_table['offset']
            sh_size = chosen_table['size']
            
            mutation_type = random.randint(0, 3)
            
            # insert very long string
            if mutation_type == 0:
                insert_pos = sh_offset + random.randint(0, min(sh_size - 1, 100))
                long_string = b'A' * random.choice([100, 500, 1000, 5000]) + b'\x00'
                end_pos = min(insert_pos + len(long_string), sh_offset + sh_size)
                data[insert_pos:end_pos] = long_string[:end_pos - insert_pos]
            
            # remove null terminators
            elif mutation_type == 1:
                for i in range(sh_offset, min(sh_offset + sh_size, len(data))):
                    if data[i] == 0 and random.random() < 0.3:
                        data[i] = ord('X')
            
            # add weird characters
            elif mutation_type == 2:
                pos = sh_offset + random.randint(0, sh_size - 1)
                if pos < len(data):
                    data[pos] = random.choice([0xFF, 0x00, ord('%'), ord('$'), 0x7F])
            
            # corrupt part of string table
            else:
                corrupt_start = sh_offset + random.randint(0, sh_size // 2)
                corrupt_len = random.randint(1, min(100, sh_size // 4))
                corrupt_end = min(corrupt_start + corrupt_len, sh_offset + sh_size)
                data[corrupt_start:corrupt_end] = random.randbytes(corrupt_end - corrupt_start)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _insert_dummy_section(self, data):
        if not self.elf_obj:
            return data

        data = bytearray(data)

        try:
            e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
            e_shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
            e_shentsize = struct.unpack('<H', data[0x3a:0x3c])[0]
            e_shstrndx = struct.unpack('<H', data[0x3e:0x40])[0]

            if e_shoff == 0 or e_shnum == 0:
                return bytes(data)

            insert_idx = random.randint(0, e_shnum)
            
            dummy_sh = bytearray(e_shentsize)
            struct.pack_into('<I', dummy_sh, 0x00, 0)                               # sh_name (invalid index)
            struct.pack_into('<I', dummy_sh, 0x04, random.choice([1, 2, 3, 8]))     # sh_type (various types)
            struct.pack_into('<Q', dummy_sh, 0x08, random.choice([0x3, 0x6, 0x7]))  # sh_flags (various combos)
            struct.pack_into('<Q', dummy_sh, 0x10, 0)                               # sh_addr
            struct.pack_into('<Q', dummy_sh, 0x18, random.choice([0, len(data), len(data) + 0x1000]))   # sh_offset
            struct.pack_into('<Q', dummy_sh, 0x20, random.choice([0, 0x100, 0x1000, 0x10000]))          # sh_size
            struct.pack_into('<I', dummy_sh, 0x28, 0)                               # sh_link
            struct.pack_into('<I', dummy_sh, 0x2c, 0)                               # sh_info
            struct.pack_into('<Q', dummy_sh, 0x30, random.choice([1, 0x1000, 0x10000]))                 # sh_addralign
            struct.pack_into('<Q', dummy_sh, 0x38, 0)                               # sh_entsize

            insert_pos = e_shoff + (insert_idx * e_shentsize)
            data[insert_pos:insert_pos] = dummy_sh

            data[0x3c:0x3e] = struct.pack('<H', e_shnum + 1)
            
            # If we inserted before or at e_shstrndx we need to increment e_shstrndx
            # because all section indices after insertion point are now shifted by 1
            if insert_idx <= e_shstrndx and e_shstrndx != 0xFFFF:  # SHN_UNDEF check
                new_shstrndx = e_shstrndx + 1
                data[0x3e:0x40] = struct.pack('<H', new_shstrndx)

        except Exception:
            pass

        return bytes(data)

    def _corrupt_magic_bytes(self, data):
        data = bytearray(data)
        data[0:4] = random.choice([
            b'\x7fELF',
            b'\x7fELE',  # last byte off
            b'\x00ELF',  # wrong magic
            b'ELF\x7f',  # reversed
            b'\xFF\xFF\xFF\xFF',
            b'\x00\x00\x00\x00',
        ])
        return bytes(data)
    
    def _mutate_section_contents(self, data):
        """Mutate the actual contents of loadable sections (.text, .rodata, etc.)"""
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            # Find PROGBITS sections with ALLOC flag (loadable sections)
            candidates = []
            for section in self.elf_obj.iter_sections():
                # SHT_PROGBITS type and SHF_ALLOC flag (0x2)
                if section['sh_type'] == 'SHT_PROGBITS' and (section['sh_flags'] & 0x2):
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    
                    if sh_offset + sh_size <= len(data) and sh_size > 0:
                        candidates.append({
                            'offset': sh_offset,
                            'size': sh_size,
                            'name': section.name
                        })
            
            if not candidates:
                return bytes(data)
            
            # Pick a random section to mutate
            chosen = random.choice(candidates)
            off = chosen['offset']
            size = chosen['size']
            
            # Pick a random range within the section to mutate
            start = off + random.randint(0, max(0, size - 1))
            length = random.randint(1, min(64, size - (start - off)))
            
            # Flip bits in the chosen range
            for i in range(start, min(start + length, off + size)):
                data[i] ^= random.randint(1, 255)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_relocations(self, data):
        """Mutate relocation entries (SHT_REL or SHT_RELA sections)"""
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            # Find relocation sections
            reloc_sections = []
            for section in self.elf_obj.iter_sections():
                if section['sh_type'] in ['SHT_REL', 'SHT_RELA']:
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    sh_entsize = section['sh_entsize']
                    
                    if sh_offset + sh_size > len(data) or sh_entsize == 0:
                        continue
                    
                    num_entries = sh_size // sh_entsize
                    if num_entries == 0:
                        continue
                    
                    reloc_sections.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'entsize': sh_entsize,
                        'num_entries': num_entries,
                        'type': section['sh_type'],
                        'name': section.name
                    })
            
            if not reloc_sections:
                return bytes(data)
            
            # Pick a random relocation section
            chosen = random.choice(reloc_sections)
            
            # Pick a random relocation entry
            entry_idx = random.randint(0, chosen['num_entries'] - 1)
            entry_offset = chosen['offset'] + (entry_idx * chosen['entsize'])
            
            mutation_type = random.randint(0, 2)
            
            # Mutate r_offset (offset where relocation applies)
            if mutation_type == 0:
                r_offset_pos = entry_offset + 0x00
                current = struct.unpack('<Q', data[r_offset_pos:r_offset_pos+8])[0]
                new_offset = current + random.choice([-1, 1, -8, 8, 0x100, -0x100, 0x1000])
                if new_offset < 0:
                    new_offset = 0
                data[r_offset_pos:r_offset_pos+8] = struct.pack('<Q', new_offset)
            
            # Mutate r_info (symbol index and relocation type)
            elif mutation_type == 1:
                r_info_pos = entry_offset + 0x08
                current = struct.unpack('<Q', data[r_info_pos:r_info_pos+8])[0]
                # r_info contains: symbol index (upper 32 bits) and type (lower 32 bits)
                # Flip some bits
                new_info = current ^ random.choice([1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0x100000000])
                data[r_info_pos:r_info_pos+8] = struct.pack('<Q', new_info)
            
            # Mutate r_addend (only for RELA entries)
            else:
                if chosen['type'] == 'SHT_RELA' and chosen['entsize'] >= 24:
                    r_addend_pos = entry_offset + 0x10
                    if r_addend_pos + 8 <= len(data):
                        current = struct.unpack('<q', data[r_addend_pos:r_addend_pos+8])[0]  # signed
                        new_addend = current + random.choice([-1, 1, -8, 8, -100, 100, -0x1000, 0x1000])
                        data[r_addend_pos:r_addend_pos+8] = struct.pack('<q', new_addend)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_dynamic_section(self, data):
        """Mutate the dynamic section (SHT_DYNAMIC)"""
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            # Find the dynamic section
            dynamic_sections = []
            for section in self.elf_obj.iter_sections():
                if section['sh_type'] == 'SHT_DYNAMIC':
                    sh_offset = section['sh_offset']
                    sh_size = section['sh_size']
                    sh_entsize = section['sh_entsize']
                    
                    if sh_offset + sh_size > len(data) or sh_entsize == 0:
                        continue
                    
                    num_entries = sh_size // sh_entsize
                    if num_entries == 0:
                        continue
                    
                    dynamic_sections.append({
                        'offset': sh_offset,
                        'size': sh_size,
                        'entsize': sh_entsize,
                        'num_entries': num_entries,
                        'name': section.name
                    })
            
            if not dynamic_sections:
                return bytes(data)
            
            # Pick the first dynamic section (usually only one)
            chosen = dynamic_sections[0]
            
            # Pick a random dynamic entry
            entry_idx = random.randint(0, chosen['num_entries'] - 1)
            entry_offset = chosen['offset'] + (entry_idx * chosen['entsize'])
            
            # Each dynamic entry has: d_tag (8 bytes) and d_un (8 bytes)
            mutation_type = random.randint(0, 2)
            
            # Mutate d_tag (type of dynamic entry)
            if mutation_type == 0:
                d_tag_pos = entry_offset
                # Common DT_* tags: DT_NULL(0), DT_NEEDED(1), DT_STRTAB(5), DT_SYMTAB(6), etc.
                new_tag = random.choice([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                    0x6ffffef5,  # DT_GNU_HASH
                    0x6ffffffe,  # DT_VERNEED
                    0x6fffffff,  # DT_VERNEEDNUM
                    0xffffffff,  # Invalid tag
                    random.randint(0, 0xffffffffffffffff)
                ])
                data[d_tag_pos:d_tag_pos+8] = struct.pack('<Q', new_tag)
            
            # Mutate d_un (value/pointer/address)
            elif mutation_type == 1:
                d_un_pos = entry_offset + 8
                current = struct.unpack('<Q', data[d_un_pos:d_un_pos+8])[0]
                new_val = current + random.choice([-1, 1, -8, 8, 0x100, -0x100, 0x1000, -0x1000])
                if new_val < 0:
                    new_val = 0
                data[d_un_pos:d_un_pos+8] = struct.pack('<Q', new_val)
            
            # Completely randomize the entry
            else:
                data[entry_offset:entry_offset+chosen['entsize']] = random.randbytes(chosen['entsize'])
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _rebuild_string_table_with_pattern(self, data, pattern_type):
        # helper function to rebuild string table with specific heap allocation patterns
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
            e_shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
            e_shentsize = struct.unpack('<H', data[0x3a:0x3c])[0]
            e_shstrndx = struct.unpack('<H', data[0x3e:0x40])[0]
            
            if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
                return bytes(data)
            
            # get the section header string table
            shstrtab_hdr_offset = e_shoff + (e_shstrndx * e_shentsize)
            shstrtab_offset = struct.unpack('<Q', data[shstrtab_hdr_offset + 0x18:shstrtab_hdr_offset + 0x20])[0]
            shstrtab_size = struct.unpack('<Q', data[shstrtab_hdr_offset + 0x20:shstrtab_hdr_offset + 0x28])[0]
            
            if shstrtab_offset >= len(data) or shstrtab_size == 0:
                return bytes(data)
            
            crafted_names = []
            
            if pattern_type == 'off_by_one':
                # names with lengths just under power-of-2 boundaries
                # triggers off-by-one when allocator rounds up
                for length in [7, 15, 23, 31, 39, 47, 55, 63, 127]:
                    name = random.choice([b'A', b'X', b'Z']) * length
                    crafted_names.append(name)
            
            elif pattern_type == 'same_size':
                same_length = random.choice([15, 23, 31, 47, 63])
                for i in range(min(e_shnum, 50)):
                    char = chr(ord('A') + (i % 26)).encode()
                    name = char * same_length
                    crafted_names.append(name)
            
            elif pattern_type == 'alternating':
                for i in range(min(e_shnum, 40)):
                    if i % 2 == 0:
                        name = b'S' * 15
                    else:
                        name = b'L' * 127
                    crafted_names.append(name)
            
            elif pattern_type == 'graduated':
                for i in range(min(e_shnum, 30)):
                    length = 7 + (i * 4)
                    name = b'G' * min(length, 127)
                    crafted_names.append(name)
            
            elif pattern_type == 'exhaustive':
                for i in range(min(e_shnum, 20)):
                    length = random.choice([100, 200, 500, 1000])
                    name = b'C' * length
                    crafted_names.append(name)
            
            elif pattern_type == 'varied':
                lengths = [8, 16, 24, 32, 48, 64, 15, 31, 47, 63]
                for i in range(min(e_shnum, len(lengths) * 3)):
                    length = lengths[i % len(lengths)]
                    name = b'V' * length
                    crafted_names.append(name)
            
            else:
                return bytes(data)
            
            # rebuild the string table with crafted names
            new_strtab = bytearray(b'\x00')
            name_offsets = [0] 
            
            for i, name in enumerate(crafted_names):
                if i + 1 >= e_shnum:
                    break
                offset = len(new_strtab)
                name_offsets.append(offset)
                new_strtab.extend(name + b'\x00')
            
            # pad to original size or larger
            target_size = max(shstrtab_size, len(new_strtab))
            while len(new_strtab) < target_size:
                new_strtab.append(0)
            
            # replace the string table
            end_pos = min(shstrtab_offset + len(new_strtab), len(data))
            data[shstrtab_offset:end_pos] = new_strtab[:end_pos - shstrtab_offset]
            
            # update section header name indices
            for i in range(min(len(name_offsets), e_shnum)):
                sh_offset = e_shoff + (i * e_shentsize)
                if i < len(name_offsets) and sh_offset + 4 <= len(data):
                    struct.pack_into('<I', data, sh_offset, name_offsets[i])
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _mutate_section_names(self, data):
        # mutate section name lengths and content to trigger various heap issues
        # random heap exploitation pattern
        patterns = ['off_by_one', 'same_size', 'alternating', 'graduated', 'exhaustive', 'varied']
        pattern = random.choice(patterns)
        return self._rebuild_string_table_with_pattern(data, pattern)
    
    def _create_many_sections(self, data):
        # create many sections to increase heap allocation pressure
        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
            e_shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
            e_shentsize = struct.unpack('<H', data[0x3a:0x3c])[0]
            
            if e_shoff == 0:
                return bytes(data)
            
            # add many dummy sections to force many heap allocations
            # this can trigger UAF issues when the program tries to cleanup/access them
            num_new_sections = random.randint(30, 100)
            
            for i in range(num_new_sections):
                dummy_sh = bytearray(e_shentsize)
                struct.pack_into('<I', dummy_sh, 0x00, random.randint(0, 200))  # sh_name
                struct.pack_into('<I', dummy_sh, 0x04, random.choice([1, 2, 3, 8]))  # sh_type
                struct.pack_into('<Q', dummy_sh, 0x08, random.choice([0x3, 0x6, 0x7]))  # sh_flags
                struct.pack_into('<Q', dummy_sh, 0x10, 0)  # sh_addr
                struct.pack_into('<Q', dummy_sh, 0x18, len(data))  # sh_offset
                struct.pack_into('<Q', dummy_sh, 0x20, random.randint(0, 1000))  # sh_size
                struct.pack_into('<I', dummy_sh, 0x28, 0)  # sh_link
                struct.pack_into('<I', dummy_sh, 0x2c, 0)  # sh_info
                struct.pack_into('<Q', dummy_sh, 0x30, random.choice([1, 8, 16]))  # sh_addralign
                struct.pack_into('<Q', dummy_sh, 0x38, 0)  # sh_entsize
                
                # append to end of section header table
                append_pos = e_shoff + (e_shnum * e_shentsize)
                data[append_pos:append_pos] = dummy_sh
                e_shnum += 1
            
            # update section count
            struct.pack_into('<H', data, 0x3c, e_shnum)
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _corrupt_section_order(self, data):
        # manipulate section ordering and properties to trigger memory corruption

        if not self.elf_obj:
            return data
        
        data = bytearray(data)
        
        try:
            e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
            e_shnum = struct.unpack('<H', data[0x3c:0x3e])[0]
            e_shentsize = struct.unpack('<H', data[0x3a:0x3c])[0]
            e_shstrndx = struct.unpack('<H', data[0x3e:0x40])[0]
            
            if e_shoff == 0 or e_shnum < 3:
                return bytes(data)
            
            corruption_type = random.randint(0, 3)
            
            if corruption_type == 0:
                # swap section headers to confuse processing order
                if e_shnum > 2:
                    idx1 = random.randint(1, e_shnum - 1)
                    idx2 = random.randint(1, e_shnum - 1)
                    
                    sh1_offset = e_shoff + (idx1 * e_shentsize)
                    sh2_offset = e_shoff + (idx2 * e_shentsize)
                    
                    if sh1_offset + e_shentsize <= len(data) and sh2_offset + e_shentsize <= len(data):
                        temp = data[sh1_offset:sh1_offset + e_shentsize]
                        data[sh1_offset:sh1_offset + e_shentsize] = data[sh2_offset:sh2_offset + e_shentsize]
                        data[sh2_offset:sh2_offset + e_shentsize] = temp
            
            elif corruption_type == 1:
                # make sections point to overlapping or invalid offsets
                for i in range(1, min(e_shnum, 10)):
                    sh_offset = e_shoff + (i * e_shentsize)
                    if sh_offset + e_shentsize <= len(data):
                        # corrupt sh_offset field
                        offset_field = sh_offset + 0x18
                        new_offset = random.choice([0, len(data), len(data) + 0x1000, 0xFFFFFFFF])
                        struct.pack_into('<Q', data, offset_field, new_offset)
            
            elif corruption_type == 2:
                # corrupt section sizes to trigger buffer issues
                for i in range(1, min(e_shnum, 10)):
                    sh_offset = e_shoff + (i * e_shentsize)
                    if sh_offset + e_shentsize <= len(data):
                        size_field = sh_offset + 0x20
                        new_size = random.choice([0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFF, 1, 0])
                        struct.pack_into('<Q', data, size_field, new_size)
            
            else:
                # duplicate section entries
                if e_shnum > 1:
                    src_idx = random.randint(1, e_shnum - 1)
                    dst_idx = random.randint(1, e_shnum - 1)
                    
                    src_offset = e_shoff + (src_idx * e_shentsize)
                    dst_offset = e_shoff + (dst_idx * e_shentsize)
                    
                    if src_offset + e_shentsize <= len(data) and dst_offset + e_shentsize <= len(data):
                        data[dst_offset:dst_offset + e_shentsize] = data[src_offset:src_offset + e_shentsize]
        
        except Exception:
            pass
        
        return bytes(data)
    
    def _malformed_section_count(self, data):
        """Set section count to extreme values to trigger allocation issues"""
        data = bytearray(data)

        new_count = random.choice([
            0,           # no sections
            1,           # just null section
            0xFFFF,      # maximum value
            0x7FFF,      # half max
            100,         # many but reasonable
            500,         # many sections
            1000,
            5000,
            random.randint(50, 200),
        ])
        struct.pack_into('<H', data, 0x3c, new_count)
        
        return bytes(data)
    
    def generate(self):
        yield b""
        yield b"\x7fELF"                    # just magic bytes
        yield b"\x7fELF" + b"\x00" * 100    # magic + padding
        yield self.example_input[:4]        # just header start
        yield self.example_input[:64]       # just ELF header

        for size in [1, 2, 4, 8, 16, 32, 63, 64, 100, 200]:
            if len(self.example_input) > size:
                yield self.example_input[:size]
        
        
        # corrupted magic bytes
        for _ in range(6):
            yield self._corrupt_magic_bytes(self.example_input)
        
        # append/prepend garbage
        for size in [100, 1000, 10000, 100000]:
            yield self.example_input + random.randbytes(size)
        
        for size in [100, 1000, 10000]:
            yield random.randbytes(size) + self.example_input
        
        
        # insert dummy sections
        for _ in range(10):
            yield self._insert_dummy_section(self.example_input)
        
        # random large files with ELF magic
        for _ in range(5):
            size = random.choice([1000, 5000, 10000, 50000])
            random_data = bytearray(random.randbytes(size))
            random_data[0:4] = b'\x7fELF'
            yield bytes(random_data)
        
        # ELF header mutations
        for _ in range(40):
            yield self._mutate_elf_header(self.example_input)
        
        for _ in range(60):
            yield self._mutate_section_names(self.example_input)

        for _ in range(30):
            yield self._create_many_sections(self.example_input)

        for _ in range(40):
            yield self._corrupt_section_order(self.example_input)
        
        # Malformed section counts
        for _ in range(20):
            yield self._malformed_section_count(self.example_input)
        
        # program header mutations
        for _ in range(30):
            yield self._mutate_program_headers(self.example_input)
        
        # symbol table mutations
        for _ in range(30):
            yield self._mutate_symbol_table(self.example_input)

        # section header mutations
        for _ in range(60):
            yield self._mutate_section_headers(self.example_input)
        
        # string table mutations
        for _ in range(40):
            yield self._mutate_string_table(self.example_input)
        
        # section contents mutations (mutate .text, .rodata, etc.)
        for _ in range(30):
            yield self._mutate_section_contents(self.example_input)
        
        # relocation table mutations
        for _ in range(25):
            yield self._mutate_relocations(self.example_input)
        
        # dynamic section mutations
        for _ in range(20):
            yield self._mutate_dynamic_section(self.example_input)

        # combined mutations
        for _ in range(100):
            mutated = self.example_input
            num_mutations = random.randint(2, 4)
            
            for _ in range(num_mutations):
                mutation_func = random.choice([
                    self._mutate_elf_header,
                    self._mutate_section_headers,
                    self._mutate_program_headers,
                    self._mutate_symbol_table,
                    self._mutate_string_table,
                    self._mutate_section_contents,
                    self._mutate_relocations,
                    self._mutate_dynamic_section,
                    self._mutate_section_names,
                    self._create_many_sections,
                    self._corrupt_section_order,
                ])
                mutated = mutation_func(mutated)
            
            yield mutated

        while True:
            yield self.mutate_bytes(self.example_input)