import subprocess
import sys
import os
import time
import json
from pathlib import Path
from pwn import process, remote, gdb, args, context, u64, asm

from fuzzers import (
    BaseFuzzer,
    PlaintextFuzzer,
    JsonFuzzer,
    XmlFuzzer,
    CsvFuzzer,
    JpegFuzzer,
    ElfFuzzer,
    PdfFuzzer,
)

context.log_level = 'error'  # Reduce pwn noise
context.update(arch='amd64', os='linux')

# Debug flag - set to True to print every iteration's payload
DEBUG_PRINT_PAYLOADS = False

BINARIES_PATH = (Path(__file__).parent / "binaries").resolve()
INPUTS_PATH = (Path(__file__).parent / "example_inputs").resolve()
OUTPUT_PATH = (Path(__file__).parent / "fuzzer_output").resolve()

BIN_SH = u64(b'/bin/sh\x00')
BIN_SH_SC = asm(f'''
                mov rbx, {BIN_SH}
                xor rsi, rsi
                xor rdx, rdx
                mov rax, 0x3b
                push rbx
                mov rdi, rsp
                syscall
            ''')

# placeholder for now
gdb_script = """

"""

def start(binary_name, argv=[], *a, **kwargs):
    """Start a process for the given binary."""
    binary_path = BINARIES_PATH / binary_name
    if args.GDB:
        return gdb.debug([str(binary_path)] + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        # probably dont need this lol
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process([str(binary_path)] + argv, *a, **kwargs)


def detect_input_type(data):
    """Detect the input format type from the data."""
    # Check for ELF
    if data.startswith(b'\x7fELF'):
        return 'ELF'
    
    # Check for JPEG
    if data.startswith(b'\xff\xd8\xff'):
        return 'JPEG'
    
    # Check for PDF
    if data.startswith(b'%PDF'):
        return 'PDF'
    
    # Try to parse as JSON
    try:
        json.loads(data.decode('utf-8', errors='ignore'))
        return 'JSON'
    except:
        pass
    
    # Check for XML
    try:
        data_str = data.decode('utf-8', errors='ignore').strip()
        if data_str.startswith('<?xml') or data_str.startswith('<'):
            return 'XML'
    except:
        pass
    
    # Check for CSV (look for comma-separated values)
    try:
        data_str = data.decode('utf-8', errors='ignore')
        lines = data_str.strip().split('\n')
        if len(lines) > 0:
            # Check if first line has commas and consistent column count
            first_line_cols = len(lines[0].split(','))
            if first_line_cols > 1:
                # Check if other lines have similar structure
                consistent = all(len(line.split(',')) == first_line_cols for line in lines[:3])
                if consistent:
                    return 'CSV'
    except:
        pass
    
    # Default to plaintext
    return 'PLAINTEXT'


def get_fuzzer_class(input_type):
    """Return the appropriate fuzzer class for the given input type."""
    fuzzer_map = {
        'PLAINTEXT': PlaintextFuzzer,
        'JSON': JsonFuzzer,
        'XML': XmlFuzzer,
        'CSV': CsvFuzzer,
        'JPEG': JpegFuzzer,
        'ELF': ElfFuzzer,
        'PDF': PdfFuzzer,
    }
    return fuzzer_map.get(input_type, BaseFuzzer)


def fuzz_binary(binary_name, max_time=60):
    """Fuzz a single binary and return results."""
    print(f"\n[*] Fuzzing binary: {binary_name}")
    
    # Load the valid input
    input_file = INPUTS_PATH / f"{binary_name}.txt"
    if not input_file.exists():
        print(f"[!] No example input found for {binary_name}")
        return []
    
    with open(input_file, 'rb') as f:
        valid_input = f.read()
    
    print(f"[*] Loaded valid input ({len(valid_input)} bytes)")
    
    # Detect input type
    input_type = detect_input_type(valid_input)
    print(f"[*] Detected input type: {input_type}")
    
    # Get appropriate fuzzer class and instantiate it
    fuzzer_class = get_fuzzer_class(input_type)
    print(f"[*] Using fuzzer: {fuzzer_class.__name__}")
    
    try:
        fuzzer = fuzzer_class(valid_input)
    except Exception as e:
        print(f"[!] Error initializing fuzzer: {e}")
        return []
    
    crashes = []
    iterations = 0
    start_time = time.time()
    
    # Use the fuzzer's generator to get mutated inputs
    for mutated in fuzzer.generate():
        if (time.time() - start_time) >= max_time:
            break
        
        iterations += 1
        
        if DEBUG_PRINT_PAYLOADS:
            print(f"[DEBUG] Iteration {iterations}: Sending {len(mutated)} bytes")
            if len(mutated) <= 100:
                print(f"[DEBUG] Payload: {mutated}")
            else:
                print(f"[DEBUG] Payload (first 100 bytes): {mutated[:100]}...")
        
        try:
            # Run the binary with mutated input
            p = start(binary_name)
            p.send(mutated)
            p.shutdown('send')
            
            # Wait briefly for crash
            try:
                if hasattr(p, 'poll'):
                    result = p.poll(block=False)  # type: ignore
                    if result is None:
                        # Still running, wait a bit
                        time.sleep(0.1)
                        result = p.poll(block=False)  # type: ignore
                    
                    # Check if it crashed (non-zero exit)
                    # Exit code -6 is SIGABRT (abort()), which doesn't count as a crash
                    if result is not None and result != 0 and result != -6:
                        crashes.append({
                            'input': mutated,
                            'exit_code': result,
                            'iteration': iterations
                        })
                        print(f"[+] Crash found! Exit code: {result}, Iteration: {iterations}")
            except Exception:
                pass
            
            p.close()
            
        except Exception as e:
            # Binary might have crashed before we could interact
            if "SIGSEGV" in str(e) or "SIGABRT" in str(e) or "SIGILL" in str(e):
                crashes.append({
                    'input': mutated,
                    'error': str(e),
                    'iteration': iterations
                })
                print(f"[+] Crash found! Error: {str(e)[:50]}, Iteration: {iterations}")
        
        if iterations % 100 == 0:
            print(f"[*] Iterations: {iterations}, Time: {int(time.time() - start_time)}s")
    
    print(f"[*] Finished fuzzing {binary_name}: {iterations} iterations, {len(crashes)} crashes")
    return crashes


def save_results(binary_name, crashes):
    """Save fuzzing results to output file."""
    OUTPUT_PATH.mkdir(exist_ok=True)
    output_file = OUTPUT_PATH / f"{binary_name}.txt"
    
    with open(output_file, 'w') as f:
        f.write(f"Fuzzing results for {binary_name}\n")
        f.write(f"="*50 + "\n\n")
        f.write(f"Total crashes found: {len(crashes)}\n\n")
        
        for i, crash in enumerate(crashes, 1):
            f.write(f"Crash #{i}:\n")
            f.write(f"  Iteration: {crash['iteration']}\n")
            if 'exit_code' in crash:
                f.write(f"  Exit code: {crash['exit_code']}\n")
            if 'error' in crash:
                f.write(f"  Error: {crash['error']}\n")
            f.write(f"  Input (hex): {crash['input'].hex()}\n")
            f.write(f"  Input (repr): {repr(crash['input'][:100])}\n")
            f.write("\n")
    
    print(f"[*] Results saved to {output_file}")


def main() -> int:
    print("="*60)
    print("Starting Fuzzer")
    print("="*60)
    
    # Check if specific binary was requested
    target_binary = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
        target_binary = sys.argv[1]
    
    # Get list of binaries to fuzz
    binaries = []
    if target_binary:
        binary_path = BINARIES_PATH / target_binary
        if binary_path.exists():
            binaries = [target_binary]
            print(f"[*] Fuzzing single binary: {target_binary}")
        else:
            print(f"[!] Binary not found: {target_binary}")
            return 1
    else:
        # Fuzz all binaries
        binaries = [f.name for f in BINARIES_PATH.iterdir() if f.is_file()]
        binaries.sort()
        print(f"[*] Fuzzing all binaries ({len(binaries)} total)")
    
    # Fuzz each binary
    for binary_name in binaries:
        try:
            crashes = fuzz_binary(binary_name, max_time=60)
            save_results(binary_name, crashes)
        except Exception as e:
            print(f"[!] Error fuzzing {binary_name}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print("Fuzzing completed successfully")
    print("="*60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
