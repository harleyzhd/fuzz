import subprocess
import sys
import os
import time
import json
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
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


def describe_exit(result):
    """Return a human-readable description for a process return code."""
    if result is None:
        return "TIMEOUT"
    try:
        rc = int(result)
    except Exception:
        return str(result)
    if rc < 0:
        sig = -rc
        try:
            name = signal.Signals(sig).name
        except Exception:
            name = f"SIG{sig}"
        return f"terminated by signal {sig} ({name})"
    if rc > 128:
        sig = rc - 128
        try:
            name = signal.Signals(sig).name
        except Exception:
            name = f"SIG{sig}"
        return f"exit {rc} (likely signal {sig} ({name}))"
    return f"exit {rc}"


# generator / backpressure / safety config
GENERATOR_YIELD_TIMEOUT = float(os.environ.get("GENERATOR_YIELD_TIMEOUT", "5.0"))
GEN_QUEUE_MAX = int(os.environ.get("GEN_QUEUE_MAX", "4"))
MAX_MUTATED_SIZE = int(os.environ.get("MAX_MUTATED_SIZE", str(200_000)))
ITER_SLEEP = float(os.environ.get("ITER_SLEEP", "0.0"))

def _start_generator_thread(gen, q, stop_event, name):
    """Start one daemon thread per binary: pull from gen and push ('value', item)
    or ('stop', None) / ('error', exc) into q. Use timeouts on q.put so thread
    can exit promptly when stop_event is set."""
    def runner():
        try:
            while True:
                item = next(gen)
                # try to enqueue, but break if stop requested
                while not stop_event.is_set():
                    try:
                        q.put(('value', item), timeout=1.0)
                        break
                    except queue.Full:
                        continue
                if stop_event.is_set():
                    return
        except StopIteration:
            while not stop_event.is_set():
                try:
                    q.put(('stop', None), timeout=1.0)
                    break
                except queue.Full:
                    continue
            return
        except Exception as e:
            while not stop_event.is_set():
                try:
                    q.put(('error', e), timeout=1.0)
                    break
                except queue.Full:
                    continue
            return

    t = threading.Thread(target=runner, name=f"gen-{name}", daemon=True)
    t.start()
    try:
        print(f"[GEN THREAD START] time={time.time():.3f} gen_id={id(gen)} thread={t.name} active={threading.active_count()}", flush=True)
        print(f"[GEN THREAD MAP] pid={os.getpid()} thread_name={t.name} thread_ident={t.ident} -> binary={name}", flush=True)
    except Exception:
        pass
    return t

def _get_from_queue(q, timeout, gen_id=None, tname=None):
    try:
        return q.get(timeout=timeout)
    except queue.Empty:
        try:
            print(f"[GEN THREAD TIMEOUT] time={time.time():.3f} gen_id={gen_id} thread={tname} timeout={timeout}s", flush=True)
        except Exception:
            pass
        return ('timeout', None)


def fuzz_binary(binary_name, max_time=50):
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
    
    # Start a bounded producer thread for this binary's generator
    gen = fuzzer.generate()
    gen_queue = queue.Queue(maxsize=GEN_QUEUE_MAX)
    gen_stop_event = threading.Event()
    print(f"[GEN QUEUE] binary={binary_name} queue_max={GEN_QUEUE_MAX}, max_mutated_size={MAX_MUTATED_SIZE}, iter_sleep={ITER_SLEEP}", flush=True)
    gen_thread = _start_generator_thread(gen, gen_queue, gen_stop_event, name=binary_name)
    try:
        print(f"[THREADS SNAPSHOT] pid={os.getpid()} threads={[ (t.name, t.ident) for t in threading.enumerate() ]}", flush=True)
    except Exception:
        pass

    while True:
        kind, val = _get_from_queue(gen_queue, GENERATOR_YIELD_TIMEOUT, gen_id=id(gen), tname=gen_thread.name)
        if kind == 'timeout':
            print(f"[!] Fuzzer generator timed out after {GENERATOR_YIELD_TIMEOUT}s — skipping {binary_name}")
            try:
                gen.close()
            except Exception:
                pass
            gen_stop_event.set()
            try:
                gen_thread.join(timeout=2.0)
            except Exception:
                pass
            return crashes
        if kind == 'stop':
            gen_stop_event.set()
            try:
                gen_thread.join(timeout=2.0)
            except Exception:
                pass
            break
        if kind == 'error':
            print(f"[!] Error from fuzzer generator: {val}")
            gen_stop_event.set()
            try:
                gen_thread.join(timeout=2.0)
            except Exception:
                pass
            return crashes

        mutated = val
        # coerce to bytes and truncate very large payloads
        try:
            if isinstance(mutated, (bytes, bytearray)):
                if len(mutated) > MAX_MUTATED_SIZE:
                    mutated = bytes(mutated[:MAX_MUTATED_SIZE])
            else:
                mb = str(mutated).encode('utf-8', errors='ignore')
                if len(mb) > MAX_MUTATED_SIZE:
                    mb = mb[:MAX_MUTATED_SIZE]
                mutated = mb
        except Exception:
            mutated = b""

        if (time.time() - start_time) >= max_time:
            break

        iterations += 1
        
        if DEBUG_PRINT_PAYLOADS:
            try:
                plen = len(mutated) if isinstance(mutated, (bytes, bytearray)) else 0
            except Exception:
                plen = 0
            print(f"[DEBUG] Iteration {iterations}: Sending {plen} bytes")
            if plen and plen <= 100:
                print(f"[DEBUG] Payload: {mutated}")
            else:
                print(f"[DEBUG] Payload (first 100 bytes): {mutated[:100]}...")
        
        try:
            p = start(binary_name)
            p.send(mutated)
            p.shutdown('send')
            
            try:
                if hasattr(p, 'poll'):
                    result = p.poll(block=False)  # type: ignore
                    if result is None:
                        time.sleep(1.5)
                        result = p.poll(block=False)  # type: ignore

                    # treat as crash if non-zero exit (except 1)
                    if result is not None and result != 0 and result != 1:
                        desc = describe_exit(result)
                        preview = b""
                        try:
                            preview = p.recvall(timeout=0.2)
                        except Exception:
                            try:
                                preview = p.recv(timeout=0.05)
                            except Exception:
                                preview = b""
                        crashes.append({
                            'input': mutated,
                            'exit_code': result,
                            'iteration': iterations,
                            'desc': desc,
                            'output': preview
                        })
                        print(f"[+] Crash found! {desc}, Iteration: {iterations}")
                        try:
                            p.close()
                        except Exception:
                            pass
                        gen_stop_event.set()
                        try:
                            gen_thread.join(timeout=2.0)
                        except Exception:
                            pass
                        return crashes
            except Exception:
                pass
            
            try:
                p.close()
            except Exception:
                pass
            if ITER_SLEEP and ITER_SLEEP > 0:
                time.sleep(ITER_SLEEP)
        except Exception as e:
            if "SIGSEGV" in str(e) or "SIGABRT" in str(e) or "SIGILL" in str(e):
                crashes.append({
                    'input': mutated,
                    'error': str(e),
                    'iteration': iterations
                })
                print(f"[+] Crash found! Error: {str(e)[:50]}, Iteration: {iterations}")
                gen_stop_event.set()
                try:
                    gen_thread.join(timeout=2.0)
                except Exception:
                    pass
                return crashes

        if iterations % 100 == 0:
            print(f"[*] Iterations: {iterations}, Time: {int(time.time() - start_time)}s")
    
    # ensure generator thread cleaned up
    try:
        gen_stop_event.set()
        gen_thread.join(timeout=2.0)
        if gen_thread.is_alive():
            print(f"[WARN] gen thread for {binary_name} still alive at end", flush=True)
    except Exception:
        pass
    print(f"[*] Finished fuzzing {binary_name}: {iterations} iterations, {len(crashes)} crashes")
    return crashes


def save_results(binary_name, crashes):
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
            if 'desc' in crash:
                f.write(f"  Description: {crash['desc']}\n")
            if 'error' in crash:
                f.write(f"  Error: {crash['error']}\n")
            f.write(f"  Input (hex): {crash['input'].hex()}\n")
            f.write(f"  Input (repr): {repr(crash['input'][:100])}\n")
            if 'output' in crash and isinstance(crash['output'], (bytes, bytearray)):
                try:
                    out_preview = crash['output'].decode('utf-8', errors='ignore').replace("\n","\\n")
                except Exception:
                    out_preview = "<binary output>"
                f.write(f"  Output (repr): {repr(out_preview[:200])}\n")
                f.write(f"  Output (hex): {crash['output'].hex()[:400]}\n")
            f.write("\n")
    
    print(f"[*] Results saved to {output_file}")


def main() -> int:
    print("="*60)
    print("Starting Fuzzer")
    print("="*60)
    
    target_binary = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
        target_binary = sys.argv[1]
    
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
        binaries = [f.name for f in BINARIES_PATH.iterdir() if f.is_file()]
        binaries.sort()
        print(f"[*] Fuzzing all binaries ({len(binaries)} total)")
    
    # use the number of logical CPUs as thread amount
    cpu = os.cpu_count() or 1
    threads = cpu if cpu >= 1 else 1
    print(f"[*] Binaries to fuzz: {binaries}", flush=True)
    print(f"[*] System logical CPUs (os.cpu_count()) = {cpu}", flush=True)
    print(f"[*] Using threads = {threads}", flush=True)
    
    if threads <= 1:
        for binary_name in binaries:
            try:
                crashes = fuzz_binary(binary_name, max_time=60)
                save_results(binary_name, crashes)
            except Exception as e:
                print(f"[!] Error fuzzing {binary_name}: {e}")
                import traceback
                traceback.print_exc()
    else:
        print(f"[*] Running fuzzing in parallel with {threads} threads")
        def _worker_task(name):
            try:
                crashes = fuzz_binary(name, max_time=60)
                save_results(name, crashes)
            except Exception as e:
                print(f"[!] Error fuzzing {name}: {e}")
                import traceback
                traceback.print_exc()

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = { ex.submit(_worker_task, name): name for name in binaries }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    fut.result()
                    print(f"[*] Finished {name}")
                except Exception as e:
                    print(f"[!] Worker error for {name}: {e}")
    
    print("\n" + "="*60)
    print("Fuzzing completed successfully")
    print("="*60)
    return 0


if __name__ == '__main__':
    sys.exit(main())