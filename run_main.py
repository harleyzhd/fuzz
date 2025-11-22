import argparse
import subprocess
import sys
import os
import time
import json
import onnx
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import signal
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
    OnnxFuzzer,
)

context.log_level = 'error'  # Reduce pwn noise
context.update(arch='amd64', os='linux')

# Debug flag - set to True to print every iteration's payload
DEBUG_PRINT_PAYLOADS = False
# also allow environment-controlled debug
FUZZ_DEBUG = bool(os.environ.get("FUZZ_DEBUG", "") and os.environ.get("FUZZ_DEBUG") not in ("0", "false", "False"))

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

def start(binary_name, argv=[], *a, binary_override=None, **kwargs):
    binary_path = Path(binary_override) if binary_override else (BINARIES_PATH / binary_name)
    cmd = [str(binary_path)]
    if binary_override and binary_path.suffix == ".py" and not os.access(binary_path, os.X_OK):
        cmd = [sys.executable, str(binary_path)]
    if not binary_path.exists():
        raise FileNotFoundError(f"binary not found: {binary_path}")
    if args.GDB:
        return gdb.debug(cmd + argv, gdbscript=gdb_script, *a, **kwargs)
    elif args.REMOTE:
        # probably dont need this lol
        return remote(sys.argv[1], sys.argv[2], *a, **kwargs)
    else:
        return process(
            cmd + argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            *a,
            **kwargs,
        )


def detect_input_type(data, filename=None):
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
    
    if filename and filename.lower().endswith(".onnx"):
        return 'ONNX'
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
        'ONNX': OnnxFuzzer,
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
    # Negative return code: Python encodes signal terminations as -SIGNUM
    if rc < 0:
        sig = -rc
        try:
            name = signal.Signals(sig).name
        except Exception:
            name = f"SIG{sig}"
        return f"terminated by signal {sig} ({name})"
    # High exit codes (>=129) sometimes indicate 128+SIGNUM
    if rc > 128:
        sig = rc - 128
        try:
            name = signal.Signals(sig).name
        except Exception:
            name = f"SIG{sig}"
        return f"exit {rc} (likely signal {sig} ({name}))"
    return f"exit {rc}"


# seconds to wait for the fuzzer generator to produce the next payload before giving up
GENERATOR_YIELD_TIMEOUT = float(os.environ.get("GENERATOR_YIELD_TIMEOUT", "5.0"))

# Backpressure / safety settings
# maximum queued mutated payloads per generator thread (defaults to small number)
GEN_QUEUE_MAX = int(os.environ.get("GEN_QUEUE_MAX", "4"))
# maximum mutated payload size (bytes) we'll send to the target (truncate if larger)
MAX_MUTATED_SIZE = int(os.environ.get("MAX_MUTATED_SIZE", str(200_000)))
# optional small sleep between iterations to reduce process churn (seconds)
ITER_SLEEP = float(os.environ.get("ITER_SLEEP", "0.0"))
# maximum crashes to record per binary before stopping fuzzing that target
# maximum time to wait for target before treating as hang
PROCESS_TIMEOUT = float(os.environ.get("PROC_WAIT_TIMEOUT", "0.5"))
POLL_INTERVAL = float(os.environ.get("PROC_POLL_INTERVAL", "0.01"))

def _start_generator_thread(gen, q, name):
    """Start one daemon thread per binary that repeatedly pulls from the generator and pushes into q."""
    def runner():
        try:
            while True:
                item = next(gen)
                # put will block if queue is full -> backpressure the generator
                q.put(('value', item))
        except StopIteration:
            q.put(('stop', None))
        except Exception as e:
            q.put(('error', e))

    t = threading.Thread(target=runner, name=f"gen-{name}", daemon=True)
    t.start()
    try:
        print(f"[GEN THREAD START] time={time.time():.3f} gen_id={id(gen)} thread={t.name} active={threading.active_count()}", flush=True)
        # explicit mapping print: which thread serves which binary (and id)
        try:
            print(f"[GEN THREAD MAP] pid={os.getpid()} thread_name={t.name} thread_ident={t.ident} -> binary={name}", flush=True)
        except Exception:
            pass
    except Exception:
        pass
    return t

def _get_from_queue(q, timeout, gen_id=None, tname=None):
    """Get an item from q with timeout and print concise thread visibility lines."""
    try:
        item = q.get(timeout=timeout)
        return item
    except queue.Empty:
        try:
            print(f"[GEN THREAD TIMEOUT] time={time.time():.3f} gen_id={gen_id} thread={tname} timeout={timeout}s", flush=True)
        except Exception:
            pass
        return ('timeout', None)


def fuzz_binary(binary_name, max_time=50, input_path=None, binary_override=None):
    print(f"\n[*] Fuzzing binary: {binary_name}")
    
    input_file = Path(input_path) if input_path else (INPUTS_PATH / f"{binary_name}.txt")
    if not input_file.exists():
        print(f"[!] No example input found for {binary_name} at {input_file}")
        return []
    
    with open(input_file, 'rb') as f:
        valid_input = f.read()
    
    print(f"[*] Loaded valid input ({len(valid_input)} bytes)")
    
    # Detect input type
    input_type = detect_input_type(valid_input, filename=input_file.name)
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
    seen_signatures = set()
    iterations = 0
    start_time = time.time()
    
    # Use the fuzzer's generator to get mutated inputs — start one persistent generator thread per binary
    gen = fuzzer.generate()
    # bounded queue -> prevents unbounded memory growth if generator outpaces consumer
    gen_queue = queue.Queue(maxsize=GEN_QUEUE_MAX)
    print(f"[GEN QUEUE] binary={binary_name} queue_max={GEN_QUEUE_MAX}, max_mutated_size={MAX_MUTATED_SIZE}, iter_sleep={ITER_SLEEP}", flush=True)
    gen_thread = _start_generator_thread(gen, gen_queue, name=binary_name)
    # quick snapshot of threads for visibility: name and identifier, plus process PID
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
            return crashes
        if kind == 'stop':
            break
        if kind == 'error':
            print(f"[!] Error from fuzzer generator: {val}")
            return crashes

        mutated = val
        # ensure mutated is bytes and truncate overly large payloads to avoid spikes
        try:
            if isinstance(mutated, (bytes, bytearray)):
                if len(mutated) > MAX_MUTATED_SIZE:
                    mutated = bytes(mutated[:MAX_MUTATED_SIZE])
            else:
                # convert to bytes safely and truncate
                mb = str(mutated).encode('utf-8', errors='ignore')
                if len(mb) > MAX_MUTATED_SIZE:
                    mb = mb[:MAX_MUTATED_SIZE]
                mutated = mb
        except Exception:
            # fallback: use an empty payload on unexpected issues
            mutated = b""
        
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
            if input_type == 'ONNX':
                try:
                    onnx.load_model_from_string(mutated)
                except Exception as exc:
                    crash_info = {
                        'input': mutated,
                        'exit_code': -6,
                        'iteration': iterations,
                        'desc': f"onnx parse error: {exc}",
                    }
                    crashes.append(crash_info)
                    print(f"[+] ONNX parse error treated as crash: {exc}, Iteration: {iterations}")
                    return crashes
            # Run the binary with mutated input
            p = start(binary_name, binary_override=binary_override)
            try:
                p.send(mutated)
            except Exception as err:
                sig = ("send", str(err))
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    crashes.append({
                        'input': mutated,
                        'error': f"send failure: {err}",
                        'iteration': iterations,
                    })
                    print(f"[+] Crash found (send failure): {err}, Iteration: {iterations}")
                else:
                    print(f"[!] Duplicate crash signature ignored (send failure): {err}")
                try:
                    p.close()
                except Exception:
                    pass
                return crashes

            p.shutdown('send')

            try:
                if hasattr(p, 'poll'):
                    CSV_LONG_WAIT = 1.5    # seconds
                    wait_seconds = PROCESS_TIMEOUT
                    if input_type == 'CSV':
                        wait_seconds = max(wait_seconds, CSV_LONG_WAIT)

                    poll_result = None
                    deadline = time.time() + wait_seconds
                    while time.time() < deadline:
                        try:
                            poll_result = p.poll(block=False)  # type: ignore
                        except Exception:
                            poll_result = getattr(p, 'returncode', None)
                            break
                        if poll_result is not None:
                            break
                        time.sleep(POLL_INTERVAL)

                    if poll_result is None:
                        crashes.append({
                            'input': mutated,
                            'iteration': iterations,
                            'timeout': True,
                            'error': f"process hang >{wait_seconds:.2f}s"
                        })
                        print(f"[!] Potential hang: {binary_name} timed out after {wait_seconds:.2f}s at iteration {iterations}")
                        try:
                            p.close()
                        except Exception:
                            pass
                        continue

                    out = b""
                    try:
                        err_data = p.proc.stderr.read() if hasattr(p.proc, "stderr") else b""
                        if err_data:
                            out += err_data if isinstance(err_data, bytes) else err_data.encode('utf-8', errors='ignore')
                    except Exception:
                        pass
                    try:
                        data = p.recvall(timeout=0.2)
                        out += data
                    except Exception:
                        try:
                            data = p.recv(timeout=0.1)
                            out += data
                        except Exception:
                            pass

                    if poll_result not in (None, 0, 1):
                        desc = describe_exit(poll_result)
                        preview = ""
                        try:
                            preview = out.decode('utf-8', errors='ignore').replace("\n","\\n")
                        except Exception:
                            preview = "<binary output>"

                        if poll_result == 1 and input_type == 'PLAINTEXT':
                            try:
                                p.close()
                            except Exception:
                                pass
                            continue

                        abort_pattern = (
                            "stack smashing detected",
                            "__stack_chk_fail",
                            "stack-buffer-overflow",
                            "Stack smashing detected",
                        )
                        is_stack_smash = False
                        if poll_result in (-6, 134):
                            lower = preview.lower()
                            is_stack_smash = any(pattern.lower() in lower for pattern in abort_pattern)

                        crash_info = {
                            'input': mutated,
                            'exit_code': poll_result,
                            'iteration': iterations,
                            'desc': desc,
                            'output': out
                        }
                        if poll_result in (-6, 134) and not is_stack_smash:
                            crash_info['logical_abort'] = True

                        sig = (
                            "poll",
                            poll_result,
                            crash_info.get('desc'),
                            crash_info.get('logical_abort'),
                            preview[:160],
                        )
                        if sig not in seen_signatures:
                            seen_signatures.add(sig)
                            crashes.append(crash_info)
                            tag = "[+]" if not crash_info.get("logical_abort") else "[!] (logical abort)"
                            print(f"{tag} {desc}, Exit code: {poll_result}, Iteration: {iterations}, preview: {preview[:160]}")
                        else:
                            print(f"[!] Duplicate crash signature ignored for exit {poll_result} iteration {iterations}")
                        try:
                            p.close()
                        except Exception:
                            pass
                        return crashes
            except Exception:
                pass

            p.close()

        except Exception as e:
            # Binary might have crashed before we could interact
            if any(sig in str(e) for sig in ("SIGSEGV", "SIGABRT", "SIGILL", "send failure")):
                sig = ("exception", str(e))
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    crashes.append({
                        'input': mutated,
                        'error': str(e),
                        'iteration': iterations
                    })
                    print(f"[+] Crash found! Error: {str(e)[:50]}, Iteration: {iterations}")
                else:
                    print(f"[!] Duplicate exception crash ignored: {str(e)[:50]}")
                return crashes
        
        if iterations % 100 == 0:
            print(f"[*] Iterations: {iterations}, Time: {int(time.time() - start_time)}s")
    
    # generator finished (either exhausted or loop ended). Log if it finished early.
    elapsed = time.time() - start_time
    if elapsed < max_time and iterations < 5 and (not crashes):
        print(f"[FUZZ INFO] generator for {binary_name} finished after {iterations} iterations (elapsed {elapsed:.2f}s); max_time={max_time}s", flush=True)
    print(f"[*] Finished fuzzing {binary_name}: {iterations} iterations, {len(crashes)} crashes")
    return crashes


def save_results(binary_name, crashes):
    """Save fuzzing results to output file."""
    OUTPUT_PATH.mkdir(exist_ok=True)
    output_file = OUTPUT_PATH / f"bad_{binary_name}.txt"
    json_file = OUTPUT_PATH / f"bad_{binary_name}.json"

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
            if 'timeout' in crash and crash.get('timeout'):
                f.write(f"  Timeout/Hang: True\n")
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
    
    try:
        serializable = []
        for crash in crashes:
            entry = crash.copy()
            if isinstance(entry.get("input"), (bytes, bytearray)):
                entry["input_hex"] = entry["input"].hex()
                entry.pop("input", None)
            if isinstance(entry.get("output"), (bytes, bytearray)):
                entry["output_hex"] = entry["output"].hex()
                entry.pop("output", None)
            serializable.append(entry)
        with open(json_file, "w") as jf:
            json.dump({"target": binary_name, "crash_count": len(crashes), "crashes": serializable}, jf, indent=2)
    except Exception as e:
        print(f"[!] Failed to write JSON summary: {e}")
    print(f"[*] Results saved to {output_file} (and {json_file})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple multi-format fuzzer runner")
    parser.add_argument("-t", "--target", help="Path to a single seed file to fuzz")
    parser.add_argument("-b", "--binary", help="Path to the executable/script to fuzz against")
    parser.add_argument("--max-time", type=float, default=60, help="Seconds to fuzz each target")
    parser.add_argument("legacy", nargs="?", help="Legacy single binary name under binaries/")
    args_ns, leftovers = parser.parse_known_args()
    sys.argv = sys.argv[:1] + leftovers

    print("="*60)
    print("Starting Fuzzer")
    print("="*60)

    target_entries = []  # list of tuples (display_name, input_path, binary_override)
    if args_ns.target:
        input_path = Path(args_ns.target)
        if not input_path.exists():
            print(f"[!] Target seed not found: {input_path}")
            return 1
        if not args_ns.binary:
            print("[!] --binary is required when fuzzing an explicit --target file")
            return 1
        if args_ns.binary and not Path(args_ns.binary).exists():
            print(f"[!] Binary not found: {args_ns.binary}")
            return 1
        target_entries.append((input_path.name, input_path, args_ns.binary))
        print(f"[*] Fuzzing single seed file: {input_path}")
    elif args_ns.legacy:
        legacy_name = args_ns.legacy
        binary_path = BINARIES_PATH / legacy_name
        if not binary_path.exists():
            print(f"[!] Binary not found: {legacy_name}")
            return 1
        if args_ns.binary and not Path(args_ns.binary).exists():
            print(f"[!] Binary not found: {args_ns.binary}")
            return 1
        target_entries.append((legacy_name, None, args_ns.binary))
        print(f"[*] Fuzzing single binary: {legacy_name}")
    else:
        binaries = [f.name for f in BINARIES_PATH.iterdir() if f.is_file()]
        binaries.sort()
        target_entries = [(name, None, None) for name in binaries]
        print(f"[*] Fuzzing all binaries ({len(target_entries)} total)")

    # Determine parallelism:
    # - If FUZZ_PARALLEL env is set, use it.
    # - Otherwise default to os.cpu_count() (logical CPUs) capped by number of binaries.
    #   os.cpu_count() corresponds to your cores/hyperthreads (e.g., 4 on a 4-core VM).
    workers_env = os.environ.get("FUZZ_PARALLEL", "").strip()
    cpu = os.cpu_count() or 1
    if workers_env:
        try:
            workers = max(1, int(workers_env))
        except Exception:
            workers = 1
    else:
        workers = min(max(1, cpu), max(1, len(target_entries)))
    # Hard cap for safety during testing
    HARD_WORKER_LIMIT = 2
    workers_before_cap = workers
    workers = max(1, min(workers, HARD_WORKER_LIMIT, len(target_entries)))
    print(f"[*] Targets to fuzz: {[name for name, _, _ in target_entries]}", flush=True)
    print(f"[*] System logical CPUs (os.cpu_count()) = {cpu}", flush=True)
    print(f"[*] FUZZ_PARALLEL env='{workers_env}' -> requested={workers_before_cap}, using_workers={workers} (hard cap {HARD_WORKER_LIMIT})", flush=True)

    if workers <= 1:
        # Serial (existing) behavior
        for binary_name, input_path, binary_override in target_entries:
            try:
                crashes = fuzz_binary(binary_name, max_time=args_ns.max_time, input_path=input_path, binary_override=binary_override)
                save_results(binary_name, crashes)
            except Exception as e:
                print(f"[!] Error fuzzing {binary_name}: {e}")
                import traceback
                traceback.print_exc()
    else:
        # Parallel execution across binaries
        print(f"[*] Running fuzzing in parallel with {workers} workers")
        def _worker_task(name, ipath, binary_override):
            try:
                crashes = fuzz_binary(name, max_time=args_ns.max_time, input_path=ipath, binary_override=binary_override)
                save_results(name, crashes)
            except Exception as e:
                print(f"[!] Error fuzzing {name}: {e}")
                import traceback
                traceback.print_exc()

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = { ex.submit(_worker_task, name, ipath, bover): name for name, ipath, bover in target_entries }
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
