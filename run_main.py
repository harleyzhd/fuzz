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
import ctypes
from ctypes import c_ulonglong, c_uint, c_void_p, c_long, c_int, byref
import tempfile
import shutil
import shlex
import re
from subprocess import PIPE, Popen, run, TimeoutExpired

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
GEN_QUEUE_MAX = int(os.environ.get("GEN_QUEUE_MAX", "4"))
MAX_MUTATED_SIZE = int(os.environ.get("MAX_MUTATED_SIZE", str(200_000)))

# ptrace constants & helper (minimal prototype)
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = c_long
libc.ptrace.argtypes = [c_uint, c_uint, c_void_p, c_void_p]

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", c_ulonglong),
        ("r14", c_ulonglong),
        ("r13", c_ulonglong),
        ("r12", c_ulonglong),
        ("rbp", c_ulonglong),
        ("rbx", c_ulonglong),
        ("r11", c_ulonglong),
        ("r10", c_ulonglong),
        ("r9", c_ulonglong),
        ("r8", c_ulonglong),
        ("rax", c_ulonglong),
        ("rcx", c_ulonglong),
        ("rdx", c_ulonglong),
        ("rsi", c_ulonglong),
        ("rdi", c_ulonglong),
        ("orig_rax", c_ulonglong),
        ("rip", c_ulonglong),
        ("cs", c_ulonglong),
        ("eflags", c_ulonglong),
        ("rsp", c_ulonglong),
        ("ss", c_ulonglong),
        ("fs_base", c_ulonglong),
        ("gs_base", c_ulonglong),
        ("ds", c_ulonglong),
        ("es", c_ulonglong),
        ("fs", c_ulonglong),
        ("gs", c_ulonglong),
    ]

def _run_with_ptrace_coverage(binary_path: str, input_bytes: bytes, step_limit: int = 2000, timeout: float = 1.0):
    """Run the external ptrace helper as a separate process to avoid forking from multithreaded fuzzer.
    Returns (exit_code, set_of_rips, aborted_flag). The helper prints JSON: {"rc": <int|null>, "rips":[ "0x...","..." ], "aborted": bool }"""
    helper = Path(__file__).parent / "coverage_ptrace_runner.py"
    if not helper.exists():
        return (None, set(), False)

    try:
        proc = Popen([sys.executable, str(helper), str(binary_path), str(step_limit), str(timeout)],
                     stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate(input=input_bytes, timeout=timeout + 1.0)
        try:
            decoded = out.decode('utf-8', errors='ignore').strip()
            if not decoded:
                return (None, set(), False)
            obj = json.loads(decoded)
            rc = obj.get("rc", None)
            rips = obj.get("rips", []) or []
            aborted = bool(obj.get("aborted", False))
            cov = set()
            for h in rips:
                try:
                    cov.add(int(h, 16))
                except Exception:
                    try:
                        cov.add(int(str(h), 0))
                    except Exception:
                        pass
            return (rc, cov, aborted)
        except Exception:
            return (None, set(), False)
    except TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return (None, set(), True)
    except Exception:
        return (None, set(), False)

def _run_with_perf_coverage(binary_path: str, input_bytes: bytes, freq: int = 200, timeout: float = 1.0):
    """Run binary under `perf record` and parse `perf script` output to extract sampled IP addresses.
    Returns (exit_code, set_of_ips). This requires `perf` installed and accessible.
    This is a pragmatic backend — faster than ptrace single-step in many cases, but still heavier than DBI.
    """
    tmpdir = tempfile.mkdtemp(prefix="fuzz_perf_")
    perf_data = os.path.join(tmpdir, "perf.data")
    try:
        # Build perf record command
        # -F freq (samples per second), -o perf.data, -- to separate perf args and command
        cmd = ["perf", "record", "-F", str(freq), "-o", perf_data, "--", binary_path]
        try:
            # Run under a subprocess; supply input_bytes via stdin; capture returncode
            proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            try:
                out, err = proc.communicate(input=input_bytes, timeout=timeout)
            except TimeoutExpired:
                # Timeout: kill perf (and child) and attempt to collect whatever
                proc.kill()
                try:
                    out, err = proc.communicate(timeout=0.5)
                except Exception:
                    out, err = b"", b""
                # treat as timeout
                rc = None
                cov = set()
                return (rc, cov)
            rc = proc.returncode
        except FileNotFoundError:
            # perf not installed
            return (None, set())

        # Now parse perf script
        try:
            ps = run(["perf", "script", "-i", perf_data], stdout=PIPE, stderr=PIPE, timeout=5.0)
            script_out = ps.stdout.decode("utf-8", errors="ignore")
        except Exception:
            script_out = ""
        # Extract hex tokens like 4005d0 or 0x4005d0; we'll normalize to int
        ips = set()
        # regex: 0x... or hex sequence at end of token
        for m in re.finditer(r'0x[0-9a-fA-F]+', script_out):
            try:
                ips.add(int(m.group(0), 16))
            except Exception:
                continue
        # also match bare hex like `4005d0` preceded by space and followed by :
        for m in re.finditer(r'\s([0-9a-fA-F]{3,16}):', script_out):
            try:
                ips.add(int(m.group(1), 16))
            except Exception:
                continue
        return (rc, ips)
    finally:
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass


def _start_generator_thread(gen, q, stop_event, name):
    """Start one daemon thread per binary: pull from gen and push ('value', item)
    or ('stop', None) / ('error', exc) into q. Uses q.put with timeout so thread
    can exit when stop_event is set."""
    def runner():
        try:
            while True:
                item = next(gen)
                # enqueue with timeout so we can check stop_event periodically
                while not stop_event.is_set():
                    try:
                        q.put(('value', item), timeout=1.0)
                        break
                    except queue.Full:
                        continue
                if stop_event.is_set():
                    return
        except StopIteration:
            # try to push stop marker (non-blocking with timeouts)
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
        try:
            print(f"[GEN THREAD MAP] pid={os.getpid()} thread_name={t.name} thread_ident={t.ident} -> binary={name}", flush=True)
        except Exception:
            pass
    except Exception:
        pass
    return t


def _get_from_queue(q, timeout, gen_id=None, tname=None):
    """Get an item from q with timeout; print a concise timeout line for visibility."""
    try:
        item = q.get(timeout=timeout)
        return item
    except queue.Empty:
        try:
            print(f"[GEN THREAD TIMEOUT] time={time.time():.3f} gen_id={gen_id} thread={tname} timeout={timeout}s", flush=True)
        except Exception:
            pass
        return ('timeout', None)


def fuzz_binary(binary_name, max_time=50):
    """
    Simplified fuzz loop: iterate fuzzer.generate(), optionally collect coverage
    (perf preferred, ptrace fallback), accumulate unique PCs (cov_total),
    and fall back to the original process-run behavior when coverage backends
    don't produce results.
    """
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

    # accumulate unique instruction addresses (program counters) seen across all iterations
    cov_total = set()
 
    # Simple generator loop (original-style)
    for mutated in fuzzer.generate():
        # time budget
        if (time.time() - start_time) >= max_time:
            break

        # ensure mutated is bytes and bounded
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
                try:
                    print(f"[DEBUG] Payload (first 100 bytes): {mutated[:100]}...")
                except Exception:
                    pass

        # Use ptrace helper directly for coverage
        binary_path = str((BINARIES_PATH / binary_name).resolve())
        cov = set()
        rc = None
        aborted = False
        rc, cov, aborted = _run_with_ptrace_coverage(
            binary_path,
            mutated,
            step_limit=int(os.environ.get("COV_STEP_LIMIT", "2000")),
            timeout=float(os.environ.get("COV_TIMEOUT", "1.0")),
        )

        # accumulate unique coverage
        try:
            if cov:
                cov_total.update(cov)
        except Exception:
            pass

        # Prefer coverage-run exit code if it indicates a crash (and wasn't aborted).
        # Otherwise *always* run the target normally to detect crashes as the original runner did.
        if (not aborted) and (rc is not None and isinstance(rc, int) and rc != 0 and rc != 1):
            # Coverage-run reported a crash
            desc = describe_exit(rc)
            crashes.append({
                'iteration': iterations,
                'exit_code': rc,
                'desc': desc,
                'input': mutated,
                'cov': cov,
                'total_cov': len(cov_total),
            })
            print(f"[+] Crash found! {desc}, Iteration: {iterations} unique_cov={len(cov_total)}", flush=True)
            try:
                if cov:
                    cov_list = sorted(list(cov))[:8]
                    print(f"    coverage (sample): {', '.join(hex(x) for x in cov_list)}", flush=True)
            except Exception:
                pass
            return crashes

        # Run the target normally (pwntools process) to detect crashes reliably.
        try:
            p = start(binary_name)
            try:
                if mutated:
                    p.send(mutated)
                p.shutdown('send')
            except Exception:
                pass

            try:
                if hasattr(p, 'poll'):
                    result = p.poll(block=False)  # type: ignore
                    if result is None:
                        # short wait like original
                        time.sleep(1.5)
                        result = p.poll(block=False)
                    if result is not None and result != 0 and result != 1:
                        desc = describe_exit(result)
                        out = b""
                        try:
                            out = p.recvall(timeout=0.2)
                        except Exception:
                            try:
                                out = p.recv(timeout=0.05)
                            except Exception:
                                out = b""
                        crashes.append({
                            'input': mutated,
                            'exit_code': result,
                            'iteration': iterations,
                            'desc': desc,
                            'output': out,
                            'total_cov': len(cov_total)
                        })
                        print(f"[+] Crash found! {desc}, Iteration: {iterations} unique_cov={len(cov_total)}")
                        try:
                            p.close()
                        except Exception:
                            pass
                        return crashes
            except Exception:
                pass

            try:
                p.close()
            except Exception:
                pass
        except Exception as e:
            # best-effort crash detection for exceptions while starting/communicating
            if "SIGSEGV" in str(e) or "SIGABRT" in str(e) or "SIGILL" in str(e):
                crashes.append({
                    'input': mutated,
                    'error': str(e),
                    'iteration': iterations
                })
                print(f"[+] Crash found! Error: {str(e)[:50]}, Iteration: {iterations}")
                return crashes

    # Final crash report
    if crashes:
        print(f"\n[*] Fuzzing completed with {len(crashes)} potential crashes detected")
        for i, crash in enumerate(crashes, 1):
            print(f"  Crash #{i}: Iteration {crash['iteration']}, Exit code {crash.get('exit_code')}, Description: {crash.get('desc')}")
    else:
        print(f"\n[*] Fuzzing completed with no crashes detected")

    # Print total unique coverage count (pcs = program counters / instruction addresses)
    try:
        print(f"[COV TOTAL] binary={binary_name} unique_pcs={len(cov_total)}", flush=True)
    except Exception:
        pass

    return crashes


def save_results(binary_name, crashes):
    """Save fuzzing results to output file."""
    OUTPUT_PATH.mkdir(exist_ok=True)
    output_file = OUTPUT_PATH / f"{binary_name}.txt"

    with open(output_file, 'w') as f:
        f.write(f"Fuzzing results for {binary_name}\n")
        f.write("="*50 + "\n\n")
        f.write(f"Total crashes found: {len(crashes)}\n\n")

        for i, crash in enumerate(crashes, 1):
            f.write(f"Crash #{i}:\n")
            f.write(f"  Iteration: {crash.get('iteration')}\n")
            if 'exit_code' in crash:
                f.write(f"  Exit code: {crash['exit_code']}\n")
            # include unique coverage count if available
            if 'total_cov' in crash:
                f.write(f"  Unique coverage (pcs): {crash['total_cov']}\n")
            if 'desc' in crash:
                f.write(f"  Description: {crash['desc']}\n")
            if 'error' in crash:
                f.write(f"  Error: {crash['error']}\n")
            try:
                f.write(f"  Input (hex): {crash['input'].hex()}\n")
            except Exception:
                f.write(f"  Input (hex): <unavailable>\n")
            try:
                f.write(f"  Input (repr): {repr(crash['input'][:100])}\n")
            except Exception:
                f.write(f"  Input (repr): <unavailable>\n")
            if 'output' in crash and isinstance(crash['output'], (bytes, bytearray)):
                try:
                    out_preview = crash['output'].decode('utf-8', errors='ignore').replace("\n","\\n")
                except Exception:
                    out_preview = "<binary output>"
                f.write(f"  Output (repr): {repr(out_preview[:200])}\n")
                try:
                    f.write(f"  Output (hex): {crash['output'].hex()[:400]}\n")
                except Exception:
                    f.write(f"  Output (hex): <unavailable>\n")
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
        binaries = [f.name for f in BINARIES_PATH.iterdir() if f.is_file()]
        binaries.sort()
        print(f"[*] Fuzzing all binaries ({len(binaries)} total)")

    # use the number of logical CPUs as worker count
    cpu = os.cpu_count() or 1
    workers = cpu if cpu >= 1 else 1
    print(f"[*] System logical CPUs (os.cpu_count()) = {cpu}", flush=True)
    print(f"[*] Using workers = {workers}", flush=True)

    if workers <= 1:
        for binary_name in binaries:
            try:
                crashes = fuzz_binary(binary_name, max_time=600)
                save_results(binary_name, crashes)
            except Exception as e:
                print(f"[!] Error fuzzing {binary_name}: {e}")
                import traceback
                traceback.print_exc()
    else:
        print(f"[*] Running fuzzing in parallel with {workers} workers")
        def _worker_task(name):
            try:
                crashes = fuzz_binary(name, max_time=600)
                save_results(name, crashes)
            except Exception as e:
                print(f"[!] Error fuzzing {name}: {e}")
                import traceback
                traceback.print_exc()

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = { ex.submit(_worker_task, name): name for name in binaries }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    fut.result()
                    print(f"[*] Finished {name}")
                except Exception as e:
                    print(f"[!] Worker error for {name}: {e}")

    print("\n" + "="*60)
    print("Fuzzing completed")
    print("="*60)
    return 0


if __name__ == '__main__':
    sys.exit(main())