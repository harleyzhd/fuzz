#!/usr/bin/env python3
"""
Small helper run as a fresh Python process to perform ptrace single-step on a target binary.

Usage:
  python3 coverage_ptrace_runner.py <binary_path> <step_limit> <timeout_seconds>

Reads stdin and feeds it to the traced child as its stdin.
Outputs a single JSON object on stdout: {"rc": <int|null>, "rips": [<hex...>, ...]}
"""
import os
import sys
import time
import json
import signal
import ctypes
from ctypes import c_ulonglong, c_uint, c_void_p, c_long, c_int, byref

PTRACE_TRACEME = 0
PTRACE_GETREGS = 12
PTRACE_SINGLESTEP = 9

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = c_long
libc.ptrace.argtypes = [c_uint, c_uint, c_void_p, c_void_p]

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", c_ulonglong), ("r14", c_ulonglong), ("r13", c_ulonglong), ("r12", c_ulonglong),
        ("rbp", c_ulonglong), ("rbx", c_ulonglong), ("r11", c_ulonglong), ("r10", c_ulonglong),
        ("r9", c_ulonglong), ("r8", c_ulonglong), ("rax", c_ulonglong), ("rcx", c_ulonglong),
        ("rdx", c_ulonglong), ("rsi", c_ulonglong), ("rdi", c_ulonglong), ("orig_rax", c_ulonglong),
        ("rip", c_ulonglong), ("cs", c_ulonglong), ("eflags", c_ulonglong), ("rsp", c_ulonglong),
        ("ss", c_ulonglong), ("fs_base", c_ulonglong), ("gs_base", c_ulonglong),
        ("ds", c_ulonglong), ("es", c_ulonglong), ("fs", c_ulonglong), ("gs", c_ulonglong),
    ]

def main():
    if len(sys.argv) < 4:
        print(json.dumps({"rc": None, "rips": [], "aborted": False}))
        return 0
    binary_path = sys.argv[1]
    try:
        step_limit = int(sys.argv[2])
    except Exception:
        step_limit = 2000
    try:
        timeout = float(sys.argv[3])
    except Exception:
        timeout = 1.0

    # read all stdin to forward to child
    input_bytes = sys.stdin.buffer.read()

    # create a pipe for child's stdin
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        # child: set up stdin and request being traced, then exec target
        try:
            os.dup2(rfd, 0)
            # close fds in child
            try:
                os.close(wfd)
            except Exception:
                pass
            libc.ptrace(PTRACE_TRACEME, 0, None, None)
            os.execv(binary_path, [binary_path])
        except Exception:
            os._exit(127)
    # parent helper process
    os.close(rfd)
    try:
        if input_bytes:
            os.write(wfd, input_bytes)
        os.close(wfd)
    except Exception:
        try:
            os.close(wfd)
        except Exception:
            pass

    start = time.time()
    rips = []
    steps = 0
    aborted = False
    # wait for child stop after exec/ptrace
    try:
        pid_ret, status = os.waitpid(pid, 0)
    except Exception:
        pid_ret, status = 0, 0

    # single-step loop
    while True:
        if (time.time() - start) > timeout:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
            aborted = True
            break
        if steps >= step_limit:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
            aborted = True
            break
        r = libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)
        if r == -1:
            break
        try:
            pid_ret, status = os.waitpid(pid, 0)
        except Exception:
            break
        if os.WIFEXITED(status):
            rc = os.WEXITSTATUS(status)
            print(json.dumps({"rc": rc, "rips": [hex(x) for x in rips], "aborted": False}))
            return 0
        if os.WIFSIGNALED(status):
            rc = -os.WTERMSIG(status)
            print(json.dumps({"rc": rc, "rips": [hex(x) for x in rips], "aborted": False}))
            return 0
        # stopped: get RIP
        regs = user_regs_struct()
        res = libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
        if res != -1:
            rips.append(int(regs.rip))
        steps += 1

    # try to reap child and return final status if available
    final_rc = None
    try:
        pid_ret, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            final_rc = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            final_rc = -os.WTERMSIG(status)
    except Exception:
        final_rc = None

    # If we aborted due to timeout/step-limit, report aborted=True and rc=null
    if aborted:
        print(json.dumps({"rc": None, "rips": [hex(x) for x in rips], "aborted": True}))
    else:
        print(json.dumps({"rc": final_rc, "rips": [hex(x) for x in rips], "aborted": False}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
