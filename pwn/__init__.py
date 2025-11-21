import subprocess
import time


class _Args:
    GDB = False
    REMOTE = False


args = _Args()


class _ProcWrapper:
    def __init__(self, argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, *a, **kw):
        self.proc = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr)

    def send(self, data):
        if self.proc.stdin:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def shutdown(self, how):
        if how == "send" and self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()

    def poll(self, block=False):
        if block:
            return self.proc.wait()
        return self.proc.poll()

    def recvall(self, timeout=None):
        try:
            out, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            return b""
        data = b""
        if out:
            data += out
        if err:
            data += err
        return data

    def recv(self, timeout=None):
        if self.proc.stdout is None:
            return b""
        if timeout:
            end = time.time() + timeout
            while time.time() < end and self.proc.poll() is None:
                time.sleep(0.01)
        try:
            return self.proc.stdout.read()
        except Exception:
            return b""

    def close(self):
        try:
            self.proc.terminate()
        except Exception:
            pass


def process(argv, *a, **kw):
    return _ProcWrapper(argv, *a, **kw)


def remote(*a, **kw):
    raise NotImplementedError("remote not supported in stub")


def gdb(*a, **kw):
    raise NotImplementedError("gdb not supported in stub")


class _Context:
    log_level = "error"
    arch = "amd64"
    os = "linux"

    def update(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


context = _Context()


def u64(x):
    return 0


def asm(x):
    return b""
