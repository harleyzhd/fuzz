import os
import sys
import onnx
from onnx import checker

def main():
    data = sys.stdin.buffer.read()
    if not data:
        print("empty input")
        return 0
    try:
        model = onnx.load_model_from_string(data)
        # If parsing produced a nearly-empty graph relative to the input bytes, treat as corrupt.
        if len(model.graph.node) == 0 or len(model.graph.output) == 0 or model.ByteSize() * 2 < len(data):
            os.abort()
        checker.check_model(model)
        return 0
    except Exception as exc:
        print(f"[onnx] error: {exc}", file=sys.stderr)
        os.abort()

if __name__ == "__main__":
    sys.exit(main())
