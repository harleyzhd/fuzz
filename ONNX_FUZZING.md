# ONNX Fuzzing: What Changed and How to Use

## Key Changes
- Added aggressive structural mutations in `fuzzers/onnx_fuzzer.py`:
  - Opset/IR tweaks: randomize `ir_version`, bump/down opset versions, add extra blank/odd opset imports.
  - Custom/unknown nodes: inject nodes in a custom domain with new outputs wired into graph outputs.
  - Shape/data mismatches: change initializer dims while altering raw_data length; remove initializers still referenced.
  - Control-flow breakage: damage `If`/`Loop`/`Scan` subgraphs (invalid/missing body).
  - External data hints: mark initializers as `EXTERNAL` pointing to missing blobs.
  - Existing mutations retained (attributes corruption, output shuffling, opset corruption, etc.) plus low-probability random garbage.
- Parser harness (`scripts/run_onnx.py`) aborts on parse/validation errors or “emptied” graphs so crashes are surfaced.
- `run_main.py` supports `--target` for arbitrary files and `--binary` for custom executables/scripts; writes both `.txt` and `.json` reports.

## How to Run
- Single model against the parser harness:  
  `.\venv\bin\python run_main.py --target squeezenet1.1-7.onnx --binary scripts/run_onnx.py --max-time 5`
- Swap in any ONNX file via `--target` and, if needed, a different runtime/runner via `--binary`.
- Outputs land in `fuzzer_output/<target>.txt` and `.json`.

## Quick Effect
- With the current strategies, malformed structural samples typically trigger parse/validation aborts within the first few iterations, giving fast, reproducible crashes.
- For deeper runtime paths, raise `--max-time` and/or `MAX_MUTATED_SIZE`, and point `--binary` to the actual runtime you want to probe (e.g., ONNX Runtime, Triton, etc.).
