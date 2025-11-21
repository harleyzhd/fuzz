# Setup

Remember to set permission for all the binaries - `chmod -R +x /path/to/directory`

# Running the Fuzzer

From inside the Docker container use `./run_fuzzer.sh`

If you want to test specific binary use `python3 run_main.py FILE_NAME`

To fuzz all binaries use `python3 run_main.py`

# Input types

This fuzzer is capable of fuzzing plaintext, JSON, CSV, XML, JPEG, ELF and PDF.

For further information on how this fuzzer works please check the writeup.md file