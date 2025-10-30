# Setup

Remember to set permission for all the binaries - `chmod -R +x /path/to/directory`

# Running the Fuzzer

From inside the Docker container use `./run_fuzzer.sh`

If you want to test specific binary use `python3 run_main.py FILE_NAME`

To fuzz all binaries use `python3 run_main.py`


# Old readme
This folder is a possible example submission.

As a student **you can change any file in this directory except for run_fuzzer.sh**.

We will be providing the `run_fuzzer.sh` file.

You must supply a folder with at least a DockerFile that describes how to build/compile/run your fuzzer.

See the assignment spec for more details.
