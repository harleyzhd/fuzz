# Start from a default ubuntu image.
FROM ubuntu:22.04

# Install Python so the container can run the Python runner
RUN apt-get update && apt-get install -y python3 python3-pip && rm -rf /var/lib/apt/lists/*

RUN pip install pwntools pikepdf pyelftools

# Copy fuzzer code and dependencies
COPY fuzzer /
COPY run_main.py /
COPY fuzzers/ /fuzzers/
RUN chmod +x /fuzzer

# Run it via the bash wrapper (which calls python3 /run_main.py)
CMD ["/bin/bash", "/fuzzer"]

