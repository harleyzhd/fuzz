The fuzzer exists in the run_main.py file which has multiple Class structures set up to enable easy modification of implemented file types and addition of future ones. 

When the fuzzer is run it grabs all files either submitted directly too it or that are available within the binaries path. It takes every binary and checks the valid input type before initialising the specific file type fuzzer and running its generate function. 

The classes approach allows us to reuse the fuzz_binary function instead of creating specific functions for each, streamlining debugging and allow us to create change across the whole system rather than just one at a time.

The fuzzer then repeatedly sends the generated data to the target binary and checks to see if the binary has crashed, if this occurs it will print the exact iteration and exit code. It stops fuzzing when either the generated data has run out or the time has exceeded 60 seconds (to enforce to 10 minute maximum run time). Once this has occured it will print the number of interactions and total crashes as well as return the unique crashes..

Once the fuzz_binary function has completed we save the unique crashes to a text file with the same name as the binary. This output contains the interation, exit/ error code, a representation of the input in hexadecimal and the first 100 characters of input represented as a string

Currently we have implemented fuzzing for two file types, .json and .csv. The JSON generator generates a empty files, large files, invalid JSON, files containing format strings, files with deeply nested objects, extremly large numbers for integer overflow and a long string for buffer overflow. 

The JSON class also runs a mutation on some of the parsed data which will randomly either remove a key, add a new key, modify a value, create a deeply nested structure or attempt to duplicate a key (invalid JSON)

The CSV generator uses a similar framework to the JSON fuzzer but focuses on mutating rows and fields in ways that can break CSV parsers. It generates different types of common inputs, such as empty or oversized inputs, and mutates data by changing individual fields (adding quotes, replacing commas, inserting newlines), as well as performing row-level mutations that can reverse, delete, clear, or duplicate entire rows. During fuzzing, the harness sends the generated inputs to the target binary, which monitors for crashes or unexpected exits. 

The XML class has 2 main methods of fuzzing the submitted binaries, firstly it checks a few specific edgecases that commonly cause crashes, these include empty inputs, broken tags and invalid headers. After these have been checked it starts mutating an example input file. There are a significant number of mutations such as invalid utf-8 injection, null byte injection, deleting random chunks of the data, comment injection and even just excessivly large inputs. There are also some non-mutation based inputs such as deep nesting and entity bombs. This covers a wide range on potential bad inputs for xml binaries. 

It is also effective at finding bugs such as buffer overflows, parsing errors, or crashes caused by inconsistent row lengths and invalid delimiters. Future improvements could include adding grammar-aware mutation (respecting proper CSV escaping), feedback-based mutation guidance, and better crash deduplication.
