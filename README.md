# Custom Linux ELF Debugger

A ptrace-based function-call tracer in C for x86-64 Linux, written as a course project. Given a function name and a 64-bit ELF executable, it sets a breakpoint on that function, runs the program, and prints the integer arguments of each call and the return value of each top-level call.

## Additional Contributors
*  https://github.com/InfyfnI

## Features
* **ELF symbol lookup:** reads the ELF header and section headers, finds the symbol table (`SHT_SYMTAB`) and takes the function's address from its `st_value`. The address is used as-is, with no load-base adjustment, so the target must be a non-PIE executable that still has its symbol table.
* **Breakpoints with `ptrace`:** forks and `execv`s the target under `PTRACE_TRACEME`, writes an `int3` (`0xCC`) at the function's entry with `PTRACE_POKETEXT`, and restores the original instruction to continue past it, then re-arms the breakpoint.
* **Call tracing:** for each call, prints up to six integer arguments (from `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`; the count is given on the command line), then, for the outermost call, breaks on its return address and prints the `int` return value from `rax`.
* **Recursion:** recursive entries are reported as nested calls; the return breakpoint checks the stack pointer, so the return value is reported once, for the outermost call.
* Exits with status 1 if the symbol is not found.

---

## Requirements
* x86-64 Linux
* `gcc` (the test script builds with `-std=c99`)

## Usage
```
./prf <sym_name> <number of input params> <elf_path> [optional input params for elf file]
```

## Tests
`run_tests.sh` expects a `./tests` directory, which is not included in this repository. It builds every `.c` file in `./tests` with `gcc -std=c99 *.c -o prf`, then runs 17 cases (20-second timeout each) against target programs `programN.out` and compares the output with `outN.txt`. Case 12 checks that a missing symbol exits with status 1.

To run, place the debugger source, the target programs and the expected outputs in `./tests`, then:
```
chmod +x run_tests.sh
./run_tests.sh
```
`run_tests2.sh` runs the same cases but appends all output to a single `studentout.txt` and keeps the build output.
