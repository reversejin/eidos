# eidos
debugger | deobfuscator | binary analysis

## why this exists

I need better tools for reverse engineering and debugging. Most existing options feel clunky or force you into their particular way of doing things. This is my attempt to build something cleaner.

The basic idea: you need both static analysis (looking at the binary) and dynamic analysis (watching it run) to really understand what's going on. Most tools treat these as separate worlds, but they should work together.

## my approach to RE

Most tools make you choose: either you're doing static RE (IDA, Ghidra) or dynamic debugging (gdb, x64dbg). But the interesting stuff happens when you combine both views. Why did this function get called? What data flowed through here? Which branches never execute? You need both perspectives to answer these questions properly.

I also think decompilation is overrated. Sure, pseudocode looks nice, but it's often misleading. The assembly is what actually runs. I'd rather have really good assembly analysis with clear control flow than pretty C code that might be wrong.

For debugging, I want to see execution traces, not just single-step through code. Modern debuggers are stuck in the 1970s — step, step, step, set breakpoint, continue. That's fine for simple bugs, but for complex control flow or obfuscated code, you need to see patterns across many executions. That's where dynamic tracing comes in.

## what i have now

This is still early days. Right now there's:

- Binary parsers for ELF, PE, and Mach-O formats
- Basic block analysis to map out program structure
- Dynamic tracing using Linux ptrace to watch execution
- A way to correlate the static and dynamic views

The static analysis pulls apart binaries to find functions, sections, control flow. The dynamic part traces execution and shows which code paths actually get used. Put them together and you get a clearer picture of what the program really does versus what it could theoretically do.

## how it works

The C layer handles the low-level stuff — parsing binary formats and system calls for tracing. Rust wraps this to make it safer without killing performance.

Static analysis builds control flow graphs from disassembled code. Dynamic tracing captures real execution traces. The interesting bit is combining these — marking static structures with evidence of actual use.

## what's missing

Lots. The control flow analysis is pretty basic right now. GUI doesn't exist yet (planning something like x64dbg but less annoying). Only works on Linux x64.

The goal is eventually having a proper graphical interface for this stuff, but that's down the road. For now, it's more of a proof of concept and a playground for building the core functionality. I want to get the underlying analysis and tracing working well before worrying about making it look good
