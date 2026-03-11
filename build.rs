fn main() {
    let sources = [
        "c/src/common.c",
        "c/src/elf.c",
        "c/src/pe.c",
        "c/src/macho.c",
        "c/src/ptrace_trace.c",
    ];

    cc::Build::new()
        .files(sources)
        .include("c/include")
        .flag("-std=c11")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Wpedantic")
        .compile("eidos_c");

    println!(
        "cargo:rerun-if-changed=c/include/eidos.h"
    );
    println!(
        "cargo:rerun-if-changed=c/include/internal.h"
    );
    for src in sources {
        println!("cargo:rerun-if-changed={src}");
    }
}
