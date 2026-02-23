use std::{env, fs, mem};

const DEFAULT_SHELLCODE_PATH: &str = "shellcode.bin";

fn main() {
    // Accept an optional path argument: ./executor [shellcode.bin]
    let args: Vec<String> = env::args().collect();
    let path = if args.len() >= 2 {
        &args[1]
    } else {
        DEFAULT_SHELLCODE_PATH
    };

    let shellcode = fs::read(path).unwrap_or_else(|e| {
        eprintln!("[executor] Error reading '{}': {}", path, e);
        eprintln!(
            "[executor] Usage: {} [path/to/shellcode.bin]",
            args[0]
        );
        std::process::exit(1);
    });

    println!(
        "[executor] Loaded {} bytes from '{}' → executing...",
        shellcode.len(),
        path
    );

    // Allocate an executable region and copy the shellcode into it.
    // SAFETY: We transmute a raw byte slice into a function pointer and call it.
    // This is inherently unsafe — only use in a controlled lab environment.
    let exec_shellcode: extern "C" fn() -> ! =
        unsafe { mem::transmute(shellcode.as_ptr()) };

    exec_shellcode();
}
