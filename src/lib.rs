//! Indirect systemcalls on x64 windows with JOP/ROP support.
//!
//! Provides functions and macros to find and call x64 Windows functions and system calls, 
//! and to obfuscate return addresses through the use of JOP/ROP chains found at runtime.
//! It's also written in no_alloc, no_std rust so it can be compiled to shellcode and offers 
//! support for user defined API hashing.

#![feature(naked_functions)]
#![feature(c_variadic)]
#![no_std]
#![allow(internal_features)]
#![feature(panic_internals)]
pub mod peb_walk;
pub mod pfunction;
pub mod syscall;
pub mod helper;
pub mod jop;
pub mod hashing;

// Re exporting the proc macro all over the floor 
pub use jopcall_proc_macro::*;
/// The function type that any RUNTIME_HASHER needs to be.
type RuntimeHasherFunction = unsafe fn(&str) -> u128;
#[no_mangle]
/// A static variable that you can overwrite with your own hashing function. This means that if you
/// have your own hashing function that returns a u128, you can have the library use that whenever
/// it's searching for strings on the system. Combine this with your own compile time hashing macro
/// to implement custom API hashing.
pub static mut RUNTIME_HASHER: RuntimeHasherFunction = crate::hashing::default_hasher;
