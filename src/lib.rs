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

type RuntimeHasherFunction = unsafe fn(&str) -> u128;
#[no_mangle]
pub static mut RUNTIME_HASHER: RuntimeHasherFunction = crate::hashing::default_hasher;
