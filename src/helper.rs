#![allow(non_camel_case_types)]
use core::arch::asm;
// Custom errors to allow for no-std
/// Custom error implementations, their names are fairly self explanatory.
#[derive(Debug)]
pub enum JopcallError {
    NoByteMatch,
    InvalidSSN,
    InvalidAddress,
    NoGadget,
    OverMaxGadgets,
    DllNotFound,
    FunctionNotFound,
}

/// A unicode string struct just for you :)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UNICODE_STRING {
    pub length:u16,
    pub maxlength:u16,
    pub buffer:*mut u16,
}

/// Takes in a string slice pattern of bytes and a source byte slice and returns
/// the position of the requested pattern. So for example,
/// If you called this with search_bytes(&\[0x02\],&\[0x01,0x02,0x03\]) it would return 
/// a usize of 1 (The second item in the slice).
pub fn search_bytes(pattern:&[u8], source:&[u8])->Result<usize, JopcallError> {
    source.windows(pattern.len()).position(|byte| byte == pattern).ok_or(JopcallError::NoByteMatch)
}

// Certainly not a serious randomization algorithm but good enough for these purposes.
/// A very stupid pseudorandom functions to allow you to pick random items from your gadget chains.
pub unsafe fn pseudorandom()->u32{
    let rng:u32;
    asm!(
    "
    xor eax, eax 
    cpuid
    rdtsc
    xor eax, ecx
    shr eax, 2
    xor eax, edx
    shr eax, 2
    xor eax, r8d
    shr eax, 2
    xor eax, r9d
    xchg eax, ecx 
    rdtsc 
    rol eax, cl 
    ",
    out("eax") rng,
    );
    rng
}
/// You can call this function on your gadget chains in order to return a random index so you
/// aren't calling through the same sequence of gadgets every time.
pub unsafe fn pick_random<T: Clone>(slice:&[T])->T{
    let seed = pseudorandom();
    slice[seed as usize % slice.len()].clone()
}
