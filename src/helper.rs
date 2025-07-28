#![allow(non_camel_case_types)]
use core::arch::asm;
// Custom errors to allow for no-std
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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UNICODE_STRING {
    pub length:u16,
    pub maxlength:u16,
    pub buffer:*mut u16,
}

pub fn search_bytes(pattern:&[u8], source:&[u8])->Result<usize, JopcallError> {
    source.windows(pattern.len()).position(|byte| byte == pattern).ok_or(JopcallError::NoByteMatch)
}

// Certainly not a serious randomization algorithm but good enough for these purposes.
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

pub unsafe fn pick_random<T: Clone>(slice:&[T])->T{
    let seed = pseudorandom();
    slice[seed as usize % slice.len()].clone()
}
