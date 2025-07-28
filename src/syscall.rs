use core::ffi::c_void;
use crate::helper::{search_bytes, JopcallError};
use core::arch::global_asm;
use core::ptr::slice_from_raw_parts;

/// A struct representing a parsed system call. You are free to modify these if you wanted to do
/// something like make a syscall to a neighbor ala hell's gate or hall or whichever one does that.
/// This also tells you if the syscall is hooked (Some windows APIs are by default) if you'd like
/// to act on that in any way.
#[repr(C)]
#[derive(Debug)]
pub struct Syscall {
    pub ssn:u16,
    pub address:*const c_void,
    pub hooked:bool,
}

/// A macro which makes it much easier to make an indirect syscall via JOP. You first need to
/// provide it a slice of gadgets where the first gadget is used to jump to rcx and the rest are
/// placed on the stack as return values after the syscall. There is a maximum of 5 gadgets. It
/// then takes a syscall struct of the syscall you want to call, and variadic arguments for the
/// NtApi arguments that the syscall takes. 
///
/// gadget_list format:
/// 1: something that ends in jmp rcx without clobbering any registers or misaligning the stack 
/// 2: The address that the syscall returns to 
/// 3+ Any combination of gadgets you want as long as it ends in a ret
#[macro_export]
macro_rules! jopcall {
    // Passed with gadget array as first argument.
    ($gadget_list:expr, $syscall:expr $(,$args:expr)*) => {
        {
            fn enforce_syscall(value:&$crate::syscall::Syscall)->&$crate::syscall::Syscall{
                &value
        }
            fn enforce_slice(value:&[*const c_void])->&[*const c_void]{
                if value.len() > 5 {
                    panic!("Too many gadgets! Provide fewer than 5");
                }
                value
        }
        
        let gadget_list = enforce_slice($gadget_list);
        let gadget_count = gadget_list.len() as u16;
        let pgadget_list = (*(gadget_list.clone())).as_ptr() as *const c_void;
        let syscall = enforce_syscall(&$syscall);
        let ssn = syscall.ssn;
        let address = syscall.address;
        let mut arg_count:u16 = 0;
        $(
            let arg = $args;
            arg_count += 1;
        )*
        let syscall_count = $crate::syscall::SyscallCount(gadget_count, arg_count);
        $crate::syscall::isc(pgadget_list, ssn, address, syscall_count, $($args), *)
        }
    }
}
/// This is a macro to make a syscall without any return address obfuscation. Simply pass the
/// syscall struct of the syscall you want to call and any arguments it takes.
#[macro_export]
macro_rules! syscall{
    // Passed with no gadget list, so it just jumps directly to the syscall and returns 
    // as normal
    ($syscall:expr $(,$args:expr)*) => {
        {
        fn enforce_syscall(value:&$crate::syscall::Syscall)->&$crate::syscall::Syscall{
            &value
        }
        let syscall = enforce_syscall(&$syscall);
        let ssn = syscall.ssn;
        let address = syscall.address;
        let pgadget_list = [syscall.address;1];
        let mut arg_count:u16 = 0;
        $(
            let arg = $args;
            arg_count += 1;
        )*
        let syscall_count = $crate::syscall::SyscallCount(1 as u16, arg_count);
        $crate::syscall::isc(pgadget_list.as_ptr() as *const c_void, ssn, address, syscall_count, $($args), *)
    }
}
}
/// A macro that makes it easier to build the syscall struct. You pass it the hashed name of a dll
/// (Almost certainly ntdll.dll) and the name of the specific syscall (NtWhatever or ZwWhatever)
/// and it will construct the struct for you.
#[macro_export]
macro_rules! get_syscall{
    ($dll_name:expr, $syscall_name:expr) => {
       $crate::syscall::lookup_syscall($crate::pfunction::get_function_pointer($crate::peb_walk::get_dll_base_address($dll_name).unwrap(), $syscall_name)) 
    }
}


// Represents a field passed to the syscall (isc) assembly function below.
// It is formatted this way to allow the counts to be accessible in one 32 bit 
// value split along the E#X / #X delimeter ( so as to not require another register)
// This should be abstracted away from the end user by the macro/functions used to call 
// run_syscall
// (gadget, arg_count)
#[repr(C)]
pub struct SyscallCount(pub u16, pub u16);

/// A raw function to look up a syscall. It takes the memory address of a parsed Nt function and
/// attempts to find the syscall stub and extract the SSN and syscall address from it by using the
/// search_bytes function defined elsewhere in the program. If the function call provided isn't a
/// syscall (For example if it's an RtlWhatever NTApi function) or if it is mangled in some way, it
/// will return an error. This also looks for hooks and will reflect that in the Syscall struct.
/// Note that some legitimate syscalls are hooked by default.
pub unsafe fn lookup_syscall(function_address:*const c_void)->Result<Syscall, JopcallError>{

    // We search for these to avoid EDR hooking. This appears immediately following the ntdll
    // function call if it's a traditional syscall. Without this, it's either hooked or the end
    // user typed in something incorrect
    let ntdll_prefix:&[u8] = &[0x4C, 0x8B, 0xD1, 0xB8];
    // This is a totally arbitrary number of 36 but it's enough to catch NtQuerySystemTime which is
    // a naturally hooked "normal" nt syscall so I'm satisfied with it
    let function_bytes:&[u8] = &*slice_from_raw_parts(function_address as *const u8, 36) as &[u8];
    // I know that this is strange, but if the index returned by this is 0 (meaning it's right at
    // the start), it's equivelant to false, otherwise it's true
    let prefix_offset:usize = match search_bytes(&ntdll_prefix, function_bytes) {
        Ok(index) => index,
        Err(e) => {return Err(e)}
    };
    
    // There are some naturally hooked ntdll syscalls such as NtQuerySystemTime, but this should
    // return on anything that matches the prefix bytes within a size 16 array even if the first
    // argument is a jmp
    let hooked = if prefix_offset > 0 {
        true
    } else {
        false
    };

    // Grabs the next 4 bytes following the ntdll prefix size + the offset to the first byte of the
    // pattern. If not hooked and in most cases, this will just be next 4 bytes after (function_address+4)
    let ssn_bytes:&[u8] = &*slice_from_raw_parts(function_address.cast::<u8>().offset((ntdll_prefix.len() + prefix_offset) as isize) as *const u8, 4) as &[u8];
    
    // Check to ensure there is a valid SSN format.
    if ssn_bytes[2] != 0 && ssn_bytes[3] != 0 {
        return Err(JopcallError::InvalidSSN);
    }
    
    // This is some weird voodoo bullshit shamelessly stolen from hell's gate.
    let ssn:u16 = (ssn_bytes[1] as u16) << 8 | ssn_bytes[0] as u16;
 
    // intel x64 syscall instruction
    let syscall_instruction:&[u8] = &[0x0F, 0x05];
    let syscall_offset:usize = match search_bytes(syscall_instruction,function_bytes) {
        Ok(index) => index,
        Err(e) => {return Err(e)}
    };

    let address:*const c_void = function_address.cast::<u8>().offset(syscall_offset as isize) as *const c_void; 

    Ok(Syscall {
        ssn,
        address,
        hooked
    })
}

// I know that this function name is hardly descriptive, but the name has to match 
// the label in the assembly below and that assembly gets copy pasted with labels included
extern "C" { 
/// Super voodoo bullshit that does a lot of things. I would encourage you not to call this
/// directly, but if you do it takes a list of gadgets as defined in the jopcall macro, the ssn of
/// a syscall, the address of a syscall, and a struct that contains the number of arguments and
/// gadgets passed. It then takes whatever variadic arguments the syscall would take. Note that if
/// you mess up any of these values it will probably crash horribly and the function itself is x64
/// assembly. If you really want to play with this there are a lot of comments in the source code
/// in src/syscall.rs i'd encourage you to look at instead.
    pub fn isc(
    gadget_list:*const c_void,
    ssn:u16,
    addr:*const c_void,
    syscall_count:SyscallCount, 
    ...)->i64;
}

global_asm!(
"
    .global isc
    isc:
    mov [rsp - 0x8], rsi
    mov [rsp - 0x10], rdi 
    mov [rsp - 0x18], r12
    mov [rsp - 0x20], r14
", // Moves gadget_list pointer into r11 and the arg_count struct into rcx
" 
    mov r11, rcx 
    mov rcx, r9
", // Calculates the offset of function parameters by pulling it out of cx
   // register into r14 and bitshifting it left 3 times (equivelant to cx * 8)
"    
    xor r14, r14
    mov r14w, cx
    shl r14w, 3

", // Extracts the number of syscall arguments to rcx
"
    shr ecx, 16 
    movzx ecx, cx
", // Moves r14 into rax and pushes all gadget addresses to the stack except for the first one
"
    mov rax, r14
 
    cmp rax, 0x08
    je 2f
    
    sub rax, 0x08 

    3:
    push [r11 + rax];
    sub rax, 0x08 
    cmp rax, 0
    jne 3b
    
    2:
", // Dereferences the first gadget in the list (jmp rcx) 
"   mov r11, [r11]    


", // Places the SSN into the correct register
"   
    mov eax, edx
    mov r12, r8

", // Moves the first 4 arguments into the proper registers from the stack
"   

    sub r14, 0x08
    mov r10, [rsp + 0x28 + r14]
    mov rdx, [rsp + 0x30 + r14]
    mov r8,  [rsp + 0x38 + r14]
    mov r9,  [rsp + 0x40 + r14]
    
    sub rcx, 0x4 
    jle 4f 

", // Realigns stack arguments to the correct location to be passed to the syscall
"   
    
    lea rsi, [rsp + 0x48 + r14]
    lea rdi, [rsp + 0x28]

    rep movsq

    4:

",  // Places the syscall address into rcx, restores callee registers, and jumps to the first gadget
"   
    mov rcx, r12
    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]
    mov r14, [rsp - 0x20]
    jmp r11
"
);

