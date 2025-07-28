use jopcall::hash;
use jopcall::get_syscall;
use jopcall::helper::pick_random;
use jopcall::jop::get_image_memory_sections;
use core::ffi::c_void;
use jopcall::syscall;
use jopcall::jopcall;
use jopcall::get_gadgets;
use jopcall::functioncall;
use core::ptr::null;
use jopcall::RUNTIME_HASHER;

fn main() {
    unsafe {
    // Dynamically finding and calling windows API functions
    let ntstatus = functioncall!(hash!("kernel32.dll"), hash!("WinExec"), b"calc.exe\0".as_ptr() as *const i8, 1 as u32); 
    println!("{}", format!("NTSTATUS Code: {:#x} | Called WinExec to open calc.exe without exposing WinExec in the IAT.", ntstatus));
    // Building our gadget chain by searching through executable memory sections.
    // pop rcx; ret
    let poprcx = get_gadgets!(hash!("ntdll.dll"), &[0x59, 0xc3], 16, 12);
    // jmp rcx;
    let jmprcx = get_gadgets!(hash!("kernelbase.dll"), &[0xff, 0xe1], 16, 12);
    // ret;
    let retgad = get_gadgets!(hash!("userenv.dll"), &[0xc3], 16, 12);
    
    // Shortening the arrays to the size of gadgets returned.
    let poprcx = &poprcx.1[..poprcx.0.unwrap()];
    let jmprcx = &jmprcx.1[..jmprcx.0.unwrap()];
    let retgad = &retgad.1[..retgad.0.unwrap()];
    
    // Retrieving information about the syscall such as its addresss and SSN.
    #[allow(non_snake_case)]
    let NtPowerInformation = get_syscall!(hash!("ntdll.dll"), hash!("NtPowerInformation")).unwrap();
    hash!("NtPowerInformation");  
    // Argument for NtPowerInformation
    let mut outputbuffer: [u64;32] = [0;32];

    // Making a syscall with no gadgets.
    let ntstatus = syscall!(NtPowerInformation, 0 as u32, 0 as usize, 0 as u64, &mut outputbuffer, size_of::<[u64;32]>());
    println!("{}", format!("NTSTATUS Code: {:#x} | Indirect Systemcall without JOP or ROP", ntstatus));

    #[allow(non_snake_case)]
    let NtWriteFile = get_syscall!(hash!("ntdll.dll"), hash!("NtWriteFile")).unwrap();
    
    // Setting up a struct for the NtWriteFile call.
    #[repr(C)]
    struct Iosb {
        status: i32,
        information: u32
    }
    let mut iosb = Iosb {
        status: 0, 
        information: 0
    };

    // Getting the handle for stdout
    let stdouthandle = functioncall!(hash!("kernel32.dll"), hash!("GetStdHandle"), 0_u32.wrapping_sub(11) as u32) as usize;
    let message: &[u8;76] = b"This message was made with indirect syscalls. See the path it took below:\n\n\0"; 
    println!("We're now going to make 10 syscalls in a row, all with different addresses for their gadgets:");
    
    for _i in 0..10{
        // Building a chain of gadgets. The first one in the chain jumps to the syscall, and all
        // others are placed onto the stack in order (LIFO). This implementation selects a random
        // address for each gadget from the selection found earlier.
        let gadgetchain:[*const c_void; 4] = [pick_random(&jmprcx), pick_random(&poprcx), pick_random(&retgad), pick_random(&jmprcx)];  
        let ntstatus = jopcall!(&gadgetchain, NtWriteFile, stdouthandle as *const c_void, null::<*const c_void>(), null::<*const c_void>(), null::<*const c_void>(), &mut iosb as *mut _ as *mut c_void, message.as_ptr() as *const c_void, message.len() as usize, null::<*const c_void>(), 0 as usize);
        
        // Making a syscall through ROP/JOP.
        println!("{}", format!("NTSTATUS Code: {:#x} | R/JOP Chain: {:#x}->{:#x}->{:#x}->{:#x}", ntstatus,  gadgetchain[0] as usize, gadgetchain[1] as usize, gadgetchain[2] as usize, gadgetchain[3] as usize));
    
    };
    

    println!("Now we're going to show rewriting the default hash! to show that you can implement your own hashing.");
    unsafe fn new_hasher(input: &str)->u128 {
        input.len() as u128
    }
    println!("Before we overwrite the built in function: {}", format!("{}", RUNTIME_HASHER("Hello, world!")));
    RUNTIME_HASHER = new_hasher;
    println!("After we overwrite the built in function: {}", format!("{}", RUNTIME_HASHER("Hello, world!")));
    
    }
}
