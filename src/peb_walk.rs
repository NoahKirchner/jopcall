/*
* Peb walk idek how tf my peb talk
*
* NOTE: This should only be called once probably as it's technically unstable to walk the PEB like
* this as following these links during loading or unloading can cause instability.
*
*
*
*
*/
// What kind of dogshit language nitpicks your variable names constantly?
#![allow(non_camel_case_types)]
use core::ffi::c_void;
use core::ffi::CStr;
use core::arch::asm;
use crate::helper::JopcallError;
use crate::helper::UNICODE_STRING;
use crate::RUNTIME_HASHER;

//@TODO maybe add a 32 bit feature? very big maybe. Also maybe modify this to just be "get dll base
//address" so that it can be used for other things. Again big maybe
pub unsafe fn get_dll_base_address(dll:u128)->Result<*const c_void, JopcallError>{
    // Locally scoped struct for the doubly linked list 
    // @TODO remove debug
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Debug)]
    struct LIST_ENTRY<'a> {
        pub flink: *mut LIST_ENTRY<'a>,
        pub blink: *mut LIST_ENTRY<'a>,
    }
    // Fucking unicode. @TODO(maybe) consider moving this to its own file if necessary.
    
    let peb_address: *const *const c_void;
    // Moves GS Register+0x60 into local variable peb_address
    asm!("mov {}, gs:0x60", out(reg) peb_address);
    // PEB + 0x18 is pointer to PEB ldr address on 64 bit operating systems
    // Offsets are done like this because they are multiples of the type being offset, so 0x18*u64
    // is obviously very different than an 18 byte offset.
    let ldr_address: *const c_void = *(peb_address.cast::<u8>().offset(0x18) as *const *const c_void);
    // Offset from start of peb_ldr_data is 0x20 on x64. This is also the head of the linked list
    // for modules
    
    let in_memory_order_module_list: *const LIST_ENTRY = ldr_address.cast::<u8>().offset(0x20) as *const LIST_ENTRY; 
    let module_list: LIST_ENTRY = *in_memory_order_module_list;

    let mut plink: LIST_ENTRY = *module_list.flink;
    // Guard so we don't endlessly parse through the linked list.
    let guard: LIST_ENTRY = *module_list.flink;
    let dll_base_address: *const c_void;
   
    while *plink.flink != *guard.blink {
        // Our current list entry
        let clink = plink;
        // Dereference plink's flink to point to the item in the list
        let entry = plink.flink as *const c_void;
        // Certified unicode hater
        let dllname:UNICODE_STRING = *(entry.cast::<u8>().offset(0x48) as *const UNICODE_STRING);
        let length = dllname.length;
        let wbuffer = core::slice::from_raw_parts(&*dllname.buffer, length as usize).iter().copied();
        // I anticipate that the maximum size for a dll is 255 chars for compatibility reasons. If
        // not, oops!
        let mut buffer:[u8; 255] = core::mem::zeroed();
        
        // Loop through the enumerated buffer and throw all ascii characters into the buffer. If
        // whitespace, a control character, or something else is encountered then add in a null
        // byte and break.
        for (index, character) in core::char::decode_utf16(wbuffer).enumerate(){
            match character {
                Ok(x) => {
                    if x.is_ascii() && !x.is_control() && !x.is_ascii_whitespace() {
                        buffer[index] = x.to_ascii_lowercase() as u8
                    } else {
                        buffer[index] = 0x00;
                        break;
                    }},
                Err(_) => continue,
            }
            
        }
        
        //@TODO maybe better error handling, but honestly if this crashes then something has
        //probably gone horribly horribly wrong but we'll keep trying.
        let entry_name = match CStr::from_bytes_until_nul(&buffer){
            Ok(x)=>x,
            Err(_)=>continue,
        };

        // @TODO compile time hash this mfer. Also I'm not doing any more error handling i dont
        // care 
        if RUNTIME_HASHER(entry_name.to_str().unwrap()) == dll {
            // InInitializationOrderLinks (Reserved2) !!NOT!! dllbase
            dll_base_address = *(entry.cast::<u8>().offset(0x20) as *const *const c_void);
            return Ok(dll_base_address)
        } else {
            // Iterate to the next field in the linked list.
            plink = *clink.flink;
            continue
        }

    }
    //We're removing all debug information anyway. If this fails we shouldn't do anything BUT
    //panic.
    Err(JopcallError::DllNotFound)
} 




