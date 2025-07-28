use core::ffi::c_void;
use core::ptr::slice_from_raw_parts;
use crate::helper::{JopcallError, search_bytes};

const SECTION_HEADER_SIZE:isize = 0x28;
const SECTION_MEM_EXECUTE:u32 = 0x20000000;


#[derive(Copy, Clone, Debug)]
pub struct MemorySection {
    virtual_size:u32,
    address:*const c_void,
    characteristics:u32
}

#[macro_export]
macro_rules! get_gadgets {
    ($dll_name:expr, $gadget_asm:expr, $max_sections:expr, $max_gadgets:expr) => {
        {
        let dll_base_address = $crate::peb_walk::get_dll_base_address($dll_name).unwrap();
        let mut memory_sections:[$crate::jop::MemorySection;$max_gadgets] = [core::mem::zeroed();$max_gadgets];
        let memory_section_count = get_image_memory_sections(dll_base_address, &mut memory_sections);
        let mut gadget_buffer:[*const c_void; $max_gadgets] = [core::ptr::null(); $max_gadgets];
        let gadget_count = $crate::jop::search_gadget($gadget_asm,&memory_sections,&mut gadget_buffer);
        (gadget_count, gadget_buffer)
        }
    }
}

// Takes a mutable reference to a slice and fills it either to the size of the slice or to the
// maximum number of sections, returning the value. If this fails the program will panic so no
// errors
pub unsafe fn get_image_memory_sections<'a>(dll_base_address:*const c_void, section_buffer:&'a mut [MemorySection])->usize{
    let e_lfanew:u32 = *(dll_base_address.cast::<u8>().offset(0x3C) as *const u32);
    let nt_header_address: *const c_void = dll_base_address.cast::<u8>().offset(e_lfanew as isize) as *const c_void;
    let number_of_sections:isize = *(nt_header_address.cast::<u8>().offset(0x06) as *const u16) as isize;
    // Take the number of total sections or the size of the array provided, whichever is less
    let sections_to_read = core::cmp::min(number_of_sections, section_buffer.len() as isize);

    let section_header_address: *const c_void = nt_header_address.cast::<u8>().offset(0x108) as *const c_void; 

    for section_number in 0..sections_to_read{
        let header_address:*const c_void = section_header_address.cast::<u8>().offset(section_number*SECTION_HEADER_SIZE) as *const c_void;
        let rva:u32 = *(header_address.cast::<u8>().offset(0x0C) as *const u32);
        let address = dll_base_address.cast::<u8>().offset(rva as isize) as *const c_void;

        // This is technically the SizeOfRawData field because virtualsize is a union
        let virtual_size:u32 = *(header_address.cast::<u8>().offset(0x10) as *const u32);
        let characteristics = *(header_address.cast::<u8>().offset(0x24) as *const u32);
        section_buffer[section_number as usize] = MemorySection {
            virtual_size,
            address,
            characteristics
        }
    }
    
    return sections_to_read as usize;
}

pub unsafe fn search_gadget<'a>(gadget_asm:&[u8],section_list: &[MemorySection], gadget_buffer:&'a mut [*const c_void])->Result<usize, JopcallError>{
    let gadget_number = gadget_buffer.len();
    let mut gadget_counter:usize = 0;

    // For every section with executable characteristics
    for section in section_list.iter().filter(|section|section.characteristics & SECTION_MEM_EXECUTE != 0) {
        let section_memory:&[u8] = &*slice_from_raw_parts(section.address.cast::<u8>() as *const u8, section.virtual_size as usize);
         
        let mut search_index = 0;
        
        // This searches through the provided memory section, starting from the point of the last
        // found gadget 
        while gadget_number > gadget_counter {
            if gadget_counter >= gadget_number {
                break
            }
            let search_memory = &section_memory[search_index..];
            let gadget = search_bytes(gadget_asm, search_memory);
            match gadget {
                Ok(index) => {
                    gadget_buffer[gadget_counter] = section.address.cast::<u8>().offset((search_index + index) as isize) as *const c_void;
                    // So we don't find the same gadget over and over
                    search_index = search_index+index+gadget_asm.len();
                    gadget_counter+=1;
                },
                Err(_) => {break}
            }
        }

    }

    // If there are no found gadgets, return an error, otherwise return the number of gadgets
    // overwritten in the passed slice
    if gadget_counter == 0 {
        return Err(JopcallError::NoGadget);
    } else {
        return Ok(gadget_counter);
    }
}



