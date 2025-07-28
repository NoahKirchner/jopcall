#![allow(non_camel_case_types)]
use core::ffi::{c_void, c_char};
use core::ffi::CStr;

use crate::RUNTIME_HASHER;

/// This macro makes it extremely easy to call a windows function from your Rust code without
/// importing it. Simply provide the hashed name of the dll, the hashed name of the function you
/// want to call, and then whichever arguments it requires passed as if they are variadics. Please
/// be very careful about your types, passing the wrong type is undefined behaviour and causes some
/// extremely strange behaviour.
#[macro_export]
macro_rules! functioncall {
    ($dll_name:expr, $function_name:expr $(,$args:expr)*) => {
        {
        let dll_base_address = $crate::peb_walk::get_dll_base_address($dll_name).unwrap();
        let function_pointer = $crate::pfunction::get_function_pointer(dll_base_address, $function_name);
        let function_call: unsafe extern "C" fn(...) -> i64 = core::mem::transmute(function_pointer);
        (function_call)($($args),*)
        }
    }
}


//32 bit compatibility will require a different version of this function, as the NT headers are
//   different depending on this 
/// This takes in a dll base address and a hashed function name, uses a bunch of fixed offsets to
/// parse through the PE and NT header of the provided dll's export address table, and returns a
/// pointer to the requested function to be called or parsed.
pub unsafe fn get_function_pointer(dll_base_address: *const c_void, function_name:u128)->*const c_void{
    
    // Getting export directory 
    //@TODO check for magic number
    let e_lfanew: *const i32 = *dll_base_address.cast::<u8>().offset(0x3C) as *const i32;
    let nt_header_address: *const c_void = dll_base_address.cast::<u8>().offset(e_lfanew as isize) as *const c_void;
    // 0x18 offset found from windbg           dt -r1 nt!_IMAGE_NT_HEADERS64 <PEB_ADDR>+<E_LFANEW>
    let optional_header_address:*const c_void = nt_header_address.cast::<u8>().offset(0x18) as *const c_void;
    
    // Thankfully for us the export directory is the 0th one in the array, but this technically
    // takes us to a linked list of IMAGE_DATA_DIRECTORY structures. The value we're looking for is
    // at 0th offset and is a u32
    let export_directory_rva: *const u32 = optional_header_address.cast::<u8>().offset(0x70) as *const u32;
    let export_directory_address: *const c_void = dll_base_address.cast::<u8>().offset(*export_directory_rva as isize) as *const c_void;
    
    // Parsing table for functions
    //
    // These values can be and are different, specifically for ntdll.
    let number_of_functions: u32 = *(export_directory_address.cast::<u8>().offset(0x14) as *const u32);
    let number_of_names: u32 = *(export_directory_address.cast::<u8>().offset(0x18) as *const u32);
   
    // Constructing tables
    
    // Get the RVAs to the tables 
    let address_of_functions: *const u32 = export_directory_address.cast::<u8>().offset(0x1C) as *const u32;
    let address_of_names: *const u32 = export_directory_address.cast::<u8>().offset(0x20) as *const u32;
    let address_of_ordinals: *const u32 = export_directory_address.cast::<u8>().offset(0x24) as *const u32;

    // Map the tables into arrays equivelant with their values
    let address_table: &[u32] = core::slice::from_raw_parts(dll_base_address.cast::<u8>().offset(*address_of_functions as isize) as *const u32, number_of_functions as usize);
    let name_table: &[u32] = core::slice::from_raw_parts(dll_base_address.cast::<u8>().offset(*address_of_names as isize) as *const u32, number_of_names as usize);
    let ordinal_table: &[u16] = core::slice::from_raw_parts(dll_base_address.cast::<u8>().offset(*address_of_ordinals as isize) as *const u16, number_of_names as usize);

    // Need to do error handling here to return an error if the function isn't found, but I need to
    // figure out how to do this while respecting no_std.
    let name_index = name_table.iter().position(|func_name|

        { 
        let current_name = CStr::from_ptr(dll_base_address.offset(*func_name as isize) as *const c_char).to_str().unwrap();
        RUNTIME_HASHER(current_name) == function_name
        }).unwrap();
        
    let ordinal = ordinal_table[name_index];
    let address = address_table[ordinal as usize];

    dll_base_address.cast::<u8>().offset(address as isize) as *const c_void
    
}
