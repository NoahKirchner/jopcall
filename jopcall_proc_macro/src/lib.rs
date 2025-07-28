extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};

/// A procedural macro that hashes a &str at compile time so that the RUNTIME_HASHER can find it.
/// If you replace the RUNTIME_HASHER with a custom function, you're likely going to want to
/// replace this too.
#[proc_macro]
pub fn hash(input: TokenStream) -> TokenStream {

    // Parse the input as a string literal
    let input_str = parse_macro_input!(input as LitStr);
    
    // The replacement logic (replace "old" with "new")
    let mut hash:u128 = 0;
        for char in input_str.value().chars() {
            let internal_char = char.to_ascii_lowercase();
            hash = hash.wrapping_mul(65599).wrapping_add(internal_char as u128);
        }

        let mut counter: u32 = 38;
        
        while hash > 0 && counter > 0 {
            hash /= 10;
            hash ^= hash >> 33;
            hash = hash.wrapping_mul(0x5bd1e995);
            counter = counter.wrapping_sub(1);
        }

    // Generate the output as a string literal with the replaced value
    let converted = quote!{#hash};
        
    
    TokenStream::from(converted)
    }
