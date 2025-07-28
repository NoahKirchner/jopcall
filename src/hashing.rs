// This is a really bad implementation of the sbdm hashing function with some stolen parts of
// MurmurHash2
/// The built in hashing function. If you intend to replace this, you need to have it  
/// take in a &str and return a u128 that (ideally) doesn't collide.
pub unsafe fn default_hasher(input:&str)->u128 {
    let mut hash:u128 = 0;
    for char in input.chars() {
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
    hash

}
