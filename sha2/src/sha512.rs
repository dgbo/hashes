use super::{GenericArray, U128};

cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress;
    } else if #[cfg(all(feature = "asm", any(target_arch = "x86", target_arch = "x86_64")))] {
        fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
            for block in blocks {
                sha2_asm::compress512(state, block);
            }
        }
    } else {
        mod soft;
        use soft::compress;
    }
}

/// SHA-512 compression function.
pub fn compress512(state: &mut [u64; 8], blocks: &[GenericArray<u8, U128>]) {
    // SAFETY: GenericArray<u8, U128> and [u8; 128] have
    // exactly the same memory layout
    #[allow(unsafe_code)]
    let blocks: &[[u8; 128]] = unsafe { &*(blocks as *const _ as *const [[u8; 128]]) };
    compress(state, blocks)
}
