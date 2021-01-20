//! An implementation of the [RIPEMD-160][1] cryptographic hash.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use ripemd160::{Ripemd160, Digest};
//!
//! // create a RIPEMD-160 hasher instance
//! let mut hasher = Ripemd160::new();
//!
//! // process input message
//! hasher.update(b"Hello world!");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 20]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("7f772647d88750add82d8e1a7a3e5c0902a346a3"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/RIPEMD
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::BlockBuffer,
    consts::{U20, U64},
    generic_array::{typenum::Unsigned, GenericArray},
    AlgorithmName, FixedOutputCore, UpdateCore, UpdateCoreWrapper,
};

mod block;
use block::{compress, Block, DIGEST_BUF_LEN, H0};

/// Core RIPEMD-160 hasher state.
#[derive(Clone)]
pub struct Ripemd160Core {
    h: [u32; DIGEST_BUF_LEN],
    block_len: u64,
}

impl UpdateCore for Ripemd160Core {
    type BlockSize = U64;

    #[inline]
    fn update_blocks(&mut self, blocks: &[Block]) {
        // Assumes that `block_len` does not overflow
        self.block_len += blocks.len() as u64;
        for block in blocks {
            compress(&mut self.h, block);
        }
    }
}

impl FixedOutputCore for Ripemd160Core {
    type OutputSize = U20;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
        let mut h = self.h;
        buffer.len64_padding_le(bit_len, |block| compress(&mut h, block));

        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Ripemd160Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: H0,
            block_len: 0,
        }
    }
}

impl AlgorithmName for Ripemd160Core {
    const NAME: &'static str = "Ripemd160";
}

impl fmt::Debug for Ripemd160Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd160Core { ... }")
    }
}

/// RIPEMD-160 hasher state.
pub type Ripemd160 = UpdateCoreWrapper<Ripemd160Core>;
