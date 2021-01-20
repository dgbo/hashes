//! An implementation of the [MD5][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! use md5::{Md5, Digest};
//! use hex_literal::hex;
//!
//! // create a Md5 hasher instance
//! let mut hasher = Md5::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("5eb63bbbe01eeed093cb22bb8f5acdc3"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/MD5
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "asm")]
extern crate md5_asm as utils;

#[cfg(not(feature = "asm"))]
mod utils;

pub use digest::{self, Digest};

use crate::utils::compress;

use core::fmt;
use digest::{
    block_buffer::BlockBuffer,
    generic_array::{
        typenum::{Unsigned, U16, U64},
        GenericArray,
    },
    AlgorithmName, FixedOutputCore, Reset, UpdateCore, UpdateCoreWrapper,
};

mod consts;

type Block = GenericArray<u8, U64>;

/// Core MD5 hasher state.
#[derive(Clone)]
pub struct Md5Core {
    block_len: u64,
    state: [u32; 4],
}

impl UpdateCore for Md5Core {
    type BlockSize = U64;

    #[inline]
    fn update_blocks(&mut self, blocks: &[Block]) {
        self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
        for block in blocks {
            compress(&mut self.state, convert(block))
        }
    }
}

impl FixedOutputCore for Md5Core {
    type OutputSize = U16;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        let bit_len = self
            .block_len
            .wrapping_mul(Self::BlockSize::U64)
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);
        let mut s = self.state;
        buffer.len64_padding_le(bit_len, |b| compress(&mut s, convert(b)));
        for (chunk, v) in out.chunks_exact_mut(4).zip(s.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Md5Core {
    #[inline]
    fn default() -> Self {
        Self {
            block_len: 0,
            state: consts::S0,
        }
    }
}

impl Reset for Md5Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Md5Core {
    const NAME: &'static str = "Md5";
}

impl fmt::Debug for Md5Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md5Core { ... }")
    }
}

/// MD5 hasher state.
pub type Md5 = UpdateCoreWrapper<Md5Core>;

#[inline(always)]
fn convert(d: &Block) -> &[u8; 64] {
    #[allow(unsafe_code)]
    unsafe {
        &*(d.as_ptr() as *const [u8; 64])
    }
}
