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

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "asm"))]
mod utils;

pub use digest::{self, Digest};

use crate::utils::compress;

use digest::{
    block_buffer::BlockBuffer,
    generic_array::{
        typenum::{Unsigned, U16, U64},
        GenericArray,
    },
    AlgorithmName, FixedOutputCore, Reset, UpdateCore, UpdateCoreWrapper,
};

mod consts;

/// Core MD5 hasher state.
#[derive(Clone)]
pub struct Md5Core {
    blocks: u64,
    state: [u32; 4],
}

impl Default for Md5Core {
    #[inline]
    fn default() -> Self {
        Self {
            blocks: 0,
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

opaque_debug::implement!(Md5Core);

#[inline(always)]
fn convert(d: &GenericArray<u8, U64>) -> &[u8; 64] {
    #[allow(unsafe_code)]
    unsafe {
        &*(d.as_ptr() as *const [u8; 64])
    }
}

impl UpdateCore for Md5Core {
    type BlockSize = U64;

    #[inline]
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]) {
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.blocks = self.blocks.wrapping_add(blocks.len() as u64);
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
        let bs = Self::BlockSize::U64;
        let len = 8 * (buffer.get_pos() as u64 + bs * self.blocks);
        buffer.len64_padding_le(len, |d| compress(&mut self.state, convert(d)));

        for (chunk, v) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

/// MD5 hasher state.
pub type Md5 = UpdateCoreWrapper<Md5Core>;
