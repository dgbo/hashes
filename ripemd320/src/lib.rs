//! An implementation of the [RIPEMD-320][1] cryptographic hash.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use ripemd320::{Ripemd320, Digest};
//!
//! // create a RIPEMD-320 hasher instance
//! let mut hasher = Ripemd320::new();
//!
//! // process input message
//! hasher.update(b"Hello world!");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 40]
//! let result = hasher.finalize();
//! assert_eq!(&result[..], &hex!("
//!     f1c1c231d301abcf2d7daae0269ff3e7bc68e623
//!     ad723aa068d316b056d26b7d1bb6f0cc0f28336d
//! ")[..]);
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
use digest::block_buffer::BlockBuffer;
use digest::consts::{U40, U64};
use digest::generic_array::{GenericArray, typenum::Unsigned};
use digest::{AlgorithmName, FixedOutputCore, Reset, UpdateCore, UpdateCoreWrapper};

mod block;
use block::{compress, DIGEST_BUF_LEN, H0, Block};

/// Core RIPEMD-320 hasher state.
#[derive(Clone)]
pub struct Ripemd320Core {
    h: [u32; DIGEST_BUF_LEN],
    block_len: u64,
}

impl UpdateCore for Ripemd320Core {
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

impl FixedOutputCore for Ripemd320Core {
    type OutputSize = U40;

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

impl Default for Ripemd320Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: H0,
            block_len: 0,
        }
    }
}

impl Reset for Ripemd320Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Ripemd320Core {
    const NAME: &'static str = "Ripemd320";
}

impl fmt::Debug for Ripemd320Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ripemd320Core { ... }")
    }
}

/// RIPEMD-320 hasher state.
pub type Ripemd320 = UpdateCoreWrapper<Ripemd320Core>;
