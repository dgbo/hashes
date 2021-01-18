use digest::block_buffer::{block_padding::ZeroPadding, BlockBuffer};
use digest::consts::U64;
use digest::generic_array::GenericArray;

use crate::consts::{BLOCK_SIZE, C};
use crate::table::SHUFFLED_LIN_TABLE;

type Block = [u8; 64];

#[derive(Copy, Clone)]
pub(crate) struct StreebogState {
    pub(crate) h: Block,
    pub(crate) n: [u32; 8],
    pub(crate) sigma: Block,
}

#[inline(always)]
fn lps(h: &mut Block, n: &Block) {
    for i in 0..64 {
        h[i] ^= n[i];
    }

    let mut buf = [0u64; 8];

    for i in 0..4 {
        for j in 0..8 {
            let b = h[2 * i + 8 * j] as usize;
            buf[2 * i] ^= SHUFFLED_LIN_TABLE[j][b];
            let b = h[2 * i + 1 + 8 * j] as usize;
            buf[2 * i + 1] ^= SHUFFLED_LIN_TABLE[j][b];
        }
    }

    for (chunk, v) in h.chunks_exact_mut(8).zip(buf.iter()) {
        chunk.copy_from_slice(&v.to_le_bytes());
    }
}

impl StreebogState {
    fn g(&mut self, n: &Block, m: &Block) {
        let mut key = [0u8; 64];
        let mut block = [0u8; 64];

        key.copy_from_slice(&self.h);
        block.copy_from_slice(m);

        lps(&mut key, n);

        #[allow(clippy::needless_range_loop)]
        for i in 0..12 {
            lps(&mut block, &key);
            lps(&mut key, &C[i]);
        }

        for i in 0..64 {
            self.h[i] ^= block[i] ^ key[i] ^ m[i];
        }
    }

    fn update_sigma(&mut self, m: &Block) {
        let mut carry = 0;
        for (a, b) in self.sigma.iter_mut().zip(m.iter()) {
            carry = (*a as u16) + (*b as u16) + (carry >> 8);
            *a = (carry & 0xFF) as u8;
        }
    }

    fn update_n(&mut self, len: u32) {
        let mut carry = 0;
        // note: `len` can not be bigger than block size,
        // so `8*len` will never overflow
        adc(&mut self.n[0], 8 * len, &mut carry);
        adc(&mut self.n[1], 0, &mut carry);
        adc(&mut self.n[2], 0, &mut carry);
        adc(&mut self.n[3], 0, &mut carry);
        adc(&mut self.n[4], 0, &mut carry);
        adc(&mut self.n[5], 0, &mut carry);
        adc(&mut self.n[6], 0, &mut carry);
        adc(&mut self.n[7], 0, &mut carry);
    }

    fn get_n_bytes(&self) -> Block {
        let mut block = [0; 64];
        for (chunk, v) in block.chunks_exact_mut(4).zip(self.n.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
        block
    }

    fn compress(&mut self, block: &GenericArray<u8, U64>, msg_len: u32) {
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        self.g(&self.get_n_bytes(), block);
        self.update_n(msg_len);
        self.update_sigma(block);
    }

    pub(crate) fn update_blocks(&mut self, blocks: &[GenericArray<u8, U64>]) {
        for block in blocks {
            self.compress(block, BLOCK_SIZE as u32);
        }
    }

    pub(crate) fn finalize(&mut self, buffer: &mut BlockBuffer<U64>) {
        let pos = buffer.get_pos();
        let block = buffer.pad_with::<ZeroPadding>();
        block[pos] = 1;
        self.compress(block, pos as u32);
        self.g(&[0u8; 64], &self.get_n_bytes());
        let sigma = self.sigma;
        self.g(&[0u8; 64], &sigma);
    }
}

#[inline(always)]
fn adc(a: &mut u32, b: u32, carry: &mut u32) {
    let ret = (*a as u64) + (b as u64) + (*carry as u64);
    *a = ret as u32;
    *carry = (ret >> 32) as u32;
}
