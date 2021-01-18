use digest::{
    block_buffer::BlockBuffer,
    generic_array::{typenum::U64, GenericArray},
    AlgorithmName, FixedOutputCore, Reset, UpdateCore, UpdateCoreWrapper,
};

use crate::streebog::StreebogState;

/// Core Streebog512 hasher state.
#[derive(Clone)]
pub struct Streebog512Core {
    state: StreebogState,
}

impl Default for Streebog512Core {
    #[inline]
    fn default() -> Self {
        let state = StreebogState {
            h: [0u8; 64],
            n: Default::default(),
            sigma: Default::default(),
        };
        Self { state }
    }
}

impl Reset for Streebog512Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Streebog512Core {
    const NAME: &'static str = "Streebog512";
}

opaque_debug::implement!(Streebog512Core);

impl UpdateCore for Streebog512Core {
    type BlockSize = U64;

    #[inline]
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]) {
        self.state.update_blocks(blocks);
    }
}

impl FixedOutputCore for Streebog512Core {
    type OutputSize = U64;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        self.state.finalize(buffer);
        out.copy_from_slice(&self.state.h)
    }
}

/// Streebog512 hasher state.
pub type Streebog512 = UpdateCoreWrapper<Streebog512Core>;
