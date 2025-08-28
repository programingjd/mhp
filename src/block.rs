use crate::Nonce;
use blake2::digest::FixedOutput;
use blake2::{Blake2b512, Digest};
use hkdf::SimpleHkdf;

const BLOCK_SIZE: usize = 1024;
type Block = [u8; BLOCK_SIZE];
const BLOCK_COUNT: usize = 262_144;
pub(crate) const PROOF_BYTE_COUNT: usize = BLOCK_COUNT.ilog2() as usize * 32;
const U64_VALUE_COUNT: u128 = u64::MAX as u128 + 1;

pub(crate) fn challenge_index(merkle_root: &[u8], i: usize) -> usize {
    let mut hasher = Blake2b512::new_with_prefix(merkle_root);
    hasher.update(i.to_le_bytes());
    let hash = hasher.finalize_fixed();
    let seed = u64::from_le_bytes(hash[..8].try_into().unwrap()) as u128;
    (((seed * (BLOCK_COUNT - 2) as u128) / U64_VALUE_COUNT) as usize) + 2
}

pub(crate) fn reference_block_index(index: usize, block: Block) -> usize {
    let i = index as u64;
    let r1 = mix(u64::from_le_bytes(block[0..8].try_into().unwrap()), i);
    let r2 = mix(u64::from_le_bytes(block[8..16].try_into().unwrap()), i);
    let r = mix(r1, r2) as u128;
    let j = (i - 1) as u128;
    ((r * j) >> 64) as usize
}

pub(crate) fn init_blocks(nonce: Nonce) -> [Block; BLOCK_COUNT] {
    let mut blocks = [[0u8; BLOCK_SIZE]; BLOCK_COUNT];
    blocks[0] = new_block(nonce, &0u32.to_le_bytes(), nonce);
    let mut block = new_block(nonce, &1u32.to_le_bytes(), nonce);
    blocks[1] = block;
    for index in 2..BLOCK_COUNT {
        let reference_block = blocks[reference_block_index(index, block)];
        block = new_block(nonce, &block, &reference_block);
        blocks[index] = block;
    }
    blocks
}

fn new_block(nonce: Nonce, input1: &[u8], input2: &[u8]) -> Block {
    let mut hasher = Blake2b512::new_with_prefix(input1);
    hasher.update(input2);
    let hash = hasher.finalize_fixed();
    let mut block = [0u8; BLOCK_SIZE];
    SimpleHkdf::<Blake2b512>::new(Some(nonce), &hash)
        .expand(&[], &mut block)
        .expect("failed to expand hash");
    block
}

fn mix(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
        .rotate_left(13)
        .wrapping_add(b)
        .rotate_left(32)
        ^ b
}
