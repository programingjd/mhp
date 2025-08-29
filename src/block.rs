use crate::{K, Nonce};
use blake2::digest::FixedOutput;
use blake2::{Blake2b512, Digest};
use hkdf::SimpleHkdf;

pub(crate) const ITERATION_COUNT: usize = 64;
pub(crate) const BLOCK_SIZE: usize = 1024;
pub(crate) type Block = [u8; BLOCK_SIZE];
pub(crate) const BLOCK_COUNT: usize = 262_144;
pub(crate) const TREE_PROOF_BYTE_COUNT: usize = BLOCK_COUNT.ilog2() as usize * 32;
pub(crate) const CHALLENGE_PROOF_BYTE_COUNT: usize =
    4 + 4 + (BLOCK_SIZE + TREE_PROOF_BYTE_COUNT) * 3;
pub(crate) const FULL_PROOF_BYTE_COUNT: usize = 32 + CHALLENGE_PROOF_BYTE_COUNT * K;
const U64_VALUE_COUNT: u128 = u64::MAX as u128 + 1;

pub(crate) fn challenge_index(merkle_root: &[u8], i: usize) -> usize {
    let mut hasher = Blake2b512::new_with_prefix(merkle_root);
    hasher.update(i.to_le_bytes());
    let hash = hasher.finalize_fixed();
    let seed = u64::from_le_bytes(hash[..8].try_into().unwrap()) as u128;
    (((seed * (BLOCK_COUNT - 2) as u128) / U64_VALUE_COUNT) as usize) + 2
}

pub(crate) fn reference_block_index(index: usize, block: &Block) -> usize {
    let i = index as u64;
    let r1 = mix(u64::from_le_bytes(block[0..8].try_into().unwrap()), i);
    let r2 = mix(u64::from_le_bytes(block[8..16].try_into().unwrap()), i);
    let r = mix(r1, r2) as u128;
    let j = (i - 1) as u128;
    ((r * j) >> 64) as usize
}

pub(crate) fn init_blocks(nonce: Nonce) -> Box<[Block; BLOCK_COUNT]> {
    let mut blocks = Vec::with_capacity(BLOCK_COUNT);
    blocks.push(allocate_block(0u32, nonce));
    blocks.push(allocate_block(1u32, nonce));
    for _ in 2..BLOCK_COUNT {
        blocks.push([0u8; BLOCK_SIZE]);
    }
    for index in 2..BLOCK_COUNT {
        let reference_index = reference_block_index(index, &blocks[index - 1]);
        fill_block(nonce, &mut blocks, index, reference_index);
    }
    blocks.into_boxed_slice().try_into().unwrap()
}

fn allocate_block(i: u32, nonce: Nonce) -> Block {
    let mut hasher = Blake2b512::new_with_prefix(i.to_le_bytes());
    hasher.update(nonce);
    let mut hash = hasher.finalize_fixed();
    for _ in 0..ITERATION_COUNT {
        hash = Blake2b512::digest(&hash);
    }
    let mut allocated = [0u8; BLOCK_SIZE];
    SimpleHkdf::<Blake2b512>::new(Some(nonce), &hash)
        .expand(&[], &mut allocated)
        .expect("failed to expand hash");
    allocated
}

fn fill_block(nonce: Nonce, blocks: &mut [Block], index: usize, reference_index: usize) {
    let mut hasher = Blake2b512::new_with_prefix(blocks[index - 1]);
    hasher.update(blocks[reference_index]);
    let mut hash = hasher.finalize_fixed();
    for _ in 0..ITERATION_COUNT {
        hash = Blake2b512::digest(&hash);
    }
    SimpleHkdf::<Blake2b512>::new(Some(nonce), &hash)
        .expand(&[], &mut blocks[index])
        .expect("failed to expand hash");
}

fn mix(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
        .rotate_left(13)
        .wrapping_add(b)
        .rotate_left(32)
        ^ b
}
