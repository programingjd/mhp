use crate::hasher::HASH_LENGTH;
use crate::{K, Nonce};
use blake2::digest::FixedOutput;
use blake2::{Blake2b, Blake2b512, Digest};
use hkdf::SimpleHkdf;

pub(crate) const ITERATION_COUNT: usize = 32;
pub(crate) const BLOCK_SIZE: usize = 1024;
pub(crate) type Block = [u8; BLOCK_SIZE];
pub(crate) const CHAIN_BLOCK_COUNT: usize = 131_072;
pub(crate) const TOTAL_BLOCK_COUNT: usize = CHAIN_BLOCK_COUNT * 2;
pub(crate) const TREE_PROOF_BYTE_COUNT: usize = TOTAL_BLOCK_COUNT.ilog2() as usize * HASH_LENGTH;
const ESTIMATED_CHALLENGE_PROOF_BYTE_COUNT: usize =
    4 + 4 + BLOCK_SIZE + BLOCK_SIZE + HASH_LENGTH + 4 + (TREE_PROOF_BYTE_COUNT / 2);
pub(crate) const ESTIMATED_FULL_PROOF_BYTE_COUNT: usize =
    32 + ESTIMATED_CHALLENGE_PROOF_BYTE_COUNT * K;
const U64_VALUE_COUNT: u128 = u64::MAX as u128 + 1;

pub(crate) fn challenge_index(merkle_root: &[u8], i: usize) -> usize {
    let mut hasher = Blake2b512::new_with_prefix(merkle_root);
    hasher.update(i.to_le_bytes());
    let hash = hasher.finalize_fixed();
    let seed = u64::from_le_bytes(hash[..8].try_into().unwrap()) as u128;
    let offset = if hash[8] > 127 { CHAIN_BLOCK_COUNT } else { 0 };
    (((seed * (CHAIN_BLOCK_COUNT - 2) as u128) / U64_VALUE_COUNT) as usize) + 2 + offset
}

pub(crate) fn reference_block_index(index: usize, parent_block: &Block) -> usize {
    let offset = if index < CHAIN_BLOCK_COUNT {
        0
    } else {
        CHAIN_BLOCK_COUNT
    };
    let i = (index - offset) as u64;
    let r1 = mix(
        u64::from_le_bytes(parent_block[0..8].try_into().unwrap()),
        i,
    );
    let r2 = mix(
        u64::from_le_bytes(parent_block[8..16].try_into().unwrap()),
        i,
    );
    let r = mix(r1, r2) as u128;
    let j = (i - 1) as u128;
    ((r * j) >> 64) as usize + offset
}

pub(crate) fn generate_chains(nonce: Nonce) -> [Box<[Block; CHAIN_BLOCK_COUNT]>; 2] {
    let hash: [u8; 32] = Blake2b::digest(nonce).into();
    let (nonce1, nonce2) = hash.split_at(16);
    let nonce1: Nonce = nonce1.try_into().unwrap();
    let nonce2: Nonce = nonce2.try_into().unwrap();
    [
        generate_chain(nonce1, 0),
        generate_chain(nonce2, CHAIN_BLOCK_COUNT),
    ]
}

fn generate_chain(nonce: Nonce, offset: usize) -> Box<[Block; CHAIN_BLOCK_COUNT]> {
    let mut blocks = Vec::with_capacity(CHAIN_BLOCK_COUNT);
    blocks.push(allocate_block(0u32, nonce));
    blocks.push(allocate_block(1u32, nonce));
    for _ in 2..CHAIN_BLOCK_COUNT {
        blocks.push([0u8; BLOCK_SIZE]);
    }
    for index in 2..CHAIN_BLOCK_COUNT {
        let reference_index = reference_block_index(index + offset, &blocks[index - 1]);
        fill_block(nonce, &mut blocks, index, reference_index - offset);
    }
    blocks.into_boxed_slice().try_into().unwrap()
}

fn allocate_block(i: u32, nonce: Nonce) -> Block {
    let mut hasher = Blake2b512::new_with_prefix(i.to_le_bytes());
    hasher.update(nonce);
    let mut hash = hasher.finalize_fixed();
    for _ in 0..ITERATION_COUNT {
        hash = Blake2b512::digest(hash);
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
        hash = Blake2b512::digest(hash);
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
