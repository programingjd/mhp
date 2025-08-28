use crate::block::{PROOF_BYTE_COUNT, challenge_index, init_blocks, reference_block_index};
use crate::hasher::Blake2bHasher;
use rs_merkle::{Hasher, MerkleTree};

mod block;
mod hasher;

pub type Nonce<'a> = &'a [u8; 16];

const K: usize = 32;

pub fn generate_proof(nonce: Nonce) -> Vec<u8> {
    let mut output = Vec::new();
    let blocks = init_blocks(nonce);
    let leaves = blocks
        .into_iter()
        .map(|it| Blake2bHasher::hash(&it))
        .collect::<Vec<_>>();
    let tree = MerkleTree::<Blake2bHasher>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    for i in 0..K {
        let index = challenge_index(&root, i);
        let proof = tree.proof(&[index]).to_bytes();
        debug_assert!(proof.len() == PROOF_BYTE_COUNT);
        let block = blocks[index - 1];
        let reference_index = reference_block_index(index, block);
        let parent_proof = tree.proof(&[index - 1]).to_bytes();
        debug_assert!(parent_proof.len() == PROOF_BYTE_COUNT);
        let reference_proof = tree.proof(&[reference_index]).to_bytes();
        debug_assert!(reference_proof.len() == PROOF_BYTE_COUNT);
        output.extend_from_slice(&(index as u32).to_le_bytes());
        output.extend_from_slice(&(reference_index as u32).to_le_bytes());
        output.extend_from_slice(&blocks[index]);
        output.extend_from_slice(&block);
        output.extend_from_slice(&blocks[reference_index]);
        output.extend_from_slice(&proof);
        output.extend_from_slice(&parent_proof);
        output.extend_from_slice(&reference_proof);
    }
    output.extend_from_slice(&root);
    output
}
