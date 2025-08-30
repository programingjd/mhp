use crate::block::{
    BLOCK_SIZE, Block, CHAIN_BLOCK_COUNT, ITERATION_COUNT, TOTAL_BLOCK_COUNT, challenge_index,
    reference_block_index,
};
use crate::hasher::{Blake2bHasher, HASH_LENGTH};
use crate::parser::Parser;
use crate::{K, Nonce};
use blake2::digest::FixedOutput;
use blake2::{Blake2b, Blake2b512, Digest};
use hkdf::SimpleHkdf;
use rs_merkle::{Hasher, MerkleProof};

pub fn verify_proof(nonce: Nonce, proof: &[u8]) -> Option<()> {
    let hash: [u8; 32] = Blake2b::digest(nonce).into();
    let (nonce1, nonce2) = hash.split_at(16);
    let nonce1: Nonce = nonce1.try_into().unwrap();
    let nonce2: Nonce = nonce2.try_into().unwrap();
    let mut parser = Parser::new(proof);
    let root = *parser.read::<HASH_LENGTH>()?;
    for i in 0..K {
        let index = parser.read_uint()?;
        if index != challenge_index(&root, i) {
            return None;
        }
        let reference_index = parser.read_uint()?;
        let block_hash = *parser.read::<HASH_LENGTH>()?;
        let blocks = parser.read_slice(BLOCK_SIZE * 2)?;
        let (parent_block, reference_block) = blocks.split_at_checked(BLOCK_SIZE)?;
        let parent_block: &Block = parent_block.try_into().unwrap();
        if reference_index != reference_block_index(index, parent_block) {
            return None;
        }
        let reference_block: &Block = reference_block.try_into().unwrap();
        let block = compute_block(
            if index < CHAIN_BLOCK_COUNT {
                nonce1
            } else {
                nonce2
            },
            parent_block,
            reference_block,
        );
        if block_hash != Blake2bHasher::hash(&block) {
            return None;
        }
        let parent_block_hash = Blake2bHasher::hash(parent_block);
        let reference_block_hash = Blake2bHasher::hash(reference_block);
        let len = parser.read_uint()?;
        let proof = parser.read_slice(len)?;
        let proof = MerkleProof::<Blake2bHasher>::from_bytes(proof).ok()?;
        let mut indexed_leaves = [
            (index - 1, parent_block_hash),
            (index, block_hash),
            (reference_index, reference_block_hash),
        ];
        indexed_leaves.sort_by_key(|&(i, _)| i);
        let mut indices = [0; 3];
        let mut leaves = [[0; HASH_LENGTH]; 3];
        for (i, (index, hash)) in indexed_leaves.into_iter().enumerate() {
            indices[i] = index;
            leaves[i] = hash;
        }
        if !proof.verify(root, &indices, &leaves, TOTAL_BLOCK_COUNT) {
            return None;
        }
    }
    if !parser.unread().is_empty() {
        return None;
    }
    Some(())
}

fn compute_block(nonce: Nonce, parent_block: &Block, reference_block: &Block) -> Block {
    let mut hasher = Blake2b512::new_with_prefix(parent_block);
    hasher.update(reference_block);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ESTIMATED_FULL_PROOF_BYTE_COUNT;
    use std::fs::{OpenOptions, read_dir};
    use std::io::Read;

    // #[ignore]
    #[test]
    fn test_verify_proof() {
        for entry in read_dir("test_data").unwrap() {
            if let Ok(entry) = entry {
                let nonce = entry
                    .file_name()
                    .to_str()
                    .unwrap()
                    .as_bytes()
                    .chunks(2)
                    .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                    .collect::<Vec<u8>>();
                let mut proof = Vec::with_capacity(ESTIMATED_FULL_PROOF_BYTE_COUNT);
                assert!(
                    OpenOptions::new()
                        .read(true)
                        .open(format!("test_data/{}", entry.file_name().display()))
                        .unwrap()
                        .read_to_end(&mut proof)
                        .unwrap()
                        > K * (4
                            + 4
                            + BLOCK_SIZE
                            + BLOCK_SIZE
                            + 32
                            + 4
                            + TOTAL_BLOCK_COUNT.ilog2() as usize)
                );
                verify_proof(
                    nonce.as_slice().try_into().unwrap(),
                    proof.as_slice().try_into().unwrap(),
                )
                .unwrap();
                println!("{} verified", entry.path().display());
            }
        }
    }
}
