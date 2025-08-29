use crate::block::{
    BLOCK_COUNT, BLOCK_SIZE, Block, FULL_PROOF_BYTE_COUNT, TREE_PROOF_BYTE_COUNT, challenge_index,
    reference_block_index,
};
use crate::hasher::Blake2bHasher;
use crate::{K, Nonce};
use blake2::digest::FixedOutput;
use blake2::{Blake2b512, Digest};
use hkdf::SimpleHkdf;
use rs_merkle::{Hasher, MerkleProof};

pub fn verify_proof(nonce: Nonce, proof: &[u8; FULL_PROOF_BYTE_COUNT]) -> Option<()> {
    let mut remaining = proof.as_slice();
    let (root, rest) = remaining.split_at(32);
    remaining = rest;
    for i in 0..K {
        let (index, rest) = remaining.split_at(4);
        remaining = rest;
        let index = u32::from_le_bytes(index.try_into().unwrap()) as usize;
        if index != challenge_index(root, i) {
            return None;
        }
        let (reference_index, rest) = remaining.split_at(4);
        remaining = rest;
        let reference_index = u32::from_le_bytes(reference_index.try_into().unwrap()) as usize;
        let (block, rest) = remaining.split_at(BLOCK_SIZE);
        remaining = rest;
        let (proof, rest) = remaining.split_at(TREE_PROOF_BYTE_COUNT);
        remaining = rest;
        let proof = MerkleProof::<Blake2bHasher>::from_bytes(proof).ok()?;
        if !proof.verify(
            root.try_into().unwrap(),
            &[index],
            &[Blake2bHasher::hash(block)],
            BLOCK_COUNT,
        ) {
            return None;
        }
        let (parent_block, rest) = remaining.split_at(BLOCK_SIZE);
        remaining = rest;
        let parent_block = parent_block.try_into().unwrap();
        if reference_index != reference_block_index(index, parent_block) {
            return None;
        }
        let (proof, rest) = remaining.split_at(TREE_PROOF_BYTE_COUNT);
        remaining = rest;
        let proof = MerkleProof::<Blake2bHasher>::from_bytes(proof).ok()?;
        if !proof.verify(
            root.try_into().unwrap(),
            &[index - 1],
            &[Blake2bHasher::hash(parent_block)],
            BLOCK_COUNT,
        ) {
            return None;
        }
        let (reference_block, rest) = remaining.split_at(BLOCK_SIZE);
        remaining = rest;
        let (proof, rest) = remaining.split_at(TREE_PROOF_BYTE_COUNT);
        remaining = rest;
        let proof = MerkleProof::<Blake2bHasher>::from_bytes(proof).ok()?;
        if !proof.verify(
            root.try_into().unwrap(),
            &[reference_index],
            &[Blake2bHasher::hash(reference_block)],
            BLOCK_COUNT,
        ) {
            return None;
        }
        let reference_block = reference_block.try_into().unwrap();
        if block != compute_block(nonce, parent_block, reference_block) {
            return None;
        }
    }
    Some(())
}

fn compute_block(nonce: Nonce, parent_block: &Block, reference_block: &Block) -> Block {
    let mut hasher = Blake2b512::new_with_prefix(parent_block);
    hasher.update(reference_block);
    let hash = hasher.finalize_fixed();
    let mut allocated = [0u8; BLOCK_SIZE];
    SimpleHkdf::<Blake2b512>::new(Some(nonce), &hash)
        .expand(&[], &mut allocated)
        .expect("failed to expand hash");
    allocated
}

#[cfg(test)]
mod tests {
    use super::*;
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
                let mut proof = Vec::with_capacity(FULL_PROOF_BYTE_COUNT);
                assert_eq!(
                    FULL_PROOF_BYTE_COUNT,
                    OpenOptions::new()
                        .read(true)
                        .open(format!("test_data/{}", entry.file_name().display()))
                        .unwrap()
                        .read_to_end(&mut proof)
                        .unwrap()
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
