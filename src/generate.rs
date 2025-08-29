use crate::block::{FULL_PROOF_BYTE_COUNT, challenge_index, init_blocks, reference_block_index};
use crate::hasher::Blake2bHasher;
use crate::{K, Nonce};
use rs_merkle::{Hasher, MerkleTree};

pub fn generate_proof(nonce: Nonce) -> Box<[u8; FULL_PROOF_BYTE_COUNT]> {
    let mut output = Vec::new();
    let blocks = init_blocks(nonce);
    let leaves = blocks
        .iter()
        .map(|it| Blake2bHasher::hash(it))
        .collect::<Vec<_>>();
    let tree = MerkleTree::<Blake2bHasher>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    output.extend_from_slice(&root);
    for i in 0..K {
        let index = challenge_index(&root, i);
        let proof = tree.proof(&[index]).to_bytes();
        let block = &blocks[index - 1];
        let reference_index = reference_block_index(index, block);
        let parent_proof = tree.proof(&[index - 1]).to_bytes();
        let reference_proof = tree.proof(&[reference_index]).to_bytes();
        output.extend_from_slice(&(index as u32).to_le_bytes());
        output.extend_from_slice(&(reference_index as u32).to_le_bytes());
        output.extend_from_slice(&blocks[index]);
        output.extend_from_slice(&proof);
        output.extend_from_slice(block);
        output.extend_from_slice(&parent_proof);
        output.extend_from_slice(&blocks[reference_index]);
        output.extend_from_slice(&reference_proof);
    }
    output.into_boxed_slice().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::FULL_PROOF_BYTE_COUNT;
    use rand::TryRngCore;
    use rand::rngs::OsRng;
    use std::fmt::{Formatter, LowerHex};
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn test_generate_proof() {
        proof();
    }

    #[ignore]
    #[test]
    fn record_proof() {
        let (nonce, proof) = proof();
        assert_eq!(FULL_PROOF_BYTE_COUNT, proof.len());
        OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(format!("test_data/{:x}", Hex(nonce.as_ref())))
            .unwrap()
            .write_all(proof.as_ref())
            .unwrap();
    }

    fn proof() -> ([u8; 16], Box<[u8; FULL_PROOF_BYTE_COUNT]>) {
        let mut nonce = [0u8; 16];
        OsRng::default()
            .try_fill_bytes(&mut nonce)
            .expect("failed to generate nonce");
        let proof = generate_proof(&nonce);
        (nonce, proof)
    }

    struct Hex<'a>(&'a [u8]);

    impl LowerHex for Hex<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            for &it in self.0 {
                write!(f, "{:02x}", it)?;
            }
            Ok(())
        }
    }
}
