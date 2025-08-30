use crate::block::{
    CHAIN_BLOCK_COUNT, FULL_PROOF_BYTE_COUNT, challenge_index, generate_chains,
    reference_block_index,
};
use crate::hasher::Blake2bHasher;
use crate::{K, Nonce};
use rs_merkle::{Hasher, MerkleTree};

pub fn generate_proof(nonce: Nonce) -> Box<[u8; FULL_PROOF_BYTE_COUNT]> {
    let mut output = Vec::with_capacity(FULL_PROOF_BYTE_COUNT);
    let chains = generate_chains(nonce);
    let leaves = chains
        .iter()
        .flat_map(|it| it.iter().map(|it| Blake2bHasher::hash(it)))
        .collect::<Vec<_>>();
    let tree = MerkleTree::<Blake2bHasher>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    output.extend_from_slice(&root);
    for i in 0..K {
        let index = challenge_index(&root, i);
        let proof = tree.proof(&[index]).to_bytes();
        let block = if index - 1 < CHAIN_BLOCK_COUNT {
            &chains[0][index - 1]
        } else {
            &chains[1][index - 1 - CHAIN_BLOCK_COUNT]
        };
        let reference_index = reference_block_index(index, block);
        let parent_proof = tree.proof(&[index - 1]).to_bytes();
        let reference_proof = tree.proof(&[reference_index]).to_bytes();
        let parent_block = if index < CHAIN_BLOCK_COUNT {
            &chains[0][index]
        } else {
            &chains[1][index - CHAIN_BLOCK_COUNT]
        };
        let reference_block = if reference_index < CHAIN_BLOCK_COUNT {
            &chains[0][reference_index]
        } else {
            &chains[1][reference_index - CHAIN_BLOCK_COUNT]
        };
        output.extend_from_slice(&(index as u32).to_le_bytes());
        output.extend_from_slice(&(reference_index as u32).to_le_bytes());
        output.extend_from_slice(parent_block);
        output.extend_from_slice(&proof);
        output.extend_from_slice(block);
        output.extend_from_slice(&parent_proof);
        output.extend_from_slice(reference_block);
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
    use std::time::SystemTime;

    #[test]
    fn test_generate_proof() {
        proof();
    }

    // #[ignore]
    #[test]
    fn record_proof() {
        let t = SystemTime::now();
        let (nonce, proof) = proof();
        println!("{}s", t.elapsed().unwrap().as_millis() as f32 / 1000.0);
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
