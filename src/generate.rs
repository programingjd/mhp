use crate::block::{
    Block, CHAIN_BLOCK_COUNT, ESTIMATED_FULL_PROOF_BYTE_COUNT, challenge_index, generate_chains,
    reference_block_index,
};
use crate::hasher::Blake2bHasher;
use crate::{K, Nonce};
use rs_merkle::{Hasher, MerkleTree};

pub fn generate_proof(nonce: Nonce) -> Box<[u8]> {
    let chains = generate_chains(nonce);
    combine_chains(&chains)
}

pub fn combine_chains(chains: &[Box<[Block; CHAIN_BLOCK_COUNT]>; 2]) -> Box<[u8]> {
    let mut output = Vec::with_capacity(ESTIMATED_FULL_PROOF_BYTE_COUNT);
    let leaves = chains
        .iter()
        .flat_map(|it| it.iter().map(|it| Blake2bHasher::hash(it)))
        .collect::<Vec<_>>();
    let tree = MerkleTree::<Blake2bHasher>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    output.extend_from_slice(&root);
    for i in 0..K {
        let index = challenge_index(&root, i);
        let block = if index < CHAIN_BLOCK_COUNT {
            &chains[0][index]
        } else {
            &chains[1][index - CHAIN_BLOCK_COUNT]
        };
        let parent_block = if index - 1 < CHAIN_BLOCK_COUNT {
            &chains[0][index - 1]
        } else {
            &chains[1][index - 1 - CHAIN_BLOCK_COUNT]
        };
        let reference_index = reference_block_index(index, parent_block);
        let reference_block = if reference_index < CHAIN_BLOCK_COUNT {
            &chains[0][reference_index]
        } else {
            &chains[1][reference_index - CHAIN_BLOCK_COUNT]
        };
        let block_hash = Blake2bHasher::hash(block);
        let mut indices = [index - 1, index, reference_index];
        indices.sort_unstable();
        let proof = tree.proof(&indices).to_bytes();
        output.extend_from_slice(&(index as u32).to_le_bytes());
        output.extend_from_slice(&(reference_index as u32).to_le_bytes());
        output.extend_from_slice(&block_hash);
        output.extend_from_slice(parent_block);
        output.extend_from_slice(reference_block);
        output.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        output.extend_from_slice(&proof);
    }
    output.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{
        BLOCK_SIZE, TOTAL_BLOCK_COUNT, generate_first_chain, generate_second_chain,
    };
    use rand::TryRngCore;
    use rand::rngs::OsRng;
    use std::fmt::{Formatter, LowerHex};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::thread;
    use std::time::SystemTime;

    #[test]
    fn test_generate_proof() {
        let nonce = nonce();
        let proof1 = proof(&nonce, false);
        let proof2 = proof(&nonce, true);
        assert_eq!(proof1.len(), proof2.len());
        assert_eq!(Blake2bHasher::hash(&proof1), Blake2bHasher::hash(&proof2));
    }

    #[ignore]
    #[test]
    fn test_fixed_nonce() {
        let nonce = [
            0xd7, 0xb1, 0xd8, 0x90, 0xe9, 0x1d, 0xf4, 0x8f, 0xeb, 0x61, 0x6a, 0xbc, 0x39, 0x64,
            0xda, 0x12,
        ];
        let proof = proof(&nonce, true);
        OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(format!("{:x}", Hex(nonce.as_ref())))
            .unwrap()
            .write_all(proof.as_ref())
            .unwrap();
    }

    #[ignore]
    #[test]
    fn record_proof() {
        let nonce = nonce();
        let proof = proof(&nonce, true);
        OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(format!("test_data/{:x}", Hex(nonce.as_ref())))
            .unwrap()
            .write_all(proof.as_ref())
            .unwrap();
    }

    fn nonce() -> [u8; 16] {
        let mut nonce = [0u8; 16];
        OsRng::default()
            .try_fill_bytes(&mut nonce)
            .expect("failed to generate nonce");
        nonce.try_into().unwrap()
    }

    fn proof(nonce: Nonce, parallel: bool) -> Box<[u8]> {
        let t = SystemTime::now();
        let proof = if parallel {
            let nonce = nonce.clone();
            let join1 = thread::spawn(move || generate_first_chain(&nonce));
            let join2 = thread::spawn(move || generate_second_chain(&nonce));
            let chain1 = join1.join().unwrap();
            let chain2 = join2.join().unwrap();
            combine_chains(&[chain1, chain2])
        } else {
            generate_proof(&nonce)
        };
        println!("{}s", t.elapsed().unwrap().as_millis() as f32 / 1000.0);
        assert!(
            proof.len()
                > K * (4
                    + 4
                    + BLOCK_SIZE
                    + BLOCK_SIZE
                    + 32
                    + 4
                    + TOTAL_BLOCK_COUNT.ilog2() as usize)
        );
        proof
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
