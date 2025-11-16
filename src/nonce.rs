use blake2::digest::typenum::U16;
use blake2::digest::{FixedOutput, Mac};
use blake2::{Blake2b512, Blake2bMac};
use hkdf::SimpleHkdf;
use std::array::from_fn;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct NonceProducer<const MAX: usize> {
    pub generation: u16,
    bitset: [AtomicBool; MAX],
    iv: [u8; 32],
    mac_key: [u8; 32],
}

impl<const MAX: usize> NonceProducer<MAX> {
    pub fn for_generation(generation: u16, seed: &[u8; 32]) -> Self {
        Self::generate(generation, seed)
    }
    pub fn nonce(&self) -> Option<(usize, [u8; 16])> {
        let k = self.next_index()?;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(
            &Blake2bMac::<U16>::new_from_slice(&self.mac_key)
                .expect("invalid blake2b mac key length")
                .chain_update(self.generation.to_le_bytes())
                .chain_update((k as u64).to_le_bytes())
                .chain_update(self.iv)
                .finalize_fixed(),
        );
        Some((k, nonce))
    }
    pub fn verify(&mut self, k: usize, nonce: &[u8; 16]) -> Option<()> {
        if Blake2bMac::<U16>::new_from_slice(&self.mac_key)
            .expect("invalid blake2b mac key length")
            .chain_update(self.generation.to_le_bytes())
            .chain_update((k as u64).to_le_bytes())
            .chain_update(self.iv)
            .finalize_fixed()
            .as_slice()
            == nonce
        {
            Some(())
        } else {
            None
        }
    }
    fn next_index(&self) -> Option<usize> {
        for (i, it) in self.bitset.iter().enumerate() {
            if it
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Some(i);
            }
        }
        None
    }
    fn generate(generation: u16, seed: &[u8; 32]) -> Self {
        let kdf = SimpleHkdf::<Blake2b512>::new(None, seed);
        let mut iv = [0u8; 32];
        kdf.expand(b"initialization vector", &mut iv)
            .expect("invalid kdf length expansion");
        let mut mac_key = [0u8; 32];
        kdf.expand(b"blake2b mac signing key", &mut mac_key)
            .expect("invalid kdf length expansion");
        Self {
            generation,
            bitset: from_fn(|_| AtomicBool::new(false)),
            iv,
            mac_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::TryRngCore;
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;

    const MAX: usize = 10_000;

    #[test]
    fn test_nonce() {
        let mut seed = [0u8; 32];
        let mut rng = OsRng::default();
        rng.try_fill_bytes(&mut seed)
            .expect("failed to generate seed");
        let mut set = BTreeSet::new();
        for _ in 0..10 {
            let generation = OsRng::default()
                .try_next_u32()
                .expect("failed to generate generation") as u16;
            let producer = NonceProducer::<MAX>::for_generation(generation, &seed);
            for i in 0..MAX {
                let nonce = producer.nonce();
                assert!(nonce.is_some());
                let (k, nonce) = nonce.unwrap();
                assert_eq!(k, i);
                assert!(set.insert(nonce));
            }
            assert!(producer.nonce().is_none());
        }
    }
}
