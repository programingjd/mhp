use blake2::digest::typenum::U16;
use blake2::digest::{FixedOutput, Mac};
use blake2::{Blake2b512, Blake2bMac};
use hkdf::SimpleHkdf;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::array::from_fn;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct NonceProducer<const MAX: usize> {
    rng: StdRng,
    generation: u16,
    bitset: [AtomicBool; MAX],
    iv: [u8; 32],
    mac_key: [u8; 32],
}

impl<const MAX: usize> NonceProducer<MAX> {
    pub fn for_generation(generation: u16, seed: [u8; 32]) -> Self {
        Self::generate(generation, StdRng::from_seed(seed))
    }
    pub fn next(&self) -> Self {
        Self::generate(
            self.generation.wrapping_add(1),
            StdRng::from_rng(&mut self.rng.clone()),
        )
    }
    pub fn nonce(&self) -> Option<(usize, [u8; 16])> {
        let k = self.next_index()?;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(
            &Blake2bMac::<U16>::new_from_slice(&self.mac_key)
                .expect("invalid blake2b mac key length")
                .chain_update((k as u64).to_le_bytes())
                .chain_update(self.iv)
                .finalize_fixed(),
        );
        Some((k, nonce))
    }
    pub fn verify(&mut self, k: usize, nonce: &[u8; 16]) -> Option<()> {
        if Blake2bMac::<U16>::new_from_slice(&self.mac_key)
            .expect("invalid blake2b mac key length")
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
    fn generate(generation: u16, mut rng: StdRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let kdf = SimpleHkdf::<Blake2b512>::new(None, &seed);
        let mut iv = [0u8; 32];
        kdf.expand(b"initialization vector", &mut iv)
            .expect("invalid kdf length expansion");
        let mut mac_key = [0u8; 32];
        kdf.expand(b"blake2b mac signing key", &mut mac_key)
            .expect("invalid kdf length expansion");
        Self {
            rng,
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
    use std::collections::BTreeSet;
    use std::fmt::{Formatter, LowerHex};

    const MAX: usize = 10_000;

    #[test]
    fn test_nonce() {
        let mut seed = [0u8; 32];
        StdRng::from_os_rng().fill_bytes(&mut seed);
        let producer = NonceProducer::<MAX>::for_generation(0, seed);
        let mut set = BTreeSet::new();
        for i in 0..MAX {
            let nonce = producer.nonce();
            assert!(nonce.is_some());
            let (k, nonce) = nonce.unwrap();
            assert_eq!(k, i);
            assert!(set.insert(nonce));
            println!("{:2x}", Hex(nonce.as_slice()));
        }
        assert!(producer.nonce().is_none());
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
