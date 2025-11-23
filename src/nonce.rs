use blake2::digest::typenum::U16;
use blake2::digest::{FixedOutput, Mac};
use blake2::{Blake2b512, Blake2bMac};
use hkdf::SimpleHkdf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::UNIX_EPOCH;
use std::{ptr, thread};

pub struct RollingWindow<const T: usize = 900, const N: usize = 512_000> {
    generations: Option<Arc<RwLock<Producers<N>>>>,
    rotator: Option<thread::JoinHandle<()>>,
}

struct Producers<const N: usize> {
    gen1: NonceProducer<N>,
    gen2: NonceProducer<N>,
}

impl<const N: usize> Producers<N> {
    pub(crate) fn rotate(&mut self) {
        std::mem::swap(&mut self.gen1, &mut self.gen2);
        self.gen2.generation = self.gen1.generation.wrapping_add(1);
        // Replace with AtomicU64::get_mut_slice when stabilize
        // Tracking issue: https://github.com/rust-lang/rust/issues/76314
        let slice: &mut [u64] =
            unsafe { &mut *(&mut *self.gen2.bitset as *mut [AtomicU64] as *mut [u64]) };
        slice.fill(0);
        self.gen2.cursor.store(0, Ordering::Relaxed);
    }
}

pub struct VerifiableNonce {
    pub generation: u16,
    pub counter: usize,
    pub nonce: [u8; 16],
}

impl<const T: usize, const N: usize> RollingWindow<T, N> {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        const { assert!(T > 0, "T must be greater than 0") };
        const { assert!(N % 64 == 0, "N must be a multiple of 64") };
        let generation = (UNIX_EPOCH.elapsed().unwrap().as_secs() / T as u64) as u16;
        let (gen1, gen2) = NonceProducer::<N>::for_generations(generation, &seed);
        let generations = Arc::new(RwLock::new(Producers { gen1, gen2 }));
        let gens = Arc::downgrade(&generations);
        let rotator = Some(thread::spawn(move || {
            loop {
                let current_timestamp = UNIX_EPOCH.elapsed().unwrap().as_secs();
                let next_rotation_timestamp = (current_timestamp / T as u64 + 1) * T as u64;
                let sleep_duration = next_rotation_timestamp.saturating_sub(current_timestamp) + 1;
                thread::park_timeout(std::time::Duration::from_secs(sleep_duration));
                match gens.upgrade() {
                    Some(gens) => {
                        let mut generations = gens
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let generation =
                            (UNIX_EPOCH.elapsed().unwrap().as_secs() / T as u64) as u16;
                        while generation != generations.gen1.generation {
                            generations.rotate();
                        }
                    }
                    None => break,
                }
            }
        }));
        Self {
            generations: Some(generations),
            rotator,
        }
    }
    pub fn nonce(&self) -> Option<VerifiableNonce> {
        let gen2 = &self.generations.as_ref()?.read().ok()?.gen2;
        let (counter, nonce) = gen2.nonce()?;
        Some(VerifiableNonce {
            generation: gen2.generation,
            counter,
            nonce,
        })
    }
    pub fn verify(&self, nonce: &VerifiableNonce) -> Option<()> {
        let generations = &self.generations.as_ref()?.read().ok()?;
        let producer = if nonce.generation == generations.gen2.generation {
            &generations.gen2
        } else if nonce.generation == generations.gen1.generation {
            &generations.gen1
        } else {
            return None;
        };
        producer.verify(nonce.counter, &nonce.nonce)
    }
}

impl<const T: usize, const N: usize> Drop for RollingWindow<T, N> {
    fn drop(&mut self) {
        self.generations = None;
        if let Some(handle) = self.rotator.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

pub struct NonceProducer<const MAX: usize = 512_000> {
    pub generation: u16,
    cursor: AtomicUsize,
    bitset: Box<[AtomicU64]>,
    iv: [u8; 32],
    mac_key: [u8; 32],
}

impl<const MAX: usize> NonceProducer<MAX> {
    pub fn for_generation(generation: u16, seed: &[u8; 32]) -> Self {
        const { assert!(MAX % 64 == 0, "MAX must be a multiple of 64") };
        Self::generate(generation, seed)
    }
    pub(crate) fn for_generations(generation: u16, seed: &[u8; 32]) -> (Self, Self) {
        (
            Self::generate(generation, seed),
            Self::generate(generation.wrapping_add(1), seed),
        )
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
    pub fn verify(&self, k: usize, nonce: &[u8; 16]) -> Option<()> {
        if Blake2bMac::<U16>::new_from_slice(&self.mac_key)
            .expect("invalid blake2b mac key length")
            .chain_update(self.generation.to_le_bytes())
            .chain_update((k as u64).to_le_bytes())
            .chain_update(self.iv)
            .finalize_fixed()
            .as_slice()
            == nonce
        {
            if k < MAX {
                let i = k / 64;
                let j = k % 64;
                let mask = 1u64 << j;
                if self.bitset[i].fetch_or(mask, Ordering::Relaxed) & mask == 0 {
                    Some(())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
    fn next_index(&self) -> Option<usize> {
        // we could probably optimize with a simple fetch_add as
        // it's unlikely to overflow and wrap around,
        // but fetch_update makes sure that doesn't happen.
        if let Ok(j) = self
            .cursor
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |it| {
                if it == MAX { None } else { Some(it + 1) }
            })
        {
            Some(j)
        } else {
            None
        }
    }
    fn generate(generation: u16, seed: &[u8; 32]) -> Self {
        let kdf = SimpleHkdf::<Blake2b512>::new(Some(&generation.to_le_bytes()), seed);
        let mut iv = [0u8; 32];
        kdf.expand(b"initialization vector", &mut iv)
            .expect("invalid kdf length expansion");
        let mut mac_key = [0u8; 32];
        kdf.expand(b"blake2b mac signing key", &mut mac_key)
            .expect("invalid kdf length expansion");
        let len = MAX / 64;
        let mut bitset = Vec::<AtomicU64>::with_capacity(len);
        // SAFETY: we zero the memory to initialize,
        // which is safe because the pointer is correctly aligned by the vec.
        unsafe {
            bitset.set_len(len);
            ptr::write_bytes(bitset.as_mut_ptr(), 0, len);
        }
        let bitset = bitset.into_boxed_slice();
        Self {
            generation,
            cursor: AtomicUsize::default(),
            bitset,
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
    use std::thread::sleep;

    const MAX: usize = 10 * 1024;

    #[test]
    fn test_nonce_producer() {
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

    #[test]
    fn test_rolling_window() {
        let mut seed = [0u8; 32];
        let mut rng = OsRng::default();
        rng.try_fill_bytes(&mut seed)
            .expect("failed to generate seed");
        let window = RollingWindow::<1, 128>::from_seed(&seed);
        let mut set = BTreeSet::new();
        let mut generation = None;
        let mut last = None;
        for _ in 0..10 {
            let nonce = window.nonce().unwrap();
            if let Some(generation) = generation {
                assert_eq!(nonce.generation, generation);
            } else {
                generation = Some(nonce.generation);
            }
            assert!(set.insert(nonce.nonce));
            assert!(window.verify(&nonce).is_some());
            last = Some(nonce);
        }
        sleep(std::time::Duration::from_millis(1_000));
        let window = RollingWindow::<1, 128>::from_seed(&seed);
        let nonce = last.unwrap();
        assert!(window.verify(&nonce).is_some());
        let nonce = window.nonce().unwrap();
        let generation = generation.unwrap();
        assert_eq!(generation + 1, nonce.generation);
        assert!(window.verify(&nonce).is_some());
        assert!(window.verify(&nonce).is_none());
    }
}
