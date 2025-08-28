use blake2::{Blake2b, Digest};
use rs_merkle::Hasher;

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct Blake2bHasher;

impl Hasher for Blake2bHasher {
    type Hash = [u8; 32];
    fn hash(data: &[u8]) -> Self::Hash {
        Blake2b::digest(data).into()
    }
}
