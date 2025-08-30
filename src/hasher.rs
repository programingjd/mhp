use blake2::Blake2bVar;
use blake2::digest::VariableOutput;
use rs_merkle::Hasher;

pub(crate) const HASH_LENGTH: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct Blake2bHasher;

impl Hasher for Blake2bHasher {
    type Hash = [u8; HASH_LENGTH];
    fn hash(data: &[u8]) -> Self::Hash {
        let mut output = [0u8; HASH_LENGTH];
        Blake2bVar::digest_variable(data, &mut output).unwrap();
        output
    }
}
