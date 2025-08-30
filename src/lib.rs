mod block;
pub mod generate;
mod hasher;
mod parser;
mod verify;

pub type Nonce<'a> = &'a [u8; 16];

const K: usize = 10;

#[cfg(test)]
mod tests {
    use crate::generate::generate_proof;
    use rand::TryRngCore;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_proof() {
        let mut nonce = [0u8; 16];
        OsRng::default()
            .try_fill_bytes(&mut nonce)
            .expect("failed to generate nonce");
        let proof = generate_proof(&nonce);
        println!("{}", proof.len());
    }
}
