#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

mod block;
pub mod generate;
mod hasher;
#[cfg(feature = "server")]
mod parser;
#[cfg(feature = "server")]
mod verify;

pub type Nonce<'a> = &'a [u8; 16];

const K: usize = 10;

// #[cfg(feature = "wasm")]
// #[wasm_bindgen]
// pub fn generate_proof(nonce: Vec<u8>) -> Vec<u8> {
//     generate::generate_proof(nonce.as_slice().try_into().unwrap()).into_vec()
// }

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn generate_first_chain(nonce: Vec<u8>) -> Vec<u8> {
    let chain = block::generate_first_chain(nonce.as_slice().try_into().unwrap());
    let raw = Box::into_raw(chain) as *mut u8;
    let n = block::CHAIN_BLOCK_COUNT * block::BLOCK_SIZE;
    unsafe { Vec::from_raw_parts(raw, n, n) }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn generate_second_chain(nonce: Vec<u8>) -> Vec<u8> {
    let chain = block::generate_second_chain(nonce.as_slice().try_into().unwrap());
    let raw = Box::into_raw(chain) as *mut u8;
    let n = block::CHAIN_BLOCK_COUNT * block::BLOCK_SIZE;
    unsafe { Vec::from_raw_parts(raw, n, n) }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn combine_chains(first_chain: Vec<u8>, second_chain: Vec<u8>) -> Vec<u8> {
    let first_chain: Box<[u8]> = first_chain.into_boxed_slice();
    let raw = Box::into_raw(first_chain) as *mut [block::Block; block::CHAIN_BLOCK_COUNT];
    let first_chain = unsafe { Box::from_raw(raw) };
    let second_chain: Box<[u8]> = second_chain.into_boxed_slice();
    let raw = Box::into_raw(second_chain) as *mut [block::Block; block::CHAIN_BLOCK_COUNT];
    let second_chain = unsafe { Box::from_raw(raw) };
    generate::combine_chains(&[first_chain, second_chain]).into_vec()
}
