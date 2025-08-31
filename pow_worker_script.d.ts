declare module 'pow_worker_script' {
  /**
   * Generates the first chain of the proof of work for the given nonce.
   * @param {Uint8Array} nonce (16 bytes long)
   * @return {Promise<Uint8Array>}
   */
  export function chain1(nonce: Uint8Array): Promise<Uint8Array>;

  /**
   * Generates the second chain of the proof of work for the given nonce.
   * @param {Uint8Array} nonce (16 bytes long)
   * @return {Promise<Uint8Array>}
   */
  export function chain2(nonce: Uint8Array): Promise<Uint8Array>;

  /**
   * Combines the two chains to generate the proof of work.
   * @param {Uint8Array} first_chain
   * @param {Uint8Array} second_chain
   * @return {Promise<Uint8Array>}
   */
  export function combine(first_chain: Uint8Array, second_chain: Uint8Array): Promise<Uint8Array>;
}
