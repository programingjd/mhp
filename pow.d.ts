declare module 'pow' {
  /**
   * Generates the proof of work for the given nonce.
   * @param {Uint8Array} nonce (16 bytes long)
   * @return {Promise<Uint8Array>}
   */
  export function generate(nonce: Uint8Array): Promise<Uint8Array>;
}