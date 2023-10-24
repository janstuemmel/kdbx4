/**
 * @param {ArrayBuffer} password 
 * @returns {Promise<ArrayBuffer>}
 */
export const generateCompositeKey = async (password) => sha256(password).then(sha256)

/**
 * 
 * @param {CryptoKey} key 
 * @returns {(data: ArrayBuffer) => (iv: ArrayBuffer) => Promise<Uint8Array>}
 */
export const calculateAesEcb = (key) => (data) => (iv) => 
  crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, data)
    .then((res) => new Uint8Array(res))

/**
 * 
 * @param {ArrayBuffer} data 
 * @returns {Promise<CryptoKey>}
 */
export const importAesCbcKey = (data) =>
  crypto.subtle.importKey('raw', data, 'AES-CBC', false, ['encrypt', 'decrypt'])

/**
 * Computes AES ECB key derivation
 * Works by using AES-CBC with a zero buffer as data 
 * 
 * @param {ArrayBuffer} password 
 * @param {ArrayBuffer} seed 
 * @param {number} rounds
 * @returns {Promise<Uint8Array>}
 */
export const computeAesKdf = async (password, seed, rounds) => {
  const key = await importAesCbcKey(seed);
  const ecb = calculateAesEcb(key);
  const pw = new Uint8Array(password);
  let iv1 = pw.subarray(0, 16), 
      iv2 = pw.subarray(16, 32);

  while (rounds > 0) {
    const currentRounds = Math.min(rounds, 10000)
    const iv = ecb(new ArrayBuffer(16 * currentRounds));
    iv1.set((await iv(iv1)).subarray(-32, -16), 0)
    iv2.set((await iv(iv2)).subarray(-32, -16), 0)
    rounds -= currentRounds;
  }

  return new Uint8Array([...iv1, ...iv2])
}

/**
 * 
 * @param {ArrayBuffer} buf 
 * @returns {Promise<ArrayBuffer>}
 */
export const sha256 = (buf) => crypto.subtle.digest('SHA-256', buf)

/**
 * 
 * @param {ArrayBuffer} buf 
 * @returns {Promise<ArrayBuffer>}
 */
export const sha512 = (buf) => crypto.subtle.digest('SHA-512', buf)
