/**
 * @param {ArrayBuffer} password
 * @returns {Promise<ArrayBuffer>}
 */
export const computeCompositeKey = async password =>
  sha256(password).then(sha256);

/**
 *
 * @param {CryptoKey} key
 * @returns {(data: ArrayBuffer) => (iv: ArrayBuffer) => Promise<Uint8Array>}
 */
export const calculateAesEcb = key => data => iv =>
  crypto.subtle.encrypt({name: 'AES-CBC', iv}, key, data)
    .then(response => new Uint8Array(response));

/**
 *
 * @param {ArrayBuffer} data
 * @returns {Promise<CryptoKey>}
 */
export const importAesCbcKey = data =>
  crypto.subtle.importKey('raw', data, 'AES-CBC', false, ['encrypt', 'decrypt']);

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
  const iv1 = pw.subarray(0, 16);
  const iv2 = pw.subarray(16, 32);

  while (rounds > 0) {
    const currentRounds = Math.min(rounds, 10_000);
    const iv = ecb(new ArrayBuffer(16 * currentRounds));
    // eslint-disable-next-line no-await-in-loop
    const [result1, result2] = await Promise.all([iv(iv1), iv(iv2)]);
    iv1.set(result1.subarray(-32, -16), 0);
    iv2.set(result2.subarray(-32, -16), 0);
    rounds -= currentRounds;
  }

  return new Uint8Array([...iv1, ...iv2]);
};

/**
 *
 * @param {import("./header.js").KdfParams} parameters
 * @returns {(compositeKey: ArrayBuffer) => Promise<Uint8Array>}
 */
export const computeDerivedKey = parameters => compositeKey => {
  switch (parameters.type) {
    case 'AES-KDF': {
      return computeAesKdf(compositeKey, parameters.S, parameters.R);
    }

    default: {
      throw new Error('argon KDF not implemented');
    }
  }
};

/**
 *
 * @param {ArrayBuffer} password
 * @param {import("./header.js").Kdbx4Header} header
 */
export const computeKeys = async (password, {kdfParams, masterSeed}) =>
  computeCompositeKey(password)
    .then(computeDerivedKey(kdfParams))
    .then(key => new Uint8Array([
      ...new Uint8Array(masterSeed),
      ...key,
      0x01,
    ]))
    .then(keyAndSeed => Promise.all([
      sha256(keyAndSeed.subarray(0, 64)),
      sha512(keyAndSeed),
    ]));

/**
 *
 * @param {ArrayBuffer} buf
 * @returns {Promise<ArrayBuffer>}
 */
export const sha256 = buf => crypto.subtle.digest('SHA-256', buf);

/**
 *
 * @param {ArrayBuffer} buf
 * @returns {Promise<ArrayBuffer>}
 */
export const sha512 = buf => crypto.subtle.digest('SHA-512', buf);
