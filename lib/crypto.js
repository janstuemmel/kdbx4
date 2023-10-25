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
 * @returns {Promise<ArrayBuffer>}
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

  return sha256(new Uint8Array([...iv1, ...iv2]).buffer);
};

/**
 *
 * @param {import("./header.js").KdfParams} parameters
 * @returns {(compositeKey: ArrayBuffer) => Promise<ArrayBuffer>}
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
      ...new Uint8Array(key),
      0x01,
    ]))
    .then(keyAndSeed => Promise.all([
      sha256(keyAndSeed.subarray(0, 64)),
      sha512(keyAndSeed),
    ]));

/**
 * @param {number | bigint} blockIndex
 * @param {ArrayBuffer} data
 */
export const computeHmacBlockKey = async (blockIndex, data) => {
  const block = new Uint8Array([
    ...new Uint8Array(8),
    ...new Uint8Array(data),
  ]);

  new DataView(block.buffer).setBigUint64(0, BigInt(blockIndex), true);
  return sha512(block.buffer);
};

/**
 * @param {ArrayBuffer} file
 * @param {number} headerSize
 * @param {ArrayBuffer} hmac
 */
export const computeHeaderHmac = async (file, headerSize, hmac) =>
  computeHmacBlockKey(BigInt('0xFFFFFFFFFFFFFFFF'), hmac)
    .then(hmacSha256(file.slice(0, headerSize)));

/**
 * @param {ArrayBuffer} data
 * @returns {(key: ArrayBuffer) => Promise<ArrayBuffer>}
 */
export const hmacSha256 = data => key => crypto.subtle
  .importKey('raw', key, {name: 'HMAC', hash: {name: 'SHA-256'}}, false, ['sign'])
  .then(k => crypto.subtle.sign({name: 'HMAC', hash: {name: 'SHA-256'}}, k, data));

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
