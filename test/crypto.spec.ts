import { expect, it } from 'vitest';
import { db1, db2 } from './fixtures/test.base64.js';
import { base64ToBuffer } from './util.js';
import { getHeader } from '../lib/header.js';
import { computeAesKdf, generateCompositeKey } from '../lib/crypto.js';
import { bufferToHex, hexToBuffer } from '../lib/util.js';

const testFile1 = base64ToBuffer(db1.file)
const testPassword1 = new TextEncoder().encode(db1.password)
const testFile2 = base64ToBuffer(db2.file)
const testPassword2 = new TextEncoder().encode(db2.password)

// skip because takes too long for tests
it.skip('should compute AES-KDF from test db1', async () => {
  const { kdfParams: { R, S } } = getHeader(testFile1) as { kdfParams: KdfParamsAesKdf }
  
  expect(bufferToHex(S)).toEqual(db1.seed)
  expect(R).toEqual(db1.iterations)

  const compositeKey = await generateCompositeKey(testPassword1);
  const key = await computeAesKdf(compositeKey, S, R)

  expect(bufferToHex(key)).toEqual(db1.derivedKey)
});

it('should compute AES-KDF from test db2', async () => {
  const { kdfParams: { R, S } } = getHeader(testFile2) as { kdfParams: KdfParamsAesKdf }
  
  expect(bufferToHex(S)).toEqual(db2.seed)
  expect(R).toEqual(db2.iterations)

  const compositeKey = await generateCompositeKey(testPassword2);
  const key = await computeAesKdf(compositeKey, S, R)
  
  expect(bufferToHex(key)).toEqual(db2.derivedKey)
});

it('should compute AES-KDF from seed and password', async () => {
  const compositeKey = await generateCompositeKey(testPassword1)
  const seed = hexToBuffer('ead850e8c70df4968e1963f39c5721fda70477e1596369b50a6e410f4dae552e');
  const rounds = 10
  const key = await computeAesKdf(compositeKey, seed, rounds)

  expect(bufferToHex(key))
    .toEqual('c52fddff0292d20ff83b9872463358aa51d117084a37e58dbc8560efae1a2a1d')
})
