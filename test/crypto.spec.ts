import {expect, it} from 'vitest';
import {type KdfParamsAesKdf, getHeader} from '../lib/header.js';
import {computeAesKdf, computeCompositeKey, computeHeaderHmac, computeHmacBlockKey, computeKeys} from '../lib/crypto.js';
import {bufferToHex, hexToBuffer, base64ToBuffer} from '../lib/util.js';
import {db1, db2} from './fixtures/test.base64.js';

const testFile1 = base64ToBuffer(db1.file);
const testPassword1 = new TextEncoder().encode(db1.password);
const testFile2 = base64ToBuffer(db2.file);
const testPassword2 = new TextEncoder().encode(db2.password);

// Skip because takes too long for tests
it.skip('should compute AES-KDF from test db1', async () => {
  const {kdfParams} = getHeader(testFile1) as {kdfParams: KdfParamsAesKdf};

  expect(bufferToHex(kdfParams.S)).toEqual(db1.seed);
  expect(kdfParams.R).toEqual(db1.iterations);

  const compositeKey = await computeCompositeKey(testPassword1);
  const key = await computeAesKdf(compositeKey, kdfParams.S, kdfParams.R);

  expect(bufferToHex(key)).toEqual(db1.derivedKey);
});

it('should compute AES-KDF from test db2', async () => {
  const {kdfParams} = getHeader(testFile2) as {kdfParams: KdfParamsAesKdf};

  expect(bufferToHex(kdfParams.S)).toEqual(db2.seed);
  expect(kdfParams.R).toEqual(db2.iterations);

  const compositeKey = await computeCompositeKey(testPassword2);
  const key = await computeAesKdf(compositeKey, kdfParams.S, kdfParams.R);

  expect(bufferToHex(key)).toEqual(db2.derivedKey);
});

it('should compute AES-KDF from seed and password', async () => {
  const compositeKey = await computeCompositeKey(testPassword1);
  const seed = hexToBuffer('ead850e8c70df4968e1963f39c5721fda70477e1596369b50a6e410f4dae552e');
  const rounds = 10;
  const key = await computeAesKdf(compositeKey, seed, rounds);

  expect(bufferToHex(key))
    .toEqual('118de96e743b4f685af3103361dc0d069650c549e2da693df7d2f90f6014dc75');
});

it('should compute correct encryption key and main hmac with AES-KDF from db2', async () => {
  const header = getHeader(testFile2);
  const keys = await computeKeys(testPassword2, header);

  expect(keys.map(bufferToHex)).toEqual([
    '0bbcbd6ba5e8a850bf6b2d5014414737f58e63540f516517e1ef4a8f19ff0ca6',
    '84a8002dd1c6d555559a5d4929743abb7b5229f8780088991feaf843efda43244e5cff9eb8dcdf8d2942d49fb5017e24da8e7dc11941db8c8a906b60364c96ec',
  ]);
});

it('should compute hmac block key', async () => {
  const header = getHeader(testFile2);
  const [_, hmac] = await computeKeys(testPassword2, header);
  const blockKey = await computeHmacBlockKey(BigInt('0xFFFFFFFFFFFFFFFF'), hmac);
  expect(bufferToHex(blockKey)).toEqual('132239be0cea1a6e897de764493cdbd5158f1f3a47622d507567b99b90e18899bbd038901ad8d0502e010c5b49bc3b6622401f12ea08361f16040d3fcc73f7c5');
});

it('should compute header hmac', async () => {
  const header = getHeader(testFile2);
  console.log(header.headerHmac);
  const [_, hmac] = await computeKeys(testPassword2, header);
  const hh = await computeHeaderHmac(testFile2, header.size, hmac);
  console.log(hh);
});
