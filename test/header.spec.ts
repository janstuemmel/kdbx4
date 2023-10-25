import {expect, it} from 'vitest';
import {getHeader} from '../lib/header.js';
import {computeHeaderHmac, computeKeys, sha256} from '../lib/crypto.js';
import {base64ToBuffer, bufferToHex} from '../lib/util.js';
import {db1, db2} from './fixtures/test.base64.js';

it('should parse kdbx4 header', () => {
  expect(getHeader(base64ToBuffer(db1.file))).toMatchSnapshot();
});

it('header hash should equal calculated header hash', async () => {
  const buf = base64ToBuffer(db2.file);
  const h = getHeader(buf);
  const headerHash = await sha256(buf.slice(0, h.size));
  expect(bufferToHex(headerHash)).toEqual(bufferToHex(h.headerHash));
});

it('header hmac should equal calculated header hmac', async () => {
  const buf = base64ToBuffer(db2.file);
  const pw = new TextEncoder().encode(db2.password);
  const header = getHeader(buf);
  const [_, hmac] = await computeKeys(pw, header);
  const headerHmac = await computeHeaderHmac(buf, header.size, hmac);
  expect(header.headerHmac).toEqual(headerHmac);
});
