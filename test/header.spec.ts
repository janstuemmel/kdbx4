import {expect, it} from 'vitest';
import {getHeader} from '../lib/header.js';
import {db1, db2} from './fixtures/test.base64.js';
import {base64ToBuffer} from './util.js';

it('should parse kdbx4 header', () => {
  expect(getHeader(base64ToBuffer(db1.file))).toMatchSnapshot();
});

it('foo', () => {
  const h = getHeader(base64ToBuffer(db2.file));
  console.log(h);
});
