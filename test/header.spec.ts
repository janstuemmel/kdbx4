import {expect, it} from 'vitest';
import {getHeader} from '../lib/header.js';
import {db1} from './fixtures/test.base64.js';
import {base64ToBuffer} from './util.js';

it('should parse kdbx4 header', () => {
  expect(getHeader(base64ToBuffer(db1.file))).toMatchSnapshot();
});
