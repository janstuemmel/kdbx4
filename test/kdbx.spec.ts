import {it} from 'vitest';
import {Kdbx4} from '../lib/kdbx.js';
import {db1} from './fixtures/test.base64.js';

it('initialize kdbx db from base64', () => {
  Kdbx4.fromBase64(db1.file);
});
