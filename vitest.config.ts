/* eslint-disable @typescript-eslint/consistent-type-assertions */
/* eslint-disable import/no-anonymous-default-export */
import {type InlineConfig} from 'vitest';

export default {
  test: {
    reporters: ['verbose'],
    browser: {
      provider: 'playwright',
      name: 'chromium',
      enabled: true,
      headless: true,
    },
  } as InlineConfig,
};
