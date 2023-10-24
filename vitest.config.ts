import { InlineConfig } from 'vitest';

export default {
  test: {
    reporters: ['verbose'],
    browser: {
      provider: 'playwright',
      name: 'chromium',
      enabled: true,
      headless: true,
    },
  } as InlineConfig
};
