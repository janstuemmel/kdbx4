import { InlineConfig } from 'vitest';

export default {
  test: {
    browser: {
      provider: 'playwright',
      name: 'chromium',
      enabled: true,
      headless: true,
    },
  } as InlineConfig
};
