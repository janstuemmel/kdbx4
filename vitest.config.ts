import { InlineConfig } from 'vitest';

export default {
  test: {
    browser: {
      name: 'firefox',
      enabled: true,
      headless: true,
    },
  } as InlineConfig
};
