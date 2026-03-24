import { registerPlugin } from '@capacitor/core';

import type { SSLPinningPlugin } from './definitions';

const SSLPinning = registerPlugin<SSLPinningPlugin>('SSLPinning', {
  web: () => import('./web').then((m) => new m.SSLPinningWeb()),
});

export * from './definitions';
export { SSLPinning };
