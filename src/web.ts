import { WebPlugin } from '@capacitor/core';

import type { PluginVersionResult, SSLPinningConfigurationState, SSLPinningPlugin } from './definitions';

export class SSLPinningWeb extends WebPlugin implements SSLPinningPlugin {
  async getConfiguration(): Promise<SSLPinningConfigurationState> {
    return {
      configured: false,
      certs: [],
      pins: [],
      excludedDomains: [],
    };
  }

  async getPluginVersion(): Promise<PluginVersionResult> {
    return {
      version: 'web',
    };
  }
}
