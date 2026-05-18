/**
 * Plugin version payload.
 */
export interface PluginVersionResult {
  /**
   * Version identifier returned by the platform implementation.
   */
  version: string;
}

/**
 * Static SSL pinning configuration currently visible to the plugin.
 */
export interface SSLPinningConfigurationState {
  /**
   * Whether at least one certificate is configured for native pinning.
   */
  configured: boolean;

  /**
   * Certificate paths from `capacitor.config.*` relative to the app root.
   */
  certs: string[];

  /**
   * SHA-256 public key pins in `sha256/<base64>` format.
   */
  pins: string[];

  /**
   * Fully-qualified URLs that should bypass SSL pinning.
   */
  excludedDomains: string[];
}

/**
 * Plugin configuration added under `plugins.SSLPinning` in `capacitor.config.*`.
 */
export interface SSLPinningPluginConfig {
  /**
   * Certificate files relative to the application root.
   *
   * During `bunx cap sync`, this plugin copies them into `webDir/certs` so native runtimes can load them from
   * the bundled web assets.
   */
  certs?: string[];

  /**
   * SHA-256 public key pins in `sha256/<base64>` format.
   *
   * When configured, the plugin extracts the public key from the server's leaf certificate,
   * computes its SHA-256 hash, and compares it against these pins. Supports key rotation by
   * specifying multiple pins — at least one must match.
   */
  pins?: string[];

  /**
   * Fully-qualified URLs that should bypass pinning.
   *
   * Match is done by origin, and by path-prefix when the configured URL contains a path.
   */
  excludedDomains?: string[];
}

/**
 * Capacitor API for inspecting SSL pinning configuration.
 *
 * Native enforcement is applied automatically to `CapacitorHttp` requests when:
 * 1. `plugins.CapacitorHttp.enabled` is `true`
 * 2. `plugins.SSLPinning.certs` contains at least one certificate
 */
export interface SSLPinningPlugin {
  /**
   * Returns the active native configuration visible to the plugin.
   */
  getConfiguration(): Promise<SSLPinningConfigurationState>;

  /**
   * Returns the native implementation version marker.
   */
  getPluginVersion(): Promise<PluginVersionResult>;
}
