# Example App for `@capgo/capacitor-ssl-pinning`

This Vite project links directly to the local plugin source so you can inspect the active SSL pinning configuration while developing.

## Getting started

```bash
bun install
bun run start
```

To test on native shells:

```bash
bunx cap add ios
bunx cap add android
bunx cap sync
```

Native shells enable the privacy screen automatically on load. Use the example buttons to disable it temporarily, then re-enable it and confirm the app switcher preview is hidden again.
