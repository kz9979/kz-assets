# kz-assets

Shared public assets for KZ projects.

## Web Integrity Shield v1.0

Web Integrity Shield is a safe client-side integrity deterrent that can lock a page to authorized domains, show a lock screen on unauthorized hosts, discourage right-click/view-source shortcuts, optionally warn when DevTools may be open, and print a console notice.

### Source and production files

- `src/web-integrity-shield-v1.0.js` is the readable maintenance source. Keep edits in this file clean and reviewable.
- `dist/web-integrity-shield-v1.0.min.js` is the production obfuscated file for websites/CDN use. Do not hand-edit this generated file.
- Frontend JavaScript cannot be hidden 100%, because browsers must download and execute it. Obfuscation is only a deterrent, but it makes casual reading, copying, and editing much harder than plain minification.

### Usage

Declare the authorized domain for the current website before loading the production obfuscated shield file:

```html
<script>
window.WEB_INTEGRITY_SHIELD_CONFIG = {
  allowedDomains: [
    "example.com"
  ],
  allowSubdomains: true,
  allowLocalhost: false,
  unauthorizedMode: "lock",
  redirectUrl: "",
  protectRightClick: true,
  protectViewSourceShortcuts: true,
  protectDevTools: false,
  showConsoleWarning: true
};
</script>

<script src="https://rawcdn.githack.com/kz9979/kz-assets/main/dist/web-integrity-shield-v1.0.min.js"></script>
```

For better privacy and cleaner deployment, do not place all client/project domains in every webpage. Each webpage should only declare its own authorized domain.

### Configuration

| Option | Default | Description |
| --- | --- | --- |
| `allowedDomains` | `[]` | Domains authorized to run the protected page. Add only the current website domain. |
| `allowSubdomains` | `true` | Allows subdomains of each declared domain. |
| `allowLocalhost` | `false` | Allows local development hosts when explicitly enabled. |
| `unauthorizedMode` | `"lock"` | Unauthorized behavior. Use `"lock"` for the safe lock screen, `"blank"` for an empty page, or `"redirect"` with `redirectUrl`. |
| `redirectUrl` | `""` | Redirect target used only when `unauthorizedMode` is `"redirect"`. If empty, the shield falls back to the lock screen. |
| `protectRightClick` | `true` | Prevents the browser context menu as a deterrent. |
| `protectViewSourceShortcuts` | `true` | Prevents common view-source and DevTools shortcut keys as a deterrent. |
| `protectDevTools` | `false` | Optionally logs a warning when DevTools-like viewport changes are detected. |
| `showConsoleWarning` | `true` | Prints a console notice indicating whether protection is active or blocked. |

### Build

Regenerate the production obfuscated file from the readable source with:

```sh
npm run build:wis
```

The local build script (`scripts/build-wis.js`) uses only Node.js built-ins, so it does not require a private registry or third-party npm package access. It compacts the source, base64-encodes the payload into escaped chunks, reverses the chunk table, and emits a small `_0x...` loader so the checked-in distribution file is production-obfuscated rather than simple whitespace minification.

Run syntax checks for both the readable source and generated distribution file with:

```sh
npm run check:wis
```
