# kz-assets

Shared public assets for KZ projects.

## Web Integrity Shield v1.0

Web Integrity Shield is a safe client-side integrity deterrent that can lock a page to authorized domains, show a lock screen on unauthorized hosts, discourage right-click/view-source shortcuts, optionally warn when DevTools may be open, and print a console notice.

### Source and production files

- `src/web-integrity-shield-v1.0.js` is the readable maintenance source. Keep edits in this file clean and reviewable.
- `dist/web-integrity-shield-v1.0.min.js` is the production obfuscated file for websites/CDN use. Do not hand-edit this generated file.
- Frontend JavaScript cannot be hidden 100%, because browsers must download and execute it. Obfuscation is only a deterrent, but it makes casual reading, copying, and editing much harder than plain minification.

### Usage

Recommended deployment only needs this one script tag:

```html
<script data-cfasync="false" src="https://rawcdn.githack.com/kz9979/kz-assets/main/dist/web-integrity-shield-v1.0.min.js"></script>
```

All default protection configuration is already embedded inside the Web Integrity Shield file. No inline `window.WEB_INTEGRITY_SHIELD_CONFIG` block is required for normal deployment.

The embedded default configuration authorizes only:

- `polikliniknazmir.com`
- `www.polikliniknazmir.com`

Unauthorized domains, copied hosting, preview links, Canvas hosting, and any other non-approved hostname use the safe `"scramble"` mode by default. Scramble mode replaces the page with fake obfuscated-code style output as a deterrent; it does not freeze, crash, overload, or perform malicious behavior.

For a different website or domain, update the internal allowed domain list in `src/web-integrity-shield-v1.0.js`, then regenerate the production file with `npm run build:wis`. The production file `dist/web-integrity-shield-v1.0.min.js` must remain obfuscated and should not be hand-edited.

Optional backward compatibility is preserved: if `window.WEB_INTEGRITY_SHIELD_CONFIG` exists before the shield loads, those values override the embedded defaults. This override path is intended for advanced/custom deployments only; normal deployment should use the one-line script tag above.

### Configuration

| Option | Default | Description |
| --- | --- | --- |
| `allowedDomains` | `polikliniknazmir.com`, `www.polikliniknazmir.com` | Domains authorized to run the protected page. Update the internal list in source and rebuild for a different website. |
| `allowSubdomains` | `true` | Allows subdomains of each declared domain. |
| `allowLocalhost` | `false` | Allows local development hosts when explicitly enabled. |
| `unauthorizedMode` | `"scramble"` | Unauthorized behavior. Use `"scramble"` for fake obfuscated-code output, `"lock"` for the safe lock screen, `"blank"` for an empty page, or `"redirect"` with `redirectUrl`. |
| `redirectUrl` | `"https://polikliniknazmir.com"` | Redirect target used only when `unauthorizedMode` is `"redirect"`. If empty, the shield falls back to the lock screen. |
| `protectRightClick` | `true` | Prevents the browser context menu as a deterrent. |
| `protectViewSourceShortcuts` | `true` | Prevents common view-source and DevTools shortcut keys as a deterrent. |
| `protectDevTools` | `false` | Optionally logs a warning when DevTools-like viewport changes are detected. |
| `showConsoleWarning` | `true` | Prints a console notice indicating whether protection is active or blocked. |
| `debugMode` | `false` | Reserved for future diagnostics. |
| `showWatermark` | `false` | Reserved for optional watermark display. |

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
