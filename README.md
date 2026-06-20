# kz-assets

Shared public assets for KZ projects.

## Web Integrity Shield v1.0

Web Integrity Shield is a safe client-side integrity deterrent that can lock a page to authorized domains, show a lock screen on unauthorized hosts, discourage right-click/view-source shortcuts, optionally warn when DevTools may be open, and print a console notice.

### Usage

Declare the authorized domain for the current website before loading the minified shield file:

```html
<script>
window.WEB_INTEGRITY_SHIELD_CONFIG = {
  allowedDomains: [
    "polikliniknazmir.com"
  ],
  allowSubdomains: true,
  allowLocalhost: false,
  unauthorizedMode: "lock",
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
| `unauthorizedMode` | `"lock"` | Shows the lock screen for unauthorized hosts. Use `"console"` to warn without locking. |
| `protectRightClick` | `true` | Prevents the browser context menu as a deterrent. |
| `protectViewSourceShortcuts` | `true` | Prevents common view-source and DevTools shortcut keys as a deterrent. |
| `protectDevTools` | `false` | Optionally logs a warning when DevTools-like viewport changes are detected. |
| `showConsoleWarning` | `true` | Prints a console notice indicating whether protection is active or blocked. |
