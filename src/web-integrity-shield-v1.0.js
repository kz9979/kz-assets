/*
 * Web Integrity Shield v1.0
 * Safe client-side deterrents for basic domain authorization and content interaction protection.
 */
(function () {
  'use strict';

  var INTERNAL_WIS_CONFIG = {
    allowedDomains: [
      'polikliniknazmir.com',
      'www.polikliniknazmir.com'
    ],
    allowSubdomains: true,
    allowLocalhost: false,
    debugMode: false,
    unauthorizedMode: 'scramble',
    redirectUrl: 'https://polikliniknazmir.com',
    protectRightClick: true,
    protectViewSourceShortcuts: true,
    protectDevTools: false,
    showConsoleWarning: true,
    showWatermark: false
  };

  var userConfig = window.WEB_INTEGRITY_SHIELD_CONFIG || {};
  var config = mergeConfig(INTERNAL_WIS_CONFIG, userConfig);
  var currentHost = normalizeHost(window.location.hostname);
  var authorized = isAuthorizedHost(currentHost, config);

  if (config.showConsoleWarning) {
    showConsoleNotice(authorized);
  }

  if (!authorized) {
    handleUnauthorized(config);
    return;
  }

  installInteractionProtection(config);
  installDevToolsWarning(config);

  function mergeConfig(defaults, overrides) {
    var merged = {};
    Object.keys(defaults).forEach(function (key) {
      merged[key] = defaults[key];
    });
    Object.keys(overrides || {}).forEach(function (key) {
      merged[key] = overrides[key];
    });
    if (!Array.isArray(merged.allowedDomains)) {
      merged.allowedDomains = [];
    }
    return merged;
  }

  function normalizeHost(host) {
    return String(host || '')
      .trim()
      .toLowerCase()
      .replace(/^www\./, '')
      .replace(/\.$/, '');
  }

  function isLocalhost(host) {
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  }

  function isAuthorizedHost(host, options) {
    if (options.allowLocalhost && isLocalhost(host)) {
      return true;
    }

    return options.allowedDomains.some(function (domain) {
      var allowed = normalizeHost(domain);
      if (!allowed) {
        return false;
      }
      if (host === allowed) {
        return true;
      }
      return Boolean(options.allowSubdomains && host.endsWith('.' + allowed));
    });
  }

  function handleUnauthorized(options) {
    if (options.unauthorizedMode === 'blank') {
      renderBlankScreen();
      return;
    }

    if (options.unauthorizedMode === 'redirect') {
      redirectUnauthorized(options.redirectUrl);
      return;
    }

    if (options.unauthorizedMode === 'scramble') {
      renderScrambleScreen();
      return;
    }

    renderLockScreen();
  }

  function renderBlankScreen() {
    document.documentElement.innerHTML = '';
    document.documentElement.appendChild(document.createElement('head'));
    document.documentElement.appendChild(document.createElement('body'));
  }

  function redirectUnauthorized(redirectUrl) {
    var target = String(redirectUrl || '').trim();
    if (!target) {
      renderLockScreen();
      return;
    }
    window.location.replace(target);
  }


  function renderScrambleScreen() {
    var lines = generateScrambleLines(90);
    var css = [
      'min-height:100vh',
      'margin:0',
      'background:#020617',
      'color:#22c55e',
      'font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace',
      'white-space:pre-wrap',
      'word-break:break-word',
      'padding:24px',
      'box-sizing:border-box',
      'overflow:auto'
    ].join(';');

    document.documentElement.innerHTML = '';
    document.documentElement.appendChild(document.createElement('head'));
    document.documentElement.appendChild(document.createElement('body'));
    document.body.style.cssText = css;
    document.body.textContent = lines.join('\n');
  }

  function generateScrambleLines(count) {
    var seed = hashString(window.location.hostname + window.location.pathname);
    var tokens = ['0x', '_0x', 'function', 'return', 'const', 'let', 'var', '=>', '===', '!==', '&&', '||'];
    var output = [
      '/* Web Integrity Shield: unauthorized host */',
      '/* Protected asset output intentionally obfuscated. */',
      ''
    ];

    for (var index = 0; index < count; index += 1) {
      seed = seededNext(seed);
      var left = tokens[seed % tokens.length] + toHex(seed, 6);
      seed = seededNext(seed);
      var right = toHex(seed, 8);
      seed = seededNext(seed);
      var payload = toHex(seed ^ (index * 2654435761), 12);
      output.push('var ' + left.replace(/[^a-zA-Z0-9_$]/g, '_') + '=\'' + right + payload + '\';/* ' + toHex(seed, 4) + ' */');
    }

    return output;
  }

  function hashString(value) {
    var hash = 2166136261;
    String(value || '').split('').forEach(function (char) {
      hash ^= char.charCodeAt(0);
      hash = Math.imul(hash, 16777619);
    });
    return hash >>> 0;
  }

  function seededNext(seed) {
    return (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  }

  function toHex(value, length) {
    return ('0000000000000000' + (value >>> 0).toString(16)).slice(-length);
  }

  function renderLockScreen() {
    var css = [
      'position:fixed',
      'inset:0',
      'z-index:2147483647',
      'display:flex',
      'align-items:center',
      'justify-content:center',
      'background:#0f172a',
      'color:#f8fafc',
      'font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
      'text-align:center',
      'padding:24px'
    ].join(';');

    var panelCss = [
      'max-width:560px',
      'border:1px solid rgba(148,163,184,.35)',
      'border-radius:18px',
      'background:rgba(15,23,42,.92)',
      'box-shadow:0 24px 80px rgba(0,0,0,.45)',
      'padding:32px'
    ].join(';');

    var lock = document.createElement('div');
    lock.setAttribute('role', 'alert');
    lock.setAttribute('aria-live', 'assertive');
    lock.style.cssText = css;
    lock.innerHTML = '<div style="' + panelCss + '">' +
      '<h1 style="margin:0 0 12px;font-size:28px;line-height:1.2">Website integrity check failed</h1>' +
      '<p style="margin:0;color:#cbd5e1;font-size:16px;line-height:1.6">This page is not authorized to run this protected asset.</p>' +
      '</div>';

    document.documentElement.innerHTML = '';
    document.documentElement.appendChild(document.createElement('head'));
    document.documentElement.appendChild(document.createElement('body'));
    document.body.appendChild(lock);
  }

  function installInteractionProtection(options) {
    if (options.protectRightClick) {
      document.addEventListener('contextmenu', function (event) {
        event.preventDefault();
      });
    }

    if (options.protectViewSourceShortcuts) {
      document.addEventListener('keydown', function (event) {
        var key = String(event.key || '').toLowerCase();
        var blocked = event.key === 'F12' ||
          (event.ctrlKey && event.shiftKey && ['i', 'j', 'c'].indexOf(key) !== -1) ||
          (event.ctrlKey && key === 'u');

        if (blocked) {
          event.preventDefault();
          event.stopPropagation();
        }
      }, true);
    }
  }

  function installDevToolsWarning(options) {
    if (!options.protectDevTools) {
      return;
    }

    var threshold = 160;
    window.setInterval(function () {
      var open = window.outerWidth - window.innerWidth > threshold ||
        window.outerHeight - window.innerHeight > threshold;
      if (open) {
        console.warn('[Web Integrity Shield] Developer tools may be open. Please respect this site\'s protected assets.');
      }
    }, 1500);
  }

  function showConsoleNotice(isAuthorized) {
    var status = isAuthorized ? 'active' : 'blocked';
    console.info('[Web Integrity Shield] Protection ' + status + ' for ' + window.location.hostname + '.');
  }
}());
