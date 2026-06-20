(function () {
  "use strict";

  /* ============================================================
     KZ SECURITY SHIELD v4.2
     (Readable + Hardened Mobile Detection — fix for Chrome/iOS
      false-positive "Developer tools access detected" popup)
     ============================================================ */

  const CONFIG = {
    portalName: "KYS Secure Portal",
    sessionPrefix: "KZai",
    features: {
      antiIframe: true,
      blockContextMenu: true,
      blockKeyShortcuts: true,
      blockTextSelect: true,
      blockCopy: true,
      blockDragDrop: true,
      blockPrint: true,
      clipboardPoison: true,
      devToolsDetect: true,
      consoleWarning: true,
      consoleOverride: true,
      botDetect: true,
      honeypot: true,
      rateLimit: true,
      domTamperDetect: true,
      tabVisibility: true,
      watermark: true,
      imageProtect: true,
      userSelectLock: true
    },
    devToolThreshold: 160,
    debuggerTiming: 100,
    rateLimitMax: 15,
    rateLimitWindow: 3000,
    consoleInterval: 3000,
    consoleIntervalMob: 10000,
    auditEndpoint: null,
    enableRedirect: false,
    redirectUrl: "/unauthorized",
    blockContextMobile: false
  };

  /* ------------------------------------------------------------
     MOBILE DETECTION — HARDENED (v4.2 fix)
     Problem in v4.0: relied only on navigator.userAgent + innerWidth.
     Chrome on iOS in "Desktop Site" mode (or certain auto Request-
     Desktop-Site behaviour) can report a desktop-style userAgent and
     a larger innerWidth, causing isMobileDevice to wrongly return
     false on a real iPhone — letting the devTools window-size check
     run and false-positive trigger on normal address-bar/toolbar
     resize during scroll.

     Fix: add a screen.width/height check. The physical screen
     resolution does NOT change when a browser spoofs its UA or
     viewport width, so it's a much more reliable mobile signal.
     Also: fail-safe on error — assume mobile (skip the check)
     rather than assume desktop (risk a false popup).
     ------------------------------------------------------------ */
  const isMobileDevice = function () {
    try {
      const ua = navigator.userAgent || "";
      const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet/i.test(ua);

      // PRIMARY SIGNAL (v4.2): raw touch capability, with no width/UA
      // combination attached. "Request Desktop Site" in Chrome/Safari
      // spoofs the userAgent string AND the reported innerWidth AND
      // (in some cases) the screen.width/height object — but it does
      // NOT remove the underlying touchscreen hardware capability.
      // A device either has touch event support or it doesn't; this
      // is the single most spoof-resistant signal available.
      const hasTouchCapability = ("ontouchstart" in window) || navigator.maxTouchPoints > 0;

      const isMacTouch = /Macintosh/i.test(ua) && navigator.maxTouchPoints > 1;

      // Physical screen size fallback — extra safety net, even though
      // it can occasionally be scaled under aggressive desktop emulation.
      const smallestScreenDimension = Math.min(
        window.screen && window.screen.width ? window.screen.width : Infinity,
        window.screen && window.screen.height ? window.screen.height : Infinity
      );
      const looksLikePhoneScreen = smallestScreenDimension <= 500;

      return isMobileUA || hasTouchCapability || isMacTouch || looksLikePhoneScreen;
    } catch (err) {
      // Fail-safe: if detection itself errors out, assume mobile so we
      // never wrongly run the strict desktop devtools checks.
      return true;
    }
  }();

  const log = (msg) => {
    try {
      console.warn("[KZ SHIELD v4.2] [" + (isMobileDevice ? "MOBILE" : "DESKTOP") + "]", msg);
    } catch (_) {}
  };

  function generateSessionId() {
    const ts = Date.now().toString(36).toUpperCase();
    const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
    return CONFIG.sessionPrefix + "-" + ts + "-" + rand;
  }
  const sessionId = generateSessionId();

  function sendAudit(eventName, extra = {}) {
    if (!CONFIG.auditEndpoint) return;
    try {
      navigator.sendBeacon(CONFIG.auditEndpoint, JSON.stringify({
        event: eventName,
        sessionId: sessionId,
        ts: Date.now(),
        mobile: isMobileDevice,
        url: location.href,
        ...extra
      }));
    } catch (_) {}
  }

  // 1. Anti-iframe (clickjacking protection)
  if (CONFIG.features.antiIframe) {
    (function () {
      try {
        if (window.top !== window.self) {
          window.top.location = window.self.location;
        }
      } catch (_) {
        try {
          window.top.document.body.innerHTML = "";
        } catch (_) {}
        log("Iframe hijack attempt neutralised.");
        sendAudit("iframe_attempt");
      }
    })();
  }

  // 2. Basic bot/automation detection
  if (CONFIG.features.botDetect) {
    (function () {
      const signals = [];
      if (navigator.webdriver) signals.push("webdriver");
      if (window.__selenium_evaluate) signals.push("selenium_evaluate");
      if (window.__driver_evaluate) signals.push("driver_evaluate");
      if (window._Selenium_IDE_Recorder) signals.push("selenium_ide");
      if (window.callSelenium) signals.push("call_selenium");
      if (window._phantom) signals.push("phantom");
      if (window.__nightmare) signals.push("nightmare");
      if (navigator.userAgent.includes("HeadlessChrome")) signals.push("headless_chrome");
      if (window.__playwright) signals.push("playwright");
      if (window.__pw_manual) signals.push("pw_manual");
      if (!window.chrome && navigator.userAgent.includes("Chrome")) signals.push("no_chrome_obj");
      if (navigator.languages && navigator.languages.length === 0) signals.push("no_languages");

      if (signals.length > 0) {
        log("Bot/automation detected: " + signals.join(", "));
        sendAudit("bot_detected", { signals });
      }
    })();
  }

  // 3. Honeypot link (catches naive scrapers)
  if (CONFIG.features.honeypot) {
    (function () {
      function onReady(fn) {
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", fn);
        } else {
          fn();
        }
      }
      onReady(function () {
        const trap = document.createElement("a");
        trap.href = "#kz-trap";
        trap.style.cssText = "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;";
        trap.setAttribute("tabindex", "-1");
        trap.setAttribute("aria-hidden", "true");
        trap.textContent = "sitemap";
        trap.addEventListener("click", function (e) {
          e.preventDefault();
          log("Honeypot triggered — possible bot/scraper.");
          sendAudit("honeypot_click");
        });
        document.body.appendChild(trap);
      });
    })();
  }

  // 4. Click rate limiting
  if (CONFIG.features.rateLimit) {
    (function () {
      let clickCount = 0;
      let windowStart = Date.now();
      document.addEventListener("click", function () {
        const now = Date.now();
        if (now - windowStart > CONFIG.rateLimitWindow) {
          clickCount = 0;
          windowStart = now;
        }
        clickCount++;
        if (clickCount > CONFIG.rateLimitMax) {
          log("Rate limit exceeded: " + clickCount + " clicks / " + CONFIG.rateLimitWindow + "ms");
          sendAudit("rate_limit_exceeded", { clicks: clickCount });
          clickCount = 0;
        }
      }, { passive: true });
    })();
  }

  // 5. DOM tamper detection (watches for removal of [data-kz] elements)
  if (CONFIG.features.domTamperDetect && typeof MutationObserver !== "undefined") {
    (function () {
      function onReady(fn) {
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", fn);
        } else {
          fn();
        }
      }
      onReady(function () {
        const observer = new MutationObserver(function (mutations) {
          for (const mutation of mutations) {
            mutation.removedNodes.forEach(function (node) {
              if (node.nodeType === 1) {
                const tag = node.getAttribute ? node.getAttribute("data-kz") : null;
                if (tag) {
                  log("DOM tampering detected — KZ element removed: " + tag);
                  sendAudit("dom_tamper", { element: tag });
                }
              }
            });
          }
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
      });
    })();
  }

  // 6. Block right-click context menu (desktop only, unless blockContextMobile is set)
  if (CONFIG.features.blockContextMenu) {
    document.addEventListener("contextmenu", function (e) {
      if (isMobileDevice && !CONFIG.blockContextMobile) {
        return;
      }
      e.preventDefault();
    });
  }

  // 7. Block common DevTools keyboard shortcuts (desktop only)
  if (CONFIG.features.blockKeyShortcuts && !isMobileDevice) {
    document.addEventListener("keydown", function (e) {
      const key = e.key ? e.key.toLowerCase() : "";
      if (e.key === "F12") {
        e.preventDefault();
        return;
      }
      if (e.ctrlKey && e.shiftKey && ["i", "j", "c", "k"].includes(key)) {
        e.preventDefault();
        return;
      }
      if (e.ctrlKey && ["u", "s", "p"].includes(key)) {
        e.preventDefault();
        return;
      }
      if (e.key === "PrintScreen") {
        e.preventDefault();
        log("PrintScreen attempt detected.");
        sendAudit("printscreen_attempt");
      }
    });
  }

  // 8. Block text selection (except inside form fields)
  if (CONFIG.features.blockTextSelect) {
    document.addEventListener("selectstart", function (e) {
      const tag = e.target.tagName;
      if (!["INPUT", "TEXTAREA", "SELECT"].includes(tag)) {
        e.preventDefault();
      }
    });
  }

  // 9. Copy/cut handling
  if (CONFIG.features.clipboardPoison) {
    document.addEventListener("copy", function (e) {
      const tag = document.activeElement ? document.activeElement.tagName : "";
      if (["INPUT", "TEXTAREA"].includes(tag)) {
        return;
      }
      e.preventDefault();
      // Optional: inject a watermark into clipboard instead of blocking outright.
      // e.clipboardData.setData('text/plain', window.getSelection().toString() + `\n\n— ${CONFIG.portalName}`);
    });
  } else if (CONFIG.features.blockCopy) {
    document.addEventListener("copy", function (e) {
      const tag = document.activeElement ? document.activeElement.tagName : "";
      if (!["INPUT", "TEXTAREA"].includes(tag)) {
        e.preventDefault();
      }
    });
  }
  document.addEventListener("cut", function (e) {
    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (!["INPUT", "TEXTAREA"].includes(tag)) {
      e.preventDefault();
    }
  });

  // 10. Block drag-and-drop
  if (CONFIG.features.blockDragDrop) {
    document.addEventListener("dragstart", function (e) {
      e.preventDefault();
    });
  }

  // 11. Block printing
  if (CONFIG.features.blockPrint) {
    window.addEventListener("beforeprint", function (e) {
      e.preventDefault();
      alert("⛔ Printing is not permitted on this portal.");
      log("Print attempt blocked.");
      sendAudit("print_attempt");
    });
    (function () {
      const style = document.createElement("style");
      style.setAttribute("data-kz", "print-block");
      style.innerHTML = `
        @media print {
          body > *:not([data-kz]) { display:none !important; visibility:hidden !important; }
          body::after {
            content: "⛔ This content is protected. Printing is not permitted.";
            display: block; font-size: 20px; text-align: center;
            margin-top: 100px; color: #cc0000;
          }
        }
      `;
      if (document.head) {
        document.head.appendChild(style);
      } else {
        document.addEventListener("DOMContentLoaded", () => document.head.appendChild(style));
      }
    })();
  }

  // 12. DevTools detection — DESKTOP ONLY (isMobileDevice now hardened, see above)
  // v4.2: removed the window-size-delta method entirely. It was the
  // least reliable signal — triggered by address bar resize, split
  // screen, "Desktop Site" mode, foldable devices, etc. The debugger
  // timing method below is far more accurate and has near-zero
  // false-positive rate on real desktop browsers.
  if (CONFIG.features.devToolsDetect && !isMobileDevice) {
    // 12a. debugger statement timing method
    (function () {
      setInterval(function () {
        const start = performance.now();
        debugger;
        const elapsed = performance.now() - start;
        if (elapsed > CONFIG.debuggerTiming) {
          log("DevTools detected (debugger timing: " + elapsed.toFixed(1) + "ms).");
          sendAudit("devtools_timing", { elapsed });
          if (CONFIG.enableRedirect) {
            window.location.href = CONFIG.redirectUrl;
          }
        }
      }, 3000);
    })();

    // 12b. console.log toString() override method
    (function () {
      let triggered = false;
      const probe = /./;
      probe.toString = function () {
        triggered = true;
        return "";
      };
      setInterval(function () {
        triggered = false;
        console.log("%c", probe);
        if (triggered) {
          log("DevTools detected (toString override).");
          sendAudit("devtools_tostring");
          if (CONFIG.enableRedirect) {
            window.location.href = CONFIG.redirectUrl;
          }
        }
      }, 2000);
    })();
  }

  // 13. console.log override — only allow KZai-tagged logs through
  if (CONFIG.features.consoleOverride) {
    (function () {
      const originalLog = console.log.bind(console);
      console.log = function (...args) {
        if (args[0] && typeof args[0] === "string" && args[0].includes("KZai")) {
          return originalLog(...args);
        }
      };
    })();
  }

  // 14. Periodic console warning banner
  if (CONFIG.features.consoleWarning) {
    (function () {
      const interval = isMobileDevice ? CONFIG.consoleIntervalMob : CONFIG.consoleInterval;
      setInterval(function () {
        try {
          console.clear();
        } catch (_) {}
        try {
          console.log(
            "%c[ KZai SECURITY PROTOCOL v4.2 | SESSION: RESTRICTED ]",
            "color:#ff3333;font-size:18px;font-weight:bold;font-family:monospace;letter-spacing:1px;"
          );
          console.log(
            "%c🛑  SECURITY WARNING\n%cThis portal is protected. Any attempt to inspect or modify the source code may be logged and reported.\n\nSession ID: " + sessionId,
            "font-size:13px;color:#fff;background:#1a1a1a;padding:12px 16px;border-left:5px solid #ff3333;font-family:monospace;",
            "font-size:11px;color:#aaa;background:#1a1a1a;padding:4px 16px 12px;font-family:monospace;"
          );
        } catch (_) {}
      }, interval);
    })();
  }

  // 15. Tab visibility tracking
  if (CONFIG.features.tabVisibility) {
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        log("Tab hidden — " + new Date().toISOString());
        sendAudit("tab_hidden");
      }
    });
  }

  function onDomReady(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  onDomReady(function () {
    // 16. Invisible watermark (session id embedded, faint text overlay)
    if (CONFIG.features.watermark) {
      const marker = document.createElement("div");
      marker.setAttribute("data-kz-session", sessionId);
      marker.setAttribute("aria-hidden", "true");
      marker.style.cssText = "display:none;";
      document.body.appendChild(marker);

      const style = document.createElement("style");
      style.setAttribute("data-kz", "watermark");
      style.innerHTML = `
        body::after {
          content: "${CONFIG.portalName}";
          position: fixed; bottom: 10px; right: 12px;
          opacity: 0.18; font-size: 11px;
          font-family: 'Courier New', monospace;
          letter-spacing: 0.5px; color: #000;
          pointer-events: none; z-index: 2147483647; user-select: none;
        }
      `;
      document.head.appendChild(style);
    }

    // 17. Basic image protection (no drag, no context menu, no long-press save on mobile)
    if (CONFIG.features.imageProtect) {
      function protectImages() {
        document.querySelectorAll("img").forEach(function (img) {
          if (img.dataset.kzProtected) return;
          img.dataset.kzProtected = "1";
          img.setAttribute("draggable", "false");
          img.style.userSelect = "none";
          img.style.webkitUserDrag = "none";
          img.addEventListener("contextmenu", function (e) {
            e.preventDefault();
          });
          if (isMobileDevice) {
            let pressTimer;
            img.addEventListener("touchstart", function () {
              pressTimer = setTimeout(function () {}, 500);
            }, { passive: true });
            img.addEventListener("touchend", function () {
              clearTimeout(pressTimer);
            }, { passive: true });
            img.addEventListener("touchmove", function () {
              clearTimeout(pressTimer);
            }, { passive: true });
          }
        });
      }
      protectImages();
      new MutationObserver(protectImages).observe(document.body, { childList: true, subtree: true });
    }

    log("Security Shield v4.2 initialised. Session: " + sessionId);
  });

  // 18. Global user-select lock (text inputs remain selectable)
  if (CONFIG.features.userSelectLock) {
    (function () {
      const style = document.createElement("style");
      style.setAttribute("data-kz", "user-select");
      style.innerHTML = `
        body, body * {
          -webkit-user-select: none !important;
          -moz-user-select: none !important;
          -ms-user-select: none !important;
          user-select: none !important;
          -webkit-touch-callout: none;
        }
        input, textarea, select, [contenteditable="true"] {
          -webkit-user-select: text !important;
          -moz-user-select: text !important;
          -ms-user-select: text !important;
          user-select: text !important;
          -webkit-touch-callout: default !important;
        }
      `;
      if (document.head) {
        document.head.appendChild(style);
      } else {
        document.addEventListener("DOMContentLoaded", () => document.head.appendChild(style));
      }
    })();
  }
})();
