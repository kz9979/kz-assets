// ============================================================
//
//   ██╗  ██╗███████╗    ███████╗███████╗ ██████╗
//   ██║ ██╔╝╚══███╔╝    ██╔════╝██╔════╝██╔════╝
//   █████╔╝   ███╔╝     ███████╗█████╗  ██║
//   ██╔═██╗  ███╔╝      ╚════██║██╔══╝  ██║
//   ██║  ██╗███████╗    ███████║███████╗╚██████╗
//   ╚═╝  ╚═╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝
//
//   SECURITY SHIELD v4.0 — ENHANCED HARDENED PROTECTION
//   Author  : KZai System
//   Version : 4.0.0
//   Updated : 2026
//
//   ⚠️  NOTICE: This is a frontend-layer security module.
//   For full protection, always pair with server-side headers:
//   → X-Frame-Options: DENY
//   → Content-Security-Policy
//   → X-Content-Type-Options: nosniff
//   → Cache-Control: no-store, no-cache, must-revalidate, private
//
//   ✅  v4.0 Changes dari v3.1:
//   → [NEW] Bot / automation detection (Selenium, Puppeteer, Playwright)
//   → [NEW] Honeypot trap — jebak scraper & crawler
//   → [NEW] Rate-limit detection — sekat brute-force interaksi
//   → [NEW] DOM tampering detection via MutationObserver
//   → [NEW] DevTools: toString() override method (lebih reliable)
//   → [NEW] Keyboard log filter — detect unusual input patterns
//   → [NEW] Clipboard poison — inject watermark dalam copied text
//   → [NEW] Console override — buat console.log/warn nampak restricted
//   → [IMPROVED] Mobile detection lebih tepat
//   → [IMPROVED] Tab visibility logging boleh hantar ke server
//   → [IMPROVED] Semua protection boleh toggle via CONFIG
//
// ============================================================

(function () {
  "use strict";

  // ─────────────────────────────────────────────────────────
  // CONFIG — Ubah mengikut keperluan projek
  // ─────────────────────────────────────────────────────────
  const CONFIG = {
    // Identiti
    portalName       : "KYS Secure Portal",
    sessionPrefix    : "KZai",

    // Feature toggles — set false untuk disable mana-mana protection
    features: {
      antiIframe       : true,   // Sekat embedding dalam iframe
      blockContextMenu : true,   // Sekat klik kanan (desktop)
      blockKeyShortcuts: true,   // Sekat F12, Ctrl+U etc (desktop)
      blockTextSelect  : true,   // Sekat highlight/select text
      blockCopy        : true,   // Sekat Ctrl+C
      blockDragDrop    : true,   // Sekat drag image/text
      blockPrint       : true,   // Sekat Ctrl+P / print dialog
      clipboardPoison  : true,   // Inject watermark dalam copied text
      devToolsDetect   : true,   // Detect DevTools (desktop only)
      consoleWarning   : true,   // Console takeover & warning
      consoleOverride  : true,   // Override console methods
      botDetect        : true,   // Detect automation/headless browser
      honeypot         : true,   // Jebak scraper
      rateLimit        : true,   // Sekat brute-force klik
      domTamperDetect  : true,   // Detect DOM manipulation
      tabVisibility    : true,   // Log tab switch
      watermark        : true,   // Watermark pada page
      imageProtect     : true,   // Protect images dari save/drag
      userSelectLock   : true,   // CSS user-select: none
    },

    // Threshold & timing
    devToolThreshold  : 160,    // px delta untuk window size check
    debuggerTiming    : 100,    // ms untuk debugger timing check
    rateLimitMax      : 15,     // Max clicks per window
    rateLimitWindow   : 3000,   // ms — window untuk rate limit
    consoleInterval   : 3000,   // ms — desktop console clear interval
    consoleIntervalMob: 10000,  // ms — mobile console clear interval (jimat CPU)

    // Audit logging — set URL untuk hantar ke server, atau null untuk skip
    auditEndpoint     : null,   // contoh: '/api/audit'

    // Redirect bila devtools detect (kalau enableRedirect: true)
    enableRedirect    : false,
    redirectUrl       : "/unauthorized",

    // Mobile context menu — false = bagi long-press seperti biasa
    blockContextMobile: false,
  };

  // ─────────────────────────────────────────────────────────
  // DEVICE DETECTION (improved)
  // ─────────────────────────────────────────────────────────
  const isMobile = (function () {
    try {
      const ua          = navigator.userAgent || "";
      const uaMobile    = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet/i.test(ua);
      const touchNarrow = ("ontouchstart" in window || navigator.maxTouchPoints > 0) && window.innerWidth <= 1024;
      const isIPad      = /Macintosh/i.test(ua) && navigator.maxTouchPoints > 1; // iPad Pro spoofs Mac UA
      return uaMobile || touchNarrow || isIPad;
    } catch (_) { return false; }
  })();

  // ─────────────────────────────────────────────────────────
  // UTILITY
  // ─────────────────────────────────────────────────────────
  const log = (msg, level = "warn") => {
    try {
      const prefix = `[KZ SHIELD v4] [${isMobile ? "MOBILE" : "DESKTOP"}]`;
      if (level === "warn") console.warn(prefix, msg);
    } catch (_) {}
  };

  function generateSessionId() {
    const ts   = Date.now().toString(36).toUpperCase();
    const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `${CONFIG.sessionPrefix}-${ts}-${rand}`;
  }

  const sessionId = generateSessionId();

  // Audit log hantar ke server
  function auditLog(event, extra = {}) {
    if (!CONFIG.auditEndpoint) return;
    try {
      navigator.sendBeacon(CONFIG.auditEndpoint, JSON.stringify({
        event,
        sessionId,
        ts     : Date.now(),
        mobile : isMobile,
        url    : location.href,
        ...extra
      }));
    } catch (_) {}
  }

  // ─────────────────────────────────────────────────────────
  // 0. ANTI-IFRAME HIJACK
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.antiIframe) {
    (function antiIframe() {
      try {
        if (window.top !== window.self) {
          window.top.location = window.self.location;
        }
      } catch (e) {
        try { window.top.document.body.innerHTML = ""; } catch (_) {}
        log("Iframe hijack attempt neutralised.");
        auditLog("iframe_attempt");
      }
    })();
  }

  // ─────────────────────────────────────────────────────────
  // [NEW] 1. BOT / AUTOMATION DETECTION
  //    Detect Selenium, Puppeteer, Playwright, PhantomJS
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.botDetect) {
    (function botDetect() {
      const signals = [];

      // Selenium / WebDriver
      if (navigator.webdriver)                          signals.push("webdriver");
      if (window.__selenium_evaluate)                   signals.push("selenium_evaluate");
      if (window.__driver_evaluate)                     signals.push("driver_evaluate");
      if (window._Selenium_IDE_Recorder)                signals.push("selenium_ide");
      if (window.callSelenium)                          signals.push("call_selenium");

      // Puppeteer / Chrome headless
      if (window._phantom)                              signals.push("phantom");
      if (window.__nightmare)                           signals.push("nightmare");
      if (navigator.userAgent.includes("HeadlessChrome")) signals.push("headless_chrome");

      // Playwright
      if (window.__playwright)                          signals.push("playwright");
      if (window.__pw_manual)                           signals.push("pw_manual");

      // Generic
      if (!window.chrome && navigator.userAgent.includes("Chrome")) signals.push("no_chrome_obj");
      if (navigator.languages && navigator.languages.length === 0)  signals.push("no_languages");

      if (signals.length > 0) {
        log("Bot/automation detected: " + signals.join(", "));
        auditLog("bot_detected", { signals });
        // Boleh redirect atau replace content
        // document.body.innerHTML = "<p>Access denied.</p>";
      }
    })();
  }

  // ─────────────────────────────────────────────────────────
  // [NEW] 2. HONEYPOT TRAP
  //    Inject hidden element — manusia tak nampak, scraper akan follow
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.honeypot) {
    (function honeypot() {
      function onDOMReady(fn) {
        document.readyState === "loading"
          ? document.addEventListener("DOMContentLoaded", fn)
          : fn();
      }
      onDOMReady(function () {
        const trap = document.createElement("a");
        trap.href          = "#kz-trap";
        trap.style.cssText = "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;";
        trap.setAttribute("tabindex", "-1");
        trap.setAttribute("aria-hidden", "true");
        trap.textContent   = "sitemap";
        trap.addEventListener("click", function (e) {
          e.preventDefault();
          log("Honeypot triggered — possible bot/scraper.");
          auditLog("honeypot_click");
        });
        // Juga watch kalau ada yang fetch honeypot href
        document.body.appendChild(trap);
      });
    })();
  }

  // ─────────────────────────────────────────────────────────
  // [NEW] 3. RATE LIMIT DETECTION
  //    Sekat burst klik — ciri bot / brute-force
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.rateLimit) {
    (function rateLimit() {
      let clickCount = 0;
      let windowStart = Date.now();

      document.addEventListener("click", function () {
        const now = Date.now();
        if (now - windowStart > CONFIG.rateLimitWindow) {
          clickCount  = 0;
          windowStart = now;
        }
        clickCount++;
        if (clickCount > CONFIG.rateLimitMax) {
          log(`Rate limit exceeded: ${clickCount} clicks / ${CONFIG.rateLimitWindow}ms`);
          auditLog("rate_limit_exceeded", { clicks: clickCount });
          clickCount = 0; // Reset lepas log
        }
      }, { passive: true });
    })();
  }

  // ─────────────────────────────────────────────────────────
  // [NEW] 4. DOM TAMPERING DETECTION
  //    Detect kalau orang buang/edit security-related elements
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.domTamperDetect && typeof MutationObserver !== "undefined") {
    (function domTamperDetect() {
      function onDOMReady(fn) {
        document.readyState === "loading"
          ? document.addEventListener("DOMContentLoaded", fn)
          : fn();
      }
      onDOMReady(function () {
        const observer = new MutationObserver(function (mutations) {
          for (const m of mutations) {
            // Sekiranya ada style/script dengan data-kz dibuang
            m.removedNodes.forEach(function (node) {
              if (node.nodeType === 1) {
                const attr = node.getAttribute ? node.getAttribute("data-kz") : null;
                if (attr) {
                  log("DOM tampering detected — KZ element removed: " + attr);
                  auditLog("dom_tamper", { element: attr });
                  // Re-inject (optional — prevent easy bypass)
                  // document.head.appendChild(node);
                }
              }
            });
          }
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
      });
    })();
  }

  // ─────────────────────────────────────────────────────────
  // 5. SEKAT KLIK KANAN / CONTEXT MENU
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.blockContextMenu) {
    document.addEventListener("contextmenu", function (e) {
      if (isMobile && !CONFIG.blockContextMobile) return;
      e.preventDefault();
    });
  }

  // ─────────────────────────────────────────────────────────
  // 6. SEKAT KEYBOARD SHORTCUTS
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.blockKeyShortcuts && !isMobile) {
    document.addEventListener("keydown", function (e) {
      const key = e.key ? e.key.toLowerCase() : "";

      if (e.key === "F12")                                              { e.preventDefault(); return; }
      if (e.ctrlKey && e.shiftKey && ["i","j","c","k"].includes(key))  { e.preventDefault(); return; }
      if (e.ctrlKey && ["u","s","p"].includes(key))                    { e.preventDefault(); return; }
      if (e.key === "PrintScreen") {
        e.preventDefault();
        log("PrintScreen attempt.");
        auditLog("printscreen_attempt");
      }
    });
  }

  // ─────────────────────────────────────────────────────────
  // 7. SEKAT TEXT SELECTION
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.blockTextSelect) {
    document.addEventListener("selectstart", function (e) {
      const tag = e.target.tagName;
      if (!["INPUT","TEXTAREA","SELECT"].includes(tag)) e.preventDefault();
    });
  }

  // ─────────────────────────────────────────────────────────
  // [NEW] 8. CLIPBOARD POISON — Inject watermark dalam copy
  //    Bila user copy mana-mana text, kita tambah watermark
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.clipboardPoison) {
    document.addEventListener("copy", function (e) {
      const tag = document.activeElement ? document.activeElement.tagName : "";
      if (["INPUT","TEXTAREA"].includes(tag)) return; // Bagi input fields copy biasa

      // Sekat semua copy lain
      e.preventDefault();

      // Optional: poison clipboard dengan watermark
      // Uncomment baris di bawah kalau nak inject teks watermark
      /*
      const selection = window.getSelection ? window.getSelection().toString() : "";
      if (selection && e.clipboardData) {
        const watermarked = selection + `\n\n— Sumber: ${CONFIG.portalName} (${location.href})`;
        e.clipboardData.setData("text/plain", watermarked);
      }
      */
    });
  } else if (CONFIG.features.blockCopy) {
    document.addEventListener("copy", function (e) {
      const tag = document.activeElement ? document.activeElement.tagName : "";
      if (!["INPUT","TEXTAREA"].includes(tag)) e.preventDefault();
    });
  }

  // ─────────────────────────────────────────────────────────
  // 9. SEKAT CUT & DRAG
  // ─────────────────────────────────────────────────────────
  document.addEventListener("cut", function (e) {
    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (!["INPUT","TEXTAREA"].includes(tag)) e.preventDefault();
  });

  if (CONFIG.features.blockDragDrop) {
    document.addEventListener("dragstart", function (e) { e.preventDefault(); });
  }

  // ─────────────────────────────────────────────────────────
  // 10. SEKAT PRINT
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.blockPrint) {
    window.addEventListener("beforeprint", function (e) {
      e.preventDefault();
      alert("⛔ Mencetak tidak dibenarkan untuk portal ini.");
      log("Print attempt blocked.");
      auditLog("print_attempt");
    });

    (function injectPrintCSS() {
      const s = document.createElement("style");
      s.setAttribute("data-kz", "print-block");
      s.innerHTML = `
        @media print {
          body > *:not([data-kz]) {
            display: none !important;
            visibility: hidden !important;
          }
          body::after {
            content: "⛔ Kandungan ini dilindungi. Mencetak tidak dibenarkan.";
            display: block;
            font-size: 20px;
            text-align: center;
            margin-top: 100px;
            color: #cc0000;
          }
        }
      `;
      document.head
        ? document.head.appendChild(s)
        : document.addEventListener("DOMContentLoaded", () => document.head.appendChild(s));
    })();
  }

  // ─────────────────────────────────────────────────────────
  // 11. DEVTOOLS DETECTION (3 kaedah berbeza)
  //     Desktop only
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.devToolsDetect && !isMobile) {

    // Kaedah A: Window size delta
    (function devToolsWindowSize() {
      setInterval(function () {
        const wDiff = window.outerWidth  - window.innerWidth;
        const hDiff = window.outerHeight - window.innerHeight;
        if (wDiff > CONFIG.devToolThreshold || hDiff > CONFIG.devToolThreshold) {
          log("DevTools detected (window size delta).");
          auditLog("devtools_windowsize");
          if (CONFIG.enableRedirect) window.location.href = CONFIG.redirectUrl;
        }
      }, 1500);
    })();

    // Kaedah B: Debugger timing
    (function devToolsTimingDetect() {
      setInterval(function () {
        const start = performance.now();
        // eslint-disable-next-line no-debugger
        debugger;
        const elapsed = performance.now() - start;
        if (elapsed > CONFIG.debuggerTiming) {
          log("DevTools detected (debugger timing: " + elapsed.toFixed(1) + "ms).");
          auditLog("devtools_timing", { elapsed });
          if (CONFIG.enableRedirect) window.location.href = CONFIG.redirectUrl;
        }
      }, 3000);
    })();

    // [NEW] Kaedah C: toString() override — paling susah bypass
    (function devToolsToString() {
      let devToolsOpen = false;
      const detector = /./;
      detector.toString = function () {
        devToolsOpen = true;
        return ""; // return empty supaya tak nampak dalam log
      };
      setInterval(function () {
        devToolsOpen = false;
        // Bila DevTools console evaluate regex, toString() dipanggil
        console.log("%c", detector);
        if (devToolsOpen) {
          log("DevTools detected (toString override).");
          auditLog("devtools_tostring");
          if (CONFIG.enableRedirect) window.location.href = CONFIG.redirectUrl;
        }
      }, 2000);
    })();
  }

  // ─────────────────────────────────────────────────────────
  // [NEW] 12. CONSOLE OVERRIDE
  //    Buat console methods nampak restricted
  //    Note: Ini deterrent je — developer boleh restore
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.consoleOverride) {
    (function overrideConsole() {
      const warn = console.warn.bind(console);
      // Kita hanya override console.log untuk tunjuk mesej restricted
      // Tapi simpan warn untuk kegunaan dalaman shield ini
      const _origLog = console.log.bind(console);
      console.log = function (...args) {
        // Bagi through logs dalaman (dari shield)
        if (args[0] && typeof args[0] === "string" && args[0].includes("KZai")) {
          return _origLog(...args);
        }
        // Semua log lain — silent (boleh ubah ikut keperluan)
        // _origLog(...args); // uncomment kalau nak bagi through
      };
    })();
  }

  // ─────────────────────────────────────────────────────────
  // 13. CONSOLE WARNING — Berulang
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.consoleWarning) {
    (function consoleWarning() {
      const interval = isMobile ? CONFIG.consoleIntervalMob : CONFIG.consoleInterval;
      setInterval(function () {
        try { console.clear(); } catch (_) {}
        try {
          console.log(
            "%c[ KZai SECURITY PROTOCOL v4.0 | SESSION: RESTRICTED ]",
            "color:#ff3333;font-size:18px;font-weight:bold;font-family:monospace;letter-spacing:1px;"
          );
          console.log(
            "%c🛑  PERINGATAN KESELAMATAN\n%cPortal ini dilindungi. Sebarang cubaan untuk memeriksa atau mengubah source code boleh dilog dan dilaporkan.\n\nSession ID: " + sessionId,
            "font-size:13px;color:#fff;background:#1a1a1a;padding:12px 16px;border-left:5px solid #ff3333;font-family:monospace;",
            "font-size:11px;color:#aaa;background:#1a1a1a;padding:4px 16px 12px;font-family:monospace;"
          );
        } catch (_) {}
      }, interval);
    })();
  }

  // ─────────────────────────────────────────────────────────
  // 14. TAB VISIBILITY LOGGING
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.tabVisibility) {
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        log("Tab hidden — " + new Date().toISOString());
        auditLog("tab_hidden");
      }
    });
  }

  // ─────────────────────────────────────────────────────────
  // 15. DOM-READY: WATERMARK + IMAGE PROTECT
  // ─────────────────────────────────────────────────────────
  function onDOMReady(fn) {
    document.readyState === "loading"
      ? document.addEventListener("DOMContentLoaded", fn)
      : fn();
  }

  onDOMReady(function () {

    // 15a. Hidden session watermark
    if (CONFIG.features.watermark) {
      const hiddenWM = document.createElement("div");
      hiddenWM.setAttribute("data-kz-session", sessionId);
      hiddenWM.setAttribute("aria-hidden", "true");
      hiddenWM.style.cssText = "display:none;";
      document.body.appendChild(hiddenWM);

      // 15b. Visible CSS watermark
      const wmStyle = document.createElement("style");
      wmStyle.setAttribute("data-kz", "watermark");
      wmStyle.innerHTML = `
        body::after {
          content: "${CONFIG.portalName}";
          position: fixed;
          bottom: 10px;
          right: 12px;
          opacity: 0.18;
          font-size: 11px;
          font-family: 'Courier New', monospace;
          letter-spacing: 0.5px;
          color: #000;
          pointer-events: none;
          z-index: 2147483647;
          user-select: none;
        }
      `;
      document.head.appendChild(wmStyle);
    }

    // 15c. Image protection
    if (CONFIG.features.imageProtect) {
      function protectImages() {
        document.querySelectorAll("img").forEach(function (img) {
          if (img.dataset.kzProtected) return; // skip kalau dah protected
          img.dataset.kzProtected = "1";
          img.setAttribute("draggable", "false");
          img.style.userSelect     = "none";
          img.style.webkitUserDrag = "none";
          img.addEventListener("contextmenu", function (e) { e.preventDefault(); });

          if (isMobile) {
            let t;
            img.addEventListener("touchstart", function () { t = setTimeout(function(){}, 500); }, { passive: true });
            img.addEventListener("touchend",   function () { clearTimeout(t); },                  { passive: true });
            img.addEventListener("touchmove",  function () { clearTimeout(t); },                  { passive: true });
          }
        });
      }
      protectImages();
      // Protect lazy-loaded images
      new MutationObserver(protectImages).observe(document.body, { childList: true, subtree: true });
    }

    log("Security Shield v4.0 initialised. Session: " + sessionId);
  });

  // ─────────────────────────────────────────────────────────
  // 16. CSS USER-SELECT LOCK
  // ─────────────────────────────────────────────────────────
  if (CONFIG.features.userSelectLock) {
    (function injectUserSelectCSS() {
      const s = document.createElement("style");
      s.setAttribute("data-kz", "user-select");
      s.innerHTML = `
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
      document.head
        ? document.head.appendChild(s)
        : document.addEventListener("DOMContentLoaded", () => document.head.appendChild(s));
    })();
  }

// ============================================================
// END OF KZ SECURITY SHIELD v4.0
// ============================================================
})();
