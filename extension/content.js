// Gmail integration: intercepts Send, asks the native helper for a receipt
// (which triggers the approval window and biometric prompt), injects the
// receipt footer, and lets the send proceed.
//
// Policy: mail is NEVER blocked. If anything fails — helper missing, user
// declines, notary down, selectors broken — the email sends without a stamp
// and the reason lands in the console.
//
// All Gmail DOM selectors are quarantined here. Gmail's DOM is unversioned
// and changes; when stamping silently stops working, this block is where to
// look.

(() => {
  'use strict';

  const SEL = {
    buttonish: '[role="button"], button',
    composeRoot: 'div.M9, div.AD, div[role="dialog"]',
    subject: 'input[name="subjectbox"]',
    body: 'div[aria-label="Message Body"], div[g_editable="true"][role="textbox"], div[contenteditable="true"][role="textbox"]',
    recipientChip: '[data-hovercard-id*="@"], span[email]',
    recipientArea: (name) => `[name="${name}"], [aria-label^="${name}" i]`,
    fromSpan: 'span[name][email]',
    accountButton: 'a[aria-label*="@"], a[title*="@"]',
  };

  const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;

  // After the extension is updated or reloaded, content scripts in already
  // open tabs are orphaned: chrome.runtime becomes unusable and every send
  // would fail. Detect that, stay out of the way, and tell the user once.
  function alive() {
    try { return !!(chrome && chrome.runtime && chrome.runtime.id); } catch { return false; }
  }

  let staleBannerShown = false;
  function showStaleBanner() {
    if (staleBannerShown) return;
    staleBannerShown = true;
    const b = document.createElement('div');
    b.textContent = 'Inkline was updated — reload this Gmail tab to keep stamping emails.';
    b.setAttribute('style', 'position:fixed;top:0;left:50%;transform:translateX(-50%);z-index:2147483647;background:#111;color:#fff;font:13px -apple-system,sans-serif;padding:8px 16px;border-radius:0 0 8px 8px;cursor:pointer;');
    b.addEventListener('click', () => location.reload());
    document.documentElement.appendChild(b);
  }
  // If the helper does not answer in this window (hung host, user walked
  // away from the approval sheet), the email sends unstamped. Never trap mail.
  const SIGN_TIMEOUT_MS = 120_000;
  let bypassNextSend = false;

  // Send-button detection by visible label, not markup: Gmail's attributes
  // drift, but the button always says "Send".
  function sendButtonFrom(node) {
    const button = node instanceof Element ? node.closest(SEL.buttonish) : null;
    if (!button) return null;
    const label = (
      button.getAttribute('aria-label') ||
      button.getAttribute('data-tooltip') ||
      button.textContent ||
      ''
    ).trim();
    return /^send\b/i.test(label) ? button : null;
  }

  function findSendButton(root) {
    for (const el of root.querySelectorAll(SEL.buttonish)) {
      if (sendButtonFrom(el)) return el;
    }
    return null;
  }

  function chipEmail(el) {
    return el.getAttribute('data-hovercard-id') || el.getAttribute('email') || '';
  }

  function collectRecipients(root) {
    const to = [];
    const cc = [];
    for (const chip of root.querySelectorAll(SEL.recipientChip)) {
      const address = chipEmail(chip);
      if (!EMAIL_RE.test(address)) continue;
      if (chip.closest(SEL.recipientArea('cc'))) {
        cc.push(address);
      } else if (chip.closest(SEL.recipientArea('to'))) {
        to.push(address);
      } else {
        // BCC, or an area we cannot positively classify: fail closed.
        // BCC must never end up in the signed (recipient-visible) content,
        // so an unrecognized container contributes nothing.
      }
    }
    return { to: [...new Set(to)], cc: [...new Set(cc)] };
  }

  function detectFrom(root) {
    const fromSpan = root.querySelector(SEL.fromSpan);
    if (fromSpan) return fromSpan.getAttribute('email');
    for (const el of document.querySelectorAll(SEL.accountButton)) {
      const label = (el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('title') || '');
      const match = label.match(EMAIL_RE);
      if (match) return match[0];
    }
    return null;
  }

  // Gmail sprinkles invisible Unicode format characters (zero-width spaces
  // around inline images, Drive chips, and empty lines) into the compose
  // body. They survive canonicalization, so a recipient could never retype
  // the signed text. Drop them before anything is signed. U+200D (ZWJ) is
  // kept: it joins emoji sequences and is visible in effect.
  const INVISIBLE_RE = /[\u00ad\u061c\u180e\u200b\u200c\u200e\u200f\u2060-\u2064\u206a-\u206f\ufeff]/g;
  function stripInvisible(s) {
    return s.replace(INVISIBLE_RE, '');
  }

  function extractEmail(root) {
    const bodyEl = root.querySelector(SEL.body);
    const from = detectFrom(root);
    const { to, cc } = collectRecipients(root);
    if (!bodyEl || !from || to.length === 0) return null;
    return {
      email: {
        from,
        to,
        cc,
        subject: stripInvisible(root.querySelector(SEL.subject)?.value ?? ''),
        body: stripInvisible(bodyEl.innerText),
      },
      bodyEl,
    };
  }

  // A quiet, formal signature line; colour and wording come from the options
  // page (stamp-style.js). Cosmetic only — the receipt is the same regardless.
  let stampStyle = normalizeStampStyle();
  loadStampStyle().then((s) => (stampStyle = s));
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'sync' && changes.stampStyle) stampStyle = normalizeStampStyle(changes.stampStyle.newValue);
    });
  } catch {}

  function injectFooter(bodyEl, receipt) {
    const footer = document.createElement('div');
    footer.setAttribute('data-inkline', '1');
    const spacer = document.createElement('div');
    spacer.appendChild(document.createElement('br'));
    const line = buildStampLine(stampStyle, INKLINE_CONFIG.VERIFY_URL + '#' + receipt);

    footer.appendChild(spacer);
    footer.appendChild(line);

    // In replies, land after the user's writing, not below the quoted thread.
    const quote = bodyEl.querySelector('.gmail_quote');
    if (quote) {
      bodyEl.insertBefore(footer, quote);
    } else {
      bodyEl.appendChild(footer);
    }
    // Nudge Gmail to notice the DOM change before it serializes the body.
    bodyEl.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function resendClick(button) {
    bypassNextSend = true;
    button.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
  }

  async function interceptSend(button) {
    const root = button.closest(SEL.composeRoot) ?? document;
    const extracted = extractEmail(root);
    if (!extracted) {
      console.warn('[inkline] could not read the compose window (selectors out of date?) — sending unstamped');
      resendClick(button);
      return;
    }

    let response;
    try {
      response = await Promise.race([
        chrome.runtime.sendMessage({ type: 'inkline-sign', email: extracted.email }),
        new Promise((resolve) =>
          setTimeout(
            () => resolve({ ok: false, error: { code: 'timeout', message: 'no answer from the helper' } }),
            SIGN_TIMEOUT_MS
          )
        ),
      ]);
    } catch (err) {
      response = { ok: false, error: { code: 'messaging', message: String(err) } };
    }

    if (response && response.ok && response.receipt) {
      injectFooter(extracted.bodyEl, response.receipt);
      console.info('[inkline] receipt attached (' + (response.mode || 'unknown mode') + ')');
      try {
        chrome.storage.local.set({ lastStamp: { at: Date.now(), mode: response.mode || null } });
      } catch {}
      // Give Gmail a beat to ingest the DOM change before it serializes the
      // body for sending; resending in the same tick can lose the footer.
      await new Promise((resolve) => setTimeout(resolve, 150));
    } else {
      console.warn('[inkline] not stamped: ' + JSON.stringify(response ?? null));
    }
    resendClick(button);
  }

  document.addEventListener(
    'click',
    (event) => {
      const button = sendButtonFrom(event.target);
      if (!button) return;
      if (!alive()) { showStaleBanner(); return; }
      if (bypassNextSend) {
        bypassNextSend = false;
        return;
      }
      event.preventDefault();
      event.stopImmediatePropagation();
      interceptSend(button);
    },
    true
  );

  document.addEventListener(
    'keydown',
    (event) => {
      if (!(event.metaKey || event.ctrlKey) || event.key !== 'Enter') return;
      const root = event.target instanceof Element ? event.target.closest(SEL.composeRoot) : null;
      const button = root ? findSendButton(root) : null;
      if (!button) return;
      if (!alive()) { showStaleBanner(); return; }
      event.preventDefault();
      event.stopImmediatePropagation();
      interceptSend(button);
    },
    true
  );

  console.info('[inkline] content script active');
})();
