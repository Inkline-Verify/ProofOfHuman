// Relays sign requests from the Gmail content script to the native helper.
//
// The extension is untrusted plumbing by design: the helper independently
// canonicalizes, displays, and signs the content it receives, behind a
// biometric gate. Nothing this file does can make the helper sign something
// the human was not shown.

const NATIVE_HOST = 'com.inkline.presence';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'inkline-sign') return false;

  chrome.runtime.sendNativeMessage(NATIVE_HOST, { type: 'sign', email: message.email }, (response) => {
    if (chrome.runtime.lastError) {
      sendResponse({
        ok: false,
        error: {
          code: 'native_host_unavailable',
          message:
            chrome.runtime.lastError.message +
            ' — is the helper installed? Run scripts/install-native-host.sh',
        },
      });
      return;
    }
    sendResponse(response);
  });
  return true; // keep the message channel open for the async response
});

// Toolbar icon mirrors the chosen stamp theme. Purely cosmetic.
async function applyStampIcon() {
  try {
    const { stampStyle } = await chrome.storage.sync.get('stampStyle');
    const theme = (stampStyle && stampStyle.theme) || 'inkline';
    const resp = await fetch(chrome.runtime.getURL('stamps/' + theme + '.png'));
    const bitmap = await createImageBitmap(await resp.blob());
    const imageData = {};
    for (const size of [16, 32, 48, 128]) {
      const canvas = new OffscreenCanvas(size, size);
      const ctx = canvas.getContext('2d');
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(bitmap, 0, 0, size, size);
      imageData[size] = ctx.getImageData(0, 0, size, size);
    }
    await chrome.action.setIcon({ imageData });
  } catch (err) {
    console.warn('[inkline] could not update toolbar icon:', err);
  }
}
chrome.runtime.onStartup.addListener(applyStampIcon);
chrome.runtime.onInstalled.addListener(applyStampIcon);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync' && changes.stampStyle) applyStampIcon();
});
applyStampIcon();

// Status relay for the popup and onboarding page.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'inkline-status') return false;
  chrome.runtime.sendNativeMessage(NATIVE_HOST, { type: 'status' }, (response) => {
    if (chrome.runtime.lastError) {
      sendResponse({ ok: false, error: { code: 'native_host_unavailable', message: chrome.runtime.lastError.message } });
      return;
    }
    sendResponse(response);
  });
  return true;
});

// First install: open the onboarding checklist.
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
  }
});
