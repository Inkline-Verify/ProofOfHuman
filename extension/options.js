(async () => {
  // Health line: helper + enrollment state, so silent failures are visible.
  (function statusLine() {
    const dot = document.querySelector('#status .dot');
    const text = document.getElementById('status-text');
    const setup = document.getElementById('status-setup');
    setup.addEventListener('click', (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
    });
    chrome.runtime.sendMessage({ type: 'inkline-status' }, (r) => {
      const ok = !chrome.runtime.lastError && r && r.ok;
      if (ok && r.enrolled) {
        dot.className = 'dot ok'; text.textContent = 'connected, enrolled';
      } else if (ok) {
        dot.className = 'dot bad'; text.textContent = 'helper found, not enrolled.'; setup.hidden = false;
      } else {
        dot.className = 'dot bad'; text.textContent = 'helper not found.'; setup.hidden = false;
      }
    });
  })();

  let style = await loadStampStyle();

  const swatches = document.getElementById('swatches');
  const labelSel = document.getElementById('label');
  const iconBox = document.getElementById('icon');
  const preview = document.getElementById('preview');
  const saved = document.getElementById('saved');

  for (const [name, title] of Object.entries(STAMP_THEMES)) {
    const b = document.createElement('button');
    b.className = 'swatch';
    b.type = 'button';
    b.title = title;
    b.setAttribute('role', 'radio');
    b.dataset.theme = name;
    const img = document.createElement('img');
    img.src = stampSwatchUrl(name);
    img.alt = title;
    b.appendChild(img);
    b.addEventListener('click', () => update({ theme: name }));
    swatches.appendChild(b);
  }
  for (const text of STAMP_LABELS) {
    const o = document.createElement('option');
    o.value = o.textContent = text;
    labelSel.appendChild(o);
  }
  labelSel.addEventListener('change', () => update({ label: labelSel.value }));
  iconBox.addEventListener('change', () => update({ icon: iconBox.checked }));

  function render() {
    for (const b of swatches.children) b.setAttribute('aria-checked', String(b.dataset.theme === style.theme));
    labelSel.value = style.label;
    iconBox.checked = style.icon;
    preview.replaceChildren(buildStampLine(style, '#', true));
  }

  let timer;
  function update(patch) {
    style = normalizeStampStyle(Object.assign({}, style, patch));
    render();
    chrome.storage.sync.set({ stampStyle: style }, () => {
      saved.textContent = 'Saved';
      clearTimeout(timer);
      timer = setTimeout(() => (saved.textContent = ''), 1200);
    });
  }

  render();
})();
