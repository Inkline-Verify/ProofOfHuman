// Stamp appearance shared by the options page and the Gmail content script.
// Purely cosmetic: none of this touches what gets signed or verified.

// Footer text is ALWAYS the original Inkline gray; themes only change the icon.
const STAMP_TEXT_COLOR = '#8a8a8a';

const STAMP_THEMES = {
  // name: label shown in the picker
  inkline:   'Inkline',
  ink:       'Ink',
  graphite:  'Graphite',
  ocean:     'Ocean',
  forest:    'Forest',
  coral:     'Coral',
  plum:      'Plum',
  gold:      'Gold',
  rose:      'Rose',
  sky:       'Sky',
  sunset:    'Sunset',
  pastel:    'Pastel',
  rainbow:   'Rainbow',
  tutifruti: 'Tutifruti',
};

const STAMP_LABELS = [
  'Proof of human',
  'Human verified',
  'Signed by a human',
  'Sent by a human',
  'Approved with Touch ID',
];

// Icon is opt-in: a fresh install stamps text only.
const STAMP_DEFAULTS = { theme: 'inkline', label: STAMP_LABELS[0], icon: false };

function normalizeStampStyle(raw) {
  const s = Object.assign({}, STAMP_DEFAULTS, raw || {});
  if (!STAMP_THEMES[s.theme]) s.theme = STAMP_DEFAULTS.theme;
  if (!STAMP_LABELS.includes(s.label)) s.label = STAMP_DEFAULTS.label;
  s.icon = s.icon === true;
  return s;
}

// Hosted copy: goes into the email (Gmail strips chrome-extension:// URLs).
function stampImageUrl(style) {
  if (style.theme === 'inkline') return INKLINE_CONFIG.STAMP_IMG;
  return INKLINE_CONFIG.STAMP_DIR + style.theme + '.png';
}

// Bundled copy: used on extension pages (options/popup) so the picker works
// without any server running.
function stampSwatchUrl(theme) {
  return chrome.runtime.getURL('stamps/sm/' + theme + '.png');
}

function loadStampStyle() {
  return new Promise((resolve) => {
    try {
      chrome.storage.sync.get('stampStyle', (r) => resolve(normalizeStampStyle(r && r.stampStyle)));
    } catch {
      resolve(normalizeStampStyle());
    }
  });
}

// The footer line itself. Built only from markup Gmail preserves when it
// serializes the body: <div>, <i>, <font color size>, <br>, <img>, <a>.
function buildStampLine(style, href, useBundledIcon) {
  const line = document.createElement('div');
  const italic = document.createElement('i');
  const font = document.createElement('font');
  font.setAttribute('color', STAMP_TEXT_COLOR);
  font.setAttribute('size', '1');

  const imgUrl = style.icon ? (useBundledIcon ? stampSwatchUrl(style.theme) : stampImageUrl(style)) : '';
  if (imgUrl) {
    const img = document.createElement('img');
    img.src = imgUrl;
    img.alt = '';
    img.width = 14;
    img.height = 14;
    img.setAttribute('style', 'width:14px;height:14px;vertical-align:-2px;margin-right:5px;');
    font.appendChild(img);
  }

  font.appendChild(document.createTextNode(style.label + ' · '));
  const link = document.createElement('a');
  link.href = href;
  link.textContent = 'Verified with Inkline';
  font.appendChild(link);

  italic.appendChild(font);
  line.appendChild(italic);
  return line;
}
