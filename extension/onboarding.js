function setMark(stepId, state) {
  const mark = document.querySelector(`#${stepId} .mark`);
  mark.className = 'mark ' + (state === true ? 'ok' : state === false ? 'bad' : 'wait');
  mark.textContent = state === true ? '[ ok ]' : state === false ? '[ !! ]' : '[ .. ]';
}

async function check() {
  setMark('step-helper', null);
  setMark('step-enroll', null);
  const status = await new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: 'inkline-status' }, (r) => {
        resolve(chrome.runtime.lastError ? { ok: false } : (r || { ok: false }));
      });
    } catch { resolve({ ok: false }); }
  });
  const helperUp = !!status.ok;
  const enrolled = helperUp && !!status.enrolled;
  setMark('step-helper', helperUp);
  setMark('step-enroll', helperUp ? enrolled : false);
  document.getElementById('helper-fix').hidden = helperUp;
  document.getElementById('enroll-fix').hidden = !helperUp || enrolled;

  chrome.storage.sync.get('stampStyle', (r) => {
    setMark('step-style', r && r.stampStyle ? true : null);
  });
  chrome.storage.local.get('lastStamp', (r) => {
    setMark('step-test', r && r.lastStamp ? true : null);
  });
}

document.getElementById('recheck').addEventListener('click', check);
document.getElementById('open-options').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});
check();
setInterval(check, 4000);
