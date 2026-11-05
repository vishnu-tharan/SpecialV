'use strict';
(() => {
  const form = document.getElementById('unlock-form');
  const input = document.getElementById('passphrase');
  const button = document.getElementById('unlock-button');
  const status = document.getElementById('vault-status');
  const stage = document.getElementById('scrapbook-stage');
  const screen = document.getElementById('lock-screen');
  let busy = false;
  let unlocked = false;
  let generation = 0;
  let inactivity;
  let failures = 0;
  let runtimeUrl;
  const mediaUrls = [];
  function prepareAudio() {
    // Resume during the actual Unlock gesture, before asynchronous decryption.
    // The context remains silent until the correct password releases the audio.
    try {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!AudioContextClass) return;
      let context = window.__vaultAudioContext;
      if (!context || context.state === 'closed') context = window.__vaultAudioContext = new AudioContextClass();
      context.resume().catch(() => {});
    } catch {}
  }
  function closeAudio() {
    const context = window.__vaultAudioContext;
    if (context && context.state !== 'closed') context.close().catch(() => {});
    window.__vaultAudioContext = null;
  }
  // Remove credentials persisted by the previous version, without reading them.
  try { localStorage.removeItem('shaalini_auth_pin'); } catch {}
  const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));

  window.lockVault = () => {
    generation++;
    input.value = '';
    if (unlocked) {
      window.dispatchEvent(new Event('vault:lock'));
      closeAudio();
      stage.hidden = true;
      for (const url of mediaUrls) URL.revokeObjectURL(url);
      stage.replaceChildren();
      screen.hidden = false;
      button.disabled = true;
      input.disabled = true;
      // Reload disposes the private runtime, timers, listeners, media and DOM.
      location.replace(location.pathname);
    }
  };
  function activity() {
    clearTimeout(inactivity);
    if (unlocked) inactivity = setTimeout(window.lockVault, 5 * 60 * 1000);
  }
  for (const event of ['pointerdown', 'keydown', 'touchstart', 'scroll']) {
    document.addEventListener(event, activity, {passive: true});
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) window.lockVault();
  });
  window.addEventListener('pagehide', () => {
    input.value = '';
    window.dispatchEvent(new Event('vault:lock'));
    closeAudio();
    if (unlocked) stage.replaceChildren();
  });
  window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || unlocked) return;
    if (!window.isSecureContext || !crypto.subtle) {
      status.textContent = 'Use HTTPS or the local preview server to unlock.';
      return;
    }
    busy = true;
    prepareAudio();
    button.disabled = true;
    const attempt = ++generation;
    let raw;
    try {
      status.textContent = 'Unlocking…';
      const vault = window.__ENCRYPTED_VAULT__;
      if (vault?.version !== 2 || vault.iterations !== 600000) throw new Error('Unsupported vault');
      raw = new TextEncoder().encode(input.value);
      input.value = '';
      const material = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
      raw.fill(0);
      const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:bytes(vault.salt),
        iterations:vault.iterations, hash:'SHA-256'}, material, {name:'AES-GCM', length:256}, false, ['decrypt']);
      const clear = await crypto.subtle.decrypt({name:'AES-GCM', iv:bytes(vault.iv),
        additionalData:new TextEncoder().encode('private-vault-v2')}, key, bytes(vault.ciphertext));
      let payload;
      try { payload = JSON.parse(new TextDecoder().decode(clear)); }
      finally { new Uint8Array(clear).fill(0); }
      if (attempt !== generation || document.hidden) throw new Error('Cancelled');
      const style = document.createElement('style');
      style.textContent = payload.css;
      document.head.appendChild(style);
      stage.innerHTML = payload.html;
      for (const item of payload.media || []) {
        mediaUrls.push(URL.createObjectURL(new Blob([bytes(item.bytes)], {type:item.type})));
      }
      for (const element of stage.querySelectorAll('[data-vault-media]')) {
        const mediaId = Number(element.dataset.vaultMedia);
        const url = mediaUrls[mediaId];
        if (!url) throw new Error('Missing encrypted media');
        element.src = url;
        if (element.tagName === 'SOURCE' && element.parentElement?.id === 'bg-audio') {
          element.parentElement.__vaultAudioBytes = bytes(payload.media[mediaId].bytes).buffer;
        }
      }
      stage.hidden = false;
      screen.hidden = true;
      unlocked = true;
      activity();
      runtimeUrl = URL.createObjectURL(new Blob([payload.runtime], {type:'text/javascript'}));
      const runtime = document.createElement('script');
      runtime.src = runtimeUrl;
      runtime.onload = () => URL.revokeObjectURL(runtimeUrl);
      runtime.onerror = () => window.lockVault();
      document.body.appendChild(runtime);
      payload = null;
    } catch {
      if (!unlocked) {
        closeAudio();
        status.textContent = 'Unable to unlock. Check the passphrase and vault file.';
        // Convenience delay only: offline security comes from passphrase entropy.
        await new Promise(resolve => setTimeout(resolve, Math.min(1000 * ++failures, 5000)));
      } else window.lockVault();
    } finally {
      raw?.fill(0);
      input.value = '';
      busy = false;
      button.disabled = false;
    }
  });
})();
