// buildless/app.js
// Piping SSH — buildless React 19 frontend.
// Uses htm for JSX-like templates and Comlink for the WASM worker.

import { createElement as h, useState, useEffect, useRef, useMemo, Fragment } from 'react';
import { createRoot } from 'react-dom/client';
import htm from 'htm';
import * as Comlink from 'comlink';

// Bind htm to React.createElement so we can write html`<div/>` everywhere.
const html = htm.bind(h);

// ─── Utilities ────────────────────────────────────────────────────────────────

// ─── Fragment params ──────────────────────────────────────────────────────────

const P = {
  pipingServerUrl:      'server',
  sshHost:              'host',
  sshPort:              'port',
  sshUsername:          'user',
  sshPassword:          'password',
  autoConnect:          'auto_connect',
};

function parseFragmentParams() {
  return new URL(`a://a${location.hash.substring(1)}`).searchParams;
}

const fragmentParams = {
  pipingServerUrl()      { return parseFragmentParams().get(P.pipingServerUrl) ?? undefined; },
  sshHost()              { return parseFragmentParams().get(P.sshHost) ?? undefined; },
  sshPort()              { return parseFragmentParams().get(P.sshPort) ?? undefined; },
  sshUsername()          { return parseFragmentParams().get(P.sshUsername) ?? undefined; },
  sshPassword()          { return parseFragmentParams().get(P.sshPassword) ?? undefined; },
  autoConnect()          {
    const s = parseFragmentParams().get(P.autoConnect);
    return s !== null && ['', '1', 'true'].includes(s);
  },
};

function getConfiguredUrl({ pipingServerUrl, sshHost, sshPort, sshUsername, sshPassword, autoConnect }) {
  const sp = new URLSearchParams();
  if (pipingServerUrl)                           sp.set(P.pipingServerUrl, pipingServerUrl);
  if (sshHost)                                   sp.set(P.sshHost, sshHost);
  if (sshPort && sshPort !== '')                 sp.set(P.sshPort, sshPort);
  if (sshUsername)                               sp.set(P.sshUsername, sshUsername);
  if (sshPassword !== undefined)                 sp.set(P.sshPassword, sshPassword);
  if (autoConnect)                               sp.set(P.autoConnect, '1');
  const url = new URL(location.href);
  url.hash = `?${sp.toString()}`;
  return url.href.replaceAll('%3A', ':').replaceAll('%2F', '/');
}

// ─── Auth key sets store ──────────────────────────────────────────────────────

const authKeysStoreTypes = ['memory', 'session_storage', 'local_storage'];
const storeTypeLabel = { memory: 'memory', session_storage: 'session storage', local_storage: 'local storage' };

const memKeyMap = new Map();
let sessKeys = (() => { try { return JSON.parse(sessionStorage.getItem('auth_key_sets') || '[]'); } catch { return []; } })();
let localKeys = (() => { try { return JSON.parse(localStorage.getItem('auth_key_sets') || '[]'); } catch { return []; } })();

const keySubscribers = new Set();

function getStoredKeys() {
  const all = [...memKeyMap.values(), ...sessKeys, ...localKeys];
  const seen = new Set();
  return all
    .filter(k => { if (seen.has(k.sha256Fingerprint)) return false; seen.add(k.sha256Fingerprint); return true; })
    .sort((a, b) => a.addedAtMillis - b.addedAtMillis);
}

function notifyKeySubscribers() { keySubscribers.forEach(fn => fn([...getStoredKeys()])); }

function useStoredKeys() {
  const [keys, setKeys] = useState(getStoredKeys);
  useEffect(() => { keySubscribers.add(setKeys); return () => keySubscribers.delete(setKeys); }, []);
  return keys;
}

function _addKey(k) {
  switch (k.storeType) {
    case 'memory':
      memKeyMap.set(k.sha256Fingerprint, k);
      break;
    case 'session_storage':
      sessKeys = [...sessKeys, k];
      sessionStorage.setItem('auth_key_sets', JSON.stringify(sessKeys));
      break;
    case 'local_storage':
      localKeys = [...localKeys, k];
      localStorage.setItem('auth_key_sets', JSON.stringify(localKeys));
      break;
  }
  notifyKeySubscribers();
}

function removeKey(fp) {
  memKeyMap.delete(fp);
  sessKeys  = sessKeys.filter(k => k.sha256Fingerprint !== fp);
  localKeys = localKeys.filter(k => k.sha256Fingerprint !== fp);
  sessionStorage.setItem('auth_key_sets', JSON.stringify(sessKeys));
  localStorage.setItem('auth_key_sets', JSON.stringify(localKeys));
  notifyKeySubscribers();
}

function updateKey(k) { removeKey(k.sha256Fingerprint); _addKey(k); }

// ─── Server host key manager ──────────────────────────────────────────────────

const serverHostKeyMgr = {
  trust(fp) {
    const t = this._get(); t.push(fp);
    localStorage.setItem('known_host_key_fingerprints', JSON.stringify(t));
  },
  isTrusted(fp) { return this._get().includes(fp); },
  _get() { try { return JSON.parse(localStorage.getItem('known_host_key_fingerprints') || '[]'); } catch { return []; } },
};

// ─── Worker management ────────────────────────────────────────────────────────

let workerRemote, currentWorker;

function createWorkerRemote() {
  const w = new Worker(new URL('./worker.js', import.meta.url));
  return [Comlink.wrap(w), w];
}

[workerRemote, currentWorker] = createWorkerRemote();

async function getAliveWorker() {
  if (await workerRemote.existed()) {
    currentWorker.terminate();
    console.warn('[app] recreating WASM worker...');
    [workerRemote, currentWorker] = createWorkerRemote();
  }
  return workerRemote;
}

const workerGetAuthPublicKeyType  = pk  => getAliveWorker().then(r => r.getAuthPublicKeyType(pk));
const workerGetFingerprint        = pk  => getAliveWorker().then(r => r.sshSha256Fingerprint(pk));
const workerIsEncrypted           = pk  => getAliveWorker().then(r => r.sshPrivateKeyIsEncrypted(pk));
const workerGenerateRsa           = b   => getAliveWorker().then(r => r.generateRsaKeys(b));
const workerGenerateEd25519       = ()  => getAliveWorker().then(r => r.generateEd25519Keys());

async function storeAuthKeySet({ name, publicKey, privateKey, storeType }) {
  const fp = await workerGetFingerprint(publicKey);
  if (getStoredKeys().find(k => k.sha256Fingerprint === fp)) return 'already_exist';
  _addKey({ name, publicKey, privateKey, storeType, sha256Fingerprint: fp, addedAtMillis: Date.now(), enabled: true });
  return 'stored';
}

// ─── Supports request streams ─────────────────────────────────────────────────

async function checkSupportsRequestStreams() {
  try {
    if (new Request('', { method: 'POST', body: new ReadableStream(), duplex: 'half' }).headers.has('Content-Type')) return false;
    return fetch('data:a/a;charset=utf-8,', { method: 'POST', body: new ReadableStream(), duplex: 'half' })
      .then(() => true, () => false);
  } catch { return false; }
}

// ─── Global prompt ────────────────────────────────────────────────────────────

let _promptResolve = null;
let _setPromptState = null;

function showPrompt({ title, message = '', showsInput = true, inputType = 'text', placeholder = '', width = '60vw' }) {
  return new Promise(resolve => {
    _promptResolve = resolve;
    _setPromptState?.({ shows: true, title, message, showsInput, inputType, placeholder, width });
  });
}

function GlobalPrompt() {
  const [st, setSt] = useState({ shows: false, title: '', message: '', showsInput: true, inputType: 'text', placeholder: '', width: '60vw' });
  const [text, setText] = useState('');
  const [showPw, setShowPw] = useState(false);
  const inputRef = useRef(null);

  useEffect(() => {
    _setPromptState = s => { setSt(s); setText(''); setShowPw(false); };
    return () => { _setPromptState = null; };
  }, []);

  useEffect(() => {
    if (st.shows) setTimeout(() => inputRef.current?.focus(), 60);
  }, [st.shows]);

  if (!st.shows) return null;

  const cancel = () => { setSt(s => ({ ...s, shows: false })); _promptResolve?.(undefined); };
  const ok     = () => { setSt(s => ({ ...s, shows: false })); _promptResolve?.(st.showsInput ? text : ''); };
  const isPw   = st.inputType === 'password';

  return html`
    <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
         onClick=${cancel}>
      <div class="bg-gray-900 border border-gray-800 p-6"
           style=${{ width: st.width, maxWidth: '90vw', minWidth: '20rem' }}
           onClick=${e => e.stopPropagation()}>
        <h3 class="text-lg font-semibold mb-3">${st.title}</h3>
        ${st.message && html`<pre class="whitespace-pre-wrap text-sm text-gray-300 mb-4 font-sans">${st.message}</pre>`}
        ${st.showsInput && html`
          <div class="relative mb-1">
            <input ref=${inputRef}
              type=${isPw && !showPw ? 'password' : 'text'}
              value=${text}
              onInput=${e => setText(e.target.value)}
              onKeyDown=${e => e.key === 'Enter' && ok()}
              placeholder=${st.placeholder}
              class="w-full bg-gray-700 rounded px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500 ${isPw ? 'pr-10' : ''}"
            />
            ${isPw && html`
              <button type="button" onClick=${() => setShowPw(p => !p)}
                class="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white p-1">
                ${showPw ? '🙈' : '👁'}
              </button>
            `}
          </div>
        `}
        <div class="flex justify-end gap-3 mt-4">
          <button type="button" onClick=${cancel}
            class="px-4 py-2 text-gray-400 hover:text-white transition-colors">Cancel</button>
          <button type="button" onClick=${ok}
            class="px-4 py-2 bg-amber-600 hover:bg-amber-500 rounded-sm text-white transition-colors">OK</button>
        </div>
      </div>
    </div>
  `;
}

// ─── Global snackbar ──────────────────────────────────────────────────────────

let _setSnackbar = null;

function showSnackbar({ message = '', icon } = {}) { _setSnackbar?.({ shows: true, message, icon }); }

function GlobalSnackbar() {
  const [st, setSt] = useState({ shows: false, message: '' });

  useEffect(() => {
    _setSnackbar = setSt;
    return () => { _setSnackbar = null; };
  }, []);

  useEffect(() => {
    if (!st.shows) return;
    const t = setTimeout(() => setSt(s => ({ ...s, shows: false })), 2500);
    return () => clearTimeout(t);
  }, [st.shows, st.message]);

  if (!st.shows) return null;

  return html`
    <div class="fixed top-4 left-1/2 -translate-x-1/2 bg-gray-900 border border-gray-800 text-gray-300 px-4 py-2 z-40 text-xs whitespace-nowrap">
      ${st.message}
    </div>
  `;
}

// ─── CopyButton ───────────────────────────────────────────────────────────────

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const el = document.createElement('textarea');
      el.value = text; document.body.appendChild(el); el.select();
      document.execCommand('copy'); document.body.removeChild(el);
    }
    setCopied(true);
    await new Promise(r => setTimeout(r, 2000));
    setCopied(false);
  };

  return html`
    <button type="button" onClick=${copy}
      title=${copied ? 'Copied!' : 'Copy to clipboard'}
      class="p-1 text-gray-400 hover:text-white transition-colors rounded flex-shrink-0">
      ${copied
        ? html`<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20,6 9,17 4,12"/></svg>`
        : html`<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`
      }
    </button>
  `;
}

// ─── PipingSsh (terminal view) ────────────────────────────────────────────────

function PipingSsh({ pipingServerUrl, username, defaultSshPassword, onEnd }) {
  const termRef  = useRef(null);
  const fitRef   = useRef(null);
  const termApi  = useRef(null);
  const [connState, setConnState] = useState('connecting');

  // Fit terminal after DOM layout is committed (terminal div visible)
  useEffect(() => {
    if (connState !== 'connected') return;
    const raf1 = requestAnimationFrame(() => {
      fitRef.current?.();
      termApi.current?.focus();
      requestAnimationFrame(() => fitRef.current?.());
    });
    return () => cancelAnimationFrame(raf1);
  }, [connState]);

  useEffect(() => {
    let localCancelled = false;

    (async () => {
      // xterm globals injected by CDN scripts
      const { Terminal } = window;
      const { FitAddon }   = window.FitAddon;

      const term     = new Terminal({ cursorBlink: true, scrollbar: { showScrollbar: false } });
      const fitAddon = new FitAddon();
      const mc       = new MessageChannel();

      term.loadAddon(fitAddon);
      term.open(termRef.current);

      const fit = () => {
        const dims = fitAddon.proposeDimensions();
        if (!dims) return;
        mc.port1.postMessage({ type: 'resize', cols: dims.cols, rows: dims.rows });
        fitAddon.fit();
      };
      fitRef.current = fit;
      termApi.current = term;
      window.addEventListener('resize', fit);

      // WebSocketStream transport
      let transport;
      try {
        transport = await new WebSocketStream(pipingServerUrl).opened;
      } catch (e) {
        console.error('WebSocket connection failed', e);
        alert('WebSocket connection failed: ' + (e.message || e));
        localCancelled = true;
        onEnd();
        return;
      }

      const termReadable = new ReadableStream({ start(ctrl) { term.onData(d => ctrl.enqueue(d)); } });
      window.addEventListener('beforeunload', () => mc.port1.postMessage({ type: 'disconnect' }));

      // Prepare auth key sets
      const storedKeys  = getStoredKeys().filter(s => s.enabled);
      const authKeySets = (await Promise.all(storedKeys.map(async s => ({
        publicKey:  s.publicKey,
        privateKey: s.privateKey,
        encrypted:  await workerIsEncrypted(s.privateKey),
      })))).sort((a, b) => (a.encrypted ? 1 : 0) - (b.encrypted ? 1 : 0));

      let pwTried = false;

      try {
        const remote    = await getAliveWorker();
        const transfers = [transport.readable, transport.writable, termReadable, mc.port2];

        await remote.doSsh(
          Comlink.transfer({
            transport, termReadable,
            initialRows: term.rows, initialCols: term.cols,
            username,
            messagePort: mc.port2,
            authKeySets,
          }, transfers),
          Comlink.proxy({
            termWrite(data) { term.write(data); },

            async onPasswordAuth() {
              if (!pwTried && defaultSshPassword !== undefined) { pwTried = true; return defaultSshPassword; }
              const msg = pwTried ? 'try again.' : '';
              const pw  = await showPrompt({ title: 'Password', message: msg, inputType: 'password', width: '60vw' });
              if (pw === undefined) { localCancelled = true; throw new Error('aborted'); }
              pwTried = true;
              return pw;
            },

            async getAuthPrivateKeyPassphrase(fp) {
              const k    = storedKeys.find(k => k.sha256Fingerprint === fp);
              const type = await workerGetAuthPublicKeyType(k.publicKey);
              const pp   = await showPrompt({
                title:     'Passphrase',
                message:   `(${k.name}) ${type}\nEnter passphrase for key`,
                inputType: 'password',
                width:     '60vw',
              });
              if (pp === undefined) { localCancelled = true; throw new Error('aborted'); }
              return pp;
            },

            onAuthSigned(fp) {
              const k = storedKeys.find(k => k.sha256Fingerprint === fp);
              showSnackbar({ message: `Signed by ${k?.name}` });
            },

            async onHostKey({ key }) {
              if (serverHostKeyMgr.isTrusted(key.fingerprint)) return true;
              const ans = await showPrompt({
                title:       'New host',
                message:     `${key.type} key fingerprint is ${key.fingerprint}\nAre you sure you want to continue connecting?`,
                placeholder: 'yes/no/[fingerprint]',
                width:       '60vw',
              });
              if (ans === 'yes' || ans === key.fingerprint) {
                serverHostKeyMgr.trust(key.fingerprint);
                return true;
              }
              localCancelled = true;
              return false;
            },

            onConnected() {
              setConnState('connected');
            },
          }),
        );

        showSnackbar({ message: 'Finished' });
      } catch (e) {
        if (localCancelled) { showSnackbar({ message: 'Canceled' }); }
        else { console.error('SSH error', e); alert(`SSH error: ${e}`); }
      } finally {
        window.removeEventListener('resize', fit);
        onEnd();
      }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return html`
    <div style=${{ flex: 1 }}>
      ${connState === 'connecting' && html`
        <div class="flex flex-col items-center justify-center gap-6 pt-16">
          <div class="relative w-36 h-36">
            <div class="absolute inset-0 rounded-full border-2 border-gray-700"></div>
            <div class="absolute inset-0 rounded-full border-2 border-t-amber-500 animate-spin"></div>
          </div>
          <p class="text-gray-400">Connecting...</p>
        </div>
      `}
      <div ref=${termRef}
        style=${{ display: connState === 'connected' ? 'block' : 'none', width: '100%', height: 'calc(100vh - 48px)' }}
      ></div>
    </div>
  `;
}

// ─── KeysEditor ───────────────────────────────────────────────────────────────

function KeysEditor({ onSave, initialPublicKey = '', initialPrivateKey = '' }) {
  const [name,       setName]      = useState('');
  const [storeType,  setStoreType] = useState('local_storage');
  const [publicKey,  setPubKey]    = useState(initialPublicKey);
  const [privateKey, setPrivKey]   = useState(initialPrivateKey);
  const [busy,       setBusy]      = useState(false);

  useEffect(() => { if (initialPublicKey) suggestName(initialPublicKey); }, []);

  useEffect(() => { if (!name && publicKey) suggestName(publicKey); }, [publicKey]); // eslint-disable-line

  async function suggestName(pk) {
    try {
      const type     = await workerGetAuthPublicKeyType(pk);
      const existing = getStoredKeys().map(k => k.name);
      let   cand     = type;
      for (let n = 2; existing.includes(cand); n++) cand = `${type} (${n})`;
      setName(cand);
    } catch (_) { /* key not yet parseable */ }
  }

  async function handleSave(e) {
    e.preventDefault();
    if (!name || !publicKey || !privateKey) return;
    setBusy(true);
    try { onSave({ name, publicKey, privateKey, storeType }); }
    finally { setBusy(false); }
  }

  const inputClass = 'w-full bg-gray-700 rounded px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm';

  return html`
    <form onSubmit=${handleSave} class="space-y-4">
      <div>
        <label class="block text-sm text-gray-400 mb-1">Name *</label>
        <input value=${name} onInput=${e => setName(e.target.value)} required
          placeholder="e.g. Ed25519" class=${inputClass} />
      </div>

      <div>
        <label class="block text-sm text-gray-400 mb-1">Store type</label>
        <div class="flex flex-wrap gap-4">
          ${authKeysStoreTypes.map(t => html`
            <label key=${t} class="flex items-center gap-2 cursor-pointer text-sm">
              <input type="radio" name="storeType" value=${t} checked=${storeType === t}
                onChange=${() => setStoreType(t)} class="accent-blue-500" />
              ${storeTypeLabel[t]}
            </label>
          `)}
        </div>
      </div>

      <div>
        <label class="block text-sm text-gray-400 mb-1">Public key *</label>
        <textarea value=${publicKey} onInput=${e => setPubKey(e.target.value)} required rows="3"
          class="${inputClass} font-mono resize-vertical"></textarea>
      </div>

      <div>
        <label class="block text-sm text-gray-400 mb-1">Private key *</label>
        <textarea value=${privateKey} onInput=${e => setPrivKey(e.target.value)} required rows="5"
          class="${inputClass} font-mono resize-vertical"></textarea>
      </div>

      <button type="submit"
        disabled=${busy || !name || !publicKey || !privateKey}
        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-white transition-colors text-sm">
        Save
      </button>
    </form>
  `;
}

// ─── KeyGenerator ─────────────────────────────────────────────────────────────

function KeyGenerator({ onSave }) {
  const [keyType,    setKeyType]    = useState('Ed25519');
  const [keyBits,    setKeyBits]    = useState(2048);
  const [generating, setGenerating] = useState(false);
  const [generated,  setGenerated]  = useState(null);

  if (generated) {
    return html`<${KeysEditor} onSave=${onSave} initialPublicKey=${generated.publicKey} initialPrivateKey=${generated.privateKey} />`;
  }

  async function generate() {
    setGenerating(true);
    try {
      const keys = keyType === 'RSA' ? await workerGenerateRsa(keyBits) : await workerGenerateEd25519();
      setGenerated(keys);
    } finally { setGenerating(false); }
  }

  return html`
    <div class="space-y-4">
      <div class="flex gap-4">
        ${['Ed25519', 'RSA'].map(t => html`
          <label key=${t} class="flex items-center gap-2 cursor-pointer text-sm">
            <input type="radio" name="keyType" value=${t} checked=${keyType === t}
              onChange=${() => setKeyType(t)} disabled=${generating} class="accent-blue-500" />
            ${t}
          </label>
        `)}
      </div>

      ${keyType === 'RSA' && html`
        <div>
          <label class="block text-sm text-gray-400 mb-1">Key bits</label>
          <div class="flex gap-4">
            ${[2048, 4096].map(b => html`
              <label key=${b} class="flex items-center gap-2 cursor-pointer text-sm">
                <input type="radio" name="keyBits" value=${b} checked=${keyBits === b}
                  onChange=${() => setKeyBits(b)} disabled=${generating} class="accent-blue-500" />
                ${b}
              </label>
            `)}
          </div>
        </div>
        ${keyBits >= 4096 && html`
          <div class="border border-blue-700 text-blue-300 rounded p-3 text-sm">
            ⚠ It will take about 1 minute or more to generate. Ed25519 is recommended.
          </div>
        `}
      `}

      <button type="button" onClick=${generate} disabled=${generating}
        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-white transition-colors flex items-center gap-2 text-sm">
        ${generating && html`<span class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin inline-block"></span>`}
        Generate
      </button>
    </div>
  `;
}

// ─── KeyManager ───────────────────────────────────────────────────────────────

function KeyManager() {
  const keys = useStoredKeys();
  const [expanded, setExpanded] = useState(null);
  const [edits,    setEdits]    = useState({});
  const [showPriv, setShowPriv] = useState({});

  // Sync edits when keys change
  useEffect(() => {
    setEdits(prev => {
      const next = {};
      for (const k of keys) {
        next[k.sha256Fingerprint] = prev[k.sha256Fingerprint] ?? {
          name: k.name, enabled: k.enabled, storeType: k.storeType,
        };
      }
      return next;
    });
  }, [keys]);

  function getEdit(fp) {
    const k = keys.find(k => k.sha256Fingerprint === fp);
    return edits[fp] ?? (k ? { name: k.name, enabled: k.enabled, storeType: k.storeType } : {});
  }

  function hasChanged(fp) {
    const orig = keys.find(k => k.sha256Fingerprint === fp);
    const edit = edits[fp];
    if (!orig || !edit) return false;
    return orig.name !== edit.name || orig.enabled !== edit.enabled || orig.storeType !== edit.storeType;
  }

  function patchEdit(fp, patch) {
    setEdits(e => ({ ...e, [fp]: { ...e[fp], ...patch } }));
  }

  function applyUpdate(fp) {
    const orig = keys.find(k => k.sha256Fingerprint === fp);
    updateKey({ ...orig, ...edits[fp] });
    showSnackbar({ message: 'Updated' });
  }

  async function handleDelete(fp) {
    const ans = await showPrompt({ title: 'Remove key?', message: 'Are you sure to remove the key?', showsInput: false });
    if (ans === undefined) return;
    setExpanded(null);
    removeKey(fp);
  }

  function downloadText(filename, str) {
    const a   = document.createElement('a');
    a.href    = URL.createObjectURL(new Blob([str]));
    a.download = filename;
    a.click();
  }

  if (keys.length === 0) return html`
    <p class="text-gray-500 text-center py-10">No keys stored yet.</p>
  `;

  return html`
    <div class="space-y-2">
      ${keys.map(k => {
        const fp   = k.sha256Fingerprint;
        const edit = getEdit(fp);
        const open = expanded === fp;
        const pkShow = showPriv[fp];
        const addCmd = `mkdir -p ~/.ssh && echo '${k.publicKey.trim()}' >> ~/.ssh/authorized_keys`;

        return html`
          <div key=${fp} class="border border-gray-700 rounded overflow-hidden">
            <!-- Header row -->
            <button type="button"
              onClick=${() => setExpanded(open ? null : fp)}
              class="w-full flex items-center gap-3 px-4 py-3 bg-gray-800 hover:bg-gray-700 text-left transition-colors">
              <span class="text-xl ${edit.enabled ? '' : 'opacity-30'}">🔑</span>
              <div class="flex-1 min-w-0 ${!edit.enabled ? 'text-gray-500' : ''} ${hasChanged(fp) ? 'italic' : ''}">
                <div class="font-medium truncate">${edit.name || k.name}</div>
                <div class="text-xs text-gray-500 font-mono truncate">${fp}</div>
              </div>
              <span class="text-gray-500 text-xs">${open ? '▲' : '▼'}</span>
            </button>

            <!-- Expanded panel -->
            ${open && html`
              <div class="p-4 bg-gray-900 border-t border-gray-700 space-y-4">
                <!-- Enabled toggle -->
                <label class="flex items-center gap-3 cursor-pointer">
                  <input type="checkbox" checked=${edit.enabled}
                    onChange=${e => patchEdit(fp, { enabled: e.target.checked })}
                    class="w-4 h-4 accent-blue-500" />
                  <span class="text-sm">Enabled</span>
                </label>

                <!-- Name -->
                <div>
                  <label class="block text-xs text-gray-400 mb-1">Name</label>
                  <input value=${edit.name}
                    onInput=${e => patchEdit(fp, { name: e.target.value })}
                    class="w-full bg-gray-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
                </div>

                <!-- Store type -->
                <div>
                  <label class="block text-xs text-gray-400 mb-1">Store type</label>
                  <div class="flex flex-wrap gap-3">
                    ${authKeysStoreTypes.map(t => html`
                      <label key=${t} class="flex items-center gap-1.5 cursor-pointer text-sm">
                        <input type="radio" name=${'st-' + fp} value=${t} checked=${edit.storeType === t}
                          onChange=${() => patchEdit(fp, { storeType: t })} class="accent-blue-500" />
                        ${storeTypeLabel[t]}
                      </label>
                    `)}
                  </div>
                </div>

                <!-- Update button -->
                <button type="button" onClick=${() => applyUpdate(fp)}
                  disabled=${!hasChanged(fp)}
                  class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 rounded text-xs text-white transition-colors">
                  Update
                </button>

                <!-- Public key -->
                <div>
                  <label class="block text-xs text-gray-400 mb-1">Public key</label>
                  <div class="relative">
                    <textarea value=${k.publicKey} readOnly rows="2"
                      class="w-full bg-gray-700 rounded px-3 py-2 pr-16 text-xs text-white font-mono resize-none"></textarea>
                    <div class="absolute top-1 right-1 flex gap-0.5">
                      <${CopyButton} text=${k.publicKey} />
                      <button type="button" onClick=${() => downloadText(`${k.name}-pub.pem`, k.publicKey)}
                        title="Download" class="p-1 text-orange-400 hover:text-orange-300 transition-colors rounded">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7,10 12,15 17,10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                      </button>
                    </div>
                  </div>
                </div>

                <!-- Add-to-authorized-keys command -->
                <div>
                  <label class="block text-xs text-gray-400 mb-1">Command to add to ~/.ssh/authorized_keys</label>
                  <div class="relative">
                    <input value=${addCmd} readOnly
                      class="w-full bg-gray-700 rounded px-3 py-1.5 pr-10 text-xs text-white font-mono" />
                    <div class="absolute top-0.5 right-1">
                      <${CopyButton} text=${addCmd} />
                    </div>
                  </div>
                </div>

                <!-- Private key -->
                <div>
                  <div class="flex items-center justify-between mb-1">
                    <label class="text-xs text-gray-400">Private key</label>
                    <div class="flex gap-0.5">
                      <${CopyButton} text=${k.privateKey} />
                      <button type="button"
                        onClick=${() => setShowPriv(p => ({ ...p, [fp]: !p[fp] }))}
                        title=${pkShow ? 'Hide' : 'Show'}
                        class="p-1 text-gray-400 hover:text-white transition-colors rounded">
                        ${pkShow ? '🙈' : '👁'}
                      </button>
                      <button type="button" onClick=${() => downloadText(`${k.name}-priv.pem`, k.privateKey)}
                        title="Download" class="p-1 text-orange-400 hover:text-orange-300 transition-colors rounded">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7,10 12,15 17,10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                      </button>
                    </div>
                  </div>
                  ${pkShow
                    ? html`<textarea value=${k.privateKey} readOnly rows="5"
                        class="w-full bg-gray-700 rounded px-3 py-2 text-xs text-white font-mono resize-none"></textarea>`
                    : html`<input type="password" value=${k.privateKey} readOnly
                        class="w-full bg-gray-700 rounded px-3 py-1.5 text-xs text-white font-mono" />`
                  }
                </div>

                <!-- Delete -->
                <button type="button" onClick=${() => handleDelete(fp)}
                  class="px-3 py-1.5 bg-red-700 hover:bg-red-600 rounded text-xs text-white transition-colors">
                  🗑 Delete
                </button>
              </div>
            `}
          </div>
        `;
      })}
    </div>
  `;
}

// ─── Dialog wrapper ───────────────────────────────────────────────────────────

function Dialog({ title, open, onClose, children, wide = false }) {
  useEffect(() => {
    if (!open) return;
    const handler = e => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  if (!open) return null;

  return html`
    <div class="fixed inset-0 bg-black/60 flex items-start justify-center z-30 p-4 overflow-y-auto"
         onClick=${onClose}>
      <div class="bg-gray-900 border border-gray-800 my-4 flex flex-col"
           style=${{ width: wide ? '80vw' : '60vw', maxWidth: '95vw', minWidth: '20rem', minHeight: '70vh' }}
           onClick=${e => e.stopPropagation()}>
        <div class="flex items-center px-4 py-3 border-b border-gray-700 flex-shrink-0">
          <h2 class="text-base font-semibold flex-1">${title}</h2>
          <button type="button" onClick=${onClose}
            class="p-1 text-gray-400 hover:text-white transition-colors rounded">✕</button>
        </div>
        <div class="flex-1 overflow-y-auto p-4">${children}</div>
      </div>
    </div>
  `;
}

// ─── App ──────────────────────────────────────────────────────────────────────

const demoBaseUrl = 'https://websocket-tcp-proxy.navigaid.workers.dev/';

function App() {
  const [pipingServerUrl,   setPipingServerUrl]   = useState(fragmentParams.pipingServerUrl() ?? demoBaseUrl);
  const [sshHost,           setSshHost]           = useState(fragmentParams.sshHost() ?? 'terminal.shop');
  const [sshPort,           setSshPort]           = useState(fragmentParams.sshPort() ?? '22');
  const [username,          setUsername]          = useState(fragmentParams.sshUsername() ?? '');
  const [sshPassword,       setSshPassword]       = useState(fragmentParams.sshPassword() ?? '');
  const [showSshPw,         setShowSshPw]         = useState(false);
  const [emptySshPw,        setEmptySshPw]        = useState(fragmentParams.sshPassword() === '');
  const [inclPwInUrl,       setInclPwInUrl]       = useState(fragmentParams.sshPassword() !== undefined);
  const [autoConnect,       setAutoConnect]       = useState(fragmentParams.autoConnect() ?? false);
  const [showMore,          setShowMore]          = useState(false);
  const [connecting,        setConnecting]        = useState(false);
  const [supportsStreams,   setSupportsStreams]   = useState(true);
  const [keyMgrOpen,        setKeyMgrOpen]        = useState(false);
  const [newKeyOpen,        setNewKeyOpen]        = useState(false);
  const [genKeyOpen,        setGenKeyOpen]        = useState(false);

  // Effective ssh password
  const effectiveSshPassword = (sshPassword === '' && !emptySshPw) ? undefined : sshPassword;

  // Full URL with host/port as query params
  const pipingFullUrl = useMemo(() => {
    try {
      const url = new URL(pipingServerUrl);
      url.searchParams.set('hostname', sshHost);
      url.searchParams.set('port', sshPort);
      return url.href;
    } catch {
      return '';
    }
  }, [pipingServerUrl, sshHost, sshPort]);

  useEffect(() => {
    checkSupportsRequestStreams().then(s => setSupportsStreams(s));
  }, []);

  useEffect(() => {
    if (fragmentParams.autoConnect()) connect();
  }, []); // eslint-disable-line

  function connect() { setConnecting(true); }

  function formValid() {
    return !!(pipingServerUrl && sshHost && sshPort && username);
  }

  async function handleSaveKey(authKeySet) {
    setNewKeyOpen(false);
    setGenKeyOpen(false);
    const result = await storeAuthKeySet(authKeySet);
    showSnackbar({ message: result === 'already_exist' ? 'Key already exists' : 'Key saved' });
  }

  function setConfiguredUrl() {
    location.href = getConfiguredUrl({
      pipingServerUrl, sshHost, sshPort, sshUsername: username,
      sshPassword: inclPwInUrl ? effectiveSshPassword : undefined,
      autoConnect,
    });
    showSnackbar({ message: 'URL updated' });
  }

  const inputClass = 'w-full bg-transparent border border-gray-800 rounded-sm px-4 py-3 text-white text-base focus:outline-none focus:border-amber-500/50 placeholder-gray-600 transition-colors';

  return html`
    <div class="min-h-screen flex flex-col">

      <!-- App bar -->
      <header class="flex-shrink-0 h-12 flex items-center px-6 gap-4 z-10 border-b border-gray-800/50">
        <a href="" class="text-sm font-medium text-gray-200 no-underline mr-auto tracking-tight">Piping SSH</a>

        <button type="button" onClick=${() => setKeyMgrOpen(true)}
          class="text-xs text-gray-500 hover:text-gray-300 transition-colors">
          Keys
        </button>

        <a href="https://github.com/nwtgck/piping-ssh-web" target="_blank" rel="noopener"
          class="text-gray-600 hover:text-gray-400 transition-colors">
          <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
          </svg>
        </a>
      </header>

      <!-- Main content -->
      <main class="flex-1 flex flex-col">
        ${connecting
          ? html`<${PipingSsh}
              pipingServerUrl=${pipingFullUrl}
              username=${username}
              defaultSshPassword=${effectiveSshPassword}
              onEnd=${() => setConnecting(false)}
            />`
          : html`
            <div class="max-w-xl mx-auto px-6 pt-12">

              ${!supportsStreams && html`
                <div class="border border-amber-800/50 rounded-sm p-3 mb-8 text-xs text-amber-600/80">
                  ⚠ Browser not supported. Use Chrome 105+, Edge, or other Chromium-based browsers.
                </div>
              `}

              <form onSubmit=${e => { e.preventDefault(); connect(); }} class="space-y-6">

                <!-- username @ host : port -->
                <div class="flex gap-0 items-center">
                  <div class="flex-1" style=${{ minWidth: 0 }}>
                    <input name="username" autocomplete="username" value=${username} onInput=${e => setUsername(e.target.value)} required
                      placeholder="username"
                      disabled=${!supportsStreams} class=${inputClass} />
                  </div>
                  <span style=${{ userSelect: 'none', color: '#52525b', fontSize: '16px', padding: '0 6px', flexShrink: 0 }}>@</span>
                  <div class="flex-1" style=${{ minWidth: 0 }}>
                    <input name="ssh-host" autocomplete="host" value=${sshHost} onInput=${e => setSshHost(e.target.value)} required
                      placeholder="ssh host"
                      disabled=${!supportsStreams} class=${inputClass} />
                  </div>
                  <span style=${{ userSelect: 'none', color: '#52525b', fontSize: '16px', padding: '0 6px', flexShrink: 0 }}>:</span>
                  <div class="w-20 flex-shrink-0">
                    <input name="ssh-port" autocomplete="port" value=${sshPort} onInput=${e => setSshPort(e.target.value)} required
                      placeholder="port"
                      disabled=${!supportsStreams} class=${inputClass} />
                  </div>
                </div>

                <!-- Connect button -->
                <button type="submit"
                  disabled=${!formValid() || !supportsStreams}
                  class="w-full py-3 bg-amber-600 hover:bg-amber-500 disabled:opacity-30 rounded-sm text-sm text-white font-medium transition-colors tracking-wide">
                  Connect
                </button>

                <!-- Toggle / Set URL (always visible) -->
                <div class="flex items-center pt-2">
                  <button type="button" onClick=${() => setShowMore(p => !p)}
                    class="text-xs text-gray-600 hover:text-gray-400 transition-colors">
                    ${showMore ? '— Hide options' : '+ More options'}
                  </button>
                  <div class="flex-1"></div>
                  <button type="button" onClick=${setConfiguredUrl}
                    class="text-xs text-gray-600 hover:text-gray-400 transition-colors">
                    Set configured URL
                  </button>
                </div>

                <!-- More options (collapsible) - below the toggle -->
                ${showMore && html`
                  <div class="space-y-4 pt-1">

                    <!-- Piping Server URL -->
                    <div>
                      <label class="block text-xs text-gray-600 mb-1.5 tracking-wide uppercase">Piping Server</label>
                      <input list="piping-servers" value=${pipingServerUrl}
                        onInput=${e => setPipingServerUrl(e.target.value)}
                        required disabled=${!supportsStreams}
                        class=${inputClass} />
                      <datalist id="piping-servers">
                        <option value=${demoBaseUrl}/>
                      </datalist>
                    </div>

                    <!-- SSH password -->
                    <div>
                      <label class="block text-xs text-gray-600 mb-1.5 tracking-wide uppercase">SSH password</label>
                      <div class="relative">
                        <input type=${showSshPw ? 'text' : 'password'} value=${sshPassword}
                          onInput=${e => setSshPassword(e.target.value)}
                          class="${inputClass} pr-10" />
                        <button type="button" onClick=${() => setShowSshPw(p => !p)}
                          class="absolute right-2 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400 p-1">
                          ${showSshPw ? '🙈' : '👁'}
                        </button>
                      </div>
                    </div>

                    <div class="flex flex-wrap gap-x-6 gap-y-2">
                      <label class="flex items-center gap-2 cursor-pointer text-xs text-gray-500 hover:text-gray-400 transition-colors">
                        <input type="checkbox" checked=${emptySshPw}
                          onChange=${e => setEmptySshPw(e.target.checked)}
                          class="accent-amber-500" />
                        Empty password
                      </label>

                      <label class="flex items-center gap-2 cursor-pointer text-xs text-gray-500 hover:text-gray-400 transition-colors">
                        <input type="checkbox" checked=${inclPwInUrl}
                          onChange=${e => setInclPwInUrl(e.target.checked)}
                          class="accent-amber-500" />
                        Include password in URL
                      </label>

                      <label class="flex items-center gap-2 cursor-pointer text-xs text-gray-500 hover:text-gray-400 transition-colors">
                        <input type="checkbox" checked=${autoConnect}
                          onChange=${e => setAutoConnect(e.target.checked)}
                          class="accent-amber-500" />
                        Auto connect
                      </label>
                    </div>
                  </div>
                `}

              </form>

            </div>
          `
        }
      </main>

      <!-- Globals -->
      <${GlobalPrompt} />
      <${GlobalSnackbar} />

      <!-- Key manager dialog -->
      <${Dialog} title="Keys" open=${keyMgrOpen} onClose=${() => setKeyMgrOpen(false)} wide=${true}>
        <div class="flex justify-end gap-3 mb-4">
          <button type="button" onClick=${() => setNewKeyOpen(true)}
            class="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 rounded-sm text-sm text-white transition-colors">
            + New
          </button>
          <button type="button" onClick=${() => setGenKeyOpen(true)}
            class="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 rounded-sm text-sm text-white transition-colors">
            ✦ Generate
          </button>
        </div>
        <${KeyManager} />
      <//>

      <!-- New key dialog -->
      <${Dialog} title="New key" open=${newKeyOpen} onClose=${() => setNewKeyOpen(false)}>
        <${KeysEditor} onSave=${handleSaveKey} />
      <//>

      <!-- Generate key dialog -->
      <${Dialog} title="Key generator" open=${genKeyOpen} onClose=${() => setGenKeyOpen(false)}>
        <${KeyGenerator} onSave=${handleSaveKey} />
      <//>
    </div>
  `;
}

// ─── Mount ────────────────────────────────────────────────────────────────────

createRoot(document.getElementById('app')).render(html`<${App} />`);
