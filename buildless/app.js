// buildless/app.js
// Piping SSH — buildless React 19 frontend.
// Uses htm for JSX-like templates and Comlink for the WASM worker.

import { createElement as h, useState, useEffect, useRef, Fragment } from 'react';
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

// ─── Host presets store ─────────────────────────────────────────────────────

const presetHosts = [
  { name: 'Telehack',         hostname: 'telehack.com',  port: '22', username: '', password: '', agentForwarding: false },
  { name: 'Charm Cloud',     hostname: 'git.charm.sh',  port: '22', username: '', password: '', agentForwarding: false },
  { name: 'Bitreich',        hostname: 'bitreich.org',  port: '22', username: '', password: '', agentForwarding: false },
  { name: 'Terminal.Shop',   hostname: 'terminal.shop', port: '22', username: '', password: '', agentForwarding: false },
  { name: 'Whoami',          hostname: 'whoami.filippo.io', port: '22', username: '', password: '', agentForwarding: false },
  { name: 'Pwnable.kr',      hostname: 'pwnable.kr',    port: '2222', username: 'fd', password: 'guest', agentForwarding: false },
  { name: 'Exe.dev',         hostname: 'exe.dev',      port: '22', username: 'root', password: '', agentForwarding: false },
  { name: 'SDF (menu)',     hostname: 'tty.sdf.org',  port: '22', username: 'menu', password: '', agentForwarding: false },
  { name: 'SDF (new)',      hostname: 'sdf.org',      port: '22', username: 'new', password: '', agentForwarding: false },
  { name: 'Tilde.Town',     hostname: 'tilde.town',   port: '22', username: 'welcome', password: '', agentForwarding: false },
  { name: 'SSH Bot',        hostname: 'ssh.bot',      port: '22', username: 'key_c7b2m', password: '', agentForwarding: false },
  { name: 'SSH-J',          hostname: 'ssh-j.com',    port: '22', username: '', password: '', agentForwarding: false },
];

const HOSTS_STORAGE_KEY = 'preset_hosts';
const hostSubscribers = new Set();

function getStoredHosts() {
  let cached;
  try { cached = JSON.parse(localStorage.getItem(HOSTS_STORAGE_KEY) || 'null'); } catch { cached = null; }
  if (!cached || !cached.length) return [...presetHosts];
  const cacheKey = h => `${h.hostname}:${h.port}:${h.username}`;
  const cachedMap = new Map(cached.map(h => [cacheKey(h), h]));
  // Presets first, overlaid with cached data if same host/port/user
  const merged = presetHosts.map(p => cachedMap.get(cacheKey(p)) ?? p);
  // Append cached entries not in presets
  const seen = new Set(merged.map(cacheKey));
  for (const c of cached) {
    if (!seen.has(cacheKey(c))) { merged.push(c); seen.add(cacheKey(c)); }
  }
  return merged;
}

function notifyHostSubscribers() { hostSubscribers.forEach(fn => fn([...getStoredHosts()])); }

function useStoredHosts() {
  const [hosts, setHosts] = useState(getStoredHosts);
  useEffect(() => { hostSubscribers.add(setHosts); return () => hostSubscribers.delete(setHosts); }, []);
  return hosts;
}

function persistHosts(hosts) {
  localStorage.setItem(HOSTS_STORAGE_KEY, JSON.stringify(hosts));
  notifyHostSubscribers();
}

function addHost(h) {
  const hosts = getStoredHosts();
  hosts.push({ ...h, agentForwarding: false, addedAtMillis: Date.now() });
  persistHosts(hosts);
}

function removeHost(idx) {
  const hosts = getStoredHosts();
  hosts.splice(idx, 1);
  persistHosts(hosts);
}

function updateHost(idx, h) {
  const hosts = getStoredHosts();
  hosts[idx] = h;
  persistHosts(hosts);
}

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
  if (await workerRemote.exited()) {
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
const workerGenerateEcdsa         = b   => getAliveWorker().then(r => r.generateEcdsaKeys(b));

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

function showPrompt({ title, message = '', showsInput = true, inputType = 'text', placeholder = '', width = '24rem' }) {
  return new Promise(resolve => {
    _promptResolve = resolve;
    _setPromptState?.({ shows: true, title, message, showsInput, inputType, placeholder, width });
  });
}

function GlobalPrompt() {
  const [st, setSt] = useState({ shows: false, title: '', message: '', showsInput: true, inputType: 'text', placeholder: '', width: '24rem' });
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
         onKeyDown=${e => e.key === 'Escape' && cancel()}
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
              onKeyDown=${e => e.key === 'Enter' ? ok() : e.key === 'Escape' && cancel()}
              placeholder=${st.placeholder}
              class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-2 text-sm text-white focus:outline-none focus:border-amber-500/50 placeholder-gray-600 transition-colors ${isPw ? 'pr-10' : ''}"
            />
            ${isPw && html`
              <button type="button" onClick=${() => setShowPw(p => !p)}
                class="absolute right-2 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400 p-1">
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
    const t = setTimeout(() => setSt(s => ({ ...s, shows: false })), 6000);
    return () => clearTimeout(t);
  }, [st.shows, st.message]);

  if (!st.shows) return null;

  return html`
    <div class="fixed top-12 left-1/2 -translate-x-1/2 bg-gray-900 border border-amber-600/60 text-amber-300 px-5 py-3 z-50 text-sm whitespace-nowrap rounded shadow-lg shadow-amber-900/20 font-medium">
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

function PipingSsh({ pipingServerUrl, username, defaultSshPassword, agentForwarding, onEnd, onConnected, isActive = true }) {
  const termRef  = useRef(null);
  const fitRef   = useRef(null);
  const termApi  = useRef(null);
  const wrapperRef = useRef(null);
  const [connState, setConnState] = useState('connecting');

  // Fit/focus terminal when this tab becomes active
  useEffect(() => {
    if (!isActive || connState !== 'connected') return;
    const raf1 = requestAnimationFrame(() => {
      fitRef.current?.();
      termApi.current?.focus();
      requestAnimationFrame(() => fitRef.current?.());
    });
    return () => cancelAnimationFrame(raf1);
  }, [isActive, connState]);

  // ResizeObserver for reliable terminal resize on any container size change
  useEffect(() => {
    const el = wrapperRef.current;
    if (!el || connState !== 'connected') return;
    let rafId;
    const ro = new ResizeObserver(() => {
      rafId = requestAnimationFrame(() => fitRef.current?.());
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
      cancelAnimationFrame(rafId);
    };
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

      // WebSocketStream transport
      let transport;
      try {
        transport = await new WebSocketStream(pipingServerUrl).opened;
      } catch (e) {
        console.error('WebSocket connection failed', e);
        showSnackbar({ message: 'WebSocket connection failed: ' + (e.message || e) });
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
      let kiTried = false;

      try {
        const remote    = await getAliveWorker();
        const transfers = [transport.readable, transport.writable, termReadable, mc.port2];

        await remote.doSsh(
          Comlink.transfer({
            transport, termReadable, agentForwarding,
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
              const pw  = await showPrompt({ title: 'Password', message: msg, inputType: 'password' });
              if (pw === undefined) { localCancelled = true; throw new Error('aborted'); }
              pwTried = true;
              return pw;
            },

            async onKeyboardInteractive(name, instruction, questions, echos) {
              // Some servers use keyboard-interactive as a password auth replacement
              if (!kiTried && defaultSshPassword !== undefined && questions.length === 1 && !echos[0]) {
                kiTried = true;
                return [defaultSshPassword];
              }
              const header = [name, instruction].filter(Boolean).join('\n');
              const answers = [];
              for (let i = 0; i < questions.length; i++) {
                const msg = [header, questions[i]].filter(Boolean).join('\n');
                const ans = await showPrompt({
                  title: 'Authentication',
                  message: msg,
                  inputType: echos[i] ? 'text' : 'password',
                });
                if (ans === undefined) { localCancelled = true; throw new Error('aborted'); }
                answers.push(ans);
              }
              return answers;
            },

            async getAuthPrivateKeyPassphrase(fp) {
              const k    = storedKeys.find(k => k.sha256Fingerprint === fp);
              const type = await workerGetAuthPublicKeyType(k.publicKey);
              const pp   = await showPrompt({
                title:     'Passphrase',
                message:   `(${k.name}) ${type}\nEnter passphrase for key`,
                inputType: 'password',
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
                showsInput:  false,
                width:       '28rem',
              });
              if (ans !== undefined) {
                serverHostKeyMgr.trust(key.fingerprint);
                return true;
              }
              localCancelled = true;
              return false;
            },

            async onAgentConfirm(key, payload) {
              const hex = Array.from(payload).map(b => b.toString(16).padStart(2, '0')).join(' ');
              const ans = await showPrompt({
                title:       'Agent sign',
                message:     `${key}\nPayload: ${hex}\nAllow agent sign?`,
                showsInput:  false,
                width:       '32rem',
              });
              return ans !== undefined;
            },

            onConnected() {
              setConnState('connected');
              onConnected?.();
            },
          }),
        );

        showSnackbar({ message: 'Finished' });
      } catch (e) {
        if (localCancelled) { showSnackbar({ message: 'Canceled' }); }
        else { console.error('SSH error', e); showSnackbar({ message: `Connection closed: ${e.message || e}`, icon: '!' }); }
      } finally {
        onEnd?.();
      }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return html`
    <div ref=${wrapperRef} style=${{ flex: 1, overflow: 'hidden' }}>
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
        style=${{ display: connState === 'connected' ? 'block' : 'none', width: '100%', height: 'calc(100vh - 28px)', overflow: 'hidden' }}
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

  const inputClass = 'w-full bg-transparent border border-gray-800 rounded-sm px-3 py-2 text-sm text-white focus:outline-none focus:border-amber-500/50 placeholder-gray-600';

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
                onChange=${() => setStoreType(t)} class="accent-amber-500" />
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
        class="px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-30 rounded-sm text-white transition-colors text-sm">
        Save
      </button>
    </form>
  `;
}

// ─── KeyGenerator ─────────────────────────────────────────────────────────────

function KeyGenerator({ onSave }) {
  const [keyType,    setKeyType]    = useState('Ed25519');
  const [keyBits,    setKeyBits]    = useState(2048);
  const [ecdsaBits,  setEcdsaBits]  = useState(256);
  const [generating, setGenerating] = useState(false);
  const [generated,  setGenerated]  = useState(null);

  if (generated) {
    return html`<${KeysEditor} onSave=${onSave} initialPublicKey=${generated.publicKey} initialPrivateKey=${generated.privateKey} />`;
  }

  async function generate() {
    setGenerating(true);
    try {
      let keys;
      if (keyType === 'RSA')             keys = await workerGenerateRsa(keyBits);
      else if (keyType === 'ECDSA')      keys = await workerGenerateEcdsa(ecdsaBits);
      else                               keys = await workerGenerateEd25519();
      setGenerated(keys);
    } finally { setGenerating(false); }
  }

  const ecdsaCurves = [
    { bits: 256, label: 'NIST P-256', bitsLabel: '256 bits' },
    { bits: 384, label: 'NIST P-384', bitsLabel: '384 bits' },
    { bits: 521, label: 'NIST P-521', bitsLabel: '521 bits' },
  ];

  return html`
    <div class="space-y-4">
      <div class="flex gap-4">
        ${['Ed25519', 'ECDSA', 'RSA'].map(t => html`
          <label key=${t} class="flex items-center gap-2 cursor-pointer text-sm">
            <input type="radio" name="keyType" value=${t} checked=${keyType === t}
              onChange=${() => setKeyType(t)} disabled=${generating} class="accent-amber-500" />
            ${t}
          </label>
        `)}
      </div>

      ${keyType === 'ECDSA' && html`
        <div>
          <label class="block text-sm text-gray-400 mb-2">Curve</label>
          ${ecdsaCurves.map(c => html`
            <label key=${c.bits} class="flex items-center gap-2 cursor-pointer text-sm py-1.5">
              <input type="radio" name="ecdsaCurve" checked=${ecdsaBits === c.bits}
                onChange=${() => setEcdsaBits(c.bits)} disabled=${generating} class="accent-amber-500" />
              <span class="text-gray-200">${c.label}</span>
              <span class="text-gray-500 text-xs ml-1">— ${c.bitsLabel}</span>
            </label>
          `)}
        </div>
      `}

      ${keyType === 'RSA' && html`
        <div>
          <label class="block text-sm text-gray-400 mb-1">Key bits</label>
          <div class="flex gap-4">
            ${[2048, 4096].map(b => html`
              <label key=${b} class="flex items-center gap-2 cursor-pointer text-sm">
                <input type="radio" name="keyBits" value=${b} checked=${keyBits === b}
                  onChange=${() => setKeyBits(b)} disabled=${generating} class="accent-amber-500" />
                ${b}
              </label>
            `)}
          </div>
        </div>
        ${keyBits >= 4096 && html`
          <div class="border border-amber-800/50 text-amber-600/80 rounded-sm p-3 text-sm">
            ⚠ It will take about 1 minute or more to generate. Ed25519 is recommended.
          </div>
        `}
      `}

      <button type="button" onClick=${generate} disabled=${generating}
        class="px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-30 rounded-sm text-white transition-colors flex items-center gap-2 text-sm">
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
  const [showPriv, setShowPriv] = useState({});

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
        const open = expanded === fp;
        const pkShow = showPriv[fp];
        const addCmd = `mkdir -p ~/.ssh && echo '${k.publicKey.trim()}' >> ~/.ssh/authorized_keys`;

        return html`
          <div key=${fp} class="border border-gray-800 rounded-sm overflow-hidden">
            <!-- Header row -->
            <div class="flex items-center gap-3 px-4 py-3 bg-gray-900/50">
              <button type="button"
                onClick=${() => setExpanded(open ? null : fp)}
                class="flex items-center gap-3 flex-1 min-w-0 text-left">
                <span class="text-base ${k.enabled ? '' : 'opacity-30'}">🔑</span>
                <div class="flex-1 min-w-0 ${!k.enabled ? 'text-gray-500' : ''}">
                  <div class="text-sm truncate">${k.name}</div>
                  <div class="text-xs text-gray-600 font-mono truncate">${fp}</div>
                </div>
                <span class="text-gray-600 text-xs flex-shrink-0">${open ? '▲' : '▼'}</span>
              </button>
              <!-- Toggle switch (immediate effect) -->
              <label class="relative inline-flex items-center cursor-pointer flex-shrink-0" onClick=${e => e.stopPropagation()}>
                <input type="checkbox" checked=${k.enabled}
                  onChange=${e => { updateKey({ ...k, enabled: e.target.checked }); }}
                  class="sr-only peer" />
                <div class="w-9 h-5 bg-gray-700 rounded-full transition-colors peer-checked:bg-amber-600"></div>
                <div class="absolute left-0.5 top-0.5 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-4"></div>
              </label>
            </div>

            <!-- Expanded panel -->
            ${open && html`
              <div class="p-4 bg-gray-900 border-t border-gray-800 space-y-4">

                <!-- Name -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Name</label>
                  <input value=${k.name}
                    onInput=${e => updateKey({ ...k, name: e.target.value })}
                    class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500/50" />
                </div>

                <!-- Store type -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Store type</label>
                  <div class="flex flex-wrap gap-3">
                    ${authKeysStoreTypes.map(t => html`
                      <label key=${t} class="flex items-center gap-1.5 cursor-pointer text-xs text-gray-400">
                        <input type="radio" name=${'st-' + fp} value=${t} checked=${k.storeType === t}
                          onChange=${() => updateKey({ ...k, storeType: t })} class="accent-amber-500" />
                        ${storeTypeLabel[t]}
                      </label>
                    `)}
                  </div>
                </div>

                <!-- Public key -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Public key</label>
                  <div class="relative">
                    <textarea value=${k.publicKey} readOnly rows="2"
                      class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-2 pr-16 text-xs text-white font-mono resize-none"></textarea>
                    <div class="absolute top-1 right-1 flex gap-0.5">
                      <${CopyButton} text=${k.publicKey} />
                      <button type="button" onClick=${() => downloadText(`${k.name}-pub.pem`, k.publicKey)}
                        title="Download" class="p-1 text-gray-500 hover:text-gray-300 transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7,10 12,15 17,10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                      </button>
                    </div>
                  </div>
                </div>

                <!-- Add-to-authorized-keys command -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Command to add to ~/.ssh/authorized_keys</label>
                  <div class="relative">
                    <input value=${addCmd} readOnly
                      class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 pr-10 text-xs text-white font-mono" />
                    <div class="absolute top-0.5 right-1">
                      <${CopyButton} text=${addCmd} />
                    </div>
                  </div>
                </div>

                <!-- Private key -->
                <div>
                  <div class="flex items-center justify-between mb-1">
                    <label class="text-xs text-gray-500">Private key</label>
                    <div class="flex gap-0.5">
                      <${CopyButton} text=${k.privateKey} />
                      <button type="button"
                        onClick=${() => setShowPriv(p => ({ ...p, [fp]: !p[fp] }))}
                        title=${pkShow ? 'Hide' : 'Show'}
                        class="p-1 text-gray-500 hover:text-gray-300 transition-colors">
                        ${pkShow ? '🙈' : '👁'}
                      </button>
                      <button type="button" onClick=${() => downloadText(`${k.name}-priv.pem`, k.privateKey)}
                        title="Download" class="p-1 text-gray-500 hover:text-gray-300 transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7,10 12,15 17,10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                      </button>
                    </div>
                  </div>
                  ${pkShow
                    ? html`<textarea value=${k.privateKey} readOnly rows="5"
                        class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-2 text-xs text-white font-mono resize-none"></textarea>`
                    : html`<input type="password" value=${k.privateKey} readOnly
                        class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-xs text-white font-mono" />`
                  }
                </div>

                <!-- Delete -->
                <div class="flex justify-end pt-1">
                  <button type="button" onClick=${() => handleDelete(fp)}
                    class="px-3 py-1.5 bg-red-700 hover:bg-red-600 rounded-sm text-xs text-white transition-colors">
                    🗑 Delete
                  </button>
                </div>
              </div>
            `}
          </div>
        `;
      })}
    </div>
  `;
}

// ─── HostManager ─────────────────────────────────────────────────────────────

function HostManager({ onConnect, connections, onDisconnect }) {
  const hosts = useStoredHosts();
  const [expanded, setExpanded] = useState(null);
  const [edits, setEdits] = useState({});

  async function handleDelete(idx) {
    const ans = await showPrompt({ title: 'Remove host?', message: 'Are you sure to remove the host?', showsInput: false });
    if (ans === undefined) return;
    setExpanded(null);
    removeHost(idx);
  }

  function isActiveHost(h) {
    return connections.some(c =>
      c.hostname === h.hostname && c.port === h.port && c.username === h.username && (c.status === 'connected' || c.status === 'connecting')
    );
  }

  const inputClass = 'w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500/50 placeholder-gray-600';

  if (hosts.length === 0) return html`
    <p class="text-gray-500 text-center py-10">No hosts stored yet.</p>
  `;

  return html`
    <div class="space-y-2">
      ${hosts.map((h, idx) => {
        const open = expanded === idx;
        const active = isActiveHost(h);

        return html`
          <div key=${idx} class="border border-gray-800 rounded-sm overflow-hidden">
            <!-- Header row -->
            <div class="flex items-center gap-3 px-4 py-3 bg-gray-900/50">
              <button type="button"
                onClick=${() => setExpanded(open ? null : idx)}
                class="flex items-center gap-3 flex-1 min-w-0 text-left">
                <span class="text-base ${active ? '' : ''}">${active ? '🔌' : '🖥'}</span>
                <div class="flex-1 min-w-0">
                  <div class="text-sm truncate ${active ? 'text-amber-500' : ''}">${h.name}${active ? ' (connected)' : ''}</div>
                  <div class="text-xs text-gray-600 font-mono truncate">${h.username}@${h.hostname}:${h.port}</div>
                </div>
                <span class="text-gray-600 text-xs flex-shrink-0">${open ? '▲' : '▼'}</span>
              </button>
              <!-- Connect / Disconnect button -->
              ${active
                ? html`<button type="button" onClick=${() => onDisconnect(h)}
                    class="px-2 py-1 hover:bg-red-700/50 rounded text-sm transition-colors flex-shrink-0 leading-none"
                    title="Disconnect">
                    ⏹
                  </button>`
                : html`<button type="button" onClick=${() => onConnect(h)}
                    class="px-2 py-1 hover:bg-amber-600/50 rounded text-sm transition-colors flex-shrink-0 leading-none"
                    title="Connect">
                    →
                  </button>`
              }
            </div>

            <!-- Expanded panel -->
            ${open && html`
              <div class="p-4 bg-gray-900 border-t border-gray-800 space-y-4">
                <!-- Name -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Name</label>
                  <input value=${h.name}
                    onInput=${e => { const h2 = { ...h, name: e.target.value }; updateHost(idx, h2); }}
                    class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500/50" />
                </div>

                <!-- Hostname -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Hostname</label>
                  <input value=${h.hostname}
                    onInput=${e => { const h2 = { ...h, hostname: e.target.value }; updateHost(idx, h2); }}
                    class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500/50 font-mono" />
                </div>

                <!-- Port -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Port</label>
                  <input value=${h.port}
                    onInput=${e => { const h2 = { ...h, port: e.target.value }; updateHost(idx, h2); }}
                    class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500/50" />
                </div>

                <!-- Username -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Username</label>
                  <input value=${h.username}
                    onInput=${e => { const h2 = { ...h, username: e.target.value }; updateHost(idx, h2); }}
                    class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500/50" />
                </div>

                <!-- Password -->
                <div>
                  <label class="block text-xs text-gray-500 mb-1">Password</label>
                  <input type="password" value=${h.password}
                    onInput=${e => { const h2 = { ...h, password: e.target.value }; updateHost(idx, h2); }}
                    class="w-full bg-transparent border border-gray-800 rounded-sm px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500/50" />
                </div>

                <!-- SSH Agent Forwarding -->
                <label class="flex items-center gap-2 cursor-pointer select-none">
                  <input type="checkbox" checked=${!!h.agentForwarding}
                    onChange=${e => { const h2 = { ...h, agentForwarding: e.target.checked }; updateHost(idx, h2); }}
                    class="accent-amber-500" />
                  <span class="text-xs text-gray-500">Enable SSH agent forwarding</span>
                </label>

                <!-- Delete -->
                <div class="flex justify-end pt-1">
                  <button type="button" onClick=${() => handleDelete(idx)}
                    class="px-3 py-1.5 bg-red-700 hover:bg-red-600 rounded-sm text-xs text-white transition-colors">
                    🗑 Delete
                  </button>
                </div>
              </div>
            `}
          </div>
        `;
      })}
    </div>
  `;
}

// ─── Dialog wrapper ───────────────────────────────────────────────────────────

const dialogStack = [];

function Dialog({ title, open, onClose, children, wide = false }) {
  useEffect(() => {
    if (!open) return;
    const id = dialogStack.push(Symbol()) - 1;
    const handler = e => {
      if (e.key !== 'Escape') return;
      if (dialogStack[id] && dialogStack[dialogStack.length - 1] === dialogStack[id]) {
        onClose();
      }
    };
    document.addEventListener('keydown', handler);
    return () => {
      document.removeEventListener('keydown', handler);
      delete dialogStack[id];
      // Trim trailing holes left by deleted symbols
      while (dialogStack.length > 0 && dialogStack[dialogStack.length - 1] === undefined) dialogStack.pop();
    };
  }, [open, onClose]);

  if (!open) return null;

  return html`
    <div class="fixed inset-0 bg-black/60 flex items-start justify-center z-30 p-4 overflow-y-auto"
         onClick=${onClose}>
      <div class="bg-gray-900 border border-gray-800 my-4 flex flex-col"
           style=${{ width: wide ? '40vw' : '60vw', maxWidth: '95vw', minWidth: '16rem', minHeight: '70vh' }}
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
const FORM_STORAGE_KEY = 'piping-ssh-form';
const TABS_STORAGE_KEY = 'piping-ssh-tabs';

function loadSaved(key, fallback) {
  try {
    const saved = JSON.parse(sessionStorage.getItem(FORM_STORAGE_KEY) || '{}');
    return saved[key] !== undefined ? saved[key] : fallback;
  } catch { return fallback; }
}

function saveTabs(connections) {
  const toSave = connections
    .filter(c => c.status !== 'finished')
    .map(({ hostname, port, username, password, agentForwarding, pipingFullUrl, name }) => ({
      hostname, port, username, password, agentForwarding, pipingFullUrl, name
    }));
  try { localStorage.setItem(TABS_STORAGE_KEY, JSON.stringify(toSave)); } catch {}
}

function loadTabs() {
  try { return JSON.parse(localStorage.getItem(TABS_STORAGE_KEY) || '[]'); } catch { return []; }
}

function App() {
  const [pipingServerUrl,   setPipingServerUrl]   = useState(loadSaved('pipingServerUrl', fragmentParams.pipingServerUrl() ?? demoBaseUrl));
  const [sshHost,           setSshHost]           = useState(loadSaved('sshHost', fragmentParams.sshHost() ?? 'terminal.shop'));
  const [sshPort,           setSshPort]           = useState(loadSaved('sshPort', fragmentParams.sshPort() ?? '22'));
  const [username,          setUsername]          = useState(loadSaved('username', fragmentParams.sshUsername() ?? ''));
  const [sshPassword,       setSshPassword]       = useState(loadSaved('sshPassword', fragmentParams.sshPassword() ?? ''));
  const [showSshPw,         setShowSshPw]         = useState(false);
  const [emptySshPw,        setEmptySshPw]        = useState(loadSaved('emptySshPw', fragmentParams.sshPassword() === ''));
  const [inclPwInUrl,       setInclPwInUrl]       = useState(loadSaved('inclPwInUrl', fragmentParams.sshPassword() !== undefined));
  const [autoConnect,       setAutoConnect]       = useState(loadSaved('autoConnect', fragmentParams.autoConnect() ?? false));
  const [showMore,          setShowMore]          = useState(false);
  const [supportsStreams,   setSupportsStreams]   = useState(true);
  const [route,             setRoute]             = useState(location.hash || '#');
  const [newKeyOpen,        setNewKeyOpen]        = useState(false);
  const [genKeyOpen,        setGenKeyOpen]        = useState(false);
  const [connections,       setConnections]       = useState([]);
  const [activeConnectionId, setActiveConnectionId] = useState(null);
  const connIdCounter = useRef(0);
  const connectionsRef = useRef(connections);
  connectionsRef.current = connections;
  const restoredRef = useRef(false);
  const hasRestored = useRef(false);

  // Sync route with hash changes
  useEffect(() => {
    const handler = () => {
      const r = location.hash || '#';
      setRoute(r);
      if (r === '#keys' || r === '#hosts') {
        setActiveConnectionId(null);
      } else if (/^#\d+$/.test(r)) {
        const id = parseInt(r.substring(1), 10);
        if (connectionsRef.current.some(c => c.id === id)) setActiveConnectionId(id);
      } else if (r === '#') {
        setActiveConnectionId(null);
      }
    };
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);

  // Persist form state to sessionStorage
  useEffect(() => {
    const state = { pipingServerUrl, sshHost, sshPort, username, sshPassword, emptySshPw, inclPwInUrl, autoConnect };
    try { sessionStorage.setItem(FORM_STORAGE_KEY, JSON.stringify(state)); } catch {}
  }, [pipingServerUrl, sshHost, sshPort, username, sshPassword, emptySshPw, inclPwInUrl, autoConnect]);

  // Persist tabs to localStorage (skip initial empty save before restore)
  useEffect(() => {
    if (!hasRestored.current) return;
    saveTabs(connections);
  }, [connections]);

  // Effective ssh password
  const effectiveSshPassword = (sshPassword === '' && !emptySshPw) ? undefined : sshPassword;

  useEffect(() => {
    checkSupportsRequestStreams().then(s => setSupportsStreams(s));
  }, []);

  useEffect(() => {
    if (fragmentParams.autoConnect()) startConnection({ hostname: sshHost, port: sshPort, username, password: effectiveSshPassword });
  }, []); // eslint-disable-line

  // Restore tabs on mount
  useEffect(() => {
    if (restoredRef.current) return;
    restoredRef.current = true;
    const saved = loadTabs();
    saved.forEach(s => startConnection(s, { activate: false }));
    hasRestored.current = true;
  }, []); // eslint-disable-line

  function startConnection({ hostname, port, username, password, agentForwarding, pipingFullUrl }, { activate = true } = {}) {
    let fullUrl = pipingFullUrl;
    if (!fullUrl) {
      try {
        const url = new URL(pipingServerUrl);
        url.searchParams.set('hostname', hostname);
        url.searchParams.set('port', port);
        fullUrl = url.href;
      } catch {}
    }
    const id = ++connIdCounter.current;
    setConnections(prev => [...prev, {
      id,
      hostname,
      port,
      username,
      password: password ?? '',
      agentForwarding: agentForwarding ?? false,
      pipingFullUrl: fullUrl,
      status: 'connecting',
      name: `${username}@${hostname}`,
    }]);
    if (activate) {
      setActiveConnectionId(id);
      location.hash = `#${id}`;
    }
  }

  function closeConnection(connId) {
    const remaining = connectionsRef.current.filter(c => c.id !== connId);
    setConnections(remaining);
    if (activeConnectionId === connId) {
      setActiveConnectionId(remaining.length > 0 ? remaining[remaining.length-1].id : null);
    }
  }

  function connect(host) {
    if (host) {
      startConnection(host);
    } else {
      startConnection({ hostname: sshHost, port: sshPort, username, password: effectiveSshPassword, agentForwarding: false });
      // Save to host presets
      const hosts = getStoredHosts();
      const idx   = hosts.findIndex(h => h.hostname === sshHost && h.port === sshPort && h.username === username);
      const entry = { name: `${username}@${sshHost}`, hostname: sshHost, port: sshPort, username, password: sshPassword, addedAtMillis: Date.now() };
      if (idx !== -1) { hosts[idx] = entry; }
      else            { hosts.push(entry); }
      persistHosts(hosts);
    }
  }

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
      <header class="flex-shrink-0 flex items-center px-3 py-1 gap-1 z-10 border-b border-gray-800/50">
        <a href="#" onClick=${e => { e.preventDefault(); setActiveConnectionId(null); window.scrollTo(0, 0); location.hash = ''; }} class="flex items-center gap-1 text-xs font-medium text-gray-200 no-underline mr-2 tracking-tight flex-shrink-0">
          <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5 text-amber-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 17l4-4-4-4"/><path d="M12 19h8"/></svg>
          Piping SSH
        </a>

        <!-- Connection tabs -->
        ${connections.length > 0 && html`
          <div class="flex-1 flex items-center gap-0.5 overflow-x-auto min-w-0">
            ${connections.map(c => {
              const statusEmoji = c.status === 'connected' ? '🔌' : c.status === 'connecting' ? '🔄' : '⚪';
              return html`
                <button key=${c.id} type="button" onClick=${() => { setActiveConnectionId(c.id); location.hash = `#${c.id}`; }}
                  class="flex items-center gap-1 px-2 py-0.5 rounded text-xs whitespace-nowrap transition-colors flex-shrink-0 max-w-32
                    ${activeConnectionId === c.id ? 'bg-gray-700 text-gray-100' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}">
                  <span style=${{ fontSize: '10px' }}>${statusEmoji}</span>
                  <span class="truncate">${c.name}</span>
                  <button type="button" onClick=${e => { e.stopPropagation(); closeConnection(c.id); }}
                    class="text-gray-600 hover:text-white p-0.5 ml-0.5 flex-shrink-0">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-2.5 h-2.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                  </button>
                </button>
              `;
            })}
            <button type="button" onClick=${() => { setActiveConnectionId(null); location.hash = '#hosts'; }}
              class="flex items-center justify-center text-gray-500 hover:text-gray-300 transition-colors text-sm px-1 rounded flex-shrink-0 hover:bg-gray-800"
              title="New connection">
              <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            </button>
          </div>
        `}

        <div class="flex items-center gap-1 ml-auto">
          <a href="#keys"
            class="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors border border-gray-700 hover:border-gray-500 rounded px-2 py-0.5 no-underline">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
            Keys
          </a>
          <a href="#hosts"
            class="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors border border-gray-700 hover:border-gray-500 rounded px-2 py-0.5 no-underline">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            Hosts
          </a>

          <a href="https://github.com/nwtgck/piping-ssh-web" target="_blank" rel="noopener"
            class="text-gray-500 hover:text-gray-300 transition-colors p-0.5">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
            </svg>
          </a>
        </div>
      </header>

      <!-- Main content -->
      <main class="flex-1 flex flex-col">
        ${connections.map(c => html`
          <div style=${{ display: c.id === activeConnectionId ? 'flex' : 'none', flex: 1 }}>
            <${PipingSsh} key=${c.id}
              isActive=${c.id === activeConnectionId}
              pipingServerUrl=${c.pipingFullUrl}
              username=${c.username}
              defaultSshPassword=${c.password}
              agentForwarding=${c.agentForwarding}
              onConnected=${() => setConnections(prev => prev.map(cc => cc.id === c.id ? {...cc, status: 'connected'} : cc))}
              onEnd=${() => setConnections(prev => prev.map(cc => cc.id === c.id ? {...cc, status: 'finished'} : cc))}
            />
          </div>
        `)}
        ${!activeConnectionId && (route === '#keys'
          ? html`
            <div class="flex-1 px-6 py-8" style=${{ maxWidth: '40rem', margin: '0 auto', width: '100%' }}>
              <div class="flex items-center gap-3 mb-6">
                <h2 class="text-base font-semibold">SSH Keys</h2>
                <div class="flex gap-2 ml-auto">
                  <button type="button" onClick=${() => setNewKeyOpen(true)}
                    class="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 rounded-sm text-sm text-white transition-colors">
                    + New
                  </button>
                  <button type="button" onClick=${() => setGenKeyOpen(true)}
                    class="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-500 rounded-sm text-sm text-white transition-colors">
                    ✦ Generate
                  </button>
                </div>
              </div>
              <${KeyManager} />
            </div>
          `
          : route === '#hosts'
          ? html`
            <div class="flex-1 px-6 py-8" style=${{ maxWidth: '40rem', margin: '0 auto', width: '100%' }}>
              <h2 class="text-base font-semibold mb-6">SSH Hosts</h2>
              <${HostManager} onConnect=${connect} connections=${connections} onDisconnect=${(h) => {
                connections.filter(c => c.hostname === h.hostname && c.port === h.port && c.username === h.username).forEach(c => closeConnection(c.id));
              }} />
            </div>
          `
          : html`
            <div class="flex-1 flex flex-col items-center justify-center px-6">
              <div class="max-w-xl">

              ${!supportsStreams && html`
                <div class="border border-amber-800/50 rounded-sm p-3 mb-8 text-xs text-amber-600/80">
                  ⚠ Browser not supported. Use Chrome 105+, Edge, or other Chromium-based browsers.
                </div>
              `}

              <form onSubmit=${e => { e.preventDefault(); connect(); }} class="space-y-6">

                <!-- username @ host : port -->
                <div class="flex gap-0 items-center">
                  <div class="w-28" style=${{ flexShrink: 0 }}>
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
                  <button type="button" onClick=${setConfiguredUrl}
                    class="text-xs text-gray-500 hover:text-gray-400 transition-colors w-full text-center border border-gray-300 rounded py-1.5 mt-1">
                    Generate link
                  </button>
                  </div>
                `}

              </form>

            </div>
            </div>
          `
        )}
      </main>

      <!-- Globals -->
      <${GlobalPrompt} />
      <${GlobalSnackbar} />

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
