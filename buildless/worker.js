// buildless/worker.js
// Classic Web Worker (non-module) — loads Go WASM and exposes functions via Comlink.
//
// Serve the project from its root so that the relative paths below resolve:
//   ../public/wasm_exec.js
//   ../public/main.wasm

importScripts('https://unpkg.com/comlink@4.4.1/dist/umd/comlink.js');
importScripts('../public/wasm_exec.js');

let goExited = false;
const go = new Go(); // defined by wasm_exec.js

// The Go WASM binary calls self.pipingSshGoExportResolve(exported) to hand
// over the exported function table. We create the promise first so it is
// already waiting when go.run() executes.
const exportedPromise = new Promise((resolve) => {
  self.pipingSshGoExportResolve = resolve;
});

// Fetch and instantiate the WASM binary.
(async () => {
  try {
    const res = await fetch('../public/main.wasm');
    const result = await WebAssembly.instantiateStreaming(res, go.importObject);
    go.run(result.instance).then(() => { goExited = true; });
  } catch (e) {
    console.error('[worker] Failed to load main.wasm:', e);
  }
})();

const workerApi = {
  async existed() {
    return goExited;
  },
  async doSsh(params, functions) {
    const exported = await exportedPromise;
    return exported.doSsh(params, functions);
  },
  async getAuthPublicKeyType(publicKey) {
    const exported = await exportedPromise;
    return exported.getAuthPublicKeyType(publicKey);
  },
  async generateRsaKeys(keyBits) {
    const exported = await exportedPromise;
    return exported.generateRsaKeys(keyBits);
  },
  async generateEd25519Keys() {
    const exported = await exportedPromise;
    return exported.generateEd25519Keys();
  },
  async sshSha256Fingerprint(publicKey) {
    const exported = await exportedPromise;
    return exported.sshSha256Fingerprint(publicKey);
  },
  async sshPrivateKeyIsEncrypted(privateKey) {
    const exported = await exportedPromise;
    return exported.sshPrivateKeyIsEncrypted(privateKey);
  },
};

Comlink.expose(workerApi);
