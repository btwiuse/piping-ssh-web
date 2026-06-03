# Passkey (WebAuthn) SSH Authentication — Findings

## Goal

Allow a user to create a passkey (via browser WebAuthn API, e.g., Touch ID / Face ID) and use it to authenticate to an SSH server — without having a traditional SSH private key file.

## What's Implemented

### Passkey Generation (`buildless/app.js`)

- User can select "Passkey" as a key type in the KeyGenerator
- Calls `navigator.credentials.create()` with platform authenticator
- Extracts the public key from the COSE_Key response (`credential.response.getPublicKey()`)
- Converts the COSE public key to SSH format (`ssh-ed25519` or `ecdsa-sha2-nistp256`)
- Stores the passkey credential in localStorage with: name, credentialId, publicKey (SSH format), algorithm, algLabel, type='passkey'

### Passkey Display (`buildless/app.js`)

- Passkeys appear in the KeyManager with a 🔐 icon (vs 🔑 for regular keys)
- Shows algorithm, credential ID (truncated), and full public key
- No private key section (key stays on authenticator)

## The Core Problem

### WebAuthn signs a different payload than SSH expects

When SSH public key authentication happens, the client is asked to **sign** the SSH session data (`sessionID || SSH_MSG_USERAUTH_REQUEST`). The SSH server verifies this signature against the user's public key in `~/.ssh/authorized_keys`.

When WebAuthn authenticates (`navigator.credentials.get()`), the authenticator signs:

    SHA256(authenticatorData) || SHA256(clientDataJSON)

where `clientDataJSON` includes `{ type, challenge, origin, crossOrigin }`. This is a fixed format mandated by the WebAuthn spec.

These payloads are fundamentally different. Even if we extract the raw ECDSA (r, s) or Ed25519 signature from a WebAuthn assertion, it will not validate against the SSH session data on the server side.

### sk-ecdsa vs sk-ed25519 — same problem

Both `sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ssh-ed25519@openssh.com` have the same issue. The key type doesn't change what WebAuthn signs.

The `sk-*` key types in OpenSSH work with **FIDO2/CTAP2** hardware tokens directly, where the authenticator receives arbitrary data to sign. Browser WebAuthn (`navigator.credentials.get()`) does not expose this — it always wraps the challenge in the WebAuthn assertion format.

## Existing Projects Surveyed

### 1. [bulwarkid/ssh-passkey](https://github.com/bulwarkid/ssh-passkey) (Go)

**Direction:** SSH key → WebAuthn passkey (for website auth)
**Approach:** Takes an SSH private key file and creates a **virtual FIDO2 USB device** (via USB/IP kernel driver + virtual-fido library). The virtual device presents the SSH key as a FIDO2 credential that browsers can use.
**Relevance:** Opposite direction. Not applicable to browser WASM environment.

### 2. [abhishekgahlot2/meow-ssh](https://github.com/abhishekgahlot2/meow-ssh) (Rust)

**Direction:** WebAuthn passkey → SSH auth
**Approach:** Custom SSH server (russh + webauthn-rs) that replaces public key auth with **keyboard-interactive** auth. Server shows an auth URL, user opens it in a browser, WebAuthn assertion is validated server-side.
**Relevance:** Requires a **custom SSH server**. Can't connect to arbitrary SSH servers with `sk-*` keys in authorized_keys.

### 3. [rado0x54/ShellWatch](https://github.com/rado0x54/ShellWatch) (TypeScript)

Passkey-backed SSH for humans and AI agents. Appears to use a similar server-side approach.

### 4. ssh-wca (referenced from memory, URL not confirmed)

Concept: A PAM module that validates WebAuthn assertions for SSH. Would allow standard `ssh` client to authenticate via passkey if the server has the PAM module installed.
**Relevance:** Server-side only. Not helpful for client-only solutions.

## Approaches That Could Work

### A. Custom SSH Server (like meow-ssh)

Replace the SSH auth flow with keyboard-interactive + WebAuthn approval. Works great for your own servers (e.g., a hosted dev environment) but can't connect to arbitrary SSH servers.

### B. Server-Side PAM / AuthorizedKeysCommand

An `AuthorizedKeysCommand` script that, when triggered, initiates a WebAuthn challenge and validates the assertion. The SSH client (our WASM app) would need to:
1. Detect that the server is asking for WebAuthn
2. Call `navigator.credentials.get()` 
3. Send the assertion back through the SSH channel

This could theoretically work with standard `ssh` client software, but no production implementation exists yet.

### C. Pure Client-Side Bridge (currently not feasible)

Create a Go `PasskeySigner` that implements `ssh.Signer` and calls back to JavaScript for each `Sign()` invocation. JavaScript would call `navigator.credentials.get()` and return the assertion. **Problem: the signature covers WebAuthn data, not SSH data — server rejects it.**

## Next Steps / Open Questions

- Can we modify the Go WASM SSH library to support a custom auth method that sends WebAuthn assertions?
- Is there an existing SSH server plugin (PAM, AuthorizedKeysCommand) that accepts WebAuthn assertions?
- Could we use WebAuthn to derive a deterministic private key (seed -> Ed25519) that's then used as a regular SSH key? (Security implications unclear)
- Should we fork `golang.org/x/crypto/ssh` to add `sk-*` signer support with JS callbacks, then pair with a server-side component?

## Files Modified

- `buildless/index.html` — favicon
- `buildless/app.js` — passkey generation, storage, display in KeyManager/KeyGenerator
