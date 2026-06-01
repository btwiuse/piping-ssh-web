# Piping SSH — Buildless Frontend

A zero-build version of the Piping SSH frontend. Uses:

- **React 19** via [esm.sh](https://esm.sh) (ES modules, no bundler)
- **htm** — JSX-like tagged template literals, no compilation step
- **Tailwind CSS** — play CDN for utility classes
- **xterm.js** — terminal emulator from jsDelivr CDN
- **Comlink** — structured worker communication (main thread via esm.sh, worker via unpkg UMD)
- The same **Go WASM** binary (`main.wasm`) as the original build

## How to serve

The buildless directory must be served **from the project root** so the worker can load
`../public/wasm_exec.js` and `../public/main.wasm` via relative URLs.

```bash
# From the repository root — any static file server works, e.g.:
npx serve .
# Then open: http://localhost:3000/buildless/
```

```bash
# Or with Python:
python3 -m http.server 8080
# Then open: http://localhost:8080/buildless/
```

## Files

| File | Description |
|------|-------------|
| `index.html` | Entry point; loads CDN scripts, import map, and `app.js` as an ES module |
| `app.js` | All React components and application logic (no build step needed) |
| `worker.js` | Classic Web Worker that loads Go WASM and exposes functions via Comlink |

## Notes

- Requires a **Chromium-based browser** (Chrome 105+, Edge, etc.) for streaming fetch support.
- `main.wasm` is **not** committed to git. Build it with `cd go && make` or copy a pre-built
  binary to `public/main.wasm`.
