# jssecpro — Advanced JavaScript Security Analysis Framework

**Author:** w01f  
**Version:** 1.1.0  

**There has fasle positive alot. will fix it asap**

`jssecpro` is a plugin-based framework for **static security analysis** of JavaScript code.  
It can scan either a **local project directory** or a **remote URL** (HTML + linked JS) and generate actionable security findings.  

---

##  Features

- **Flexible Targeting**
  - Scan a **local project folder** (`--path`)
  - Scan a **live domain** (`--url`) with HTML + JS collection

- **Plugin-based Architecture**
  - Easy to add/remove plugins
  - Default plugins included:
    - `secrets` — Detect leaked API keys, tokens, and private keys
    - `danger` — Identify dangerous JS APIs (`eval`, `new Function`, etc.)
    - `domsinks` — Flag DOM XSS sinks (`innerHTML`, `insertAdjacentHTML`, etc.)
    - `framework` — Detect risky framework features (React, Vue, Angular)
    - `proto` — Prototype pollution indicators
    - `postmessage` — Insecure `postMessage` sender/receiver usage
    - `csp` — Evaluate Content Security Policy (URL scans)
    - `sri` — Detect missing Subresource Integrity on external scripts
    - `sourcemaps` — Identify exposed source maps
    - `sw_wasm` — Service Worker registration & WebAssembly usage
    - `deps` — Parse local `package.json` for dependency inventory

- **Reporting**
  - JSON (`report.json`)
  - Markdown (`report.md`)
  - HTML (`report.html`)

---

## Quick Start

### 1. Install
```bash
pip install -e .
````

### 2. Scan a directory

```bash
jssecpro scan --path ./my-web-project --out ./reports --html
```

### 3. Scan a live site

```bash
jssecpro scan --url https://example.com --out ./reports --html
```

### 4. Use selected plugins

```bash
jssecpro scan --path ./my-web-project \
  --plugins secrets,danger,domsinks,framework,proto,postmessage,csp,sri,sourcemaps,sw_wasm,deps
```

---

## Example Report

After scanning, reports are written into the `./reports/` directory:

* `report.json` → Machine-readable findings
* `report.md` → Markdown summary for docs/review
* `report.html` → Friendly HTML report (if `--html` is used)

Example snippet:

```json
[
  {
    "plugin": "secrets",
    "severity": "HIGH",
    "message": "AWS Access Key found",
    "location": "./static/app.js",
    "line": 53
  },
  {
    "plugin": "csp",
    "severity": "HIGH",
    "message": "CSP issues: uses 'unsafe-inline', no Trusted Types",
    "location": "https://example.com"
  }
]
```

---

## Plugin Development

Each plugin:

* Lives under `jssecpro/plugins/`
* Implements a `run(files, csp_headers, config)` method
* Returns a list of `Finding` objects

Minimal example:

```python
from ..core import Finding

class HelloPlugin:
    name = "hello"
    @classmethod
    def run(cls, files, csp, config):
        return [Finding(plugin=cls.name,
                        severity="INFO",
                        message="Hello from custom plugin",
                        location="(test)")]
```

---

## Legal & Ethical Notice

This tool is intended **only for authorized security testing, research, and education**.
Do **not** use it on systems without explicit permission.

---

## License

MIT License © 2025 — Author **w01f**
