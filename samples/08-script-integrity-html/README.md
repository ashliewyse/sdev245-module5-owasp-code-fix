# Sample 8: Script integrity in HTML

**OWASP category:** A08:2021 - Software and Data Integrity Failures.

## Original vulnerable code

```html
<script src="https://cdn.example.com/lib.js"></script>
```

## Flaw and possible harm

The page trusts whatever JavaScript the remote URL returns. If a supplier or CDN changes or compromises that file, malicious code can execute within the page, read accessible page data, and perform actions using the visitor's session. HTTPS protects transport but does not prove that the supplier's current file is the version the developer approved.

## Corrected code

The assignment's `cdn.example.com` address does not identify a real library/version whose hash can be verified. This runnable demonstration therefore includes a tiny local [demo-library-1.0.0.js](vendor/demo-library-1.0.0.js). It is educational code authored for this sample, not a downloaded third-party package. The library only changes a status message. [index.html](index.html) pins its actual SHA-384 digest:

```html
<script
  src="./vendor/demo-library-1.0.0.js"
  integrity="sha384-nz1vS4rmf3WGL973LScRL8ReIMbMOKkQVZoli/f/W0kQ3muMorrjC1VlL438wSTr"
  crossorigin="anonymous"
  defer></script>
```

## Why the fix works

The browser compares downloaded script bytes with the digest stored in the HTML and refuses execution if they differ. The versioned local file avoids a mutable external URL. The page also has a restrictive Content Security Policy and no fallback that loads an unverified script.

This example uses a same-origin file. If a real CDN is required, use its exact approved version URL and that file's separately verified digest. Keep `crossorigin="anonymous"`; the CDN must allow the cross-origin request through CORS. Serve the application over HTTPS in deployment.

SRI verifies unchanged bytes, not whether approved code is safe. Obtain a dependency from its trusted publisher, review its source/release and provenance, and then calculate and commit the digest. Never calculate a new hash from a fresh download on every page request: that would also accept attacker-modified bytes. Approved upgrades require review and a deliberate file/hash update. Protect the HTML and repository too; someone who can change both the script and its pin can bypass this protection.

## Verification

From the repository root with Node.js 24:

```sh
node --test samples/08-script-integrity-html/integrity.test.mjs
```

Result: **5 tests passed**. They check the actual script's digest, show appended and single-byte changes no longer match it, check the page has one pinned script without a fallback, and execute the harmless library against a minimal document stub. These are static and Node unit checks. They do **not** claim to test a browser's SRI enforcement.

For a manual browser check, run this local server from the repository root:

```sh
python -m http.server 8000 --bind 127.0.0.1 --directory samples/08-script-integrity-html
```

Open `http://127.0.0.1:8000` and check that the status says the approved library loaded. In a temporary copy, append a comment to the library while keeping the HTML pin unchanged, reload with caching disabled, and check that the status remains "The demo library has not loaded" and the developer console reports an integrity error. Restore the original file afterward. The sample's `.gitattributes` preserves LF line endings, because changing line endings also changes the digest.

## Official guidance

- [OWASP Third Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html#subresource-integrity): SRI, controlled script mirroring, CORS requirements, and dependency review.
- [MDN Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity): browser digest verification and cross-origin behavior.
