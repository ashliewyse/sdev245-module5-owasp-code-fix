import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
const library = await readFile(new URL("./vendor/demo-library-1.0.0.js", import.meta.url));
const hash = (bytes) => `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
const pin = html.match(/\bintegrity="(sha384-[A-Za-z0-9+/]{64})"/)?.[1];

test("HTML pins the exact SHA-384 of the versioned file", () => {
  assert.ok(pin, "A valid SHA-384 integrity attribute is required.");
  assert.equal(pin, hash(library));
  assert.match(html, /src="\.\/vendor\/demo-library-1\.0\.0\.js"/);
});

test("appended script content fails the pinned digest comparison", () => {
  const changed = Buffer.concat([library, Buffer.from("\n// changed bytes\n")]);
  assert.notEqual(hash(changed), pin);
});

test("one changed byte fails the pinned digest comparison", () => {
  const changed = Buffer.from(library);
  changed[changed.indexOf(Buffer.from("approved"))] ^= 1;
  assert.notEqual(hash(changed), pin);
});

test("page has exactly one pinned script and no unverified script fallback", () => {
  const scripts = [...html.matchAll(/<script\b[^>]*>[\s\S]*?<\/script>/gi)];
  assert.equal(scripts.length, 1);
  assert.match(scripts[0][0], /integrity="sha384-/);
  assert.match(scripts[0][0], /crossorigin="anonymous"/);
  assert.match(scripts[0][0], /\bdefer\b/);
  assert.doesNotMatch(html, /\bonerror\s*=/i);
});

test("approved demo code only updates the status using textContent", () => {
  const status = { textContent: "The demo library has not loaded." };
  const document = {
    getElementById(id) {
      assert.equal(id, "library-status");
      return status;
    },
  };
  runInNewContext(library.toString("utf8"), { document }, { timeout: 1000 });
  assert.equal(status.textContent, "The approved demo library loaded successfully.");
});
