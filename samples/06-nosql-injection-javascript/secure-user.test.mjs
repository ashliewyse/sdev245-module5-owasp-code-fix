import assert from "node:assert/strict";
import test from "node:test";
import { createUserHandler } from "./secure-user.mjs";

const OWNER = Object.freeze({
  id: "72ca937d-5318-4d5f-99e2-999f3f28e30b",
  username: "alice",
});

async function request({ query = { username: "alice" }, user = OWNER,
  row = { username: "alice", displayName: "Alice" }, failure } = {}) {
  const calls = [];
  const handler = createUserHandler({
    async findOne(filter, options) {
      calls.push({ filter, options });
      if (failure) throw failure;
      return row;
    },
  });
  const response = {
    headers: {},
    set(name, value) { this.headers[name] = value; return this; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await handler({ query, user }, response);
  // Every path, including 400/401/403/404/500 errors, must forbid caching.
  assert.equal(response.headers["Cache-Control"], "no-store");
  return { response, calls };
}

test("authenticated owner receives only approved fields with an ID-scoped query", async () => {
  const { response, calls } = await request({ row: {
    _id: OWNER.id, username: "alice", displayName: "Alice",
    passwordHash: "must-not-leak", resetToken: "must-not-leak", email: "private",
  } });
  assert.equal(response.code, 200);
  assert.deepEqual(response.body, { username: "alice", displayName: "Alice" });
  assert.deepEqual(calls, [{
    filter: { _id: OWNER.id, username: "alice" },
    options: { projection: { _id: 0, username: 1, displayName: 1 } },
  }]);
});

test("unauthenticated access is blocked before database lookup", async () => {
  const { response, calls } = await request({ user: null });
  assert.equal(response.code, 401);
  assert.equal(calls.length, 0);
});

test("invalid session IDs including a trailing newline are rejected", async () => {
  for (const id of [{ $ne: null }, `${OWNER.id}\n`]) {
    const { response, calls } = await request({ user: { id, username: "alice" } });
    assert.equal(response.code, 401);
    assert.equal(calls.length, 0);
  }
});

test("a session username with a trailing newline is rejected", async () => {
  const { response, calls } = await request({ user: { ...OWNER, username: "alice\n" } });
  assert.equal(response.code, 401);
  assert.equal(calls.length, 0);
});

test("another username is denied before database lookup", async () => {
  const { response, calls } = await request({ query: { username: "bob" } });
  assert.equal(response.code, 403);
  assert.equal(calls.length, 0);
});

for (const [name, query] of [
  ["operator object", { username: { $ne: null } }],
  ["duplicate parameters parsed as array", { username: ["alice", "bob"] }],
  ["bracket syntax under simple query parser", { "username[$ne]": "" }],
  ["JSON text", { username: '{"$ne":null}' }],
  ["missing username", {}],
  ["empty username", { username: "" }],
  ["oversized username", { username: "a".repeat(33) }],
  ["unexpected query key", { username: "alice", $where: "true" }],
  ["wrong scalar type", { username: 7 }],
  ["trailing newline", { username: "alice\n" }],
]) {
  test(`rejects ${name} without issuing a query`, async () => {
    const { response, calls } = await request({ query });
    assert.equal(response.code, 400);
    assert.equal(calls.length, 0);
  });
}

test("missing or renamed account returns 404", async () => {
  const { response, calls } = await request({ row: null });
  assert.equal(response.code, 404);
  assert.equal(calls[0].filter._id, OWNER.id);
});

test("database error returns a generic response", async () => {
  const { response } = await request({ failure: new Error("mongodb://secret-host/password") });
  assert.equal(response.code, 500);
  assert.deepEqual(response.body, { error: "Unable to load account." });
});

test("unexpected display name type cannot become an object in the response", async () => {
  const { response } = await request({ row: { username: "alice", displayName: { private: true } } });
  assert.deepEqual(response.body, { username: "alice", displayName: "" });
});
