'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createProfileHandler } = require('./secure-profile.cjs');

const OWNER_ID = '507f1f77bcf86cd799439011';
const OTHER_ID = '507f191e810c19729de860ea';
const PROFILE = {
  _id: OWNER_ID,
  username: 'student',
  displayName: 'Example Student',
  email: 'example@example.test',
  passwordHash: 'must-not-be-returned',
  resetToken: 'must-not-be-returned',
  role: 'admin',
};

function fixture({ record = PROFILE, databaseError = false } = {}) {
  const calls = [];
  const User = {
    findById(id) {
      calls.push(id);
      return {
        select(fields) {
          assert.equal(fields, '_id username displayName');
          return this;
        },
        lean() { return this; },
        async exec() {
          if (databaseError) throw new Error('private database connection detail');
          // Deliberately include extra fields to test the response allowlist.
          return record;
        },
      };
    },
  };
  const res = {
    headers: {},
    statusCode: undefined,
    body: undefined,
    set(name, value) { this.headers[name] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  return { handler: createProfileHandler(User), res, calls };
}

test('an anonymous request is denied before database access', async () => {
  const { handler, res, calls } = fixture();
  await handler({ params: { userId: OWNER_ID } }, res);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(calls, []);
});

test('missing and malformed authenticated IDs fail closed', async () => {
  for (const id of [undefined, null, '', 123, { id: OWNER_ID }, [OWNER_ID], 'bad-id', OWNER_ID + '\n']) {
    const { handler, res, calls } = fixture();
    await handler({ user: { id }, params: { userId: OWNER_ID } }, res);
    assert.equal(res.statusCode, 401);
    assert.deepEqual(calls, []);
  }
});

test('an owner can read their profile without disclosing extra fields', async () => {
  const { handler, res, calls } = fixture();
  await handler({ user: { id: OWNER_ID }, params: { userId: OWNER_ID } }, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, {
    id: OWNER_ID, username: 'student', displayName: 'Example Student',
  });
  assert.deepEqual(calls, [OWNER_ID]);
  assert.equal(res.headers['Cache-Control'], 'no-store');
});

test('changing the URL to another user ID is denied before lookup', async () => {
  const { handler, res, calls } = fixture();
  await handler({ user: { id: OWNER_ID }, params: { userId: OTHER_ID } }, res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { error: 'Access denied.' });
  assert.deepEqual(calls, []);
});

test('client-supplied identity and admin flags cannot override ownership', async () => {
  const { handler, res, calls } = fixture();
  await handler({
    user: { id: OWNER_ID, role: 'admin' },
    params: { userId: OTHER_ID },
    query: { id: OTHER_ID, role: 'admin' },
    body: { user: { id: OTHER_ID } },
    headers: { 'x-user-id': OTHER_ID },
  }, res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(calls, []);
});

test('malformed profile IDs are rejected before database access', async () => {
  for (const userId of [undefined, '', 'not-an-id', 'a'.repeat(25), { $ne: null }, OWNER_ID + '\n']) {
    const { handler, res, calls } = fixture();
    await handler({ user: { id: OWNER_ID }, params: { userId } }, res);
    assert.equal(res.statusCode, 400);
    assert.deepEqual(calls, []);
  }
});

test('uppercase hexadecimal IDs normalize to the same owner', async () => {
  const { handler, res, calls } = fixture();
  await handler({
    user: { id: OWNER_ID.toUpperCase() }, params: { userId: OWNER_ID },
  }, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(calls, [OWNER_ID]);
});

test('a missing owner profile returns a safe not-found response', async () => {
  const { handler, res } = fixture({ record: null });
  await handler({ user: { id: OWNER_ID }, params: { userId: OWNER_ID } }, res);
  assert.equal(res.statusCode, 404);
  assert.deepEqual(res.body, { error: 'Profile not found.' });
});

test('database failures do not leak exception details', async () => {
  const { handler, res } = fixture({ databaseError: true });
  await handler({ user: { id: OWNER_ID }, params: { userId: OWNER_ID } }, res);
  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.body, { error: 'Unable to load profile.' });
});
