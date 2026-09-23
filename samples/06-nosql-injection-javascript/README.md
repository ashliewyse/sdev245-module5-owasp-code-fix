# Sample 6: NoSQL injection in JavaScript

**OWASP category:** A03:2021 - Injection. The owner check also addresses A01:2021 - Broken Access Control.

## Original vulnerable pattern

```javascript
app.get('/user', (req, res) => {
  // Directly trusting query parameters can lead to NoSQL injection
  db.collection('users').findOne({ username: req.query.username }, (err, user) => {
    if (err) throw err;
    res.json(user);
  });
});
```

## Flaw and possible harm

The query accepts the parsed request value without checking its type. If the query parser supports nested objects, `?username[$ne]=` can become a MongoDB operator object instead of a username. The condition can match an unintended user. Returning the whole document can expose password hashes, reset tokens, or personal details. Even an ordinary username should not grant access to another account.

## Corrected code and why it works

[secure-user.mjs](secure-user.mjs) exports the corrected asynchronous route handler.

- Accept exactly one `username` key containing 3-32 ASCII letters, digits, underscores, dots, or hyphens; the first character cannot be a dot or hyphen. Objects, arrays, missing values, extra keys, operator syntax, and trailing newlines receive HTTP 400 before any database call. Both username and ID patterns require the actual end of the string.
- Require a verified session and the owner's exact username. Also constrain the database query by the session's immutable account ID, so a reused username cannot expose another account through a stale session.
- Build the filter in code and use the driver's `findOne` method. Untrusted input supplies a string value, never query structure.
- Project only `username` and `displayName`, then construct a response containing only those fields. Database exceptions produce a generic error.
- Send `Cache-Control: no-store` on success and error responses so private account responses are not stored by HTTP caches.

## Integration assumptions

This is a route-level sample, not a complete login application. It uses the modern MongoDB driver's promise API. In this sample's schema, `_id` is an immutable UUID **string**, and `username` has a unique index. Applications that store MongoDB `ObjectId` values must use their established validated ID conversion instead.

Verified authentication middleware must populate `req.user = { id, username }` from a server-managed session or validated token. Never populate it from unverified request parameters, headers, or JSON. Register the handler after that middleware, for example:

```javascript
import { createUserHandler } from './secure-user.mjs';
app.get('/user', requireLogin, createUserHandler(db.collection('users')));
```

The host application supplies Express, MongoDB, `requireLogin`, HTTPS, secure session handling, and a database account with minimal permissions. The deliberately narrow username policy must also be applied when accounts are created. No frontend should render the returned display name as HTML.

## Verification

From the repository root with Node.js 24:

```sh
node --test samples/06-nosql-injection-javascript/secure-user.test.mjs
```

Result: **18 tests passed**. Tests execute the actual handler with a stub collection and response: authorized success, response filtering, unauthenticated and cross-account rejection, operator/array/bracket/string/length/type attacks, trailing-newline rejection, absent accounts, and safe error handling. Every response path is checked for `Cache-Control: no-store`. These are route unit tests; they do not exercise an installed Express server, live MongoDB, or login middleware.

## Official OWASP references

- [NoSQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html): use controlled driver queries, validate input, and reject client-controlled operators.
- [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html): check permissions on every request and restrict access by default.
