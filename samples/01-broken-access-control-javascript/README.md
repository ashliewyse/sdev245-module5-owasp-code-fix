# Sample 1: Broken Access Control — JavaScript profile endpoint

**Status:** Corrected handler, explanation, and nine passing unit tests. Login and live database integration are outside this sample.

## Original vulnerable code

```javascript
app.get('/profile/:userId', (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
```

## Security flaw and real-world impact

The route uses the URL's user ID to select a record without checking who is requesting it or whether they own it. For example, a signed-in user could replace their own ID with another person's ID and retrieve that profile. The snippet also shows no authentication middleware, so anonymous access is possible unless the surrounding application supplies it.

This is an insecure direct object reference (IDOR), a form of Broken Access Control. Exposure could include personal information or password hashes if those fields are serialized by the model; the exact data depends on the schema. The demonstrated route reads data, so this sample does not claim that it lets an attacker edit or delete records. Returning raw database errors can also reveal internal details.

See [OWASP A01:2021 Broken Access Control](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/) and the [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html). The 2021 category names match those used by the assignment.

## Corrected code

[secure-profile.cjs](secure-profile.cjs) contains the corrected handler.

The policy is simple: an authenticated user may read only their own profile. There is no administrator exception for this endpoint because the sample does not establish a need for one.

## Why the fix works

1. **Require a verified identity.** Missing or malformed `req.user.id` produces `401`. The authentication middleware, described below, is responsible for establishing that identity.
2. **Validate the requested ID.** Only a 24-character hexadecimal MongoDB ID is accepted. Invalid input produces `400`; uppercase hexadecimal is normalized. A valid-looking ID alone never grants permission.
3. **Check ownership on every request.** A different user's ID produces `403` before any database lookup. Matching requests query by the verified user's ID. Query parameters, request bodies, headers, and role flags cannot change this decision.
4. **Limit the response.** Database projection and an explicit JSON field list return only `id`, `username`, and `displayName`.
5. **Handle failures safely.** A missing own profile produces `404`; database exceptions produce a generic `500`. Responses use `Cache-Control: no-store`.

The ownership comparison is the central access-control fix. ID validation, limited output, safe errors, and cache prevention provide additional protection. Server-side checks, least privilege, and denial unless a rule grants access follow the [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

## Integration assumptions

This is a route-level code fix for an existing Express application using a Mongoose `User` model, not a complete login application.

- The model uses MongoDB ObjectIds and has string `username` and `displayName` fields.
- Real authentication middleware must verify the session or token and load the active user before setting `req.user.id` to their MongoDB ID as a string. If it supplies an ObjectId in `req.user._id`, the trusted middleware must map `_id.toHexString()` to `id`.
- Never create `req.user` from a submitted user ID, an unverified token, or a custom identity header.
- Replace the vulnerable route with this registration after configuring authentication:

```javascript
const { createProfileHandler } = require('./secure-profile.cjs');

// app, authenticate, and User are supplied by the existing application.
// authenticate must verify the caller and establish req.user.id.
app.get('/profile/:userId', authenticate, createProfileHandler(User));
```

Session security, TLS, rate limiting, and sanitized server-side monitoring still belong to the surrounding application. This sample does not implement or test those services.

Framework references: [Express middleware](https://expressjs.com/en/guide/using-middleware/) and [Mongoose query projection](https://mongoosejs.com/docs/api/query.html#Query.prototype.select()).

## Verification

From the repository root, run:

```sh
node --test samples/01-broken-access-control-javascript/secure-profile.test.cjs
```

No package installation is needed for these unit tests. Tested on Node.js v24.18.0: **9 passed, 0 failed**.

| Scenario | Expected result |
| --- | --- |
| Anonymous request | 401; no database lookup |
| Missing or malformed authenticated ID | 401; no database lookup |
| Owner requests own profile | 200; only approved fields; no-store header |
| Owner changes URL to another ID | 403; no database lookup |
| Spoofed identity inputs or admin flags | 403; no database lookup |
| Malformed URL ID | 400; no database lookup |
| Uppercase representation of the same ID | 200 after normalization |
| Owner's record no longer exists | 404 |
| Database exception | 500 without internal error details |

The tests call the real handler with stubbed Express request/response objects and a stubbed Mongoose model. They verify authorization decisions and response behavior; they do not prove that a real login system, HTTP router, or database is configured correctly. After integration, check the endpoint with two real test accounts and an anonymous request.
