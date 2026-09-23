// GET /user?username=alice. Authentication middleware must populate req.user.
// Schema used here: users._id is an immutable UUID string; username is unique.
// (?![\s\S]) requires the actual end; JavaScript's $ also permits a final newline.
const USERNAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{2,31}(?![\s\S])/;
const USER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/i;

export function createUserHandler(users) {
  if (!users || typeof users.findOne !== "function") {
    throw new TypeError("A MongoDB users collection is required.");
  }

  return async function getOwnUser(req, res) {
    // Apply to success and every error response before checking authentication.
    res.set("Cache-Control", "no-store");
    // req.user comes from the verified session, never a query/body/header value.
    const owner = req.user;
    if (!owner || typeof owner.id !== "string" || !USER_ID.test(owner.id) ||
        typeof owner.username !== "string" || !USERNAME.test(owner.username)) {
      return res.status(401).json({ error: "Authentication required." });
    }

    const query = req.query;
    if (!query || typeof query !== "object" || Array.isArray(query) ||
        Object.keys(query).length !== 1 || !Object.hasOwn(query, "username") ||
        typeof query.username !== "string" || !USERNAME.test(query.username)) {
      return res.status(400).json({ error: "Provide one valid username." });
    }

    // This endpoint is for the signed-in owner, not a directory of private users.
    if (query.username !== owner.username) {
      return res.status(403).json({ error: "Access denied." });
    }

    try {
      // Construct the query in code. Never spread, parse, or evaluate client data.
      // Binding immutable ID also protects against stale sessions after a rename.
      const user = await users.findOne(
        { _id: owner.id, username: query.username },
        { projection: { _id: 0, username: 1, displayName: 1 } },
      );
      if (!user) {
        return res.status(404).json({ error: "Account not found." });
      }

      // A second allowlist prevents extra DB fields reaching the client.
      return res.status(200).json({
        username: user.username,
        displayName: typeof user.displayName === "string" ? user.displayName : "",
      });
    } catch {
      // Do not disclose database credentials, queries, or stack traces.
      return res.status(500).json({ error: "Unable to load account." });
    }
  };
}
