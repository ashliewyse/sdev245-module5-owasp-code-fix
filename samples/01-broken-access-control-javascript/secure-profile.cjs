'use strict';

function normalizeId(value) {
  return typeof value === 'string' && value.length === 24 && /^[0-9a-fA-F]{24}$/.test(value)
    ? value.toLowerCase()
    : null;
}

/**
 * Express handler for an owner-only profile endpoint.
 * Prerequisite: real authentication middleware sets req.user.id to a verified
 * user's MongoDB ID string. Never build req.user from request parameters.
 * User is the application's Mongoose model, passed in for easy testing.
 */
function createProfileHandler(User) {
  return async function getProfile(req, res) {
    res.set('Cache-Control', 'no-store');

    const currentUserId = normalizeId(req.user?.id);
    if (!currentUserId) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    const requestedUserId = normalizeId(req.params?.userId);
    if (!requestedUserId) {
      return res.status(400).json({ error: 'Invalid profile ID.' });
    }

    // Authentication alone is insufficient: check ownership on every request.
    // Deny before looking up the target, even if it does not exist.
    if (requestedUserId !== currentUserId) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    try {
      const user = await User.findById(currentUserId)
        .select('_id username displayName')
        .lean()
        .exec();

      if (!user) {
        return res.status(404).json({ error: 'Profile not found.' });
      }

      // An explicit response allowlist prevents accidental disclosure of
      // password hashes, reset tokens, roles, or other model fields.
      return res.status(200).json({
        id: currentUserId,
        username: user.username,
        displayName: user.displayName,
      });
    } catch {
      // Do not send database errors or stack traces to the client.
      return res.status(500).json({ error: 'Unable to load profile.' });
    }
  };
}

module.exports = { createProfileHandler };
