"""Owner-only account route for an existing Flask/Flask-Login application."""

import re

from flask import Blueprint, jsonify
from flask_login import current_user
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError


MAX_ACCOUNT_ID = (1 << 63) - 1


def parse_account_id(value):
    """Accept canonical positive decimal IDs that fit a signed 64-bit key."""
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", value):
        return None
    account_id = int(value)
    return account_id if account_id <= MAX_ACCOUNT_ID else None


def create_account_blueprint(session_factory, User):
    """Use a SQLAlchemy sessionmaker and the application's mapped User model.

    A configured Flask-Login user_loader must supply current_user from a
    verified login session. current_user.id is the integer database primary
    key; it must never come from request arguments or identity headers.
    """
    accounts = Blueprint("secure_accounts", __name__)

    @accounts.after_request
    def prevent_account_caching(response):
        response.headers["Cache-Control"] = "no-store"
        return response

    @accounts.get("/account/<user_id>")
    def get_account(user_id):
        # Explicit JSON authentication gate instead of a login-page redirect.
        if not current_user.is_authenticated or not current_user.is_active:
            return jsonify(error="Authentication required."), 401

        owner_id = getattr(current_user, "id", None)
        # bool is an int subclass in Python, so require the exact int type.
        if type(owner_id) is not int or not 1 <= owner_id <= MAX_ACCOUNT_ID:
            return jsonify(error="Authentication required."), 401

        requested_id = parse_account_id(user_id)
        if requested_id is None:
            return jsonify(error="Invalid account ID."), 400

        # Authentication is not authorization: check ownership before lookup.
        if requested_id != owner_id:
            return jsonify(error="Access denied."), 403

        try:
            # Only read the allowed fields, using the verified owner's key.
            with session_factory() as db:
                statement = select(User.id, User.username, User.display_name).where(
                    User.id == owner_id
                )
                account = db.execute(statement).mappings().one_or_none()
                if account is None:
                    return jsonify(error="Account not found."), 404
                return jsonify(
                    id=account["id"],
                    username=account["username"],
                    display_name=account["display_name"],
                ), 200
        except SQLAlchemyError:
            # The session context closes/rolls back; never expose SQL or traces.
            return jsonify(error="Unable to load account."), 500

    return accounts
