package owasp.sample05;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;

public final class UserLookup {
    private static final String FIND_USER = "SELECT id, username FROM users WHERE username = ?";
    private UserLookup() {}

    /** The caller owns the connection; this method owns and closes its statement/results. */
    public static Optional<UserSummary> findByUsername(Connection connection, String username)
            throws SQLException {
        Objects.requireNonNull(connection, "connection");
        if (username == null || username.isBlank() || username.length() > 128) {
            throw new IllegalArgumentException("Username must be 1..128 nonblank characters");
        }
        try (PreparedStatement statement = connection.prepareStatement(FIND_USER)) {
            statement.setString(1, username);
            statement.setQueryTimeout(5);
            statement.setMaxRows(1);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return Optional.empty();
                return Optional.of(new UserSummary(rows.getLong("id"), rows.getString("username")));
            }
        }
    }

    public record UserSummary(long id, String username) {}
}
