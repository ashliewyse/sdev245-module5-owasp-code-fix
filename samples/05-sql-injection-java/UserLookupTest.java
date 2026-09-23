package owasp.sample05;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

/** Strict JDBC doubles observe the API contract; these are not database integration tests. */
public final class UserLookupTest {
    private static int passed;
    @FunctionalInterface interface Test { void run() throws Exception; }
    private static void test(String name, Test action) throws Exception {
        action.run(); passed++; System.out.println("PASS " + name);
    }
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }

    private static final class JdbcProbe {
        String sql, bound;
        String failAt;
        int timeout, maxRows, executions;
        boolean found, prepared, statementClosed, resultsClosed, connectionClosed;
        JdbcProbe(boolean found) { this.found = found; }
        private void fail(String stage) throws SQLException {
            if (stage.equals(failAt)) throw new SQLException("simulated " + stage);
        }
        final ResultSet rows = (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{ResultSet.class}, (proxy, method, args) -> {
            return switch (method.getName()) {
                case "next" -> { fail("read"); yield found; }
                case "getLong" -> { check(args[0].equals("id")); yield 7L; }
                case "getString" -> { check(args[0].equals("username")); yield bound; }
                case "close" -> { resultsClosed = true; yield null; }
                default -> throw new AssertionError("Unexpected ResultSet call " + method);
            };
        });
        final PreparedStatement statement = (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{PreparedStatement.class}, (proxy, method, args) -> {
            return switch (method.getName()) {
                case "setString" -> { fail("bind"); check((int) args[0] == 1); bound = (String) args[1]; yield null; }
                case "setQueryTimeout" -> { timeout = (int) args[0]; yield null; }
                case "setMaxRows" -> { maxRows = (int) args[0]; yield null; }
                case "executeQuery" -> {
                    check(args == null || args.length == 0); check(bound != null);
                    fail("execute"); executions++; yield rows;
                }
                case "close" -> { statementClosed = true; yield null; }
                default -> throw new AssertionError("Unexpected statement call " + method);
            };
        });
        final Connection connection = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{Connection.class}, (proxy, method, args) -> {
            return switch (method.getName()) {
                case "prepareStatement" -> { fail("prepare"); prepared = true; sql = (String) args[0]; yield statement; }
                case "close" -> { connectionClosed = true; yield null; }
                default -> throw new AssertionError("Unexpected connection call " + method);
            };
        });
    }

    public static void main(String[] args) throws Exception {
        test("normal lookup returns only requested summary fields", () -> {
            JdbcProbe p = new JdbcProbe(true);
            Optional<UserLookup.UserSummary> result = UserLookup.findByUsername(p.connection, "alice");
            check(result.orElseThrow().equals(new UserLookup.UserSummary(7, "alice")));
            check(p.sql.equals("SELECT id, username FROM users WHERE username = ?"));
            check(p.timeout == 5 && p.maxRows == 1 && p.executions == 1);
        });
        test("injection payload stays entirely in bound parameter", () -> {
            JdbcProbe p = new JdbcProbe(false);
            String attack = "' OR '1'='1' --";
            check(UserLookup.findByUsername(p.connection, attack).isEmpty());
            check(p.bound.equals(attack) && !p.sql.contains(attack) && p.sql.endsWith("= ?"));
        });
        test("apostrophe in legitimate username is preserved", () -> {
            JdbcProbe p = new JdbcProbe(true);
            check(UserLookup.findByUsername(p.connection, "O'Neil").orElseThrow().username().equals("O'Neil"));
        });
        test("absent user returns empty and closes resources", () -> {
            JdbcProbe p = new JdbcProbe(false);
            check(UserLookup.findByUsername(p.connection, "missing").isEmpty());
            check(p.resultsClosed && p.statementClosed);
        });
        test("success closes owned resources and preserves caller connection", () -> {
            JdbcProbe p = new JdbcProbe(true); UserLookup.findByUsername(p.connection, "alice");
            check(p.resultsClosed && p.statementClosed && !p.connectionClosed);
        });
        test("invalid usernames rejected before SQL", () -> {
            for (String invalid : new String[]{null, "", "  ", "x".repeat(129)}) {
                JdbcProbe p = new JdbcProbe(false);
                try { UserLookup.findByUsername(p.connection, invalid); throw new AssertionError(); }
                catch (IllegalArgumentException expected) { check(!p.prepared); }
            }
        });
        for (String failure : new String[]{"prepare", "bind", "execute", "read"}) {
            test("resource cleanup and error propagation on " + failure + " failure", () -> {
                JdbcProbe p = new JdbcProbe(false); p.failAt = failure;
                try { UserLookup.findByUsername(p.connection, "alice"); throw new AssertionError(); }
                catch (SQLException expected) {
                    check(p.statementClosed == !failure.equals("prepare"));
                    check(p.resultsClosed == failure.equals("read"));
                    check(!p.connectionClosed);
                }
            });
        }
        System.out.println(passed + " tests passed");
    }
}
