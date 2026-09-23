# Sample 5: SQL injection in Java

## Original vulnerable code

```java
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

## Flaw and potential harm

The request parameter is concatenated into SQL text. A value such as `' OR '1'='1' --` can change the query's predicate and expose rows belonging to other users. Depending on the database, driver, and database account privileges, related injection paths can also modify data. The query unnecessarily requests every column, potentially including credentials or private fields. The snippet does not close its statement or result set.

## Corrected code and why it works

[UserLookup.java](UserLookup.java) defines the SQL independently of input:

```sql
SELECT id, username FROM users WHERE username = ?
```

It creates a `PreparedStatement`, binds the complete username with `setString(1, username)`, and then calls the no-argument `executeQuery()`. Input is handled as one data value, so quotes and SQL-looking text cannot change the query structure. A legitimate username containing an apostrophe remains valid; manual quote escaping is unnecessary.

Only the two fields needed for the returned summary are selected. `try-with-resources` closes the statement and result set on success, no match, or failure. A five-second query timeout and one-row result cap provide additional limits. Null, blank, and overlong input are rejected before issuing SQL; parameter binding is the injection defense, not the length check.

## Assumptions and limitations

- The schema has `users(id, username)` and enforces uniqueness for `username` using the application's intended case/collation policy.
- The caller supplies and owns a real JDBC connection and must close or return it to its pool. This method intentionally does not close that shared resource.
- Configure a least-privileged database account, encrypted database transport where applicable, driver/network timeouts, and pool limits. JDBC query-timeout support depends on the actual driver.
- This is a data lookup, not an authorization check. A web route must authenticate the requester and decide whether that requester can read the returned account information.
- The method propagates `SQLException` to the application error handler; that handler should return a generic error instead of exposing SQL details to the browser.

## Run the tests

Requires JDK 17 or newer. From the repository root in PowerShell:

```powershell
New-Item -ItemType Directory -Force work/java05 | Out-Null
javac -encoding UTF-8 -Xlint:all -d work/java05 samples/05-sql-injection-java/UserLookup.java samples/05-sql-injection-java/UserLookupTest.java
java -cp work/java05 owasp.sample05.UserLookupTest
```

Verified with `javac 17.0.19`: **10 tests passed**. Strict JDBC test doubles check unchanged SQL text, bound injection-like input, legitimate apostrophes, return values, limits, ownership, and cleanup after prepare/bind/execute/read failures. These are executable JDBC API-contract tests, **not** tests against a live database. A deployment should also run integration tests with its actual schema and JDBC driver.

## Official OWASP reference

- [SQL Injection Prevention Cheat Sheet — prepared statements, Java parameter binding, and least privilege](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

Reference reviewed September 23, 2026.
