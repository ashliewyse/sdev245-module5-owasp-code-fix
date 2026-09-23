package owasp.sample10;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import owasp.shared.PasswordHashes;

public final class AuthenticationTest {
    private static int passed;
    private static String knownHash, dummyHash;
    private static final char[] PASSWORD = "Long example passphrase 42!".toCharArray();
    @FunctionalInterface interface Test { void run() throws Exception; }
    private static void test(String name, Test action) throws Exception {
        action.run(); passed++; System.out.println("PASS " + name);
    }
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    private static AttemptLimiter limiter(AtomicLong now, int perAccount, int global, int capacity) {
        return new AttemptLimiter(perAccount, global, capacity, Duration.ofMinutes(1), now::get);
    }
    private static AuthenticationService service(AttemptLimiter limit, List<String> verified) {
        return new AuthenticationService(name -> name.equals("alice") ? knownHash
                : name.equals("broken") ? "corrupt record" : null, limit, (password, hash) -> {
            verified.add(hash);
            return PasswordHashes.verify(password, hash);
        }, dummyHash);
    }

    public static void main(String[] args) throws Exception {
        knownHash = PasswordHashes.hash(PASSWORD);
        dummyHash = PasswordHashes.hash("random test-only dummy password".toCharArray());
        test("correct password authenticates against stored KDF", () -> {
            List<String> seen = new ArrayList<>();
            check(service(new AttemptLimiter(), seen).authenticate("alice", PASSWORD));
            check(seen.equals(List.of(knownHash)));
        });
        test("wrong password returns generic false", () -> {
            check(!service(new AttemptLimiter(), new ArrayList<>()).authenticate("alice", "wrong".toCharArray()));
        });
        test("unknown user executes real dummy KDF and cannot log in", () -> {
            List<String> seen = new ArrayList<>();
            check(!service(new AttemptLimiter(), seen).authenticate("unknown", "random test-only dummy password".toCharArray()));
            check(seen.equals(List.of(dummyHash)));
        });
        test("corrupt stored hash fails closed after dummy KDF", () -> {
            List<String> seen = new ArrayList<>();
            check(!service(new AttemptLimiter(), seen).authenticate("broken", PASSWORD));
            check(seen.equals(List.of(dummyHash)));
        });
        test("invalid identifiers rejected before store lookup", () -> {
            AuthenticationService auth = new AuthenticationService(name -> { throw new AssertionError(); },
                    new AttemptLimiter(), PasswordHashes::verify, dummyHash);
            for (String name : new String[]{null, "", " alice", "a".repeat(65), "a@b", "\u0130"}) {
                check(!auth.authenticate(name, PASSWORD));
            }
        });
        test("username canonicalization matches registration policy", () -> {
            check(service(new AttemptLimiter(), new ArrayList<>()).authenticate("ALICE", PASSWORD));
        });
        test("invalid passwords rejected before expensive work", () -> {
            List<String> seen = new ArrayList<>(); AuthenticationService auth = service(new AttemptLimiter(), seen);
            check(!auth.authenticate("alice", null));
            check(!auth.authenticate("alice", new char[0]));
            check(!auth.authenticate("alice", new char[1025])); check(seen.isEmpty());
        });
        test("account limit applies across username case and before KDF", () -> {
            List<String> seen = new ArrayList<>();
            AuthenticationService auth = service(limiter(new AtomicLong(), 2, 100, 100), seen);
            check(!auth.authenticate("alice", "wrong".toCharArray()));
            check(auth.authenticate("ALICE", PASSWORD));
            check(!auth.authenticate("alice", PASSWORD)); check(seen.size() == 2);
        });
        test("account limit expires using controlled monotonic clock", () -> {
            AtomicLong now = new AtomicLong(); AttemptLimiter limit = limiter(now, 1, 10, 10);
            check(limit.allow("alice")); check(!limit.allow("alice"));
            now.set(Duration.ofSeconds(59).toNanos()); check(!limit.allow("alice"));
            now.set(Duration.ofMinutes(1).toNanos()); check(limit.allow("alice"));
        });
        test("global limit caps attempts across distinct usernames", () -> {
            AttemptLimiter limit = limiter(new AtomicLong(), 5, 2, 100);
            check(limit.allow("one")); check(limit.allow("two")); check(!limit.allow("three"));
        });
        test("full limiter fails closed without evicting active counters", () -> {
            AttemptLimiter limit = limiter(new AtomicLong(), 1, 100, 1);
            check(limit.allow("alice")); check(!limit.allow("bob")); check(!limit.allow("alice"));
        });
        test("concurrent requests cannot exceed account limit", () -> {
            AttemptLimiter limit = limiter(new AtomicLong(), 5, 100, 100);
            ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger allowed = new AtomicInteger();
            try {
                List<Future<?>> jobs = new ArrayList<>();
                for (int i = 0; i < 40; i++) jobs.add(pool.submit(() -> {
                    try { start.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
                    if (limit.allow("alice")) allowed.incrementAndGet();
                }));
                start.countDown(); for (Future<?> job : jobs) job.get();
                check(allowed.get() == 5);
            } finally { pool.shutdownNow(); }
        });
        test("public service constructor performs real authentication", () -> {
            AuthenticationService auth = new AuthenticationService(name -> name.equals("alice") ? knownHash : null);
            check(auth.authenticate("alice", PASSWORD));
        });
        System.out.println(passed + " tests passed");
    }
}
