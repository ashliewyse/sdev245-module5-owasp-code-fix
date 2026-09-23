package owasp.sample10;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/** Bounded, synchronized limits for one application process, using monotonic time. */
public final class AttemptLimiter {
    private final int perAccountLimit, globalLimit, capacity;
    private final long windowNanos;
    private final LongSupplier ticker;
    private final Map<String, Window> accounts = new HashMap<>();
    private Window global;

    public AttemptLimiter() {
        this(5, 100, 10_000, Duration.ofMinutes(1), System::nanoTime);
    }

    AttemptLimiter(int perAccountLimit, int globalLimit, int capacity,
                   Duration duration, LongSupplier ticker) {
        if (perAccountLimit < 1 || globalLimit < 1 || capacity < 1
                || duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException("Limits and duration must be positive");
        }
        this.perAccountLimit = perAccountLimit;
        this.globalLimit = globalLimit;
        this.capacity = capacity;
        this.windowNanos = duration.toNanos();
        this.ticker = java.util.Objects.requireNonNull(ticker);
    }

    /** Count every admitted attempt, including successes; never evict active limits. */
    public synchronized boolean allow(String canonicalUsername) {
        java.util.Objects.requireNonNull(canonicalUsername);
        long now = ticker.getAsLong();
        accounts.entrySet().removeIf(entry -> now - entry.getValue().started >= windowNanos);
        if (global == null || now - global.started >= windowNanos) global = new Window(now);
        if (global.used >= globalLimit) return false;
        Window account = accounts.get(canonicalUsername);
        if (account == null) {
            if (accounts.size() >= capacity) return false;
            account = new Window(now);
            accounts.put(canonicalUsername, account);
        }
        if (account.used >= perAccountLimit) return false;
        account.used++;
        global.used++;
        return true;
    }

    private static final class Window {
        final long started;
        int used;
        Window(long started) { this.started = started; }
    }
}
