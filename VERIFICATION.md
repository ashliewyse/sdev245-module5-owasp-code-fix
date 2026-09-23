# Verification record

Verified September 23, 2026 by running `run_checks.py` from the repository root.

**Result: all ten sample suites passed; 120 named tests; no Java compiler warnings.**

## Environment

- Python 3.14.6
- Node.js 24.18.0
- OpenJDK / javac 17.0.19
- Flask 3.1.3, Flask-Login 0.6.3, SQLAlchemy 2.0.54
- Windows; Python dependencies installed in an isolated virtual environment

## Results and evidence scope

| Sample | Passing tests | What was exercised |
| --- | ---: | --- |
| 1 | 9 | Real handler with stub requests, responses, and database |
| 2 | 11 | Flask/Flask-Login route with in-memory SQLite and test sessions |
| 3 | 14 | Actual PBKDF2 hashing/verification, record parsing, input boundaries |
| 4 | 9 | Actual scrypt hashing/verification, salt and record validation |
| 5 | 10 | JDBC parameter binding and resource cleanup using API-contract doubles |
| 6 | 18 | Real handler with MongoDB collection stub, query/operator/auth boundaries |
| 7 | 20 | Flask routes, temporary SQLite, atomic token consumption, replay, expiry, concurrency, rollback |
| 8 | 5 | Actual pinned file hash, byte tampering, HTML markup, Node execution of harmless library |
| 9 | 11 | Offline DNS/HTTP/socket/TLS construction and fetch-policy tests |
| 10 | 13 | Actual password verification plus deterministic and concurrent attempt-limiter checks |
| **Total** | **120** | |

## Reproduce

Install the prerequisites and Python requirements as described in [README.md](README.md), then run:

```sh
python run_checks.py
```

Each sample README also includes an independent command. The runner uses the current Python interpreter, compiles Java into an automatically removed temporary directory, and exits with failure if any suite fails.

## What these results do not establish

These are tested educational components. They are not evidence of a deployed application's overall security. Samples relying on authenticated identities still require correctly configured login/session systems. The JDBC and MongoDB examples have not been exercised against production databases. Reset delivery, an asynchronous queue, shared throttling, and session-epoch enforcement require application adapters. The SSRF tests do not contact the network. The integrity checks do not run in a browser; manual SRI steps are documented in Sample 8.

The original assignment's placeholder CDN is represented by an included harmless demonstration library with a real digest. The Python reset example copies the Sample 4 password helper so it can run independently. Neither compiled classes, local virtual environments, test databases, nor intermediate review notes belong in the repository.
