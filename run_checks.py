"""Run all ten samples and the login demo. Requires Python, Node, JDK 17+."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent


def run(label, command):
    print(f"\n{label}", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    missing = [name for name in ("node", "java", "javac") if shutil.which(name) is None]
    missing += [name for name in ("flask", "flask_login", "sqlalchemy")
                if importlib.util.find_spec(name) is None]
    if missing:
        raise SystemExit("Missing prerequisites: " + ", ".join(missing)
                         + ". See README.md setup instructions.")

    run("JavaScript samples 1, 6, and 8", [
        "node", "--test",
        "samples/01-broken-access-control-javascript/secure-profile.test.cjs",
        "samples/06-nosql-injection-javascript/secure-user.test.mjs",
        "samples/08-script-integrity-html/integrity.test.mjs",
    ])
    for folder in ("02-broken-access-control-python", "04-password-hashing-python",
                   "07-password-reset-python", "09-ssrf-python"):
        run(f"Python sample {folder[:2]}", [
            sys.executable, "-m", "unittest", "discover", "-s", f"samples/{folder}",
            "-p", "test_*.py", "-v",
        ])

    sources = sorted(str(path) for path in (ROOT / "shared" / "java").glob("*.java"))
    for folder in ("03-password-hashing-java", "05-sql-injection-java", "10-authentication-java"):
        sources.extend(str(path) for path in sorted((ROOT / "samples" / folder).glob("*.java")))
    with tempfile.TemporaryDirectory(prefix="owasp-java-") as build:
        run("Compile Java samples 3, 5, and 10", ["javac", "-encoding", "UTF-8", "-Xlint:all", "-d", build, *sources])
        for test_class in ("owasp.sample03.PasswordStorageTest", "owasp.sample05.UserLookupTest",
                           "owasp.sample10.AuthenticationTest"):
            run(test_class, ["java", "-cp", build, test_class])

    run("Working login application", [
        sys.executable, "-m", "unittest", "discover", "-s", "demo-app", "-p", "test_*.py", "-v",
    ])
    print("\nAll ten sample suites and the login application passed.", flush=True)


if __name__ == "__main__":
    main()
