# Sample 9: Server-Side Request Forgery — Python URL fetching

**Status:** Corrected fetch helper and 11 passing offline tests.

## Original vulnerable code

```python
url = input("Enter URL: ")
response = requests.get(url)
print(response.text)
```

## Security flaw and real-world impact

The caller chooses the entire destination of a request made by the application. If this runs on a server, an attacker could use that server's network position to reach internal services, loopback addresses, or cloud metadata endpoints. Responses might disclose internal data or credentials. If run only as a local script, the relevant network access is the local machine's, rather than a remote server's.

Checking a URL string once is insufficient when a permitted host redirects elsewhere or its DNS answers change before the connection. The original also has no explicit timeout or response-size limit. See [OWASP A10:2021 SSRF](https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/).

## Corrected code and why it works

[secure_fetch.py](secure_fetch.py) uses a narrow business rule: callers may select a **named, administrator-approved resource**, not supply a URL. The included `example` resource maps to `https://example.com/`. Adding a resource requires a reviewed code/configuration change; the mapping must never be populated from user input.

- The hostname, HTTPS scheme, port 443, path, and request headers come from trusted code. URL tricks, arbitrary ports, user credentials, and caller-controlled proxies are absent.
- Resolve the approved hostname to IPv4 and reject the request if any returned address is not globally routable, or is multicast/reserved. Internal, loopback, link-local, and shared address ranges fail this check.
- Connect directly to the checked numeric IPv4 address without resolving the hostname again. TLS still verifies the certificate for the original hostname, and the HTTP Host header uses that hostname. This closes the DNS check/connect gap.
- Reject redirects and all non-200 responses. The HTTP client never follows a Location header.
- Accept at most 128 KiB, disallow compressed responses, and use a five-second socket timeout. Close connections on success and failure, and return generic network errors.

The destination restriction is the main SSRF control. Address checks, TLS validation, redirect rejection, and resource limits add protection. This follows the allowlist approach in the [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## Scope and assumptions

This standard-library teaching implementation deliberately supports public IPv4 only. IPv6-only destinations are rejected. It is suitable for a small set of approved resources; it does not preserve arbitrary URL fetching. A product requiring arbitrary external URLs needs a separately reviewed design and restricted outbound network access.

The timeout applies to individual socket operations, not a total request deadline, and does not bound the operating system's DNS resolver. A deployed service must also enforce worker/request deadlines, outbound firewall rules, and rate/concurrency limits. Treat fetched content as untrusted data; do not insert it into a web page as executable HTML.

Implementation references: [Python HTTP client](https://docs.python.org/3/library/http.client.html) and [Python IP address classification](https://docs.python.org/3/library/ipaddress.html).

## Verification

From the repository root:

```sh
python -m unittest discover -s samples/09-ssrf-python -p "test_*.py" -v
```

Python 3.14.6: **11 tests passed**. No packages or network connection are required.

The tests cover disallowed resource names/URLs; a fixed approved request; private, loopback, link-local, reserved, and multicast addresses; mixed DNS answers; missing/unsupported DNS results; redirect rejection; compressed/oversized responses; generic network/TLS failures; numeric connection pinning; and preserved hostname certificate-verification settings.

These are offline tests with mocked DNS, sockets, and responses. They verify policy and transport construction, not live DNS, TLS handshakes, or deployed egress controls. For an optional real HTTPS request, run `python samples/09-ssrf-python/secure_fetch.py` and enter `example`.
