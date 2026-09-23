"""Fetch a named, approved resource rather than a caller-supplied URL.

This teaching example intentionally supports only public IPv4 destinations.
The destination mapping is trusted application configuration, never user input.
"""

import http.client
import ipaddress
import socket
import ssl
from types import MappingProxyType


APPROVED_RESOURCES = MappingProxyType({"example": ("example.com", "/")})
MAX_RESPONSE_BYTES = 128 * 1024
SOCKET_TIMEOUT_SECONDS = 5


class FetchRejected(ValueError):
    """The resource or response does not satisfy the fetch policy."""


def _public_ipv4(address):
    try:
        parsed = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError:
        return False
    return parsed.is_global and not parsed.is_multicast and not parsed.is_reserved


def _resolve_public_ipv4(hostname):
    answers = socket.getaddrinfo(
        hostname, 443, family=socket.AF_INET,
        type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
    )
    addresses = []
    for family, _, _, _, endpoint in answers:
        address = endpoint[0]
        if family != socket.AF_INET or not _public_ipv4(address):
            raise FetchRejected("Destination is not an approved public address.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise FetchRejected("No supported public address found.")
    return addresses[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the checked numeric address while authenticating the hostname."""

    def __init__(self, hostname, address):
        if not _public_ipv4(address):
            raise FetchRejected("Destination is not an approved public address.")
        self._approved_address = address
        self._verified_tls_context = ssl.create_default_context()
        super().__init__(hostname, port=443, timeout=SOCKET_TIMEOUT_SECONDS,
                         context=self._verified_tls_context)

    def connect(self):
        # A numeric AF_INET connect prevents a second DNS lookup/rebinding.
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw_socket.settimeout(self.timeout)
            raw_socket.connect((self._approved_address, 443))
            self.sock = self._verified_tls_context.wrap_socket(
                raw_socket, server_hostname=self.host,
            )
        except Exception:
            raw_socket.close()
            raise


def fetch_resource(resource_name):
    """Return up to 128 KiB of UTF-8 text from a fixed approved HTTPS resource."""
    if not isinstance(resource_name, str) or resource_name not in APPROVED_RESOURCES:
        raise FetchRejected("Choose an approved resource name.")

    hostname, path = APPROVED_RESOURCES[resource_name]
    connection = None
    try:
        address = _resolve_public_ipv4(hostname)
        connection = _PinnedHTTPSConnection(hostname, address)
        # No caller-controlled URL, headers, cookies, credentials, or proxy.
        connection.request("GET", path, headers={
            "Accept": "text/plain, text/html", "Accept-Encoding": "identity",
        })
        response = connection.getresponse()
        # http.client does not automatically follow redirects; reject all 3xx.
        if response.status != 200:
            raise FetchRejected("Remote response was not accepted.")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise FetchRejected("Compressed responses are not accepted.")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise FetchRejected("Remote response exceeded the size limit.")
        return payload.decode("utf-8", errors="replace")
    except (OSError, http.client.HTTPException):
        raise FetchRejected("Unable to retrieve the approved resource.") from None
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    name = input("Choose an approved resource (example): ")
    try:
        print(fetch_resource(name))
    except FetchRejected as error:
        print(str(error))
