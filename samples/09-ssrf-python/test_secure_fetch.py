"""Offline SSRF policy and transport-construction tests; no network requests."""

import socket
import ssl
import unittest
from unittest.mock import Mock, patch

from secure_fetch import (
    FetchRejected, MAX_RESPONSE_BYTES, _PinnedHTTPSConnection,
    _resolve_public_ipv4, fetch_resource,
)


PUBLIC_IP = "93.184.215.14"


def dns_answer(address, family=socket.AF_INET):
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.dns_patch = patch("secure_fetch.socket.getaddrinfo")
        self.dns = self.dns_patch.start()
        self.dns.return_value = [dns_answer(PUBLIC_IP)]
        self.addCleanup(self.dns_patch.stop)
        self.conn_patch = patch("secure_fetch._PinnedHTTPSConnection")
        self.factory = self.conn_patch.start()
        self.addCleanup(self.conn_patch.stop)
        self.connection = self.factory.return_value
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.getheader.return_value = "identity"
        self.response.read.return_value = b"Approved content"

    def test_only_known_resource_names_are_accepted(self):
        for name in (None, [], "", "unknown", "http://127.0.0.1/", "example/../admin",
                     "https://example.com@127.0.0.1/", "file:///etc/passwd",
                     "http://169.254.169.254/", "http://[::1]/"):
            with self.subTest(name=name), self.assertRaises(FetchRejected):
                fetch_resource(name)
        self.dns.assert_not_called()
        self.factory.assert_not_called()

    def test_approved_resource_uses_fixed_host_path_and_pinned_address(self):
        self.assertEqual(fetch_resource("example"), "Approved content")
        self.factory.assert_called_once_with("example.com", PUBLIC_IP)
        self.connection.request.assert_called_once_with("GET", "/", headers={
            "Accept": "text/plain, text/html", "Accept-Encoding": "identity",
        })
        self.response.read.assert_called_once_with(MAX_RESPONSE_BYTES + 1)
        self.connection.close.assert_called_once()
        self.dns.assert_called_once_with(
            "example.com", 443, family=socket.AF_INET,
            type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )

    def test_private_loopback_link_local_reserved_and_multicast_are_blocked(self):
        for address in ("127.0.0.1", "10.1.2.3", "172.16.1.1", "192.168.1.1",
                        "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
                        "240.0.0.1", "192.0.2.1", "::1"):
            self.dns.return_value = [dns_answer(address)]
            with self.subTest(address=address), self.assertRaises(FetchRejected):
                fetch_resource("example")
        self.factory.assert_not_called()

    def test_mixed_public_private_dns_answer_is_rejected(self):
        self.dns.return_value = [dns_answer(PUBLIC_IP), dns_answer("127.0.0.1")]
        with self.assertRaises(FetchRejected):
            fetch_resource("example")
        self.factory.assert_not_called()

    def test_empty_and_unsupported_dns_answers_are_rejected(self):
        for answers in ([], [dns_answer("2606:4700:4700::1111", socket.AF_INET6)]):
            self.dns.return_value = answers
            with self.assertRaises(FetchRejected):
                _resolve_public_ipv4("example.com")

    def test_redirects_and_error_responses_are_not_followed(self):
        for status in (301, 302, 307, 308, 404, 500):
            self.response.status = status
            with self.subTest(status=status), self.assertRaises(FetchRejected):
                fetch_resource("example")
        self.assertEqual(self.factory.call_count, 6)
        self.response.read.assert_not_called()
        self.assertEqual(self.connection.close.call_count, 6)

    def test_body_limit_and_compression_are_enforced(self):
        self.response.read.return_value = b"a" * (MAX_RESPONSE_BYTES + 1)
        with self.assertRaises(FetchRejected):
            fetch_resource("example")
        self.response.read.reset_mock()
        self.response.getheader.return_value = "gzip"
        with self.assertRaises(FetchRejected):
            fetch_resource("example")
        self.response.read.assert_not_called()

    def test_network_and_tls_errors_are_generic_and_connections_close(self):
        for error in (TimeoutError("internal timeout details"),
                      ssl.SSLCertVerificationError("private certificate details")):
            self.connection.request.side_effect = error
            with self.assertRaisesRegex(FetchRejected, "^Unable to retrieve"):
                fetch_resource("example")
        self.assertEqual(self.connection.close.call_count, 2)

    def test_dns_errors_do_not_open_connection(self):
        self.dns.side_effect = socket.gaierror("internal resolver detail")
        with self.assertRaisesRegex(FetchRejected, "^Unable to retrieve"):
            fetch_resource("example")
        self.factory.assert_not_called()


class PinnedTransportTests(unittest.TestCase):
    def test_numeric_connection_preserves_hostname_certificate_verification(self):
        with patch("secure_fetch.socket.socket") as socket_factory:
            connection = _PinnedHTTPSConnection("example.com", PUBLIC_IP)
            context = connection._verified_tls_context
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            with patch.object(context, "wrap_socket", return_value=Mock()) as wrap:
                connection.connect()
                socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
                socket_factory.return_value.connect.assert_called_once_with((PUBLIC_IP, 443))
                socket_factory.return_value.settimeout.assert_called_once_with(5)
                wrap.assert_called_once_with(socket_factory.return_value,
                                             server_hostname="example.com")
                connection.close()

    def test_transport_rechecks_address_and_closes_socket_on_tls_failure(self):
        with self.assertRaises(FetchRejected):
            _PinnedHTTPSConnection("example.com", "127.0.0.1")
        connection = _PinnedHTTPSConnection("example.com", PUBLIC_IP)
        with patch("secure_fetch.socket.socket") as socket_factory:
            with patch.object(connection._verified_tls_context, "wrap_socket",
                              side_effect=ssl.SSLError("TLS failed")):
                with self.assertRaises(ssl.SSLError):
                    connection.connect()
                socket_factory.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
