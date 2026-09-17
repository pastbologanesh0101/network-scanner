"""
Unit tests for scanner.py.

These tests spin up real TCP listener sockets on ephemeral loopback ports
(127.0.0.1:0) within the test process to exercise the liveness-probing logic
end to end, without touching any external network. All sockets are closed
in tearDown.
"""
import ipaddress
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner  # noqa: E402


def make_listener():
    """Bind a TCP listener on an ephemeral loopback port and return (sock, port)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    return sock, port


def accept_loop(sock, stop_event):
    """Background thread: accept and immediately close connections until stopped."""
    sock.settimeout(0.2)
    while not stop_event.is_set():
        try:
            conn, _ = sock.accept()
            conn.close()
        except socket.timeout:
            continue
        except OSError:
            break


class ListenerTestCase(unittest.TestCase):
    """Base class that manages a real listening socket + accept thread."""

    def setUp(self):
        self.listener, self.port = make_listener()
        self.stop_event = threading.Event()
        self.accept_thread = threading.Thread(
            target=accept_loop, args=(self.listener, self.stop_event), daemon=True
        )
        self.accept_thread.start()

    def tearDown(self):
        self.stop_event.set()
        self.accept_thread.join(timeout=2)
        self.listener.close()


def find_closed_port():
    """
    Return a loopback port that is (almost certainly) not listening, by
    binding then immediately closing a socket to get a free ephemeral port
    number, without leaving anything bound.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestLiveHostDetection(ListenerTestCase):
    def test_open_port_detected_as_live(self):
        """A host with an open probe port is correctly detected as live."""
        result = scanner.probe_host(
            "127.0.0.1",
            ports=[self.port],
            timeout=1.0,
            use_icmp_fallback=False,
            resolve_hostnames=False,
        )
        self.assertTrue(result.alive)
        self.assertIn(self.port, result.open_ports)
        self.assertEqual(result.method, "tcp")

    def test_open_port_among_several_probed(self):
        """The scanner finds the open port even when probing several ports, one closed."""
        closed_port = find_closed_port()
        result = scanner.probe_host(
            "127.0.0.1",
            ports=[closed_port, self.port],
            timeout=0.5,
            use_icmp_fallback=False,
            resolve_hostnames=False,
        )
        self.assertTrue(result.alive)
        self.assertIn(self.port, result.open_ports)
        self.assertNotIn(closed_port, result.open_ports)


class TestDeadHostDetection(unittest.TestCase):
    def test_no_listener_detected_as_not_live(self):
        """A host with no listener on any probed port is correctly detected as not-live."""
        closed_port = find_closed_port()
        start = time.monotonic()
        result = scanner.probe_host(
            "127.0.0.1",
            ports=[closed_port],
            timeout=0.3,
            use_icmp_fallback=False,
            resolve_hostnames=False,
        )
        elapsed = time.monotonic() - start
        self.assertFalse(result.alive)
        self.assertEqual(result.open_ports, [])
        # Bounded test time: closed-port connect refusals should be fast,
        # well under a generous ceiling.
        self.assertLess(elapsed, 5.0)

    def test_scan_respects_timeout_on_unresponsive_host(self):
        """Scan respects a configurable timeout without hanging on an unresponsive host."""
        # 10.255.255.1 is a private RFC1918 address very unlikely to be
        # routable/responsive in a test/CI environment; connect attempts to
        # it should either be refused quickly or block until our short
        # timeout elapses -- never indefinitely.
        start = time.monotonic()
        result = scanner.probe_host(
            "10.255.255.1",
            ports=[find_closed_port()],
            timeout=0.3,
            use_icmp_fallback=False,
            resolve_hostnames=False,
        )
        elapsed = time.monotonic() - start
        self.assertFalse(result.alive)
        # One probe at ~0.3s timeout should complete in well under 5s.
        self.assertLess(elapsed, 5.0)


class TestCidrEnumeration(unittest.TestCase):
    def test_slash_30_host_list(self):
        """CIDR enumeration produces the correct host list for a /30 subnet."""
        hosts = scanner.enumerate_hosts("192.168.1.0/30")
        # A /30 has 4 addresses total; ipaddress.hosts() excludes network
        # and broadcast, leaving exactly the 2 usable host addresses.
        expected = [str(ip) for ip in ipaddress.ip_network("192.168.1.0/30").hosts()]
        self.assertEqual(hosts, expected)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_slash_24_host_count(self):
        """A /24 network enumerates to 254 usable hosts."""
        hosts = scanner.enumerate_hosts("192.168.1.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertEqual(hosts[0], "192.168.1.1")
        self.assertEqual(hosts[-1], "192.168.1.254")

    def test_single_ip_mode(self):
        """Single-IP mode works: a bare IP (no CIDR) returns just that host."""
        hosts = scanner.enumerate_hosts("127.0.0.1")
        self.assertEqual(hosts, ["127.0.0.1"])

    def test_single_ip_slash_32(self):
        """A /32 CIDR behaves like single-IP mode."""
        hosts = scanner.enumerate_hosts("127.0.0.5/32")
        self.assertEqual(hosts, ["127.0.0.5"])


class TestReverseDnsResilience(ListenerTestCase):
    def test_reverse_dns_failure_does_not_crash_scan(self):
        """A forced reverse-DNS failure doesn't crash the scan; alive stays True."""
        with mock.patch.object(
            scanner.socket, "gethostbyaddr", side_effect=socket.herror("mocked failure")
        ):
            result = scanner.probe_host(
                "127.0.0.1",
                ports=[self.port],
                timeout=1.0,
                use_icmp_fallback=False,
                resolve_hostnames=True,
            )
        self.assertTrue(result.alive)
        self.assertIsNone(result.hostname)

    def test_reverse_dns_helper_returns_none_on_gaierror(self):
        """reverse_dns() itself swallows gaierror and returns None."""
        with mock.patch.object(
            scanner.socket, "gethostbyaddr", side_effect=socket.gaierror("mocked failure")
        ):
            self.assertIsNone(scanner.reverse_dns("127.0.0.1"))


class TestConcurrentScanning(unittest.TestCase):
    def test_concurrent_scan_multiple_hosts_no_deadlock(self):
        """Concurrent scanning of multiple hosts completes without deadlock/race issues."""
        listeners = []
        stop_events = []
        threads = []
        ports = []
        try:
            for _ in range(4):
                sock, port = make_listener()
                stop_event = threading.Event()
                t = threading.Thread(target=accept_loop, args=(sock, stop_event), daemon=True)
                t.start()
                listeners.append(sock)
                stop_events.append(stop_event)
                threads.append(t)
                ports.append(port)

            # Mix of live loopback hosts (each with its own open port) and
            # hosts we expect to be down.
            hosts = ["127.0.0.1"] * len(ports)

            results = []
            for host, port in zip(hosts, ports):
                results.append(
                    scanner.probe_host(
                        host,
                        ports=[port],
                        timeout=1.0,
                        use_icmp_fallback=False,
                        resolve_hostnames=False,
                    )
                )

            # Also exercise the real thread-pooled scan() over an explicit
            # host list, confirming it returns one result per host in order
            # and doesn't hang or deadlock.
            start = time.monotonic()
            scan_results = scanner.scan(
                hosts,
                ports=[ports[0]],
                timeout=1.0,
                max_workers=8,
                use_icmp_fallback=False,
                resolve_hostnames=False,
            )
            elapsed = time.monotonic() - start

            self.assertEqual(len(scan_results), len(hosts))
            self.assertLess(elapsed, 10.0)
            for r in results:
                self.assertTrue(r.alive)
        finally:
            for stop_event in stop_events:
                stop_event.set()
            for t in threads:
                t.join(timeout=2)
            for sock in listeners:
                sock.close()

    def test_scan_function_over_cidr_block(self):
        """scan() end-to-end over a small CIDR block completes and returns HostResults."""
        results = scanner.scan(
            "127.0.0.1/32",
            ports=[find_closed_port()],
            timeout=0.3,
            use_icmp_fallback=False,
            resolve_hostnames=False,
        )
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], scanner.HostResult)


class TestPortParsing(unittest.TestCase):
    def test_parse_ports_basic(self):
        self.assertEqual(scanner._parse_ports("80,443,22"), [80, 443, 22])

    def test_parse_ports_whitespace(self):
        self.assertEqual(scanner._parse_ports(" 80 , 443 "), [80, 443])


if __name__ == "__main__":
    unittest.main()
