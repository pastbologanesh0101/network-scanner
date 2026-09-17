#!/usr/bin/env python3
"""
Network Scanner — CIDR host-discovery tool.

Discovers which hosts in a CIDR range (or an explicit host list) are alive,
using concurrent TCP-connect probes to a small set of commonly-open ports as
a liveness signal, with an optional subprocess-based ICMP ping fallback.
No raw sockets and no root privileges are required.

AUTHORIZED USE ONLY: only scan hosts and networks that you own or that you
have explicit permission to test. Unauthorized network scanning may violate
computer-crime laws (e.g. the U.S. CFAA) and the acceptable-use policies of
most networks and cloud providers.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Union

DEFAULT_PORTS = (80, 443, 22)
DEFAULT_TIMEOUT = 0.5  # seconds, per-probe
DEFAULT_MAX_WORKERS = 64


@dataclass
class HostResult:
    """Result of probing a single host."""

    ip: str
    alive: bool
    open_ports: List[int] = field(default_factory=list)
    hostname: Optional[str] = None
    method: Optional[str] = None  # "tcp" or "icmp"
    elapsed: float = 0.0


def enumerate_hosts(target: str) -> List[str]:
    """
    Turn a target spec into a list of IP address strings.

    `target` may be:
      - a single IP address ("192.168.1.5")
      - a CIDR block ("192.168.1.0/30")

    For CIDR blocks, uses ipaddress.ip_network(..., strict=False) and returns
    the usable hosts (ip_network.hosts()). For very small networks (/31, /32)
    where .hosts() would be empty, falls back to all addresses in the network.
    """
    target = target.strip()
    try:
        # Single address (no slash, or a /32 host)
        if "/" not in target:
            ip = ipaddress.ip_address(target)
            return [str(ip)]
    except ValueError:
        pass

    network = ipaddress.ip_network(target, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        # /31 or /32 networks: .hosts() may be empty; use all addresses.
        hosts = [str(ip) for ip in network]
    return hosts


def tcp_probe(ip: str, ports: Sequence[int], timeout: float = DEFAULT_TIMEOUT) -> Optional[int]:
    """
    Attempt a TCP connect to each port in `ports` in order.

    Returns the first port that accepted a connection, or None if none did.
    """
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
        except (socket.timeout, OSError):
            continue
        finally:
            sock.close()
    return None


def tcp_probe_all(ip: str, ports: Sequence[int], timeout: float = DEFAULT_TIMEOUT) -> List[int]:
    """Return the list of all probed ports found open on `ip`."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
    return open_ports


def ping_available() -> bool:
    """Best-effort check for a usable `ping` binary on PATH."""
    return shutil.which("ping") is not None


def icmp_probe(ip: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """
    Best-effort ICMP liveness check via the system `ping` command.

    Returns False (never raises) if `ping` is unavailable, times out, is
    blocked, or otherwise fails — callers should treat this purely as an
    optional fallback signal, not a hard requirement.
    """
    if not ping_available():
        return False

    timeout_s = max(1, int(round(timeout)) or 1)
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000) or 1), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + 1,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def reverse_dns(ip: str) -> Optional[str]:
    """
    Best-effort reverse DNS lookup. Never raises — returns None on any
    failure (NXDOMAIN, timeout, herror, gaierror, etc.).
    """
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


def probe_host(
    ip: str,
    ports: Sequence[int] = DEFAULT_PORTS,
    timeout: float = DEFAULT_TIMEOUT,
    use_icmp_fallback: bool = True,
    resolve_hostnames: bool = True,
) -> HostResult:
    """Probe a single host for liveness and return a HostResult."""
    start = time.monotonic()
    open_ports = tcp_probe_all(ip, ports, timeout=timeout)
    alive = bool(open_ports)
    method = "tcp" if alive else None

    if not alive and use_icmp_fallback:
        if icmp_probe(ip, timeout=timeout):
            alive = True
            method = "icmp"

    elapsed = time.monotonic() - start

    hostname = None
    if alive and resolve_hostnames:
        hostname = reverse_dns(ip)

    return HostResult(
        ip=ip,
        alive=alive,
        open_ports=open_ports,
        hostname=hostname,
        method=method,
        elapsed=elapsed,
    )


def scan(
    target: Union[str, Iterable[str]],
    ports: Sequence[int] = DEFAULT_PORTS,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    use_icmp_fallback: bool = True,
    resolve_hostnames: bool = True,
) -> List[HostResult]:
    """
    Scan a CIDR range, single IP, or explicit iterable of hosts.

    Probes are run concurrently in a thread pool. Returns a list of
    HostResult in the same order as the enumerated hosts.
    """
    if isinstance(target, str):
        hosts = enumerate_hosts(target)
    else:
        hosts = list(target)

    if not hosts:
        return []

    results: List[Optional[HostResult]] = [None] * len(hosts)
    workers = max(1, min(max_workers, len(hosts)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {
            pool.submit(
                probe_host,
                ip,
                ports,
                timeout,
                use_icmp_fallback,
                resolve_hostnames,
            ): idx
            for idx, ip in enumerate(hosts)
        }
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            results[idx] = future.result()

    return results  # type: ignore[return-value]


def _parse_ports(spec: str) -> List[int]:
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        ports.append(int(part))
    if not ports:
        raise ValueError("no ports specified")
    return ports


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "Network Scanner: CIDR host-discovery tool. Discovers live hosts "
            "via concurrent TCP-connect probes (plus optional ICMP ping "
            "fallback). AUTHORIZED USE ONLY — only scan hosts/networks you "
            "own or are explicitly permitted to test."
        ),
    )
    parser.add_argument(
        "target",
        help="Single IP address or CIDR block to scan, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help=f"Comma-separated TCP ports to probe (default: {','.join(str(p) for p in DEFAULT_PORTS)})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-probe timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"Max concurrent worker threads (default: {DEFAULT_MAX_WORKERS})",
    )
    parser.add_argument(
        "--no-icmp",
        action="store_true",
        help="Disable ICMP ping fallback; use TCP-connect probes only",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip reverse-DNS lookups for discovered hosts",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Print every probed host, not just the live ones",
    )
    args = parser.parse_args(argv)

    try:
        ports = _parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    start = time.monotonic()
    results = scan(
        args.target,
        ports=ports,
        timeout=args.timeout,
        max_workers=args.workers,
        use_icmp_fallback=not args.no_icmp,
        resolve_hostnames=not args.no_resolve,
    )
    duration = time.monotonic() - start

    live = [r for r in results if r.alive]
    print(f"Scanning {args.target} ({len(results)} host(s), ports={ports})...\n")

    to_print = results if args.all else live
    for r in to_print:
        status = "UP  " if r.alive else "down"
        hostname = r.hostname or "-"
        if r.alive:
            ports_str = ",".join(str(p) for p in r.open_ports) if r.open_ports else r.method or "-"
            print(f"  [{status}] {r.ip:<15}  hostname={hostname:<30}  via={ports_str}")
        elif args.all:
            print(f"  [{status}] {r.ip:<15}  hostname={hostname:<30}")

    print(f"\n{len(live)}/{len(results)} host(s) alive. Scan completed in {duration:.2f}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
