# Network Scanner

A small, pure-Python **host-discovery** network scanner. Given a CIDR range
(e.g. `192.168.1.0/24`) or a single IP address, it concurrently probes each
address for liveness using fast TCP-connect attempts against a small set of
commonly-open ports (default: `80, 443, 22`), with an optional ICMP `ping`
fallback via `subprocess`. For each responsive host it attempts a best-effort
reverse-DNS lookup.

No raw sockets and no root/administrator privileges are required — this
makes it portable and safe to run from an ordinary user account.

This project focuses specifically on **host discovery** (which hosts in a
range are alive) as distinct from per-host **port enumeration** (scanning
all ports on one known-live host), which is a separate concern.

## ⚠️ Authorized use only

This tool is intended **only** for scanning hosts and networks that you own,
operate, or have **explicit written authorization** to test (e.g. your own
home lab, a company network you administer, or a CTF/lab environment set up
for this purpose). Scanning networks you do not own or lack permission to
test may violate computer-crime laws (such as the U.S. Computer Fraud and
Abuse Act) and the acceptable-use policies of most ISPs and cloud providers.
You are solely responsible for ensuring you have authorization before
scanning any network. All examples and tests in this repository only ever
target `127.0.0.0/8` (loopback) and RFC1918 private address space.

## How it works

1. **Enumerate** — `ipaddress.ip_network(...).hosts()` expands the given
   CIDR block (or a single IP) into a list of host addresses.
2. **Probe concurrently** — a `ThreadPoolExecutor` fans out TCP-connect
   attempts (`socket.connect_ex`) to each host on the configured ports, with
   a short per-probe timeout. A host is "live" as soon as any probed port
   accepts a connection.
3. **ICMP fallback (optional)** — if no TCP port responds and a `ping`
   binary is available on `PATH`, a single best-effort ICMP ping is
   attempted via `subprocess`. If `ping` is missing, blocked, or errors, the
   scanner falls back to TCP-connect-only results without failing.
4. **Reverse DNS (best-effort)** — for each live host, `socket.gethostbyaddr`
   is attempted. Any failure (NXDOMAIN, timeout, etc.) is caught and simply
   leaves the hostname unresolved — it never aborts the scan.

## Usage

```bash
# Scan a small CIDR block on the default ports (80, 443, 22)
python scanner.py 192.168.1.0/24

# Scan a single host
python scanner.py 127.0.0.1

# Custom ports, timeout, and worker count
python scanner.py 10.0.0.0/28 --ports 22,80,443,8080 --timeout 0.75 --workers 32

# Disable the ICMP fallback (TCP-connect only)
python scanner.py 192.168.1.0/28 --no-icmp

# Skip reverse-DNS lookups (faster)
python scanner.py 192.168.1.0/28 --no-resolve

# Show every probed host, not just the live ones
python scanner.py 127.0.0.0/30 --ports 80,443,22 --all
```

### CLI options

| Flag | Description | Default |
|---|---|---|
| `target` | Single IP or CIDR block, e.g. `192.168.1.0/24` | required |
| `--ports` | Comma-separated TCP ports to probe | `80,443,22` |
| `--timeout` | Per-probe timeout in seconds | `0.5` |
| `--workers` | Max concurrent worker threads | `64` |
| `--no-icmp` | Disable ICMP ping fallback | off |
| `--no-resolve` | Skip reverse-DNS lookups | off |
| `--all` | Print every probed host, not just live ones | off |

### Example output

```
$ python scanner.py 127.0.0.0/30 --ports 80,443,22
Scanning 127.0.0.0/30 (2 host(s), ports=[80, 443, 22])...

  [UP  ] 127.0.0.1        hostname=localhost                       via=22

1/2 host(s) alive. Scan completed in 0.06s.
```

## Library usage

`scanner.py` is also usable as a library:

```python
from scanner import scan

results = scan("192.168.1.0/28", ports=[22, 80, 443], timeout=0.5)
for r in results:
    if r.alive:
        print(r.ip, r.hostname, r.open_ports)
```

## Running the tests

```bash
python -m pytest tests/ -v
# or
python -m unittest discover -s tests -v
```

Tests spin up real TCP listener sockets on ephemeral loopback ports
(`127.0.0.1:0`) within the test process — no external network access is
required or performed, and all sockets are closed after each test.

## Requirements

Python 3.11+ recommended (tested on 3.11 and 3.12). Pure standard library —
no third-party dependencies for the scanner itself (`pytest` is only used
optionally to run the tests; `unittest`, part of the standard library, works
too).

## License

MIT — see [LICENSE](LICENSE).
