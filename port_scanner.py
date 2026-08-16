"""
port_scanner.py

Multithreaded TCP port scanner with banner grabbing. Uses only the
standard library (socket, threading) — no nmap or subprocess calls to
external scanner binaries.

Usage:
    python3 port_scanner.py <target_ip> <start_port> <end_port> [--timeout SECONDS] [--threads N]

Example:
    python3 port_scanner.py 192.168.56.10 1 1024 --timeout 1 --threads 100
"""

import argparse
import socket
import threading
import queue


def scan_port(target: str, port: int, timeout: float, results: list, lock: threading.Lock) -> None:
    """
    Attempt a TCP connection to a single port. On success, try a
    generic banner-grab probe and record (port, state, banner).
    Any failure (closed, filtered, or an OS-level error) is caught so
    a single bad port never crashes the whole scan.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)  # bound how long we wait per port so a filtered/
                               # firewalled port (no response at all) doesn't stall the scan
    banner = ""
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                # Generic probe — many services (SMTP, FTP, some HTTP
                # servers) reply with a banner as soon as any bytes
                # arrive, even a bare CRLF.
                sock.sendall(b"\r\n")
                data = sock.recv(1024)
                # decode with errors="replace" so non-UTF-8 banner
                # bytes (common in raw TCP banners) don't raise and
                # abort the scan — we'd rather show a partially
                # garbled banner than lose the result.
                banner = data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, ConnectionResetError, OSError):
                banner = "(no banner)"

            # The lock prevents a race condition where two scanner
            # threads append to the shared `results` list at the same
            # moment, which could otherwise interleave/corrupt list
            # state since list.append is not guaranteed atomic across
            # all Python implementations under concurrent access.
            with lock:
                results.append((port, "open", banner))
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Closed, filtered, or unreachable — not an error worth
        # reporting, just skip this port.
        pass
    finally:
        sock.close()


def worker(target: str, timeout: float, results: list, lock: threading.Lock, q: "queue.Queue") -> None:
    while True:
        try:
            port = q.get_nowait()
        except queue.Empty:
            return
        scan_port(target, port, timeout, results, lock)
        q.task_done()


def main() -> None:
    parser = argparse.ArgumentParser(description="Multithreaded TCP port scanner with banner grabbing")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("start_port", type=int, help="First port in range")
    parser.add_argument("end_port", type=int, help="Last port in range (inclusive)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port connect timeout in seconds (default 1)")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads (default 100)")
    args = parser.parse_args()

    results: list = []
    lock = threading.Lock()
    q: "queue.Queue" = queue.Queue()
    for port in range(args.start_port, args.end_port + 1):
        q.put(port)

    threads = []
    for _ in range(min(args.threads, args.end_port - args.start_port + 1)):
        t = threading.Thread(target=worker, args=(args.target, args.timeout, results, lock, q))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    results.sort(key=lambda r: r[0])

    print(f"\nScan results for {args.target} (ports {args.start_port}-{args.end_port}):")
    print(f"{'Port':<8}{'State':<8}{'Banner'}")
    print("-" * 50)
    if not results:
        print("(no open ports found)")
    for port, state, banner in results:
        print(f"{port:<8}{state:<8}{banner}")


if __name__ == "__main__":
    main()
