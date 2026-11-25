#!/usr/bin/env python3
"""Loopback benchmark of the actual AeroBox service; Python 3 standard library.

Fresh app processes, alternating baseline/candidate order, one independent origin
and optional sing-box SS server. Timings are advisory, never CI pass/fail limits.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import selectors
import socket
import socketserver
import statistics
import struct
import subprocess
import sys
import threading
import time

PAYLOAD = b"\x5a" * (64 * 1024)


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise RuntimeError(f"truncated payload: {len(result)}/{count} bytes")
        result.extend(part)
    return bytes(result)


def transfer(stream, count, send):
    while count:
        size = min(count, len(PAYLOAD))
        if send:
            stream.sendall(PAYLOAD[:size])
        elif exact(stream, size) != PAYLOAD[:size]:
            raise RuntimeError("payload corruption")
        count -= size


class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class OriginHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        try:
            action, count = struct.unpack("!cQ", exact(self.request, 9))
            if action == b"D":
                transfer(self.request, count, True)
            elif action == b"U":
                transfer(self.request, count, False)
                self.request.sendall(b"OK")
            elif action == b"E":
                for _ in range(count):
                    self.request.sendall(exact(self.request, 64))
            else:
                raise RuntimeError("unknown origin command")
        except (OSError, RuntimeError) as error:
            print(f"origin: {error}", file=sys.stderr, flush=True)


def origin_main():
    with Origin(("127.0.0.1", 0), OriginHandler) as server:
        print(json.dumps({"port": server.server_address[1]}), flush=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        sys.stdin.readline()
        server.shutdown()


def ready(process):
    deadline = time.monotonic() + 20
    buffered = b""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise RuntimeError("benchmark service did not become ready within 20 seconds")
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError(f"benchmark service exited: {process.poll()}")
            buffered += chunk
            if len(buffered) > 16384:
                raise RuntimeError("oversized benchmark startup response")
            while b"\n" in buffered:
                line, buffered = buffered.split(b"\n", 1)
                try:
                    message = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue  # The service may print listener startup messages.
                if isinstance(message, dict) and isinstance(message.get("port"), int):
                    return message


@contextlib.contextmanager
def child(command, log, cpus=None):
    with log.open("x") as output:
        # taskset applies affinity before startup and is used only when requested.
        if cpus:
            command = ["taskset", "-c", cpus, *command]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=output, text=True, bufsize=1)
        try:
            yield process
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write("quit\n")
                    process.stdin.flush()
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            process.stdin.close()
            process.stdout.close()


def counters(pid):
    # Fields after comm: state is index 0, utime/stime are indices 11 and 12.
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    status = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(("VmRSS:", "VmHWM:")):
            key, value, _ = line.split()
            status[key[:-1]] = int(value) * 1024
    return {"cpu_seconds": (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"),
            "rss_bytes": status["VmRSS"], "peak_rss_bytes": status["VmHWM"]}


def connect(proxy_port, origin_port):
    stream = socket.create_connection(("127.0.0.1", proxy_port), timeout=20)
    try:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream.sendall(b"\x05\x01\x00")
        if exact(stream, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS method rejected")
        stream.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", origin_port))
        response = exact(stream, 4)
        if response[:3] != b"\x05\x00\x00":
            raise RuntimeError(f"SOCKS connect rejected: {response.hex()}")
        if response[3] == 1:
            exact(stream, 6)
        elif response[3] == 4:
            exact(stream, 18)
        elif response[3] == 3:
            exact(stream, exact(stream, 1)[0] + 2)
        else:
            raise RuntimeError("invalid SOCKS reply address")
        return stream
    except BaseException:
        stream.close()
        raise


def workload(proxy, origin, name, count):
    durations = []
    began = time.perf_counter()
    if name in ("download", "upload"):
        with connect(proxy, origin) as stream:
            stream.sendall(struct.pack("!cQ", b"D" if name == "download" else b"U", count))
            transfer(stream, count, name == "upload")
            if name == "upload" and exact(stream, 2) != b"OK":
                raise RuntimeError("origin did not acknowledge the upload")
    elif name == "latency":
        with connect(proxy, origin) as stream:
            stream.sendall(struct.pack("!cQ", b"E", count))
            for _ in range(count):
                start = time.perf_counter()
                stream.sendall(PAYLOAD[:64])
                if exact(stream, 64) != PAYLOAD[:64]:
                    raise RuntimeError("echo corruption")
                durations.append((time.perf_counter() - start) * 1000)
    else:
        for _ in range(count):
            start = time.perf_counter()
            with connect(proxy, origin) as stream:
                stream.sendall(struct.pack("!cQ", b"D", 1))
                if exact(stream, 1) != PAYLOAD[:1]:
                    raise RuntimeError("new connection payload mismatch")
            durations.append((time.perf_counter() - start) * 1000)
    result = {"seconds": time.perf_counter() - began, "units": count}
    if durations:
        ordered = sorted(durations)
        result.update(p50_ms=statistics.median(ordered),
                      p99_ms=ordered[math.ceil(len(ordered) * .99) - 1])
    return result


def binary_info(path):
    path = path.resolve(strict=True)
    with path.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    return {"path": str(path), "sha256": digest}


def peer_config(port):
    return {"log": {"level": "error"}, "inbounds": [{"type": "shadowsocks",
            "listen": "127.0.0.1", "listen_port": port, "method": "aes-128-gcm",
            "password": "aerobox-loopback-benchmark"}], "outbounds": [{"type": "direct"}]}


def report(data, path):
    rows = ["# AeroBox network benchmark", "", "Loopback, SOCKS ingress; application service only. "
            "The GTK window, TUN and public network are not measured. CPU excludes the origin and load generator.", "",
            "Status: " + ("complete" if data["completed"] else "INCOMPLETE — do not compare these results"), "",
            "| Build | Protocol | Workload | Samples | Median rate | Median CPU s/unit | Peak RSS MiB |",
            "|---|---|---|---:|---:|---:|---:|"]
    for side in data["binaries"]:
        for case in data["cases"]:
            for name in ("download", "upload", "latency", "connections"):
                samples = [s for s in data["samples"] if (s["side"], s["case"], s["workload"]) == (side, case, name)]
                if not samples:
                    continue
                bulk = name in ("download", "upload")
                divisor = 1024 ** 2 if bulk else 1
                rate = statistics.median(s["units"] / divisor / s["seconds"] for s in samples)
                cpu = statistics.median(s["cpu_seconds"] / (s["units"] / divisor) for s in samples)
                peak = max(s["peak_rss_bytes"] for s in samples) / 1024 ** 2
                unit = "MiB/s" if bulk else "ops/s"
                rows.append(f"| {side} | {case} | {name} | {len(samples)} | {rate:.2f} {unit} | {cpu:.6f} | {peak:.2f} |")
    rows += ["", "CPU unit is MiB for bulk transfers and operation otherwise. Peak RSS is the "
             "process high-water mark; it is cumulative within a round. Raw samples include p50/p99 latency, "
             "idle RSS, binary hashes, affinity and clock resolution. Zero CPU deltas on short samples "
             "mean the measurement was below the process clock resolution, not free work.", "",
             "No significance or speedup claim is made by this report. Use release builds, multiple rounds "
             "and an otherwise idle machine; retain results.json and logs."]
    path.write_text("\n".join(rows) + "\n")


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    binaries = {"candidate": binary_info(args.candidate)}
    if args.baseline:
        binaries["baseline"] = binary_info(args.baseline)
    cases = ["direct"] + (["ss-aes128"] if args.sing_box else [])
    data = {"schema": 1, "platform": platform.platform(), "machine": platform.machine(),
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "load_affinity": sorted(os.sched_getaffinity(0)), "core_cpus": args.core_cpus,
            "server_cpus": args.server_cpus, "rounds": args.rounds, "binaries": binaries,
            "cases": cases, "samples": [], "completed": False,
            "smoke_only": args.smoke, "mib": args.mib, "operations": args.operations}
    try:
        with contextlib.ExitStack() as stack:
            origin = stack.enter_context(child([sys.executable, __file__, "--origin"],
                                               args.output / "origin.log", args.server_cpus))
            origin_port = ready(origin)["port"]
            peer_port = None
            if args.sing_box:
                data["peer"] = binary_info(args.sing_box)
                data["peer"]["version"] = subprocess.check_output([str(args.sing_box.resolve()), "version"],
                                                                  text=True, timeout=10)
                with socket.socket() as reserve:
                    reserve.bind(("127.0.0.1", 0))
                    peer_port = reserve.getsockname()[1]
                config = args.output / "peer.json"
                config.write_text(json.dumps(peer_config(peer_port)))
                peer = stack.enter_context(child([str(args.sing_box.resolve()), "run", "-c", str(config.resolve())],
                                                 args.output / "peer.log", args.server_cpus))
                deadline = time.monotonic() + 10
                while True:
                    if peer.poll() is not None:
                        raise RuntimeError("independent peer exited; see peer.log")
                    try:
                        with socket.create_connection(("127.0.0.1", peer_port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("independent peer did not listen")
                        time.sleep(.02)
            for index in range(args.rounds):
                sides = list(binaries) if index % 2 == 0 else list(reversed(binaries))
                for case in cases:
                    for side in sides:
                        label = f"{index}-{case}-{side}"
                        command = [binaries[side]["path"], case]
                        if case != "direct":
                            command.append(str(peer_port))
                        with child(command, args.output / f"{label}.log", args.core_cpus) as process:
                            hello = ready(process)
                            if hello["debug"] and not args.smoke:
                                raise RuntimeError("benchmark needs a release helper; use --smoke for tool validation")
                            if hello["case"] != case:
                                raise RuntimeError("helper started the wrong protocol")
                            workload(hello["port"], origin_port, "download", 1024 ** 2)
                            idle = counters(process.pid)["rss_bytes"]
                            for name in ("download", "upload", "latency", "connections"):
                                count = args.mib * 1024 ** 2 if name in ("download", "upload") else args.operations
                                before = counters(process.pid)
                                sample = workload(hello["port"], origin_port, name, count)
                                after = counters(process.pid)
                                sample.update(round=index, side=side, case=case, workload=name,
                                              cpu_seconds=after["cpu_seconds"] - before["cpu_seconds"],
                                              rss_bytes=after["rss_bytes"], peak_rss_bytes=after["peak_rss_bytes"],
                                              idle_rss_bytes=idle, debug=hello["debug"],
                                              version=hello.get("version"))
                                data["samples"].append(sample)
                        print(f"completed {label}", flush=True)
            data["completed"] = True
    except BaseException as error:
        data["error"] = str(error)
        raise
    finally:
        (args.output / "results.json").write_text(json.dumps(data, indent=2) + "\n")
        report(data, args.output / "report.md")


def positive(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


if __name__ == "__main__":
    if sys.argv[1:] == ["--origin"]:
        origin_main()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--candidate", required=True, type=Path)
        parser.add_argument("--baseline", type=Path)
        parser.add_argument("--sing-box", type=Path, help="optional independent SS server binary")
        parser.add_argument("--output", required=True, type=Path, help="new result directory")
        parser.add_argument("--rounds", type=positive, default=5)
        parser.add_argument("--mib", type=positive, default=64)
        parser.add_argument("--operations", type=positive, default=500)
        parser.add_argument("--core-cpus", help="taskset CPU list for AeroBox processes")
        parser.add_argument("--server-cpus", help="taskset CPU list for origin and independent server")
        parser.add_argument("--smoke", action="store_true", help="allow debug builds for correctness only")
        run(parser.parse_args())
