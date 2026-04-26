#!/usr/bin/env python3
"""
Localhost microbenchmarks for the VAULTTLS artifact.

This script measures:
  - registration latency,
  - login/handshake latency,
  - encrypted application round-trip latency,
  - approximate application throughput after key establishment.

It uses the real socket protocol against a background server subprocess.
The database files are backed up and restored automatically so the benchmark
leaves the repository state unchanged.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from client import client_login
from codec import decode_app_data, encode_app_data, encode_close
from config import HOST, PORT, SERVER_STATE_PATH, USERS_DB_PATH
from opaque_adapter import ConcreteOpaqueClient
from record import CT_APP_DATA, DirectionState
from register_user import register
from transcript import recv_frame, send_frame


def _summary(values: list[float]) -> dict:
    values = list(values)
    values.sort()
    if not values:
        return {
            "count": 0,
            "mean_ms": None,
            "stdev_ms": None,
            "min_ms": None,
            "median_ms": None,
            "p95_ms": None,
            "max_ms": None,
        }

    def q(p: float) -> float:
        if len(values) == 1:
            return values[0]
        idx = min(len(values) - 1, max(0, math.ceil(p * len(values)) - 1))
        return values[idx]

    return {
        "count": len(values),
        "mean_ms": 1000.0 * statistics.mean(values),
        "stdev_ms": 1000.0 * (statistics.pstdev(values) if len(values) > 1 else 0.0),
        "min_ms": 1000.0 * values[0],
        "median_ms": 1000.0 * statistics.median(values),
        "p95_ms": 1000.0 * q(0.95),
        "max_ms": 1000.0 * values[-1],
    }


@contextmanager
def _preserve_db_state():
    paths = [Path(USERS_DB_PATH), Path(SERVER_STATE_PATH)]
    backup_dir = Path(tempfile.mkdtemp(prefix="vaulttls_bench_backup_"))
    saved: list[tuple[Path, Path | None]] = []
    try:
        for path in paths:
            if path.exists():
                dst = backup_dir / path.name
                shutil.copy2(path, dst)
                saved.append((path, dst))
            else:
                saved.append((path, None))
        yield
    finally:
        for path, src in saved:
            if src is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, path)
        shutil.rmtree(backup_dir, ignore_errors=True)


def _wait_for_server(timeout_s: float = 10.0) -> None:
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.5):
                return
        except Exception as exc:  # pragma: no cover - tiny harness helper
            last_err = exc
            time.sleep(0.1)
    raise RuntimeError(f"Server did not start listening within {timeout_s}s: {last_err}")


@contextmanager
def _server_process(log_path: Path | None = None):
    stdout = subprocess.DEVNULL
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stdout = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=ROOT,
        stdout=stdout,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_server()
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if log_path is not None:
            stdout.close()


def _connect() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((HOST, PORT))
    return sock


def _benchmark_login_and_app(user: str, password: str, app_rounds: int, message_size: int) -> tuple[float, float, float]:
    message = b"A" * message_size
    sock = _connect()
    try:
        t0 = time.perf_counter()
        secrets, _export_key = client_login(sock, user, password, ConcreteOpaqueClient())
        login_elapsed = time.perf_counter() - t0

        send_state = DirectionState(secrets.client_app)
        recv_state = DirectionState(secrets.server_app)

        t1 = time.perf_counter()
        for _ in range(app_rounds):
            seq, ct = send_state.encrypt(CT_APP_DATA, message)
            send_frame(sock, encode_app_data(seq, ct))
            frame = recv_frame(sock)
            parsed = decode_app_data(frame)
            plaintext = recv_state.decrypt(CT_APP_DATA, parsed.seq, parsed.ciphertext)
            if plaintext != b"echo:" + message:
                raise AssertionError("Unexpected echo payload")
        app_elapsed = time.perf_counter() - t1

        send_frame(sock, encode_close())
    finally:
        sock.close()

    avg_rtt_ms = 1000.0 * app_elapsed / max(1, app_rounds)
    throughput_mib_s = (message_size * app_rounds) / max(app_elapsed, 1e-9) / (1024 * 1024)
    return login_elapsed, avg_rtt_ms, throughput_mib_s


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the VAULTTLS artifact")
    parser.add_argument("--iterations", type=int, default=8, help="number of register+login runs")
    parser.add_argument("--app-rounds", type=int, default=32, help="application echo rounds per login")
    parser.add_argument("--message-size", type=int, default=1024, help="plaintext bytes per app message")
    parser.add_argument("--output", default="results/benchmark_last.json", help="path to write JSON summary")
    parser.add_argument("--server-log", default="results/benchmark_server.log", help="path for server stdout")
    args = parser.parse_args()

    run_id = uuid.uuid4().hex[:8]
    reg_times: list[float] = []
    login_times: list[float] = []
    avg_rtts_ms: list[float] = []
    throughput_mib_s: list[float] = []

    with _preserve_db_state():
        with _server_process(Path(args.server_log)):
            for i in range(args.iterations):
                user = f"bench_{run_id}_{i}"
                password = f"Bench-{run_id}-{i}-P@ssw0rd!"

                t0 = time.perf_counter()
                register(user, password)
                reg_times.append(time.perf_counter() - t0)

                login_elapsed, avg_rtt_ms, mib_s = _benchmark_login_and_app(
                    user=user,
                    password=password,
                    app_rounds=args.app_rounds,
                    message_size=args.message_size,
                )
                login_times.append(login_elapsed)
                avg_rtts_ms.append(avg_rtt_ms)
                throughput_mib_s.append(mib_s)

    report = {
        "benchmark": "vaulttls",
        "iterations": args.iterations,
        "app_rounds": args.app_rounds,
        "message_size": args.message_size,
        "registration": _summary(reg_times),
        "login": _summary(login_times),
        "app_round_trip": {
            "count": len(avg_rtts_ms),
            "mean_ms": statistics.mean(avg_rtts_ms) if avg_rtts_ms else None,
            "stdev_ms": statistics.pstdev(avg_rtts_ms) if len(avg_rtts_ms) > 1 else 0.0,
            "min_ms": min(avg_rtts_ms) if avg_rtts_ms else None,
            "median_ms": statistics.median(avg_rtts_ms) if avg_rtts_ms else None,
            "p95_ms": sorted(avg_rtts_ms)[max(0, math.ceil(0.95 * len(avg_rtts_ms)) - 1)] if avg_rtts_ms else None,
            "max_ms": max(avg_rtts_ms) if avg_rtts_ms else None,
        },
        "throughput": {
            "count": len(throughput_mib_s),
            "mean_mib_s": statistics.mean(throughput_mib_s) if throughput_mib_s else None,
            "stdev_mib_s": statistics.pstdev(throughput_mib_s) if len(throughput_mib_s) > 1 else 0.0,
            "min_mib_s": min(throughput_mib_s) if throughput_mib_s else None,
            "median_mib_s": statistics.median(throughput_mib_s) if throughput_mib_s else None,
            "max_mib_s": max(throughput_mib_s) if throughput_mib_s else None,
        },
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nWrote benchmark report to {out}")


if __name__ == "__main__":
    main()
