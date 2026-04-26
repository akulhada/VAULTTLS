#!/usr/bin/env python3
"""
Measure how distinguishable the fake-user path is from a wrong-password path.

The goal is not to prove indistinguishability. It simply gives the artifact an
empirical study script that compares:
  1. ServerHello byte lengths for each path.
  2. End-to-end client failure time for each path.

Each wrong-password trial uses a distinct registered user so the in-memory rate
limiter does not dominate the measurements.
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
from codec import decode_alert, decode_server_hello, encode_client_hello
from config import CONTEXT_STRING, HOST, PORT, SERVER_STATE_PATH, SOCKET_TIMEOUT, USERS_DB_PATH, SERVER_ID
from opaque_adapter import ConcreteOpaqueClient
from register_user import register
from tls13_kdf import hash_bytes
from transcript import recv_frame, send_frame


def _summary(values: list[float]) -> dict:
    vals = sorted(values)
    if not vals:
        return {"count": 0, "mean": None, "stdev": None, "median": None, "p95": None, "min": None, "max": None}
    return {
        "count": len(vals),
        "mean": statistics.mean(vals),
        "stdev": statistics.pstdev(vals) if len(vals) > 1 else 0.0,
        "median": statistics.median(vals),
        "p95": vals[max(0, math.ceil(0.95 * len(vals)) - 1)],
        "min": vals[0],
        "max": vals[-1],
    }


@contextmanager
def _preserve_db_state():
    paths = [Path(USERS_DB_PATH), Path(SERVER_STATE_PATH)]
    backup_dir = Path(tempfile.mkdtemp(prefix="vaulttls_fakeuser_backup_"))
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
        deadline = time.time() + 10.0
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, PORT), timeout=0.5):
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not become ready")
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


def _server_hello_len(username: str, password: str) -> tuple[int, str]:
    client = ConcreteOpaqueClient()
    ke1, st = client.login_start(
        password=password.encode(),
        client_id=username.encode(),
        server_id=SERVER_ID,
        context=CONTEXT_STRING,
    )
    cred_id = hash_bytes(CONTEXT_STRING + username.encode())
    ch = encode_client_hello(version=1, credential_id=cred_id, client_nonce=st["nonce_c"], opaque_ke1=ke1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((HOST, PORT))
    try:
        send_frame(sock, ch)
        frame = recv_frame(sock)
        kind = "alert" if frame and frame[0] == 0x05 else "server_hello"
        if kind == "server_hello":
            # parse once to ensure the response is well-formed
            decode_server_hello(frame)
        else:
            decode_alert(frame)
        return len(frame), kind
    finally:
        sock.close()


def _failed_login_time(username: str, password: str) -> float:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((HOST, PORT))
    try:
        t0 = time.perf_counter()
        try:
            client_login(sock, username, password, ConcreteOpaqueClient())
            raise AssertionError("login unexpectedly succeeded")
        except Exception:
            return time.perf_counter() - t0
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure fake-user vs wrong-password timing")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--output", default="results/fake_user_timing_last.json")
    parser.add_argument("--server-log", default="results/fake_user_timing_server.log")
    args = parser.parse_args()

    run_id = uuid.uuid4().hex[:8]
    wrong_lengths: list[int] = []
    unknown_lengths: list[int] = []
    wrong_times_ms: list[float] = []
    unknown_times_ms: list[float] = []

    with _preserve_db_state():
        with _server_process(Path(args.server_log)):
            registered_users: list[tuple[str, str]] = []
            for i in range(args.trials):
                user = f"known_{run_id}_{i}"
                pw = f"Known-{run_id}-{i}-P@ssw0rd!"
                register(user, pw)
                registered_users.append((user, pw))

            for i, (user, pw) in enumerate(registered_users):
                wire_len, kind = _server_hello_len(user, pw + "-wrong")
                wrong_lengths.append(wire_len)
                wrong_times_ms.append(1000.0 * _failed_login_time(user, pw + "-wrong"))

                unknown_user = f"unknown_{run_id}_{i}"
                wire_len2, kind2 = _server_hello_len(unknown_user, "guess-password")
                unknown_lengths.append(wire_len2)
                unknown_times_ms.append(1000.0 * _failed_login_time(unknown_user, "guess-password"))

    report = {
        "study": "fake-user-vs-wrong-password",
        "trials": args.trials,
        "server_hello_length_bytes": {
            "wrong_password": _summary([float(x) for x in wrong_lengths]),
            "unknown_user": _summary([float(x) for x in unknown_lengths]),
            "all_equal": wrong_lengths == unknown_lengths,
            "unique_lengths_wrong": sorted(set(wrong_lengths)),
            "unique_lengths_unknown": sorted(set(unknown_lengths)),
        },
        "failure_time_ms": {
            "wrong_password": _summary(wrong_times_ms),
            "unknown_user": _summary(unknown_times_ms),
            "mean_gap_ms": abs(statistics.mean(wrong_times_ms) - statistics.mean(unknown_times_ms)) if wrong_times_ms and unknown_times_ms else None,
        },
        "interpretation": {
            "message_shape_goal": "Equal ServerHello sizes are a necessary but not sufficient condition for reduced enumeration leakage.",
            "timing_goal": "Small average timing gaps are encouraging but not a proof of indistinguishability.",
        },
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nWrote timing-study report to {out}")


if __name__ == "__main__":
    main()
