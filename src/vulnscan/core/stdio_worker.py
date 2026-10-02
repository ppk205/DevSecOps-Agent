"""Bounded, cancellable JSON-lines child-process calls (IR-16, QR-21)."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from typing import Any
from uuid import uuid4

from vulnscan.scanners.process import ScanCancelled

MAX_MESSAGE_BYTES = 8 * 1024 * 1024
PROTOCOL_VERSION = 1


def terminate_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            import signal

            try:
                getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL"))  # noqa: B009
            except ProcessLookupError:
                pass
        try:
            process.kill()
        except ProcessLookupError:
            pass
    process.wait(timeout=5)


class JSONWorker:
    """One owned worker, sequential requests, deadline covering pipe I/O too."""

    def __init__(self, command: Sequence[str]) -> None:
        self.command = list(command)
        self.process: subprocess.Popen[bytes] | None = None
        self.responses: queue.Queue[dict[str, Any] | BaseException] = queue.Queue(maxsize=4)
        self.lock = threading.Lock()

    def _start(self) -> None:
        self.responses = queue.Queue(maxsize=4)
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        process, responses = self.process, self.responses

        def read() -> None:
            try:
                assert process.stdout is not None
                while True:
                    line = process.stdout.readline(MAX_MESSAGE_BYTES + 1)
                    if not line:
                        raise RuntimeError("worker exited before replying")
                    if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
                        raise ValueError("worker reply exceeds message limit")
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise TypeError("invalid worker reply")
                    responses.put_nowait(value)
            except Exception as exc:  # noqa: BLE001 - child transport boundary
                try:
                    responses.put_nowait(exc)
                except queue.Full:
                    pass

        threading.Thread(target=read, daemon=True, name="vulnscan-worker-reader").start()

    def call(
        self,
        method: str,
        params: dict[str, Any],
        timeout: float,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> Any:
        if timeout <= 0:
            raise TimeoutError("worker deadline exceeded")
        with self.lock:
            if cancelled():
                raise ScanCancelled()
            if self.process is None or self.process.poll() is not None:
                self.close()
                self._start()
            assert self.process is not None and self.process.stdin is not None
            identifier = uuid4().hex
            data = (
                json.dumps(
                    {
                        "version": PROTOCOL_VERSION,
                        "id": identifier,
                        "method": method,
                        "params": params,
                    }
                ).encode()
                + b"\n"
            )
            if len(data) > MAX_MESSAGE_BYTES:
                raise ValueError("worker request exceeds message limit")
            deadline = time.monotonic() + timeout
            process, responses = self.process, self.responses

            def write() -> None:
                try:
                    assert process.stdin is not None
                    process.stdin.write(data)
                    process.stdin.flush()
                except (OSError, ValueError) as exc:
                    try:
                        responses.put_nowait(exc)
                    except queue.Full:
                        pass

            threading.Thread(target=write, daemon=True, name="vulnscan-worker-writer").start()
            try:
                while True:
                    if cancelled():
                        raise ScanCancelled()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("model worker deadline exceeded")
                    try:
                        response = responses.get(timeout=min(0.05, remaining))
                    except queue.Empty:
                        continue
                    if isinstance(response, BaseException):
                        raise response
                    if (
                        response.get("version") != PROTOCOL_VERSION
                        or response.get("id") != identifier
                    ):
                        raise ValueError("worker response identity mismatch")
                    if not response.get("ok"):
                        error = response.get("error", {})
                        if error.get("code") == "dependency_unavailable":
                            raise ImportError(str(error.get("message", "Laya unavailable")))
                        raise RuntimeError(str(error.get("message", "model worker failed")))
                    return response["result"]
            except BaseException:
                self.close()
                raise

    def close(self) -> None:
        if self.process is not None:
            terminate_tree(self.process)
            for stream in (self.process.stdin, self.process.stdout):
                if stream:
                    stream.close()
            self.process = None
