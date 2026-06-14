"""Periodic audit-log anchoring (mirrors TS startAuditCheckpointing).

Automates the manual ``checkpoint_audit()`` / ``verify_audit_checkpoint()``
pattern: on a background thread, every ``interval_ms`` it signs the audit head
and hands the checkpoint to ``sink``. Store checkpoints **out of the audit
writer's reach** for tail-deletion / rewrite detection to hold.
"""

from __future__ import annotations

import threading
from typing import Callable


def start_audit_checkpointing(
    engine,
    *,
    interval_ms: int,
    sink: Callable[[dict], None],
    on_error: Callable[[BaseException], None] | None = None,
) -> Callable[[], None]:
    """Start checkpointing; returns a ``stop()`` function. The worker is a daemon
    thread, so it won't keep the interpreter alive on its own."""
    stop_event = threading.Event()
    interval_s = interval_ms / 1000.0

    def loop() -> None:
        while not stop_event.wait(interval_s):
            try:
                sink(engine.checkpoint_audit())
            except BaseException as e:  # noqa: BLE001
                if on_error is not None:
                    on_error(e)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

    def stop() -> None:
        stop_event.set()
        thread.join(timeout=1.0)

    return stop
