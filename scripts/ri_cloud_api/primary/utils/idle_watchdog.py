"""Idle-timeout watchdog for the ResInsight Cloud API service.

ResInsight launches this service as a child process and normally kills it on a clean
shutdown (``RiaCloudApiService::stop``). If ResInsight crashes or is force-killed that
shutdown path never runs, and on Windows the child is not reaped automatically, so the
service would be orphaned and keep holding its port.

To guard against that, the service shuts itself down after a period with no HTTP
activity. ResInsight polls the ``/alive`` health endpoint every 10 s for its whole
lifetime, so those polls keep the idle clock reset while ResInsight is running; the
service only times out once the polls stop, i.e. ResInsight has crashed/exited.

NOTE: the idle timeout must always stay comfortably above ResInsight's health-poll
interval (``RiaCloudApiService::healthCheckIntervalMs``, currently 10 s), otherwise the
service could shut itself down while ResInsight is still alive.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI, Request
    from fastapi.responses import Response

logger = logging.getLogger("ri_cloud_api")

_IDLE_TIMEOUT_ENV = "RI_CLOUD_API_IDLE_TIMEOUT_SECONDS"
_DEFAULT_IDLE_TIMEOUT_SECONDS = 120.0
_DEFAULT_CHECK_INTERVAL_SECONDS = 5.0


class IdleTracker:
    """Tracks the time elapsed since the last recorded activity.

    Uses ``time.monotonic`` so it is immune to wall-clock adjustments.
    """

    def __init__(self) -> None:
        self._last_activity = time.monotonic()

    def touch(self) -> None:
        self._last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        return time.monotonic() - self._last_activity


def _resolve_timeout() -> float:
    raw = os.environ.get(_IDLE_TIMEOUT_ENV, "").strip()
    if not raw:
        return _DEFAULT_IDLE_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "Invalid %s=%r, falling back to %.0fs.",
            _IDLE_TIMEOUT_ENV,
            raw,
            _DEFAULT_IDLE_TIMEOUT_SECONDS,
        )
        return _DEFAULT_IDLE_TIMEOUT_SECONDS
    if value <= 0:
        return _DEFAULT_IDLE_TIMEOUT_SECONDS
    return value


def install_idle_middleware(app: "FastAPI", tracker: IdleTracker) -> None:
    """Register middleware that records activity on every request.

    Every request (including the ``/alive`` health poll, which is the heartbeat) resets
    the idle clock.
    """

    @app.middleware("http")
    async def _record_activity(request: "Request", call_next) -> "Response":
        tracker.touch()
        return await call_next(request)


async def monitor_idle(
    tracker: IdleTracker,
    timeout: float | None = None,
    interval: float = _DEFAULT_CHECK_INTERVAL_SECONDS,
) -> None:
    """Shut the service down once it has been idle for ``timeout`` seconds."""
    if timeout is None:
        timeout = _resolve_timeout()

    logger.info(
        "Idle watchdog active: shutting down after %.0fs without activity.", timeout
    )

    while True:
        await asyncio.sleep(interval)
        idle = tracker.idle_seconds()
        if idle >= timeout:
            logger.warning("No activity for %.0fs, shutting down service.", idle)
            # Graceful on POSIX (uvicorn handles SIGTERM); terminates the process on
            # Windows, which still releases the port.
            os.kill(os.getpid(), signal.SIGTERM)
            break
