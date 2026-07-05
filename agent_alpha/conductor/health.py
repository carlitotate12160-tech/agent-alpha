# agent_alpha/conductor/health.py
# A7 Observability — slice A7-c: broker queue-depth + worker health signal.
#
# This is NOT event-sourced and NOT a projection. Queue depth and worker
# liveness are LIVE broker runtime state (Redis/Celery), not engagement history,
# so they cannot come from the event stream. This is a deliberately separate,
# read-only side-probe — separate by nature, not a Lyndon #6 duplicate of the
# event-stream read models.
#
# Split: a PURE assembler (build_queue_health) that is fully unit-testable with a
# fake probe (no Redis needed → identical on Oracle), plus a thin I/O adapter
# (RedisCeleryProbe) that only fetches signals. All logic lives in the assembler.

from __future__ import annotations

import dataclasses
import datetime
import typing


@dataclasses.dataclass(frozen=True)
class QueueHealth:
    """Live operational health of the task broker.

    ``queue_depth`` is ``None`` (UNKNOWN) — never ``0`` — when the broker is
    unreachable: a down broker must not read as an empty/idle queue (anti Lyndon
    #3 false-success). ``degraded`` is the single boolean an operator alerts on.
    """

    broker_reachable: bool
    queue_depth: int | None
    worker_count: int | None
    degraded: bool
    checked_at_utc: str


@typing.runtime_checkable
class HealthProbe(typing.Protocol):
    """Live infra signals. Implementations must be bounded (short timeouts) and
    must never raise — unreachable is a value, not an exception."""

    def broker_reachable(self) -> bool: ...
    def queue_depth(self) -> int: ...
    def worker_count(self) -> int | None: ...


def build_queue_health(
    probe: HealthProbe,
    *,
    clock: typing.Callable[[], datetime.datetime] | None = None,
) -> QueueHealth:
    """Assemble a QueueHealth from probe signals. Pure given the probe."""
    _clock = clock or (lambda: datetime.datetime.now(datetime.UTC))
    checked_at_utc = _clock().isoformat()

    if not probe.broker_reachable():
        # Broker down: depth UNKNOWN (not 0), no worker info, always degraded.
        return QueueHealth(
            broker_reachable=False,
            queue_depth=None,
            worker_count=None,
            degraded=True,
            checked_at_utc=checked_at_utc,
        )

    depth = probe.queue_depth()
    workers = probe.worker_count()
    # No workers (0 or unknown) means queued work cannot drain -> degraded even
    # though the broker is up.
    degraded = workers is None or workers == 0
    return QueueHealth(
        broker_reachable=True,
        queue_depth=depth,
        worker_count=workers,
        degraded=degraded,
        checked_at_utc=checked_at_utc,
    )


class RedisCeleryProbe:
    """Concrete HealthProbe over the Redis broker + Celery control plane.

    Thin I/O only — no decision logic (that lives in build_queue_health). Every
    method swallows I/O errors and returns a value, so a wedged broker degrades
    the signal instead of raising through the endpoint. Reads only: PING / SCAN /
    LLEN / an inspect broadcast; never writes engagement state.
    """

    def __init__(
        self,
        *,
        redis_client: typing.Any,
        celery_app: typing.Any,
        queue_prefix: str,
        inspect_timeout_s: float = 1.0,
    ) -> None:
        self._client = redis_client
        self._celery = celery_app
        self._prefix = queue_prefix
        self._inspect_timeout_s = inspect_timeout_s

    @classmethod
    def from_url(
        cls,
        redis_url: str,
        celery_app: typing.Any,
        queue_prefix: str,
        *,
        timeout_s: float = 2.0,
    ) -> RedisCeleryProbe:
        from redis import Redis

        client = Redis.from_url(
            redis_url,
            socket_timeout=timeout_s,
            socket_connect_timeout=timeout_s,
        )
        return cls(redis_client=client, celery_app=celery_app, queue_prefix=queue_prefix)

    def broker_reachable(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def queue_depth(self) -> int:
        total = 0
        try:
            keys = self._client.scan_iter(match=f"{self._prefix}*", count=100)
        except Exception:
            return 0
        for key in keys:
            try:
                total += int(self._client.llen(key))
            except Exception:
                # Non-list key (WRONGTYPE) or transient error: skip, don't crash.
                continue
        return total

    def worker_count(self) -> int | None:
        try:
            replies = self._celery.control.inspect(timeout=self._inspect_timeout_s).ping()
        except Exception:
            return None
        if not replies:
            return 0
        return len(replies)
