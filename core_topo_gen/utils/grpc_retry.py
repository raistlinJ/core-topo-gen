from __future__ import annotations
import logging
import os
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return int(val)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return float(val)
    except Exception:
        return default


def _env_flag(name: str, default_on: bool = True) -> bool:
    val = os.getenv(name)
    if val is None:
        return default_on
    return val not in ("0", "false", "False", "")


RETRY_ENABLED = _env_flag("CORETG_GRPC_RETRY", default_on=True)
RETRY_ATTEMPTS = max(1, _env_int("CORETG_GRPC_RETRY_ATTEMPTS", 3))
RETRY_BASE_DELAY = max(0.0, _env_float("CORETG_GRPC_RETRY_BASE_DELAY", 0.5))
RETRY_MAX_DELAY = max(RETRY_BASE_DELAY, _env_float("CORETG_GRPC_RETRY_MAX_DELAY", 3.0))


def _should_retry(err: BaseException) -> bool:
    if not RETRY_ENABLED:
        return False
    # Try gRPC status codes when available
    try:
        import grpc  # type: ignore
        if isinstance(err, grpc.RpcError):
            try:
                code = err.code()
            except Exception:
                code = None
            if code in {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.INTERNAL}:
                return True
    except Exception:
        pass
    # Fallback to string matching for GOAWAY/ping timeouts
    try:
        msg = str(err)
    except Exception:
        return False
    msg_l = msg.lower()
    return "goaway" in msg_l or "ping_timeout" in msg_l or "unavailable" in msg_l


class _RetryingProxy:
    """Transparent proxy that retries gRPC calls on transient channel failures."""

    def __init__(self, target: Any, reconnect: Optional[Callable[[], None]] = None, logger: Optional[logging.Logger] = None):
        super().__setattr__("_target", target)
        super().__setattr__("_reconnect", reconnect)
        super().__setattr__("_logger", logger or logging.getLogger("core_topo_gen.grpc"))

    def __repr__(self) -> str:  # pragma: no cover
        t = super().__getattribute__("_target")
        return f"<_RetryingProxy for {t!r}>"

    def __getattr__(self, name: str) -> Any:
        t = super().__getattribute__("_target")
        reconnect = super().__getattribute__("_reconnect")
        log: logging.Logger = super().__getattribute__("_logger")
        attr = getattr(t, name)

        if callable(attr):
            def _callable_wrapper(*args: Any, **kwargs: Any):
                attempts = RETRY_ATTEMPTS
                delay = RETRY_BASE_DELAY
                last_err: Optional[BaseException] = None
                for attempt in range(1, attempts + 1):
                    try:
                        return wrap_object(attr(*args, **kwargs), reconnect, log)
                    except BaseException as e:  # noqa: BLE001
                        last_err = e
                        if not _should_retry(e) or attempt >= attempts:
                            raise
                        log.warning("[grpc] %s.%s() transient error: %s; retrying (%s/%s)", type(t).__name__, name, e, attempt, attempts)
                        if reconnect is not None:
                            try:
                                reconnect()
                            except Exception:
                                log.debug("[grpc] reconnect failed", exc_info=True)
                        time.sleep(delay)
                        delay = min(RETRY_MAX_DELAY, delay * 2.0)
                if last_err is not None:
                    raise last_err
                return None

            try:
                _callable_wrapper.__name__ = getattr(attr, "__name__", name)
            except Exception:
                pass
            return _callable_wrapper

        return wrap_object(attr, reconnect, log)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_target", "_reconnect", "_logger"}:
            super().__setattr__(name, value)
            return
        setattr(super().__getattribute__("_target"), name, value)


def wrap_object(obj: Any, reconnect: Optional[Callable[[], None]] = None, logger: Optional[logging.Logger] = None) -> Any:
    if obj is None or isinstance(obj, (int, float, bool, str, bytes, bytearray, tuple, list, dict, set)):
        return obj
    if isinstance(obj, _RetryingProxy):
        return obj
    try:
        import types
        if isinstance(obj, (types.ModuleType, type)):
            return obj
    except Exception:
        pass
    try:
        from google.protobuf.message import Message as _PBMessage  # type: ignore
        if isinstance(obj, _PBMessage):
            return obj
    except Exception:
        pass
    return _RetryingProxy(obj, reconnect=reconnect, logger=logger)


def wrap_core_client(core_client: Any, logger: Optional[logging.Logger] = None) -> Any:
    """Return a retrying proxy over a CoreGrpcClient instance."""
    def _reconnect() -> None:
        try:
            if hasattr(core_client, "connect"):
                core_client.connect()
        except Exception:
            logger = logging.getLogger("core_topo_gen.grpc")
            logger.debug("[grpc] reconnect failed", exc_info=True)
    return wrap_object(core_client, reconnect=_reconnect, logger=logger)