from __future__ import annotations
import logging
import re
from typing import Any, Optional
import time

logger = logging.getLogger(__name__)


def _call_create_session(core: Any, session_id: Optional[int] = None) -> Any:
    """Call CoreGrpcClient.create_session with best-effort compatibility.

    Tries different keyword names across CORE client versions, falling back to no-arg.
    Returns the created session object or raises the exception from the client.
    """
    if session_id is None:
        return core.create_session()
    # Try known kwarg names first; fall back to no-arg if unsupported
    try:
        return core.create_session(session_id=session_id)
    except TypeError:
        try:
            return core.create_session(id=session_id)
        except TypeError:
            logger.debug("create_session does not accept a session id kwarg; falling back to no-arg")
            return core.create_session()


def _extract_pycore_id_from_error(err: BaseException) -> Optional[int]:
    try:
        msg = str(err)
    except Exception:
        return None
    m = re.search(r"pycore\.(\d+)", msg)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    return None


def safe_create_session(core: Any, max_attempts: int = 5) -> Any:
    """Create a CORE session robustly, avoiding 'File exists: /tmp/pycore.N' errors.

    Strategy:
    - Pre-scan existing sessions to propose next id.
    - Attempt create_session with that id when supported; on failure with a pycore.N collision, retry with N+1.
    - Fall back to plain create_session when kwargs are not supported.
    """
    # Pre-scan to propose a candidate id
    candidate: Optional[int] = None
    try:
        sessions = core.get_sessions()
        existing_ids: list[int] = []
        for s in (sessions or []):
            sid = getattr(s, 'id', None) or getattr(s, 'session_id', None)
            if sid is not None:
                try:
                    existing_ids.append(int(sid))
                except Exception:
                    continue
        if existing_ids:
            candidate = max(existing_ids) + 1
    except Exception:
        candidate = None

    attempts = 0
    last_err: Optional[BaseException] = None
    next_try = candidate
    while attempts < max_attempts:
        attempts += 1
        try:
            return _call_create_session(core, next_try)
        except BaseException as e:  # noqa: BLE001
            last_err = e
            # Detect pycore.N collision and choose a higher id
            py_id = _extract_pycore_id_from_error(e)
            if py_id is not None:
                next_try = py_id + 1
                logger.info("[grpc] create_session collided with /tmp/pycore.%s; retrying with session_id=%s (attempt %s/%s)", py_id, next_try, attempts, max_attempts)
                time.sleep(0.2)
                continue
            # Any other error: break and raise
            break
    if last_err is not None:
        raise last_err
    # Should not reach here; fallback to no-arg call
    return core.create_session()
