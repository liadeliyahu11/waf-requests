"""Adaptive ladder: persist per-host winning transforms and promote them.

Learning is opt-in (``WAFSession(learn=True)``); nothing touches disk otherwise.
Wins are keyed by host because WAF configuration is per-host. The learned file
is user-local and gitignored.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger("waf_requests.learn")

#: Cap on remembered transforms per host (most-recent-win first).
MAX_PER_HOST = 8


def learn_file() -> Path:
    """Resolve the learned-state path; ``$WAF_REQUESTS_LEARN_FILE`` wins."""
    env = os.environ.get("WAF_REQUESTS_LEARN_FILE")
    if env:
        return Path(env)
    return Path.home() / ".waf_requests" / "learned.json"


def load_learned() -> "dict[str, list[str]]":
    """Read ``{host: [transform_id, ...]}``; ``{}`` on missing/corrupt file."""
    path = learn_file()
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        if path.exists():
            log.warning("unreadable learned file %s; starting empty", path)
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): [str(t) for t in v] for k, v in data.items() if isinstance(v, list)}


def record_win(host: str, transform_id: str) -> None:
    """Prepend ``transform_id`` to ``host``'s list and persist atomically."""
    learned = load_learned()
    wins = learned.get(host, [])
    wins = [transform_id] + [t for t in wins if t != transform_id]
    learned[host] = wins[:MAX_PER_HOST]
    path = learn_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(learned, fh, indent=2)
        os.replace(tmp, path)
    except OSError:
        log.warning("failed to persist learned state to %s", path)


def learned_order(host: str, default: "tuple[str, ...]") -> "tuple[str, ...]":
    """Learned winning transforms first, then the default ladder minus dupes."""
    wins = load_learned().get(host, [])
    return tuple(wins) + tuple(t for t in default if t not in wins)
