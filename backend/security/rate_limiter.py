"""Rate limiting utility backed by MongoDB or in-memory fallback for Lambda."""

import time
from typing import Tuple, Dict
from datetime import datetime, timezone
from backend.database.mongodb import get_database

# Global in-memory cache for fallback or testing
_memory_rate_cache: Dict[str, list] = {}


def check_rate_limit(
    identifier: str,
    action: str,
    max_requests: int,
    window_seconds: int = 60
) -> Tuple[bool, int]:
    """Check if the given identifier has exceeded the request threshold for an action. Returns (is_allowed, remaining_attempts)."""
    if not identifier:
        return True, max_requests

    key = f"ratelimit:{action}:{identifier}"
    now = time.time()
    cutoff = now - window_seconds

    db = get_database()
    if db is not None:
        try:
            collection = db["rate_limits"]
            # Clean up old records
            collection.delete_many({"key": key, "timestamp": {"$lt": cutoff}})

            # Count recent requests
            count = collection.count_documents({"key": key, "timestamp": {"$gte": cutoff}})
            if count >= max_requests:
                return False, 0

            # Record this request
            collection.insert_one({
                "key": key,
                "timestamp": now,
                "created_at": datetime.now(timezone.utc)
            })

            return True, max_requests - (count + 1)
        except Exception as e:
            # Fallback to in-memory check if DB call fails
            pass

    # In-memory fallback
    if key not in _memory_rate_cache:
        _memory_rate_cache[key] = []

    # Clean old entries
    _memory_rate_cache[key] = [t for t in _memory_rate_cache[key] if t >= cutoff]

    if len(_memory_rate_cache[key]) >= max_requests:
        return False, 0

    _memory_rate_cache[key].append(now)
    remaining = max_requests - len(_memory_rate_cache[key])
    return True, remaining
