"""MongoDB log store: audit_log, nl_query_log, recall_notices.

Database: `drugtrace_logs` (configurable). Documents reference MySQL ids
(`recall_id`, `batch_id`, `user_id`) exactly as described in docs/SCHEMA.md §8.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import pymongo
from pymongo.collection import Collection

import config

_client = pymongo.MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=3000)
_db = _client[config.MONGO_DATABASE]
_audit: Collection = _db["audit_log"]
_nl_query: Collection = _db["nl_query_log"]
_notices: Collection = _db["recall_notices"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_ready() -> None:
    """Ping MongoDB and create the documented indexes."""
    _client.admin.command("ping")
    _audit.create_index([("ts", pymongo.DESCENDING)])
    _audit.create_index([("entity", pymongo.ASCENDING), ("entity_id", pymongo.ASCENDING)])
    _nl_query.create_index([("ts", pymongo.DESCENDING)])
    _notices.create_index([("recall_id", pymongo.ASCENDING)], unique=True)


def _clean(document: dict[str, Any] | None) -> dict[str, Any] | None:
    if document is None:
        return None
    document = dict(document)
    document.pop("_id", None)
    return document


# --------------------------------------------------------------------------- #
# audit_log
# --------------------------------------------------------------------------- #
def log_audit(
    user: Any,
    action: str,
    entity: str,
    entity_id: Optional[int] = None,
    details: Optional[dict[str, Any]] = None,
    outcome: str = "OK",
    reason: Optional[str] = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "ts": _now(),
        "user_id": None,
        "username": None,
        "role": None,
        "action": action,
        "entity": entity,
        "entity_id": entity_id,
        "details": details or {},
        "outcome": outcome,
    }
    if user is not None:
        document["user_id"] = user["user_id"]
        document["username"] = user["username"]
        document["role"] = user["role"]
    if reason:
        document["reason"] = reason
    _audit.insert_one(document)
    return _clean(document) or document


def read_audit(limit: int = 200, outcome: Optional[str] = None) -> list[dict[str, Any]]:
    query: dict[str, Any] = {}
    if outcome:
        query["outcome"] = outcome
    cursor = _audit.find(query).sort("ts", pymongo.DESCENDING).limit(limit)
    return [_clean(doc) for doc in cursor if doc is not None]


# --------------------------------------------------------------------------- #
# nl_query_log
# --------------------------------------------------------------------------- #
def log_nl_query(
    *,
    user_id: Optional[int],
    question: str,
    route: str,
    intent: Optional[str],
    generated_sql: Optional[str],
    validation: str,
    row_count: int,
    latency_ms: int,
) -> None:
    _nl_query.insert_one(
        {
            "ts": _now(),
            "user_id": user_id,
            "question": question,
            "route": route,
            "intent": intent,
            "generated_sql": generated_sql,
            "validation": validation,
            "row_count": row_count,
            "latency_ms": latency_ms,
        }
    )


def read_nl_queries(limit: int = 100) -> list[dict[str, Any]]:
    return [
        _clean(doc)
        for doc in _nl_query.find().sort("ts", pymongo.DESCENDING).limit(limit)
        if doc is not None
    ]


# --------------------------------------------------------------------------- #
# recall_notices
# --------------------------------------------------------------------------- #
def save_recall_notice(document: dict[str, Any]) -> dict[str, Any]:
    document = {**document, "created_at": document.get("created_at") or _now()}
    _notices.replace_one({"recall_id": document["recall_id"]}, document, upsert=True)
    return document


def get_recall_notice(recall_id: int) -> Optional[dict[str, Any]]:
    return _clean(_notices.find_one({"recall_id": recall_id}, sort=[("created_at", -1)]))


def read_recall_notices() -> list[dict[str, Any]]:
    return [
        _clean(doc)
        for doc in _notices.find().sort("recall_id", pymongo.ASCENDING)
        if doc is not None
    ]


# --------------------------------------------------------------------------- #
# Maintenance
# --------------------------------------------------------------------------- #
def reset_logs() -> None:
    _client.drop_database(config.MONGO_DATABASE)
    ensure_ready()
