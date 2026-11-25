"""Recall creation against MySQL: recall row + affected-batch junction atomically."""

from __future__ import annotations

from datetime import date

import mysql.connector

RECALL_CLASSES = ("I", "II", "III")
RECALL_STATUSES = ("ACTIVE", "CLOSED")


def create_recall(
    conn: mysql.connector.MySQLConnection,
    *,
    recall_code: str,
    issued_date: str,
    reason: str,
    recall_class: str,
    recall_status: str,
    batch_ids: list[int],
) -> tuple[int | None, str | None]:
    recall_code = (recall_code or "").strip()
    reason = (reason or "").strip()
    recall_class = (recall_class or "").strip().upper()
    recall_status = (recall_status or "ACTIVE").strip().upper()

    if not recall_code:
        return None, "Recall code is required"
    if not reason:
        return None, "Reason is required"
    if recall_class not in RECALL_CLASSES:
        return None, "Recall class must be I, II or III"
    if recall_status not in RECALL_STATUSES:
        return None, "Recall status must be ACTIVE or CLOSED"
    if not batch_ids:
        return None, "Select at least one affected batch"

    try:
        issued_day = date.fromisoformat(issued_date)
    except (TypeError, ValueError):
        return None, "Invalid issued date"
    if issued_day > date.today():
        return None, "Recall issue date cannot be in the future"

    batch_ids = sorted({int(batch_id) for batch_id in batch_ids})

    cursor = conn.cursor(buffered=True)
    try:
        conn.start_transaction()
        placeholders = ", ".join(["%s"] * len(batch_ids))
        cursor.execute(
            f"SELECT COUNT(*) FROM medicine_batch WHERE batch_id IN ({placeholders})",
            tuple(batch_ids),
        )
        found = cursor.fetchone()[0]
        if found != len(batch_ids):
            raise ValueError("One or more selected batches do not exist")

        cursor.execute(
            """
            INSERT INTO recall (recall_code, issued_date, reason, recall_class, recall_status)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (recall_code, issued_day.isoformat(), reason, recall_class, recall_status),
        )
        recall_id = int(cursor.lastrowid)
        cursor.executemany(
            "INSERT INTO recall_affected_batch (recall_id, batch_id) VALUES (%s, %s)",
            [(recall_id, batch_id) for batch_id in batch_ids],
        )
        conn.commit()
        return recall_id, None

    except ValueError as exc:
        conn.rollback()
        return None, str(exc)
    except mysql.connector.Error as exc:
        conn.rollback()
        message = getattr(exc, "msg", None) or str(exc)
        if exc.errno == 1062 and "recall_code" in message:
            return None, "Recall code already exists"
        return None, f"Could not create recall: {message}"
    finally:
        cursor.close()
