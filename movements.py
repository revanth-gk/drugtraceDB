"""Movement recording, delegated to MySQL's `sp_record_movement` procedure.

All business rules (future date, expiry, active recall, non-negative stock,
ledger pattern) and the row lock live in the database procedure from
docs/SCHEMA.md §6. This wrapper only translates database errors for the UI.
"""

from __future__ import annotations

import mysql.connector

from db import query_one


def record_movement(
    conn: mysql.connector.MySQLConnection,
    *,
    batch_id: int,
    movement_type: str,
    quantity: int,
    movement_date: str,
    reference_no: str,
    recorded_by: int,
    from_facility_id: int | None = None,
    to_facility_id: int | None = None,
) -> tuple[int | None, str | None]:
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute(
            "CALL sp_record_movement(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                batch_id,
                from_facility_id,
                to_facility_id,
                movement_type,
                quantity,
                movement_date,
                reference_no,
                recorded_by,
            ),
        )
        while cursor.nextset():
            pass
    except mysql.connector.Error as exc:
        _safe_rollback(conn)
        return None, _translate_error(exc)
    finally:
        cursor.close()

    row = query_one(
        conn,
        "SELECT movement_id FROM stock_movement WHERE reference_no = %s",
        (reference_no,),
    )
    if row is None:
        return None, "Movement was committed but could not be read back"
    return int(row["movement_id"]), None


def _translate_error(exc: mysql.connector.Error) -> str:
    message = getattr(exc, "msg", None) or str(exc)
    if exc.errno == 1644:  # SIGNAL from the procedure
        return message
    if exc.errno == 1062:
        if "reference_no" in message:
            return "Reference number already used"
        return "Duplicate value: " + message
    if exc.errno == 1452:
        return "Unknown batch or facility"
    if exc.errno == 1265:
        return "Value is not valid for this movement type"
    return f"Could not record movement: {message}"


def _safe_rollback(conn: mysql.connector.MySQLConnection) -> None:
    try:
        conn.rollback()
    except mysql.connector.Error:
        pass
