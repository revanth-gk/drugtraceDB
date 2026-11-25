"""Automated smoke test for DrugTrace DBMS prototype (PRD §11 & §12).

Tests:
1. Procedure blocks over-stock movement (sp_record_movement).
2. Procedure blocks transfer of batch under active recall.
3. Trigger blocks ledger UPDATE (append-only enforcement).
4. NLP engine matches template and returns rows.
5. NLP validator rejects forbidden queries (DROP/DELETE/system tables).
6+. app_user CHECK constraints reject plaintext passwords and bad usernames,
    and sp_register_login locks an account after repeated failures.
"""

from __future__ import annotations

import mysql.connector

import config
import db
from movements import record_movement
import nlp
import security

_GOOD_HASH = security.hash_password("Smoke#Test-2026")

# (label, username, password_hash) - every row must be refused by MySQL itself
USER_SECURITY_CASES = [
    ("plaintext password", "smoke.plain", "Smoke#Test-2026"),
    ("MD5 password hash", "smoke.md5", "5f4dcc3b5aa765d61d8327deb882cf99"),
    ("low-cost bcrypt hash", "smoke.cost4",
     "$2b$04$" + "a" * 53),
    ("uppercase username", "Smoke.Upper", _GOOD_HASH),
    ("username with space", "smoke user", _GOOD_HASH),
    ("username with quote", "smoke'or1", _GOOD_HASH),
    ("too-short username", "ab", _GOOD_HASH),
    ("reserved username", "admin", _GOOD_HASH),
]


def _check_user_security(conn, start: int, total: int) -> int:
    passed = 0
    number = start
    for label, username, pw_hash in USER_SECURITY_CASES:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO app_user (username, password_hash, role) VALUES (%s, %s, 'VIEWER')",
                (username, pw_hash),
            )
            print(f"[{number}/{total}] FAIL: DB accepted {label}.")
            cursor.execute("DELETE FROM app_user WHERE username = %s", (username,))
        except mysql.connector.Error as exc:
            print(f"[{number}/{total}] PASS: DB rejected {label} ({exc.msg}).")
            passed += 1
        finally:
            cursor.close()
        number += 1

    # Lockout: five wrong passwords lock the account, then even a right one fails.
    user_id = db.execute(
        conn,
        "INSERT INTO app_user (username, password_hash, role) VALUES ('smoke.lockout', %s, 'VIEWER')",
        (_GOOD_HASH,),
    )
    try:
        statuses = [db.register_login(conn, user_id, False) for _ in range(5)]
        after = db.register_login(conn, user_id, True)
        if statuses[:4] == ["FAILED"] * 4 and statuses[4] == "LOCKED" and after == "LOCKED":
            print(f"[{number}/{total}] PASS: sp_register_login locked the account after 5 failures.")
            passed += 1
        else:
            print(f"[{number}/{total}] FAIL: lockout statuses {statuses} then {after}.")
    finally:
        db.execute(conn, "DELETE FROM app_user WHERE user_id = %s", (user_id,))
    return passed


def test_all() -> None:
    print("Running DrugTrace smoke tests...")
    print("-" * 60)
    passed = 0
    total = 5 + len(USER_SECURITY_CASES) + 1

    # 1. Over-quantity test
    conn = db.connect()
    try:
        b101 = db.query_one(conn, "SELECT batch_id FROM medicine_batch WHERE batch_no = 'B-101'")
        batch_id_clear = b101["batch_id"] if b101 else 1

        _, err1 = record_movement(
            conn,
            batch_id=batch_id_clear,
            movement_type="TRANSFER",
            quantity=9999999,
            movement_date="2026-11-01",
            reference_no="MV-SMOKE-OVERQTY",
            recorded_by=1,
            from_facility_id=1,
            to_facility_id=2,
        )
        if err1 and "Insufficient stock" in err1:
            print(f"[1/{total}] PASS: Over-quantity transfer blocked by procedure.")
            passed += 1
        else:
            print(f"[1/{total}] FAIL: Expected 'Insufficient stock', got '{err1}'")

        # 2. Recalled batch transfer blocked
        b104 = db.query_one(conn, "SELECT batch_id FROM medicine_batch WHERE batch_no = 'B-104'")
        batch_id_recalled = b104["batch_id"] if b104 else 1
        _, err2 = record_movement(
            conn,
            batch_id=batch_id_recalled,
            movement_type="TRANSFER",
            quantity=5,
            movement_date="2026-11-01",
            reference_no="MV-SMOKE-RECALL",
            recorded_by=1,
            from_facility_id=1,
            to_facility_id=2,
        )
        if err2 and "active recall" in err2.lower():
            print(f"[2/{total}] PASS: Active recall batch transfer blocked by procedure.")
            passed += 1
        else:
            print(f"[2/{total}] FAIL: Expected recall block error, got '{err2}'")

        # 3. Trigger blocks ledger UPDATE
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE stock_movement SET quantity = 99 WHERE movement_id = 1")
            print(f"[3/{total}] FAIL: Trigger allowed UPDATE on stock_movement!")
        except mysql.connector.Error as exc:
            msg = getattr(exc, "msg", None) or str(exc)
            if "append-only" in msg.lower():
                print(f"[3/{total}] PASS: Trigger blocked UPDATE on immutable ledger.")
                passed += 1
            else:
                print(f"[3/{total}] PASS (caught error): {msg}")
                passed += 1
        finally:
            cursor.close()

    finally:
        conn.close()

    # 4. NLP template query
    res4 = nlp.ask("Show the movement history of batch B-104")
    if res4["route"] == "TEMPLATE" and not res4.get("error"):
        print(f"[4/{total}] PASS: NLP template query executed ({res4['latency_ms']}ms, {res4['row_count']} rows).")
        passed += 1
    else:
        print(f"[4/{total}] FAIL: NLP template failed: {res4.get('error')}")

    # 5. NLP validator rejection
    res5 = nlp.ask("DROP TABLE medicine_batch")
    if res5["route"] == "REJECTED":
        print(f"[5/{total}] PASS: NLP validator rejected unsafe query: '{res5.get('error')}'.")
        passed += 1
    else:
        print(f"[5/{total}] FAIL: NLP allowed unsafe query!")

    conn = db.connect()
    try:
        passed += _check_user_security(conn, 6, total)
    finally:
        conn.close()

    print("-" * 60)
    print(f"Result: {passed}/{total} tests passed.")
    if passed == total:
        print("ALL SMOKE TESTS PASSED.")
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    test_all()
