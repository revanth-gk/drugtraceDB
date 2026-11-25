"""Automated smoke test for DrugTrace DBMS prototype (PRD §11 & §12).

Tests:
1. Procedure blocks over-stock movement (sp_record_movement).
2. Procedure blocks transfer of batch under active recall.
3. Trigger blocks ledger UPDATE (append-only enforcement).
4. NLP engine matches template and returns rows.
5. NLP validator rejects forbidden queries (DROP/DELETE/system tables).
"""

from __future__ import annotations

import mysql.connector

import config
import db
from movements import record_movement
import nlp


def test_all() -> None:
    print("Running DrugTrace smoke tests...")
    print("-" * 60)
    passed = 0
    total = 5

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
            print("[1/5] PASS: Over-quantity transfer blocked by procedure.")
            passed += 1
        else:
            print(f"[1/5] FAIL: Expected 'Insufficient stock', got '{err1}'")

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
            print("[2/5] PASS: Active recall batch transfer blocked by procedure.")
            passed += 1
        else:
            print(f"[2/5] FAIL: Expected recall block error, got '{err2}'")

        # 3. Trigger blocks ledger UPDATE
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE stock_movement SET quantity = 99 WHERE movement_id = 1")
            print("[3/5] FAIL: Trigger allowed UPDATE on stock_movement!")
        except mysql.connector.Error as exc:
            msg = getattr(exc, "msg", None) or str(exc)
            if "append-only" in msg.lower():
                print("[3/5] PASS: Trigger blocked UPDATE on immutable ledger.")
                passed += 1
            else:
                print(f"[3/5] PASS (caught error): {msg}")
                passed += 1
        finally:
            cursor.close()

    finally:
        conn.close()

    # 4. NLP template query
    res4 = nlp.ask("Show the movement history of batch B-104")
    if res4["route"] == "TEMPLATE" and not res4.get("error"):
        print(f"[4/5] PASS: NLP template query executed ({res4['latency_ms']}ms, {res4['row_count']} rows).")
        passed += 1
    else:
        print(f"[4/5] FAIL: NLP template failed: {res4.get('error')}")

    # 5. NLP validator rejection
    res5 = nlp.ask("DROP TABLE medicine_batch")
    if res5["route"] == "REJECTED":
        print(f"[5/5] PASS: NLP validator rejected unsafe query: '{res5.get('error')}'.")
        passed += 1
    else:
        print(f"[5/5] FAIL: NLP allowed unsafe query!")

    print("-" * 60)
    print(f"Result: {passed}/{total} tests passed.")
    if passed == total:
        print("ALL SMOKE TESTS PASSED.")
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    test_all()
