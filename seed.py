"""Deterministic synthetic seed data for MySQL + MongoDB.

Targets docs/PRD.md §11: 12 products, 40 batches, 6 organisations, 12
facilities, ~200 movements, 4 recalls, 3 users. Seeded scenarios:
  1. B-104 travels through 6 facilities (multi-hop journey).
  2. R-02 covers two batches (B-104, B-107).
  3. Recalled stock remains at 3+ facilities across 2 districts.
  4. B-140 is expired and B-139 expires within 30 days.
  5. Over-quantity transfer is a live demo (movement form), not seed data.
  6. Transfer of a recalled batch is blocked live (movement form).
  7. Ledger UPDATE is blocked live (Audit page button).
"""

from __future__ import annotations

import random
from datetime import date, timedelta

import mysql.connector

import db
import logs
from movements import record_movement
from recalls import create_recall
from security import hash_password, validate_password

DEMO_PASSWORD = "Demo#Trace2026"

MANUFACTURERS = [
    ("DEMO-Meridian Pharma", "LIC-DEMO-001"),
    ("DEMO-Nova Laboratories", "LIC-DEMO-002"),
    ("DEMO-Aurochem Remedies", "LIC-DEMO-003"),
    ("DEMO-Zenith Formulations", "LIC-DEMO-004"),
]

# (manufacturer_index, brand, generic, strength, form)
PRODUCTS = [
    (0, "DEMO-Paracetamol 650", "Paracetamol", "650 mg", "TABLET"),
    (0, "DEMO-Amoxi 500", "Amoxicillin", "500 mg", "CAPSULE"),
    (1, "DEMO-Cetirizine 10", "Cetirizine", "10 mg", "TABLET"),
    (1, "DEMO-Pantoprazole 40", "Pantoprazole", "40 mg", "TABLET"),
    (2, "DEMO-Metformin 500", "Metformin", "500 mg", "TABLET"),
    (2, "DEMO-Azithromycin 250", "Azithromycin", "250 mg", "TABLET"),
    (3, "DEMO-Ibuprofen 400", "Ibuprofen", "400 mg", "TABLET"),
    (3, "DEMO-ORS Sachet", "Oral Rehydration Salts", "21.8 g", "OTHER"),
    (0, "DEMO-Cough Syrup", "Dextromethorphan", "100 ml", "SYRUP"),
    (1, "DEMO-Insulin Glargine", "Insulin Glargine", "100 IU/ml", "INJECTION"),
    (2, "DEMO-Diclofenac Gel", "Diclofenac", "1%", "OINTMENT"),
    (3, "DEMO-Vitamin D3", "Cholecalciferol", "60000 IU", "CAPSULE"),
]

ORGS = [
    ("DEMO-Meridian Plant Depot", "MANUFACTURER_DEPOT"),
    ("DEMO-Northstar Distributors", "DISTRIBUTOR"),
    ("DEMO-Central Wholesale", "WHOLESALER"),
    ("DEMO-CareLine Pharmacies", "PHARMACY_CHAIN"),
    ("DEMO-Southern Logistics", "DISTRIBUTOR"),
    ("DEMO-Eastern Health Depot", "WHOLESALER"),
]

# (org_index, name, type, district)
FACILITIES = [
    (0, "DEMO-Meridian Plant Depot", "WAREHOUSE", "Bengaluru Urban"),
    (1, "DEMO-Northstar Bengaluru Hub", "WAREHOUSE", "Bengaluru Urban"),
    (2, "DEMO-Central Mysuru Warehouse", "WAREHOUSE", "Mysuru"),
    (3, "DEMO-CareLine City Pharmacy", "PHARMACY", "Bengaluru Urban"),
    (3, "DEMO-CareLine Jayanagar Pharmacy", "PHARMACY", "Bengaluru Urban"),
    (3, "DEMO-CareLine Mysuru Pharmacy", "PHARMACY", "Mysuru"),
    (4, "DEMO-Southern Mandya Depot", "WAREHOUSE", "Mandya"),
    (2, "DEMO-Central Hassan Warehouse", "WAREHOUSE", "Hassan"),
    (3, "DEMO-CareLine Hassan Pharmacy", "PHARMACY", "Hassan"),
    (4, "DEMO-Southern Tumakuru Depot", "WAREHOUSE", "Tumakuru"),
    (4, "DEMO-Southern Bengaluru Depot", "WAREHOUSE", "Bengaluru Urban"),
    (5, "DEMO-Eastern Mandya Depot", "WAREHOUSE", "Mandya"),
]

USERS = [
    ("alice.operator", "OPERATOR"),
    ("rita.recall", "RECALL_OFFICER"),
    ("victor.viewer", "VIEWER"),
]

# Batches per product, in product order. 40 batches total, B-101..B-140.
BATCHES_PER_PRODUCT = [4, 3, 3, 3, 4, 3, 4, 3, 3, 3, 3, 4]

SPECIAL_BATCHES = {"B-104", "B-107", "B-139", "B-140"}

RECALLS = [
    {
        "code": "R-01",
        "day_offset": -40,
        "reason": "Sub-potent dissolution profile found in stability testing",
        "class": "II",
        "status": "ACTIVE",
        "batches": ["B-113"],
        "advisory": "Stop distribution of batch B-113. Quarantine remaining units and await QA inspection.",
    },
    {
        "code": "R-02",
        "day_offset": -25,
        "reason": "Dissolution failure in retained samples; stop distribution",
        "class": "II",
        "status": "ACTIVE",
        "batches": ["B-104", "B-107"],
        "advisory": "Stop dispensing batches B-104 and B-107. Return all remaining stock to the distributor.",
    },
    {
        "code": "R-03",
        "day_offset": -15,
        "reason": "Label mix-up: wrong strength printed on carton",
        "class": "I",
        "status": "ACTIVE",
        "batches": ["B-124", "B-125"],
        "advisory": "Immediate quarantine of batches B-124 and B-125. Dispensing error may cause harm.",
    },
    {
        "code": "R-04",
        "day_offset": -90,
        "reason": "Minor packaging defect, corrected and closed",
        "class": "III",
        "status": "CLOSED",
        "batches": ["B-135"],
        "advisory": "Packaging defect corrected. Recall closed after stock reconciliation.",
    },
]


def _hash_password(password: str) -> str:
    return hash_password(password)


def seed_all(conn: mysql.connector.MySQLConnection) -> None:
    logs.reset_logs()
    rng = random.Random(20261105)
    today = date.today()

    # --- master data ------------------------------------------------------- #
    for name, licence in MANUFACTURERS:
        db.execute(conn, "INSERT INTO manufacturer (name, licence_no) VALUES (%s, %s)", (name, licence))

    for manufacturer_index, brand, generic, strength, form in PRODUCTS:
        db.execute(
            conn,
            """
            INSERT INTO medicine_product
              (manufacturer_id, brand_name, generic_name, strength, dosage_form)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (manufacturer_index + 1, brand, generic, strength, form),
        )

    batch_ids: dict[str, int] = {}
    batch_no = 101
    for product_index, count in enumerate(BATCHES_PER_PRODUCT, start=1):
        for _ in range(count):
            number = f"B-{batch_no}"
            batch_no += 1

            if number == "B-139":  # expiring within 30 days
                mfg = today - timedelta(days=400)
                expiry = today + timedelta(days=25)
            elif number == "B-140":  # already expired
                mfg = today - timedelta(days=600)
                expiry = today - timedelta(days=20)
            else:
                mfg = today - timedelta(days=rng.randint(90, 500))
                expiry = today + timedelta(days=rng.randint(150, 700))

            batch_ids[number] = db.execute(
                conn,
                """
                INSERT INTO medicine_batch (product_id, batch_no, mfg_date, expiry_date)
                VALUES (%s, %s, %s, %s)
                """,
                (product_index, number, mfg.isoformat(), expiry.isoformat()),
            )

    for org_name, org_type in ORGS:
        db.execute(
            conn,
            "INSERT INTO supply_org (org_name, org_type) VALUES (%s, %s)",
            (org_name, org_type),
        )

    for org_index, name, facility_type, district in FACILITIES:
        db.execute(
            conn,
            """
            INSERT INTO facility (org_id, facility_name, facility_type, district)
            VALUES (%s, %s, %s, %s)
            """,
            (org_index + 1, name, facility_type, district),
        )

    for username, role in USERS:
        assert not validate_password(DEMO_PASSWORD, username), "demo password breaks policy"
        db.execute(
            conn,
            "INSERT INTO app_user (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, _hash_password(DEMO_PASSWORD), role),
        )

    operator_id = db.query_scalar(
        conn, "SELECT user_id FROM app_user WHERE username = 'alice.operator'"
    )
    facility_ids = [row["facility_id"] for row in db.query_all(conn, "SELECT facility_id FROM facility")]

    ref_counter = 0

    def move(
        number: str,
        movement_type: str,
        quantity: int,
        day_offset: int,
        from_facility: int | None,
        to_facility: int | None,
    ) -> None:
        nonlocal ref_counter
        ref_counter += 1
        movement_id, error = record_movement(
            conn,
            batch_id=batch_ids[number],
            movement_type=movement_type,
            quantity=quantity,
            movement_date=(today + timedelta(days=day_offset)).isoformat(),
            reference_no=f"MV-{ref_counter:04d}",
            recorded_by=int(operator_id),
            from_facility_id=from_facility,
            to_facility_id=to_facility,
        )
        if error or movement_id is None:
            raise RuntimeError(f"Seed movement failed for {number}: {error}")

    # --- scenario 1 + 3: multi-hop recalled batch -------------------------- #
    move("B-104", "INITIAL_RECEIPT", 1200, -240, None, 1)
    move("B-104", "TRANSFER", 900, -220, 1, 2)
    move("B-104", "TRANSFER", 600, -200, 2, 3)
    move("B-104", "TRANSFER", 250, -180, 3, 4)
    move("B-104", "TRANSFER", 150, -170, 3, 5)
    move("B-104", "TRANSFER", 200, -160, 2, 6)
    # current: f1=300, f2=100, f3=200, f4=250, f5=150, f6=200

    # --- scenario 2: second batch in the same recall ----------------------- #
    move("B-107", "INITIAL_RECEIPT", 800, -230, None, 1)
    move("B-107", "TRANSFER", 600, -210, 1, 2)
    move("B-107", "TRANSFER", 400, -190, 2, 3)
    move("B-107", "TRANSFER", 200, -175, 3, 6)

    # --- scenario 4: expiry watch ------------------------------------------ #
    move("B-139", "INITIAL_RECEIPT", 900, -90, None, 2)
    move("B-139", "TRANSFER", 400, -60, 2, 6)
    move("B-139", "TRANSFER", 200, -50, 2, 9)

    move("B-140", "INITIAL_RECEIPT", 500, -200, None, 1)
    move("B-140", "TRANSFER", 300, -150, 1, 12)

    # --- the rest: partial-quantity chains --------------------------------- #
    for number in batch_ids:
        if number in SPECIAL_BATCHES:
            continue

        holdings: dict[int, int] = {}
        source = rng.choice(facility_ids)
        quantity = rng.choice([600, 800, 1000, 1200, 1500, 1800, 2400])
        offset = -rng.randint(250, 330)
        move(number, "INITIAL_RECEIPT", quantity, offset, None, source)
        holdings[source] = quantity

        for _ in range(rng.randint(3, 5)):
            offset += rng.randint(5, 30)
            if offset > -40:
                break
            sources = [facility_id for facility_id, qty in holdings.items() if qty > 0]
            if not sources:
                break
            src = rng.choice(sources)

            if rng.random() < 0.15:
                qty = min(holdings[src], max(1, int(holdings[src] * rng.uniform(0.05, 0.20))))
                move(number, "DAMAGE", qty, offset, src, None)
                holdings[src] -= qty
            else:
                dest = rng.choice([facility_id for facility_id in facility_ids if facility_id != src])
                qty = min(holdings[src], max(1, int(holdings[src] * rng.uniform(0.20, 0.60))))
                move(number, "TRANSFER", qty, offset, src, dest)
                holdings[src] -= qty
                holdings[dest] = holdings.get(dest, 0) + qty

    # --- recalls (created after movements) --------------------------------- #
    for spec in RECALLS:
        recall_id, error = create_recall(
            conn,
            recall_code=spec["code"],
            issued_date=(today + timedelta(days=spec["day_offset"])).isoformat(),
            reason=spec["reason"],
            recall_class=spec["class"],
            recall_status=spec["status"],
            batch_ids=[batch_ids[number] for number in spec["batches"]],
        )
        if error or recall_id is None:
            raise RuntimeError(f"Seed recall failed for {spec['code']}: {error}")

        notified_facility_ids = [
            row["facility_id"]
            for row in db.query_all(
                conn,
                "SELECT DISTINCT facility_id FROM v_recall_exposure WHERE recall_id = %s",
                (recall_id,),
            )
        ]
        logs.save_recall_notice(
            {
                "recall_id": recall_id,
                "recall_code": spec["code"],
                "issued_by": "DEMO-QA Officer",
                "advisory_text": spec["advisory"],
                "lab_reference": {
                    "lab": "DEMO-Analytical Lab",
                    "report_no": f"L-{5500 + recall_id}",
                    "finding": spec["reason"],
                },
                "notified_facility_ids": notified_facility_ids,
                "attachments": [f"notice_{spec['code'].replace('-', '')}.pdf"],
            }
        )

    # --- scenario 5 & 6 verification (PRD §11) ---------------------------- #
    _, err5 = record_movement(
        conn,
        batch_id=batch_ids["B-104"],
        movement_type="TRANSFER",
        quantity=999999,
        movement_date=today.isoformat(),
        reference_no="MV-TEST-OVERQTY",
        recorded_by=int(operator_id),
        from_facility_id=1,
        to_facility_id=2,
    )
    logs.log_audit(
        None, "MOVEMENT_RECORDED", "stock_movement", None,
        {"batch": "B-104", "qty": 999999, "type": "TRANSFER", "scenario": "Over-quantity rejection"},
        "REJECTED", err5
    )

    _, err6 = record_movement(
        conn,
        batch_id=batch_ids["B-104"],
        movement_type="TRANSFER",
        quantity=10,
        movement_date=today.isoformat(),
        reference_no="MV-TEST-RECALLBLOCKED",
        recorded_by=int(operator_id),
        from_facility_id=1,
        to_facility_id=2,
    )
    logs.log_audit(
        None, "MOVEMENT_RECORDED", "stock_movement", None,
        {"batch": "B-104", "qty": 10, "type": "TRANSFER", "scenario": "Recalled batch transfer blocked"},
        "REJECTED", err6
    )

    movement_count = db.query_scalar(conn, "SELECT COUNT(*) FROM stock_movement")
    logs.log_audit(
        None,
        "SEED_COMPLETED",
        "database",
        None,
        {
            "batches": 40,
            "movements": movement_count,
            "recalls": len(RECALLS),
            "note": "Synthetic seed loaded; every stock movement passed sp_record_movement.",
        },
        "OK",
    )

    print(
        "Seeded DrugTrace MySQL + MongoDB: "
        f"4 manufacturers, 12 products, 40 batches, 6 organisations, "
        f"12 facilities, 3 users, {movement_count} movements, 4 recalls."
    )
    _print_scenario_checks(conn)


def _print_scenario_checks(conn: mysql.connector.MySQLConnection) -> None:
    b104 = db.query_one(
        conn,
        """
        SELECT COUNT(DISTINCT facility_id) AS facilities,
               COUNT(DISTINCT district) AS districts
        FROM v_current_stock WHERE batch_no = 'B-104'
        """,
    )
    r02_batches = db.query_scalar(
        conn,
        """
        SELECT COUNT(*) FROM recall r
        JOIN recall_affected_batch rab ON rab.recall_id = r.recall_id
        WHERE r.recall_code = 'R-02'
        """,
    )
    expired = db.query_one(
        conn, "SELECT days_left FROM v_expiry_watch WHERE batch_no = 'B-140' LIMIT 1"
    )
    soon = db.query_scalar(
        conn, "SELECT MIN(days_left) FROM v_expiry_watch WHERE batch_no = 'B-139'"
    )

    print(
        "Scenario checks: "
        f"B-104 at {b104['facilities'] if b104 else 0} facilities / "
        f"{b104['districts'] if b104 else 0} districts; "
        f"R-02 covers {r02_batches} batches; "
        f"B-140 days_left={expired['days_left'] if expired else 'no stock'}; "
        f"B-139 days_left={soon}."
    )
