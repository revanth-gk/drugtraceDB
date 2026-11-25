"""Initialise or reset the DrugTrace MySQL + MongoDB prototype.

Usage:
  python init_db.py           # create/seed if missing
  python init_db.py --reset   # drop the MySQL database + Mongo logs, reseed
"""

from __future__ import annotations

import argparse

import config
import db
import logs


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialise the DrugTrace prototype database")
    parser.add_argument("--reset", action="store_true", help="drop existing data and reseed")
    args = parser.parse_args()

    logs.ensure_ready()

    if args.reset:
        db.reset_database()
        print(f"Dropped and recreated MySQL database `{config.MYSQL_DATABASE}`.")

    db.ensure_db()

    conn = db.connect()
    try:
        counts = {
            "batches": db.query_scalar(conn, "SELECT COUNT(*) FROM medicine_batch"),
            "movements": db.query_scalar(conn, "SELECT COUNT(*) FROM stock_movement"),
            "recalls": db.query_scalar(conn, "SELECT COUNT(*) FROM recall"),
        }
    finally:
        conn.close()

    print(
        f"MySQL ready at {config.MYSQL_HOST}:{config.MYSQL_PORT}/"
        f"{config.MYSQL_DATABASE} (user {config.MYSQL_USER})."
    )
    print(f"MongoDB ready at {config.MONGO_URI} (database {config.MONGO_DATABASE}).")
    print(
        f"Tables: {counts['batches']} batches, {counts['movements']} movements, "
        f"{counts['recalls']} recalls."
    )


if __name__ == "__main__":
    main()
