"""MySQL 8 connection helpers for the DrugTrace prototype."""

from __future__ import annotations

from typing import Any, Sequence

import mysql.connector
from flask import g

import config
from mysql_schema import STATEMENTS


def _base_config(database: bool = True) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "host": config.MYSQL_HOST,
        "port": config.MYSQL_PORT,
        "user": config.MYSQL_USER,
        "password": config.MYSQL_PASSWORD,
        "charset": "utf8mb4",
        "autocommit": True,
        "connection_timeout": 8,
    }
    if database:
        cfg["database"] = config.MYSQL_DATABASE
    return cfg


def connect(database: bool = True) -> mysql.connector.MySQLConnection:
    return mysql.connector.connect(**_base_config(database))


def server_connect() -> mysql.connector.MySQLConnection:
    """Connect without selecting a database."""
    return connect(database=False)


def get_db() -> mysql.connector.MySQLConnection:
    if "db" not in g or not g.db.is_connected():
        g.db = connect()
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None and db.is_connected():
        db.close()


# --------------------------------------------------------------------------- #
# Query helpers
# --------------------------------------------------------------------------- #
def query_all(
    conn: mysql.connector.MySQLConnection, sql: str, params: Sequence[Any] = ()
) -> list[dict[str, Any]]:
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql, params)
        return list(cursor.fetchall())
    finally:
        cursor.close()


def query_one(
    conn: mysql.connector.MySQLConnection, sql: str, params: Sequence[Any] = ()
) -> dict[str, Any] | None:
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(sql, params)
        return cursor.fetchone()
    finally:
        cursor.close()


def query_scalar(
    conn: mysql.connector.MySQLConnection,
    sql: str,
    params: Sequence[Any] = (),
    default: Any = None,
) -> Any:
    cursor = conn.cursor()
    try:
        cursor.execute(sql, params)
        row = cursor.fetchone()
        return row[0] if row is not None else default
    finally:
        cursor.close()


def execute(
    conn: mysql.connector.MySQLConnection, sql: str, params: Sequence[Any] = ()
) -> int:
    """Run a write and return lastrowid (or rowcount when lastrowid is 0)."""
    cursor = conn.cursor()
    try:
        cursor.execute(sql, params)
        return cursor.lastrowid or cursor.rowcount
    finally:
        cursor.close()


# --------------------------------------------------------------------------- #
# Bootstrap
# --------------------------------------------------------------------------- #
def is_initialized(conn: mysql.connector.MySQLConnection) -> bool:
    count = query_scalar(
        conn,
        """
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = %s AND table_name = 'stock_movement'
        """,
        (config.MYSQL_DATABASE,),
        default=0,
    )
    return bool(count)


def create_schema(conn: mysql.connector.MySQLConnection) -> None:
    cursor = conn.cursor()
    try:
        for statement in STATEMENTS:
            cursor.execute(statement)
    finally:
        cursor.close()


def reset_database() -> None:
    """DROP and recreate the configured database (DDL only, no seed)."""
    server = server_connect()
    try:
        cursor = server.cursor()
        try:
            cursor.execute(f"DROP DATABASE IF EXISTS `{config.MYSQL_DATABASE}`")
            cursor.execute(
                f"CREATE DATABASE `{config.MYSQL_DATABASE}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
            )
        finally:
            cursor.close()
    finally:
        server.close()


def setup_roles(server: mysql.connector.MySQLConnection) -> None:
    """Create roles and nl_reader user if missing."""
    cursor = server.cursor()
    try:
        # Create roles if supported
        try:
            cursor.execute("CREATE ROLE IF NOT EXISTS r_app, r_nl")
            cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.* TO r_app")
            cursor.execute(f"GRANT EXECUTE ON PROCEDURE `{config.MYSQL_DATABASE}`.sp_record_movement TO r_app")
            cursor.execute(f"GRANT INSERT ON `{config.MYSQL_DATABASE}`.recall TO r_app")
            cursor.execute(f"GRANT INSERT ON `{config.MYSQL_DATABASE}`.recall_affected_batch TO r_app")

            cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_current_stock TO r_nl")
            cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_batch_timeline TO r_nl")
            cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_recall_exposure TO r_nl")
            cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_expiry_watch TO r_nl")
            cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_batches TO r_nl")
        except mysql.connector.Error:
            pass  # Roles might not be supported or already granted

        # Setup nl_reader user for localhost and %
        nl_user = config.NL_READER_USER
        nl_pass = config.NL_READER_PASSWORD
        for host in ("localhost", "%", "127.0.0.1"):
            try:
                if nl_pass:
                    cursor.execute(f"CREATE USER IF NOT EXISTS '{nl_user}'@'{host}' IDENTIFIED BY %s", (nl_pass,))
                    cursor.execute(f"ALTER USER '{nl_user}'@'{host}' IDENTIFIED BY %s", (nl_pass,))
                else:
                    cursor.execute(f"CREATE USER IF NOT EXISTS '{nl_user}'@'{host}'")
                
                # Try granting role first, fallback to direct view SELECT
                try:
                    cursor.execute(f"GRANT r_nl TO '{nl_user}'@'{host}'")
                    cursor.execute(f"SET DEFAULT ROLE r_nl FOR '{nl_user}'@'{host}'")
                except mysql.connector.Error:
                    cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_current_stock TO '{nl_user}'@'{host}'")
                    cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_batch_timeline TO '{nl_user}'@'{host}'")
                    cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_recall_exposure TO '{nl_user}'@'{host}'")
                    cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_expiry_watch TO '{nl_user}'@'{host}'")
                    cursor.execute(f"GRANT SELECT ON `{config.MYSQL_DATABASE}`.v_batches TO '{nl_user}'@'{host}'")
            except mysql.connector.Error:
                pass
        try:
            cursor.execute("FLUSH PRIVILEGES")
        except mysql.connector.Error:
            pass
    finally:
        cursor.close()


def ensure_db() -> None:
    """Create the database/schema and seed it on first run."""
    try:
        server = server_connect()
    except mysql.connector.Error as exc:
        raise RuntimeError(
            "Cannot reach MySQL at "
            f"{config.MYSQL_HOST}:{config.MYSQL_PORT} as {config.MYSQL_USER}. "
            "Start the local MySQL instance (see README.md) and retry."
        ) from exc

    try:
        cursor = server.cursor()
        try:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{config.MYSQL_DATABASE}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
            )
        finally:
            cursor.close()
        setup_roles(server)
    finally:
        server.close()

    conn = connect()
    try:
        if not is_initialized(conn):
            create_schema(conn)
            from seed import seed_all  # avoids a circular import

            seed_all(conn)
    finally:
        conn.close()
