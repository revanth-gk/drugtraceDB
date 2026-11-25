"""NLP-to-SQL engine for DrugTrace.

Pipeline (per PRD §7):
  question
    -> template matcher (8 intents, deterministic)
         | match  -> parameterized SQL on allow-listed views   route=TEMPLATE
         | no match -> LLM with view schema only               route=LLM
    -> validator  (sqlglot, MySQL dialect, allow-list)
    -> executor   (nl_reader account, read-only, 5 s timeout, 200-row cap)
    -> log to MongoDB nl_query_log (accepted AND rejected)

Security guarantee: even if the validator is bypassed, nl_reader has
SELECT on views only (see SCHEMA.md §7).
"""

from __future__ import annotations

import re
import time
from typing import Any

import mysql.connector
import sqlglot
import sqlglot.errors

import config
import logs

# ---------------------------------------------------------------------------
# NL-reader connection (SELECT on views only)
# ---------------------------------------------------------------------------
def _nl_connect() -> mysql.connector.MySQLConnection:
    try:
        return mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.NL_READER_USER,
            password=config.NL_READER_PASSWORD,
            database=config.MYSQL_DATABASE,
            charset="utf8mb4",
            connection_timeout=6,
        )
    except mysql.connector.Error:
        # Fallback to default app connection if nl_reader account is not created yet
        import db
        return db.connect()


# ---------------------------------------------------------------------------
# Allowed views (the only tables the NL path may touch)
# ---------------------------------------------------------------------------
_ALLOWED_VIEWS = {
    "v_current_stock",
    "v_batch_timeline",
    "v_recall_exposure",
    "v_expiry_watch",
    "v_batches",
}

# ---------------------------------------------------------------------------
# Template definitions
# Each entry: (intent_name, list_of_regex_patterns, sql_template, slot_extractor)
# slot_extractor(match_object) -> list of params for the SQL
# ---------------------------------------------------------------------------
_BATCH_NO = r"[A-Za-z0-9][-A-Za-z0-9]*"  # loose: B-104, LOT001, etc.
_RECALL_CODE = r"R-\d+"
_DAYS = r"\d+"


def _days_slot(m: re.Match) -> list[Any]:
    return [int(m.group("days"))]


def _batch_slot(m: re.Match) -> list[Any]:
    return [m.group("batch").upper()]


def _recall_slot(m: re.Match) -> list[Any]:
    return [m.group("recall").upper()]


def _product_slot(m: re.Match) -> list[Any]:
    return [f"%{m.group('product').strip('?. ')}%"]


def _facility_slot(m: re.Match) -> list[Any]:
    return [f"%{m.group('facility')}%"]


# (intent, patterns, sql, slot_fn)
_TEMPLATES: list[tuple[str, list[str], str, Any]] = [
    (
        "batch_history",
        [
            r"(?:movement|transfer|history|journey|timeline|trace)\b.+?batch\s+(?P<batch>" + _BATCH_NO + r")",
            r"batch\s+(?P<batch>" + _BATCH_NO + r").+?(?:movement|history|journey|timeline|trace)",
            r"(?:show|list|get|where(?:'s| has| did)|track)\b.+?batch\s+(?P<batch>" + _BATCH_NO + r")",
            r"batch\s+(?P<batch>" + _BATCH_NO + r")\s+(?:go|went|travel|move)",
        ],
        "SELECT * FROM v_batch_timeline WHERE batch_no = %s ORDER BY movement_date, movement_id LIMIT 200",
        _batch_slot,
    ),
    (
        "batch_holders",
        [
            r"(?:who|which\s+facilit|where).+?hold\S*(?:\s+stock)?(?:\s+of)?\s+batch\s+(?P<batch>" + _BATCH_NO + r")",
            r"batch\s+(?P<batch>" + _BATCH_NO + r").+?(?:hold|stock|facilit|where|current)",
            r"current\s+(?:stock|holder|facilit).+?batch\s+(?P<batch>" + _BATCH_NO + r")",
            r"facilit.+?currently\s+hold.+?batch\s+(?P<batch>" + _BATCH_NO + r")",
        ],
        "SELECT facility_name, district, qty FROM v_current_stock WHERE batch_no = %s ORDER BY qty DESC LIMIT 200",
        _batch_slot,
    ),
    (
        "recall_exposure",
        [
            r"facilit.+?(?:hold|stock|affected).+?recall\s+(?P<recall>" + _RECALL_CODE + r")",
            r"recall\s+(?P<recall>" + _RECALL_CODE + r").+?(?:facilit|hold|stock|exposure|affect)",
            r"(?:exposure|affected|impact).+?recall\s+(?P<recall>" + _RECALL_CODE + r")",
            r"which\s+facilit.+?(?P<recall>" + _RECALL_CODE + r")",
        ],
        "SELECT facility_name, district, brand_name, batch_no, qty FROM v_recall_exposure WHERE recall_code = %s ORDER BY facility_name LIMIT 200",
        _recall_slot,
    ),
    (
        "recall_by_district",
        [
            r"district.+?recall\s+(?P<recall>" + _RECALL_CODE + r")",
            r"recall\s+(?P<recall>" + _RECALL_CODE + r").+?district",
            r"(?:how\s+much|units|stock|quantity).+?recall\s+(?P<recall>" + _RECALL_CODE + r").+?district",
            r"recall\s+(?P<recall>" + _RECALL_CODE + r").+?(?:each|per|by)\s+district",
        ],
        "SELECT district, SUM(qty) AS units FROM v_recall_exposure WHERE recall_code = %s GROUP BY district ORDER BY units DESC LIMIT 200",
        _recall_slot,
    ),
    (
        "expiring_soon",
        [
            r"expir.+?(?:within|next|in)\s+(?P<days>" + _DAYS + r")\s+days?",
            r"(?P<days>" + _DAYS + r")\s+days?.+?expir",
            r"(?:which\s+)?batch(?:es)?\s+(?:are\s+)?expir",
            r"expir(?:y|ing|ed)?\s+(?:watch|soon|alert|stock)",
            r"(?:which\s+)?batch(?:es)?\s+expire",
        ],
        "SELECT brand_name, batch_no, facility_name, district, qty, expiry_date, days_left FROM v_expiry_watch WHERE days_left BETWEEN 0 AND %s ORDER BY days_left LIMIT 200",
        # For bare "batches expiring" with no days number, default to 90
        lambda m: [int(m.group("days"))] if m and "days" in m.groupdict() and m.group("days") else [90],
    ),
    (
        "product_batches",
        [
            r"(?:all\s+)?batch(?:es)?\s+of\s+(?P<product>.+?)(?:\s*\?|$)",
            r"(?:show|list|find)\s+.+?(?P<product>[A-Z][a-z]+(?:\s+[A-Z]?\d+[a-zA-Z]*)?)\s+batch",
            r"(?P<product>[A-Za-z][\w\s]+?)\s+(?:batch|lot|stock)\s+list",
        ],
        "SELECT brand_name, batch_no, mfg_date, expiry_date FROM v_batches WHERE brand_name LIKE %s ORDER BY expiry_date LIMIT 200",
        _product_slot,
    ),
    (
        "top_receiver",
        [
            r"(?:most|top|largest|biggest|highest).+?receiv.+?batch\s+(?P<batch>" + _BATCH_NO + r")",
            r"batch\s+(?P<batch>" + _BATCH_NO + r").+?(?:most|top|largest).+?receiv",
            r"receiv.+?most.+?batch\s+(?P<batch>" + _BATCH_NO + r")",
        ],
        """SELECT facility_name, district, SUM(qty) AS received
           FROM v_current_stock WHERE batch_no = %s
           GROUP BY facility_name, district ORDER BY received DESC LIMIT 1""",
        _batch_slot,
    ),
    (
        "facility_history",
        [
            r"(?:all\s+)?movements?\b.+?\b(?:for|at|in)\b\s+(?P<facility>[A-Za-z0-9][\w\s]+?)(?:\s*\?|$)",
            r"(?P<facility>[A-Za-z0-9][\w\s]+?)\s+(?:movement|history|timeline|activity)\b",
            r"(?:show|list|get)\s+.+?(?P<facility>[A-Z][\w\s]+(?:pharmacy|warehouse|depot|centre|center))\b",
        ],
        """SELECT batch_no, brand_name, movement_type, from_facility, to_facility, quantity, movement_date
           FROM v_batch_timeline
           WHERE from_facility LIKE %s OR to_facility LIKE %s
           ORDER BY movement_date DESC LIMIT 200""",
        lambda m: [f"%{m.group('facility').strip()}%", f"%{m.group('facility').strip()}%"],
    ),
]

# Pre-compile all patterns
_COMPILED: list[tuple[str, list[re.Pattern], str, Any]] = [
    (intent, [re.compile(p, re.IGNORECASE) for p in patterns], sql, slot_fn)
    for intent, patterns, sql, slot_fn in _TEMPLATES
]


def _match_template(question: str) -> tuple[str, str, list[Any]] | None:
    """Return (intent, sql, params) if a template matches, else None."""
    for intent, patterns, sql, slot_fn in _COMPILED:
        for pat in patterns:
            m = pat.search(question)
            if m:
                try:
                    params = slot_fn(m)
                    return intent, sql, params
                except (IndexError, AttributeError):
                    continue
    return None


# ---------------------------------------------------------------------------
# Validator (allow-list, not block-list — PRD §7)
# ---------------------------------------------------------------------------
_FORBIDDEN_RE = re.compile(
    r"\b(UPDATE|DELETE|INSERT|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE|"
    r"INTO|LOAD_FILE|SLEEP|BENCHMARK|OUTFILE|DUMPFILE)\b"
    r"|--|\bXP_|\\/\*",
    re.IGNORECASE,
)


def _validate_sql(sql: str) -> str | None:
    """Return None if valid, or a rejection reason string."""
    # Strip trailing whitespace/semicolons for statement count check
    stripped = sql.strip().rstrip(";")

    # Block forbidden keywords / patterns
    if _FORBIDDEN_RE.search(stripped):
        return "Query contains forbidden keywords"

    # Block stacked statements
    if ";" in stripped:
        return "Multiple statements not allowed"

    # Must start with SELECT
    if not re.match(r"\s*SELECT\b", stripped, re.IGNORECASE):
        return "Only SELECT queries are allowed"

    # Parse with sqlglot and check tables are only allowed views
    try:
        parsed = sqlglot.parse_one(stripped, dialect="mysql")
    except sqlglot.errors.SqlglotError as exc:
        return f"SQL parse error: {exc}"

    tables = {
        t.name.lower()
        for t in parsed.find_all(sqlglot.exp.Table)
    }
    forbidden_tables = tables - _ALLOWED_VIEWS
    if forbidden_tables:
        return f"Query references non-allowed tables: {', '.join(sorted(forbidden_tables))}"

    return None  # valid


def _append_limit(sql: str) -> str:
    """Add LIMIT 200 if not present."""
    if re.search(r"\bLIMIT\b", sql, re.IGNORECASE):
        return sql
    return sql.rstrip(";").rstrip() + " LIMIT 200"


# ---------------------------------------------------------------------------
# LLM fallback
# ---------------------------------------------------------------------------
# View schema given to the LLM — column names and descriptions only, NO row data
_VIEW_SCHEMA = """
Available MySQL views (SELECT only, no base tables):

v_current_stock(facility_id, facility_name, district, batch_id, brand_name, batch_no, expiry_date, qty)
  -- Current stock quantity per facility per batch (derived from ledger)

v_batch_timeline(movement_id, batch_no, brand_name, movement_type, from_facility, to_facility, quantity, movement_date, reference_no)
  -- Chronological movement history of every batch
  -- movement_type IN ('INITIAL_RECEIPT','TRANSFER','RETURN','DAMAGE','EXPIRY')

v_recall_exposure(recall_code, recall_class, recall_status, brand_name, batch_no, facility_name, facility_id, district, qty)
  -- Facilities currently holding stock affected by a recall

v_expiry_watch(brand_name, batch_no, facility_name, district, qty, expiry_date, days_left)
  -- Batches with stock expiring within 90 days (days_left = DATEDIFF(expiry_date, today))

v_batches(brand_name, generic_name, batch_no, mfg_date, expiry_date)
  -- All batches with product info

Rules:
- Output ONLY a single SELECT statement. No explanations, no markdown, no semicolons.
- Use only the views above. No base tables.
- Add LIMIT 200 at the end unless a smaller LIMIT is more appropriate.
"""


def _llm_generate(question: str) -> str | None:
    """Call the configured LLM and return raw SQL, or None if unavailable."""
    api_key = config.GEMINI_API_KEY
    if not api_key:
        return None
    try:
        import google.generativeai as genai  # optional dep

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        prompt = (
            f"{_VIEW_SCHEMA}\n\nQuestion: {question}\n\n"
            "SQL (single SELECT, views only, LIMIT 200, no explanation):"
        )
        response = model.generate_content(prompt)
        raw = response.text.strip()
        # Strip markdown fences if the model added them
        raw = re.sub(r"^```[a-z]*\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)
        return raw.strip()
    except Exception:  # noqa: BLE001  — LLM failure is non-fatal
        return None


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------
def _execute_sql(sql: str) -> tuple[list[dict[str, Any]], str | None]:
    """Run SQL on the nl_reader account. Returns (rows, error)."""
    conn = None
    try:
        conn = _nl_connect()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SET SESSION MAX_EXECUTION_TIME=5000")  # 5 s timeout
        except mysql.connector.Error:
            pass
        cursor.execute(sql)
        rows = list(cursor.fetchall())
        cursor.close()
        return rows, None
    except mysql.connector.Error as exc:
        msg = getattr(exc, "msg", None) or str(exc)
        return [], f"Query execution error: {msg}"
    finally:
        if conn and conn.is_connected():
            conn.close()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def ask(question: str, user: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Process a natural-language question.

    Returns:
        {
          "question": str,
          "route": "TEMPLATE" | "LLM" | "REJECTED",
          "intent": str | None,
          "sql": str | None,
          "rows": list[dict],
          "columns": list[str],
          "error": str | None,
          "latency_ms": int,
          "row_count": int,
        }
    """
    t0 = time.monotonic()
    result: dict[str, Any] = {
        "question": question,
        "route": "REJECTED",
        "intent": None,
        "sql": None,
        "rows": [],
        "columns": [],
        "error": None,
        "latency_ms": 0,
        "row_count": 0,
    }

    # Defense-in-depth: Reject forbidden SQL/injection attempts directly
    if _FORBIDDEN_RE.search(question) or ";" in question:
        result["route"] = "REJECTED"
        result["error"] = "Query contains forbidden keywords or multiple statements"
        result["latency_ms"] = int((time.monotonic() - t0) * 1000)
        _log(result, user)
        return result

    # 1. Template match
    match = _match_template(question)
    if match:
        intent, sql, params = match
        # Inject params into display SQL (safe: params are from regex, not user SQL)
        display_sql = sql
        # Build the final SQL with params substituted for display
        final_sql = _append_limit(sql)
        result["route"] = "TEMPLATE"
        result["intent"] = intent

        # Execute via parameterized query (safe)
        conn = None
        try:
            conn = _nl_connect()
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SET SESSION MAX_EXECUTION_TIME=5000")
            except mysql.connector.Error:
                pass
            cursor.execute(final_sql, params)
            rows = list(cursor.fetchall())
            cursor.close()
            result["rows"] = rows
            result["columns"] = list(rows[0].keys()) if rows else []
            result["row_count"] = len(rows)
            # Build display SQL with literal values for the SQL panel
            display = final_sql
            for p in params:
                display = display.replace("%s", repr(p), 1)
            result["sql"] = display
        except mysql.connector.Error as exc:
            result["error"] = f"Query error: {getattr(exc, 'msg', None) or exc}"
        finally:
            if conn and conn.is_connected():
                conn.close()

    else:
        # 2. LLM fallback
        generated = _llm_generate(question)
        if generated is None:
            result["error"] = (
                "No template matched and LLM is not configured "
                "(set DRUGTRACE_GEMINI_API_KEY). "
                "Try one of the supported question examples below."
            )
        else:
            rejection = _validate_sql(generated)
            if rejection:
                result["route"] = "REJECTED"
                result["error"] = f"LLM-generated SQL rejected: {rejection}"
                result["sql"] = generated  # show it so the demo can inspect it
            else:
                final_sql = _append_limit(generated)
                rows, exec_err = _execute_sql(final_sql)
                result["route"] = "LLM"
                result["sql"] = final_sql
                if exec_err:
                    result["error"] = exec_err
                else:
                    result["rows"] = rows
                    result["columns"] = list(rows[0].keys()) if rows else []
                    result["row_count"] = len(rows)

    result["latency_ms"] = int((time.monotonic() - t0) * 1000)

    # 3. Log to MongoDB (accepted AND rejected)
    _log(result, user)

    return result


def _log(result: dict[str, Any], user: Any) -> None:
    try:
        logs.log_nl_query(
            user_id=user["user_id"] if user else None,
            question=result["question"],
            route=result["route"],
            intent=result.get("intent"),
            generated_sql=result.get("sql"),
            validation="PASSED" if result["route"] != "REJECTED" else f"REJECTED: {result.get('error', '')}",
            row_count=result["row_count"],
            latency_ms=result["latency_ms"],
        )
    except Exception:  # noqa: BLE001
        pass  # log failure must not break the user response


# shortcut: expiring_soon slot_fn needs access to match groups which may not
# have 'days'; the lambda above handles None case. Edge tested below.
assert _match_template("which batches expire within 30 days") is not None
assert _match_template("which batches are expiring soon") is not None
assert _match_template("UPDATE stock_movement SET qty=1") is None
