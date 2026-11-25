"""DrugTrace bare-bones prototype (NLP-to-SQL intentionally excluded).

Screens:
  Overview, Batch Explorer, Recall Investigation, Record Movement,
  New Recall, Audit Log.

Run:
  python app.py     -> http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import re
from datetime import date
from functools import wraps
from typing import Any, Callable

import bcrypt
import mysql.connector
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from pymongo.errors import PyMongoError

import db
import logs
from db import close_db, ensure_db, get_db, query_all, query_one, query_scalar
from movements import record_movement
from nlp import ask as nl_ask
from recalls import create_recall

app = Flask(__name__)
app.secret_key = os.environ.get("DRUGTRACE_SECRET", "drugtrace-dev-secret-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200/day"])

ensure_db()
try:
    logs.ensure_ready()
except PyMongoError as exc:
    raise RuntimeError(
        "Cannot reach MongoDB. Start the MongoDB service (or set "
        "DRUGTRACE_MONGO_URI in .env) and retry."
    ) from exc


# --------------------------------------------------------------------------- #
# Request lifecycle / auth
# --------------------------------------------------------------------------- #
@app.teardown_appcontext
def _teardown(_exc: BaseException | None) -> None:
    close_db(_exc)


@app.before_request
def _load_user() -> None:
    user_id = session.get("user_id")
    g.user = (
        query_one(get_db(), "SELECT * FROM app_user WHERE user_id = %s", (user_id,))
        if user_id
        else None
    )


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def roles_required(*roles: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                flash(
                    f"Role {g.user['role']} is not allowed to do that. "
                    f"Required: {', '.join(roles)}.",
                    "error",
                )
                return redirect(url_for("overview"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _next_reference(conn: mysql.connector.MySQLConnection) -> str:
    number = (query_scalar(conn, "SELECT COUNT(*) FROM stock_movement") or 0) + 1
    while query_one(
        conn, "SELECT 1 FROM stock_movement WHERE reference_no = %s", (f"MV-{number:04d}",)
    ):
        number += 1
    return f"MV-{number:04d}"


def _next_recall_code(conn: mysql.connector.MySQLConnection) -> str:
    number = (query_scalar(conn, "SELECT COUNT(*) FROM recall") or 0) + 1
    while query_one(conn, "SELECT 1 FROM recall WHERE recall_code = %s", (f"R-{number:02d}",)):
        number += 1
    return f"R-{number:02d}"


def _movement_context(form: Any = None) -> dict[str, Any]:
    conn = get_db()
    batches = query_all(
        conn,
        """
        SELECT b.batch_id, b.batch_no, b.expiry_date, p.brand_name, p.strength,
               COALESCE((SELECT SUM(cs.qty) FROM v_current_stock cs
                         WHERE cs.batch_id = b.batch_id), 0) AS total_stock
        FROM medicine_batch b
        JOIN medicine_product p ON p.product_id = b.product_id
        ORDER BY p.brand_name, b.batch_no
        """,
    )
    facilities = query_all(
        conn,
        "SELECT facility_id, facility_name, district FROM facility ORDER BY facility_name",
    )
    return {
        "batches": batches,
        "facilities": facilities,
        "today": date.today().isoformat(),
        "suggested_reference": _next_reference(conn),
        "form": form or {},
    }


def _recall_context(form: Any = None, selected: set[int] | None = None) -> dict[str, Any]:
    conn = get_db()
    batches = query_all(
        conn,
        """
        SELECT b.batch_id, b.batch_no, b.expiry_date, p.brand_name, p.strength,
               COALESCE((SELECT SUM(cs.qty) FROM v_current_stock cs
                         WHERE cs.batch_id = b.batch_id), 0) AS total_stock
        FROM medicine_batch b
        JOIN medicine_product p ON p.product_id = b.product_id
        ORDER BY p.brand_name, b.batch_no
        """,
    )
    return {
        "batches": batches,
        "today": date.today().isoformat(),
        "suggested_code": _next_recall_code(conn),
        "selected": selected or set(),
        "form": form or {},
    }


# --------------------------------------------------------------------------- #
# Auth routes
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login() -> Any:
    if g.user is not None:
        return redirect(url_for("overview"))

    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_one(get_db(), "SELECT * FROM app_user WHERE username = %s", (username,))

        valid = False
        if user is not None:
            try:
                valid = bcrypt.checkpw(
                    password.encode("utf-8"), user["password_hash"].encode("utf-8")
                )
            except ValueError:
                valid = False

        if valid:
            session.clear()
            session["user_id"] = user["user_id"]
            flash(f"Signed in as {user['username']} ({user['role']}).", "success")
            return redirect(url_for("overview"))

        logs.log_audit(
            user,
            "LOGIN_ATTEMPT",
            "app_user",
            user["user_id"] if user else None,
            {"username": username},
            "REJECTED",
            "Invalid username or password",
        )
        flash("Invalid username or password.", "error")

    return render_template("login.html", username=username)


@app.post("/logout")
@login_required
def logout() -> Any:
    session.clear()
    flash("Signed out.", "info")
    return redirect(url_for("login"))


_SQL_KEYWORDS = {"SELECT", "DROP", "INSERT", "DELETE", "UPDATE", "ALTER", "UNION", "OR", "AND", "EXEC", "TRUNCATE"}


@app.route("/admin/users", methods=["GET", "POST"])
@roles_required("RECALL_OFFICER")
def admin_users() -> Any:
    conn = get_db()
    if request.method == "POST":
        action = request.form.get("action", "").strip()
        if action == "create":
            new_username = request.form.get("username", "").strip()
            new_password = request.form.get("password", "")
            new_role = request.form.get("role", "").strip().upper()

            if not re.match(r"^[a-zA-Z0-9_-]{3,30}$", new_username):
                flash("Username must be 3-30 alphanumeric characters, hyphens or underscores.", "error")
                return redirect(url_for("admin_users"))
            if any(kw in new_username.upper().split() or kw == new_username.upper() for kw in _SQL_KEYWORDS):
                flash("Username contains reserved keywords.", "error")
                return redirect(url_for("admin_users"))
            if len(new_password) < 8 or not re.search(r"[\d\W_]", new_password):
                flash("Password must be at least 8 characters with at least one digit or symbol.", "error")
                return redirect(url_for("admin_users"))
            if new_role not in ("OPERATOR", "RECALL_OFFICER", "VIEWER"):
                flash("Invalid role specified.", "error")
                return redirect(url_for("admin_users"))

            existing = query_one(conn, "SELECT 1 FROM app_user WHERE username = %s", (new_username,))
            if existing:
                flash(f"User '{new_username}' already exists.", "error")
                return redirect(url_for("admin_users"))

            pw_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            user_id = db.execute(
                conn,
                "INSERT INTO app_user (username, password_hash, role) VALUES (%s, %s, %s)",
                (new_username, pw_hash, new_role),
            )
            logs.log_audit(g.user, "USER_CREATED", "app_user", user_id, {"username": new_username, "role": new_role}, "OK")
            flash(f"User '{new_username}' created as {new_role}.", "success")
            return redirect(url_for("admin_users"))

        elif action == "change_role":
            target_id = request.form.get("user_id", "").strip()
            new_role = request.form.get("role", "").strip().upper()
            if new_role not in ("OPERATOR", "RECALL_OFFICER", "VIEWER"):
                flash("Invalid role.", "error")
                return redirect(url_for("admin_users"))
            db.execute(conn, "UPDATE app_user SET role = %s WHERE user_id = %s", (new_role, target_id))
            logs.log_audit(g.user, "USER_ROLE_CHANGED", "app_user", int(target_id), {"new_role": new_role}, "OK")
            flash(f"Role updated to {new_role}.", "success")
            return redirect(url_for("admin_users"))

        elif action == "reset_password":
            target_id = request.form.get("user_id", "").strip()
            new_password = request.form.get("password", "")
            if len(new_password) < 8 or not re.search(r"[\d\W_]", new_password):
                flash("Password must be at least 8 characters with at least one digit or symbol.", "error")
                return redirect(url_for("admin_users"))
            pw_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            db.execute(conn, "UPDATE app_user SET password_hash = %s WHERE user_id = %s", (pw_hash, target_id))
            logs.log_audit(g.user, "USER_PASSWORD_RESET", "app_user", int(target_id), {}, "OK")
            flash("Password reset successfully.", "success")
            return redirect(url_for("admin_users"))

        elif action == "delete":
            target_id = request.form.get("user_id", "").strip()
            if str(g.user["user_id"]) == target_id:
                flash("Cannot delete your own account.", "error")
                return redirect(url_for("admin_users"))
            db.execute(conn, "DELETE FROM app_user WHERE user_id = %s", (target_id,))
            logs.log_audit(g.user, "USER_DELETED", "app_user", int(target_id), {}, "OK")
            flash("User deleted.", "info")
            return redirect(url_for("admin_users"))

    users = query_all(conn, "SELECT user_id, username, role FROM app_user ORDER BY username")
    return render_template("admin_users.html", users=users)


# --------------------------------------------------------------------------- #
# Overview
# --------------------------------------------------------------------------- #
@app.get("/")
@login_required
def overview() -> Any:
    conn = get_db()
    stats = {
        "batches": query_scalar(conn, "SELECT COUNT(*) FROM medicine_batch"),
        "active_recalls": query_scalar(
            conn, "SELECT COUNT(*) FROM recall WHERE recall_status = 'ACTIVE'"
        ),
        "exposed_facilities": query_scalar(
            conn,
            """
            SELECT COUNT(DISTINCT facility_id) FROM v_recall_exposure
            WHERE recall_status = 'ACTIVE'
            """,
        ),
        "expiring_60": query_scalar(
            conn,
            """
            SELECT COUNT(DISTINCT batch_no) FROM v_expiry_watch
            WHERE days_left BETWEEN 0 AND 60
            """,
        ),
    }
    active_recalls = query_all(
        conn,
        """
        SELECT r.*,
               (SELECT COUNT(*) FROM recall_affected_batch rab
                WHERE rab.recall_id = r.recall_id) AS batch_count,
               COALESCE((SELECT SUM(e.qty) FROM v_recall_exposure e
                         WHERE e.recall_id = r.recall_id), 0) AS exposed_units
        FROM recall r
        WHERE r.recall_status = 'ACTIVE'
        ORDER BY r.issued_date DESC, r.recall_id DESC
        """,
    )
    expiring = query_all(
        conn,
        """
        SELECT * FROM v_expiry_watch
        WHERE days_left BETWEEN 0 AND 90
        ORDER BY days_left, brand_name
        LIMIT 8
        """,
    )
    return render_template(
        "overview.html",
        stats=stats,
        active_recalls=active_recalls,
        expiring=expiring,
        recent_audit=logs.read_audit(6),
    )


# --------------------------------------------------------------------------- #
# Expiry watch
# --------------------------------------------------------------------------- #
@app.get("/expiry")
@login_required
def expiry() -> Any:
    conn = get_db()
    days_filter = request.args.get("days", "90").strip()
    try:
        days = int(days_filter)
        if days not in (30, 60, 90):
            days = 90
    except ValueError:
        days = 90

    rows = query_all(
        conn,
        """
        SELECT * FROM v_expiry_watch
        WHERE days_left <= %s
        ORDER BY days_left, brand_name, batch_no
        """,
        (days,),
    )
    return render_template("expiry.html", rows=rows, days=days)


# --------------------------------------------------------------------------- #
# Batches
# --------------------------------------------------------------------------- #
@app.get("/batches")
@login_required
def batches() -> Any:
    conn = get_db()
    search = request.args.get("q", "").strip()
    page_raw = request.args.get("page", "1").strip()
    try:
        page = max(1, int(page_raw))
    except ValueError:
        page = 1
    per_page = 25
    offset = (page - 1) * per_page

    base_sql = """
        FROM medicine_batch b
        JOIN medicine_product p ON p.product_id = b.product_id
        JOIN manufacturer m ON m.manufacturer_id = p.manufacturer_id
    """
    select_sql = """
        SELECT b.batch_id, b.batch_no, b.expiry_date,
               p.brand_name, p.generic_name, p.strength, p.dosage_form,
               m.name AS manufacturer,
               COALESCE((SELECT SUM(cs.qty) FROM v_current_stock cs
                         WHERE cs.batch_id = b.batch_id), 0) AS total_stock,
               NOT EXISTS (SELECT 1 FROM recall_affected_batch rab
                           JOIN recall r ON r.recall_id = rab.recall_id
                           WHERE rab.batch_id = b.batch_id
                             AND r.recall_status = 'ACTIVE') AS recall_clear
    """
    if search:
        like = f"%{search}%"
        where_clause = """
            WHERE b.batch_no LIKE %s OR p.brand_name LIKE %s
               OR p.generic_name LIKE %s OR m.name LIKE %s
        """
        params = (like, like, like, like)
        total_count = query_scalar(conn, "SELECT COUNT(*) " + base_sql + where_clause, params) or 0
        results = query_all(
            conn,
            select_sql + base_sql + where_clause + " ORDER BY b.batch_no LIMIT %s OFFSET %s",
            params + (per_page, offset),
        )
    else:
        total_count = query_scalar(conn, "SELECT COUNT(*) " + base_sql) or 0
        results = query_all(
            conn,
            select_sql + base_sql + " ORDER BY b.batch_no LIMIT %s OFFSET %s",
            (per_page, offset),
        )

    total_pages = max(1, (total_count + per_page - 1) // per_page)
    return render_template(
        "batches.html",
        batches=results,
        search=search,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
    )


@app.get("/batches/<int:batch_id>")
@login_required
def batch_detail(batch_id: int) -> Any:
    conn = get_db()
    batch = query_one(
        conn,
        """
        SELECT b.*, p.brand_name, p.generic_name, p.strength, p.dosage_form,
               m.name AS manufacturer, m.licence_no
        FROM medicine_batch b
        JOIN medicine_product p ON p.product_id = b.product_id
        JOIN manufacturer m ON m.manufacturer_id = p.manufacturer_id
        WHERE b.batch_id = %s
        """,
        (batch_id,),
    )
    if batch is None:
        abort(404)

    holders = query_all(
        conn,
        """
        SELECT facility_name, district, qty
        FROM v_current_stock WHERE batch_id = %s
        ORDER BY qty DESC, facility_name
        """,
        (batch_id,),
    )
    timeline = query_all(
        conn,
        """
        SELECT * FROM v_batch_timeline
        WHERE batch_id = %s
        ORDER BY movement_date, movement_id
        """,
        (batch_id,),
    )
    recalls = query_all(
        conn,
        """
        SELECT r.recall_id, r.recall_code, r.recall_class, r.recall_status, r.issued_date
        FROM recall r
        JOIN recall_affected_batch rab ON rab.recall_id = r.recall_id
        WHERE rab.batch_id = %s
        ORDER BY r.issued_date DESC
        """,
        (batch_id,),
    )
    total_stock = sum(row["qty"] for row in holders)
    return render_template(
        "batch_detail.html",
        batch=batch,
        holders=holders,
        timeline=timeline,
        recalls=recalls,
        total_stock=total_stock,
    )


# --------------------------------------------------------------------------- #
# Recalls
# --------------------------------------------------------------------------- #
@app.get("/recalls")
@login_required
def recalls() -> Any:
    conn = get_db()
    results = query_all(
        conn,
        """
        SELECT r.*,
               (SELECT COUNT(*) FROM recall_affected_batch rab
                WHERE rab.recall_id = r.recall_id) AS batch_count,
               COALESCE((SELECT SUM(e.qty) FROM v_recall_exposure e
                         WHERE e.recall_id = r.recall_id), 0) AS exposed_units,
               COALESCE((SELECT COUNT(DISTINCT e.facility_id) FROM v_recall_exposure e
                         WHERE e.recall_id = r.recall_id), 0) AS facility_count
        FROM recall r
        ORDER BY r.issued_date DESC, r.recall_id DESC
        """,
    )
    return render_template("recalls.html", recalls=results)


@app.get("/recalls/<int:recall_id>")
@login_required
def recall_detail(recall_id: int) -> Any:
    conn = get_db()
    recall = query_one(conn, "SELECT * FROM recall WHERE recall_id = %s", (recall_id,))
    if recall is None:
        abort(404)

    affected_batches = query_all(
        conn,
        """
        SELECT b.batch_id, b.batch_no, b.expiry_date, p.brand_name, p.strength,
               COALESCE((SELECT SUM(cs.qty) FROM v_current_stock cs
                         WHERE cs.batch_id = b.batch_id), 0) AS total_stock
        FROM recall_affected_batch rab
        JOIN medicine_batch b ON b.batch_id = rab.batch_id
        JOIN medicine_product p ON p.product_id = b.product_id
        WHERE rab.recall_id = %s
        ORDER BY p.brand_name, b.batch_no
        """,
        (recall_id,),
    )
    exposure = query_all(
        conn,
        """
        SELECT * FROM v_recall_exposure
        WHERE recall_id = %s
        ORDER BY district, facility_name, brand_name
        """,
        (recall_id,),
    )
    district_summary = query_all(
        conn,
        """
        SELECT district, SUM(qty) AS units, COUNT(DISTINCT facility_id) AS facilities
        FROM v_recall_exposure
        WHERE recall_id = %s
        GROUP BY district
        ORDER BY units DESC
        """,
        (recall_id,),
    )
    return render_template(
        "recall_detail.html",
        recall=recall,
        affected_batches=affected_batches,
        exposure=exposure,
        district_summary=district_summary,
        total_exposed=sum(row["qty"] for row in exposure),
        notice=logs.get_recall_notice(recall_id),
    )


@app.post("/recalls/<int:recall_id>/close")
@roles_required("RECALL_OFFICER")
def close_recall(recall_id: int) -> Any:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE recall SET recall_status = 'CLOSED' WHERE recall_id = %s", (recall_id,)
    )
    conn.commit()
    cursor.close()
    logs.log_audit(g.user, "RECALL_CLOSED", "recall", recall_id, {}, "OK")
    flash(f"Recall #{recall_id} closed.", "success")
    return redirect(url_for("recall_detail", recall_id=recall_id))


@app.route("/recalls/new", methods=["GET", "POST"])
@roles_required("RECALL_OFFICER")
def recall_new() -> Any:
    conn = get_db()

    if request.method == "POST":
        form = request.form
        selected = {
            int(value) for value in form.getlist("batch_ids") if value.strip().isdigit()
        }
        recall_id, error = create_recall(
            conn,
            recall_code=form.get("recall_code", ""),
            issued_date=form.get("issued_date", ""),
            reason=form.get("reason", ""),
            recall_class=form.get("recall_class", ""),
            recall_status=form.get("recall_status", "ACTIVE"),
            batch_ids=list(selected),
        )

        details = {
            "recall_code": form.get("recall_code", "").strip(),
            "recall_class": form.get("recall_class", ""),
            "status": form.get("recall_status", "ACTIVE"),
            "batch_ids": sorted(selected),
        }
        if error:
            logs.log_audit(g.user, "RECALL_CREATED", "recall", None, details, "REJECTED", error)
            flash(f"Recall not created: {error}", "error")
            return render_template(
                "recall_new.html", **_recall_context(form=form, selected=selected)
            )

        notified_facility_ids = [
            row["facility_id"]
            for row in query_all(
                conn,
                """
                SELECT DISTINCT facility_id FROM v_recall_exposure
                WHERE recall_id = %s
                """,
                (recall_id,),
            )
        ]
        logs.save_recall_notice(
            {
                "recall_id": recall_id,
                "recall_code": form.get("recall_code", "").strip(),
                "issued_by": g.user["username"],
                "advisory_text": form.get("advisory_text", "").strip()
                or "No free-form advisory entered.",
                "notified_facility_ids": notified_facility_ids,
                "attachments": [],
            }
        )
        logs.log_audit(g.user, "RECALL_CREATED", "recall", recall_id, details, "OK")
        flash(f"Recall {form.get('recall_code', '').strip()} created.", "success")
        return redirect(url_for("recall_detail", recall_id=recall_id))

    return render_template("recall_new.html", **_recall_context())


# --------------------------------------------------------------------------- #
# Record movement
# --------------------------------------------------------------------------- #
@app.route("/movements/new", methods=["GET", "POST"])
@roles_required("OPERATOR", "RECALL_OFFICER")
def movement_new() -> Any:
    conn = get_db()

    if request.method == "POST":
        form = request.form

        def optional_int(field: str) -> int | None:
            value = form.get(field, "").strip()
            return int(value) if value else None

        try:
            batch_id = int(form.get("batch_id", ""))
            quantity = int(form.get("quantity", ""))
            from_facility_id = optional_int("from_facility_id")
            to_facility_id = optional_int("to_facility_id")
        except ValueError:
            flash("Pick a batch and enter a whole-number quantity.", "error")
            return render_template("movement_new.html", **_movement_context(form))

        reference_no = form.get("reference_no", "").strip() or _next_reference(conn)
        movement_type = form.get("movement_type", "").strip().upper()
        movement_date = form.get("movement_date", "").strip() or date.today().isoformat()

        movement_id, error = record_movement(
            conn,
            batch_id=batch_id,
            movement_type=movement_type,
            quantity=quantity,
            movement_date=movement_date,
            reference_no=reference_no,
            recorded_by=g.user["user_id"],
            from_facility_id=from_facility_id,
            to_facility_id=to_facility_id,
        )

        details = {
            "batch_id": batch_id,
            "from": from_facility_id,
            "to": to_facility_id,
            "type": movement_type,
            "qty": quantity,
            "date": movement_date,
            "reference_no": reference_no,
        }

        if error:
            logs.log_audit(
                g.user, "MOVEMENT_RECORDED", "stock_movement", None, details, "REJECTED", error
            )
            flash(f"Movement rejected: {error}", "error")
            return render_template("movement_new.html", **_movement_context(form))

        logs.log_audit(
            g.user, "MOVEMENT_RECORDED", "stock_movement", movement_id, details, "OK"
        )
        flash(f"Movement #{movement_id} recorded ({movement_type}, {quantity} units).", "success")
        return redirect(url_for("batch_detail", batch_id=batch_id))

    return render_template("movement_new.html", **_movement_context())


# --------------------------------------------------------------------------- #
# Audit + security demo
# --------------------------------------------------------------------------- #
@app.get("/audit")
@login_required
def audit() -> Any:
    outcome = request.args.get("outcome", "").strip().upper()
    if outcome not in {"OK", "REJECTED"}:
        outcome = ""
    return render_template(
        "audit.html",
        entries=logs.read_audit(300, outcome=outcome or None),
        outcome=outcome,
        notices=logs.read_recall_notices(),
    )


@app.post("/demo/ledger-update")
@login_required
def demo_ledger_update() -> Any:
    """Live demo: an UPDATE on the append-only ledger is blocked by a trigger."""
    conn = get_db()
    first = query_one(
        conn, "SELECT movement_id FROM stock_movement ORDER BY movement_id LIMIT 1"
    )
    if first is None:
        flash("No ledger rows to update.", "error")
        return redirect(url_for("audit"))

    movement_id = first["movement_id"]
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE stock_movement SET quantity = quantity + 1 WHERE movement_id = %s",
            (movement_id,),
        )
    except mysql.connector.Error as exc:
        reason = getattr(exc, "msg", None) or str(exc)
        logs.log_audit(
            g.user,
            "LEDGER_UPDATE_ATTEMPT",
            "stock_movement",
            movement_id,
            {"attempted_sql": "UPDATE stock_movement SET quantity = quantity + 1"},
            "REJECTED",
            reason,
        )
        flash(f"Ledger UPDATE blocked by the append-only trigger: {reason}", "success")
    else:
        logs.log_audit(
            g.user,
            "LEDGER_UPDATE_ATTEMPT",
            "stock_movement",
            movement_id,
            {"attempted_sql": "UPDATE stock_movement SET quantity = quantity + 1"},
            "UNEXPECTED_SUCCESS",
        )
        flash("Unexpected: the ledger UPDATE succeeded.", "error")
    finally:
        cursor.close()

    return redirect(url_for("audit"))


# --------------------------------------------------------------------------- #
# Ask the Database (NLP-to-SQL)
# --------------------------------------------------------------------------- #
_EXAMPLE_QUESTIONS = [
    "Show the movement history of batch B-104",
    "Which facilities currently hold batch B-104?",
    "Which facilities hold stock affected by recall R-02?",
    "How much stock from recall R-02 remains in each district?",
    "Which batches expire within 60 days?",
    "Show all batches of Paracetamol 650",
    "Which facility received the most of batch B-104?",
    "Show all movements for City Pharmacy",
]


@app.route("/ask", methods=["GET", "POST"])
@login_required
def ask() -> Any:
    result = None
    question = ""
    if request.method == "POST":
        question = request.form.get("question", "").strip()
        if question:
            result = nl_ask(question, user=g.user)
        else:
            flash("Enter a question first.", "error")
    return render_template(
        "ask.html",
        question=question,
        result=result,
        examples=_EXAMPLE_QUESTIONS,
        nl_queries=logs.read_nl_queries(10),
    )


@app.errorhandler(404)
def not_found(_error: Any) -> Any:
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
