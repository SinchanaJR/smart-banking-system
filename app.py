import os
import re
import secrets
import sqlite3
from decimal import Decimal, InvalidOperation
from functools import wraps
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "banking.db")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)


def connect_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                account_number TEXT NOT NULL UNIQUE,
                balance_cents INTEGER NOT NULL DEFAULT 0 CHECK(balance_cents >= 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
                description TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_transactions_user_id
            ON transactions(user_id, id DESC);

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)


def get_user(user_id=None):
    uid = user_id if user_id is not None else session.get("user_id")
    if not uid:
        return None
    with connect_db() as db:
        return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") or not get_user():
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Please log in again."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("csrf_token")
            supplied = request.headers.get("X-CSRF-Token")
            if not supplied and request.form:
                supplied = request.form.get("csrf_token")
            if not expected or not supplied or not secrets.compare_digest(expected, supplied):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Security token missing or invalid. Refresh the page."}), 400
                abort(400, description="Security token missing or invalid. Refresh the page.")
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_csrf_token():
    if session.get("user_id") and not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session.get("csrf_token", "")}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    return response


def parse_amount(value):
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Enter a valid amount.")
    if not amount.is_finite() or amount <= 0:
        raise ValueError("Amount must be greater than zero.")
    cents = int(amount * 100)
    if cents > 100_000_000:
        raise ValueError("Demo transaction limit is ₹1,000,000.00.")
    return cents


def money(cents):
    return f"{cents / 100:,.2f}"


def log_event(db, user_id, event_type, detail):
    db.execute(
        "INSERT INTO audit_events (user_id, event_type, detail) VALUES (?, ?, ?)",
        (user_id, event_type, detail[:250])
    )


@app.route("/")
def home():
    return redirect(url_for("dashboard" if session.get("user_id") else "login"))


@app.route("/register", methods=["GET", "POST"])
@csrf_protect
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or len(name) > 100:
            flash("Please enter a name under 100 characters.", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.", "error")
        elif len(password) < 8 or len(password) > 128:
            flash("Password must be 8–128 characters.", "error")
        else:
            password_hash = generate_password_hash(password)
            try:
                with connect_db() as db:
                    account = "SB" + secrets.token_hex(6).upper()
                    db.execute(
                        """INSERT INTO users (name, email, password_hash, account_number)
                           VALUES (?, ?, ?, ?)""",
                        (name, email, password_hash, account)
                    )
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@csrf_protect
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            with connect_db() as db:
                log_event(db, user["id"], "LOGIN", "Successful login")
            return redirect(url_for("dashboard"))

        flash("Email or password is incorrect.", "error")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()
    with connect_db() as db:
        transactions = db.execute(
            """SELECT * FROM transactions WHERE user_id = ?
               ORDER BY id DESC LIMIT 8""",
            (user["id"],)
        ).fetchall()
        stats = db.execute(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(CASE WHEN transaction_type = 'DEPOSIT'
                          THEN amount_cents ELSE 0 END), 0) AS deposited
               FROM transactions WHERE user_id = ?""",
            (user["id"],)
        ).fetchone()
        recent_labels = db.execute(
            """SELECT transaction_type, amount_cents, created_at
               FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 7""",
            (user["id"],)
        ).fetchall()

    return render_template(
        "dashboard.html", user=user, transactions=transactions,
        stats=stats, chart_rows=list(reversed(recent_labels))
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
@csrf_protect
def profile():
    user = get_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name or len(name) > 100:
            flash("Name must be 1–100 characters.", "error")
        else:
            with connect_db() as db:
                db.execute("UPDATE users SET name = ? WHERE id = ?", (name, user["id"]))
                log_event(db, user["id"], "PROFILE_UPDATE", "Name updated")
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.route("/api/balance")
@login_required
def api_balance():
    user = get_user()
    return jsonify({
        "balance": money(user["balance_cents"]),
        "account_number": user["account_number"]
    })


@app.route("/api/transactions")
@login_required
def api_transactions():
    user = get_user()
    with connect_db() as db:
        rows = db.execute(
            """SELECT transaction_type, amount_cents, description, created_at
               FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 20""",
            (user["id"],)
        ).fetchall()
    return jsonify([{
        "type": row["transaction_type"],
        "amount": money(row["amount_cents"]),
        "description": row["description"],
        "date": row["created_at"]
    } for row in rows])


def get_json_amount():
    data = request.get_json(silent=True) or {}
    return data, parse_amount(data.get("amount"))


@app.route("/api/deposit", methods=["POST"])
@login_required
@csrf_protect
def api_deposit():
    user = get_user()
    try:
        _, cents = get_json_amount()
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    with connect_db() as db:
        db.execute("UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                   (cents, user["id"]))
        db.execute(
            """INSERT INTO transactions (user_id, transaction_type, amount_cents, description)
               VALUES (?, 'DEPOSIT', ?, 'Simulated deposit')""",
            (user["id"], cents)
        )
        log_event(db, user["id"], "DEPOSIT", f"Simulated deposit: {money(cents)}")
    return jsonify({"message": "Demo deposit recorded.", "amount": money(cents)})


@app.route("/api/withdraw", methods=["POST"])
@login_required
@csrf_protect
def api_withdraw():
    user = get_user()
    try:
        _, cents = get_json_amount()
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    with connect_db() as db:
        debit = db.execute(
            """UPDATE users SET balance_cents = balance_cents - ?
               WHERE id = ? AND balance_cents >= ?""",
            (cents, user["id"], cents)
        )
        if debit.rowcount != 1:
            return jsonify({"error": "Insufficient demo balance."}), 400
        db.execute(
            """INSERT INTO transactions (user_id, transaction_type, amount_cents, description)
               VALUES (?, 'WITHDRAWAL', ?, 'Simulated withdrawal')""",
            (user["id"], cents)
        )
        log_event(db, user["id"], "WITHDRAWAL", f"Simulated withdrawal: {money(cents)}")
    return jsonify({"message": "Demo withdrawal recorded.", "amount": money(cents)})


@app.route("/api/transfer", methods=["POST"])
@login_required
@csrf_protect
def api_transfer():
    sender = get_user()
    data = request.get_json(silent=True) or {}
    recipient_account = str(data.get("account_number", "")).strip().upper()
    try:
        cents = parse_amount(data.get("amount"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    if not recipient_account:
        return jsonify({"error": "Enter the recipient account number."}), 400

    try:
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            recipient = db.execute(
                "SELECT id, account_number FROM users WHERE account_number = ?",
                (recipient_account,)
            ).fetchone()

            if not recipient:
                db.rollback()
                return jsonify({"error": "Recipient account was not found."}), 404
            if recipient["id"] == sender["id"]:
                db.rollback()
                return jsonify({"error": "You cannot transfer to your own account."}), 400

            debit = db.execute(
                """UPDATE users SET balance_cents = balance_cents - ?
                   WHERE id = ? AND balance_cents >= ?""",
                (cents, sender["id"], cents)
            )
            if debit.rowcount != 1:
                db.rollback()
                return jsonify({"error": "Insufficient demo balance."}), 400

            db.execute("UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                       (cents, recipient["id"]))
            db.execute(
                """INSERT INTO transactions (user_id, transaction_type, amount_cents, description)
                   VALUES (?, 'TRANSFER_OUT', ?, ?)""",
                (sender["id"], cents, f"Demo transfer to {recipient_account}")
            )
            db.execute(
                """INSERT INTO transactions (user_id, transaction_type, amount_cents, description)
                   VALUES (?, 'TRANSFER_IN', ?, ?)""",
                (recipient["id"], cents, f"Demo transfer from {sender['account_number']}")
            )
            log_event(db, sender["id"], "TRANSFER_OUT", f"To {recipient_account}: {money(cents)}")
            log_event(db, recipient["id"], "TRANSFER_IN", f"From {sender['account_number']}: {money(cents)}")
            db.commit()
    except sqlite3.Error:
        return jsonify({"error": "Transfer failed. Please try again."}), 500

    return jsonify({"message": "Demo transfer completed.", "amount": money(cents)})


@app.route("/api/jarvis", methods=["POST"])
@login_required
@csrf_protect
def api_jarvis():
    user = get_user()
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip().lower()

    if not message or len(message) > 500:
        return jsonify({"reply": "Please enter a message up to 500 characters."}), 400

    if any(word in message for word in ("balance", "how much money", "funds")):
        reply = f"Your demo balance is ₹{money(user['balance_cents'])}."
    elif "account" in message:
        reply = f"Your demo account number is {user['account_number']}."
    elif any(word in message for word in ("transaction", "history", "recent activity")):
        with connect_db() as db:
            rows = db.execute(
                """SELECT transaction_type, amount_cents FROM transactions
                   WHERE user_id = ? ORDER BY id DESC LIMIT 5""",
                (user["id"],)
            ).fetchall()
        if rows:
            reply = "Recent demo activity: " + "; ".join(
                f"{row['transaction_type']} ₹{money(row['amount_cents'])}" for row in rows
            )
        else:
            reply = "There are no demo transactions yet."
    elif any(word in message for word in ("hello", "hi", "hey")):
        reply = f"Hello {user['name']}! I'm Jarvis. Ask about your balance, account, or transactions."
    elif "help" in message:
        reply = "Try: 'What is my balance?', 'Show my account number', or 'Recent transactions'."
    elif "thank" in message:
        reply = "You're welcome! I'm here to help with your demo banking dashboard."
    else:
        reply = "I'm the demo Jarvis assistant. I can answer questions about your demo balance, account number, and transaction history."

    return jsonify({"reply": reply})


@app.route("/logout", methods=["POST"])
@login_required
@csrf_protect
def logout():
    uid = session.get("user_id")
    with connect_db() as db:
        log_event(db, uid, "LOGOUT", "User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.errorhandler(400)
def bad_request(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": getattr(error, "description", "Bad request.")}), 400
    return render_template("error.html", code=400, message="Bad request. Refresh the page and try again."), 400


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found."}), 404
    return render_template("error.html", code=404, message="That page could not be found."), 404


@app.errorhandler(500)
def server_error(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error."}), 500
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500


if __name__ == "__main__":
    init_db()
    # Use debug=False; do not expose the development server to the public internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
