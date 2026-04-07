from flask import Flask, render_template, request, redirect, url_for, session, flash
from detector import analyse_text
from security import register_user, authenticate
from audit import log_event
from storage import save_result, get_user_results, read_all_results, read_audit_log

import os
import time
import random
import smtplib
from email.mime.text import MIMEText

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_to_a_random_secret_key")

SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
APP_PASSWORD = os.environ.get("APP_PASSWORD")

OTP_EXPIRE_SECONDS = 300  


def send_otp_email(receiver_email: str, otp_code: str):
    if not SENDER_EMAIL or not APP_PASSWORD:
        raise RuntimeError(
            "Missing SENDER_EMAIL or APP_PASSWORD environment variables."
        )

    msg = MIMEText(
        f"Your OTP code is: {otp_code}\n\nThis code will expire in 5 minutes."
    )
    msg["Subject"] = "Secure Phishing System - OTP Code"
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)


def is_logged_in():
    return "username" in session and "role" in session


def is_admin():
    return is_logged_in() and session.get("role") == "admin"


@app.route("/")
def home():
    if is_logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "user").strip().lower()

        ok, msg = register_user(username, password, role=role)
        log_event(f"REGISTER | user={username} | role={role} | success={ok}")

        if ok:
            flash("Registered successfully. Please login.", "success")
            return redirect(url_for("login"))

        flash(msg, "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()

        # authenticate returns: ok, msg, role
        ok, msg, role = authenticate(username, password)
        log_event(f"LOGIN_PASSWORD | user={username} | success={ok}")

        if ok:
            if not email or "@" not in email:
                flash("Please enter a valid email to receive OTP.", "danger")
                return render_template("login.html")

            otp_code = str(random.randint(100000, 999999))
            session["otp_code"] = otp_code
            session["otp_created"] = int(time.time())
            session["otp_user"] = username
            session["otp_role"] = role
            session["otp_email"] = email

            try:
                send_otp_email(email, otp_code)
            except Exception as e:
                flash(f"Failed to send OTP email: {e}", "danger")
                return render_template("login.html")

            flash("OTP sent to your email. Please enter the code.", "info")
            return redirect(url_for("otp_verify"))

        flash(msg, "danger")

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp_verify():
    if "otp_code" not in session or "otp_created" not in session:
        return redirect(url_for("login"))

    created = session.get("otp_created", 0)
    if int(time.time()) - int(created) > OTP_EXPIRE_SECONDS:
        session.clear()
        flash("OTP expired. Please login again.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        user_code = request.form.get("otp_code", "").strip()

        if user_code == session.get("otp_code"):
            session["username"] = session.get("otp_user")
            session["role"] = session.get("otp_role")
            log_event(f"OTP_VERIFY | user={session['username']} | success=True")

            # clear only OTP-related fields
            session.pop("otp_code", None)
            session.pop("otp_created", None)
            session.pop("otp_user", None)
            session.pop("otp_role", None)
            session.pop("otp_email", None)

            flash("Login success ✅", "success")
            return redirect(url_for("dashboard"))

        log_event(f"OTP_VERIFY | user={session.get('otp_user')} | success=False")
        flash("Invalid OTP.", "danger")

    return render_template("otp.html")


@app.route("/security")
def security_settings():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("security_settings.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    result = None
    score = None
    reasons = None
    email_text = ""

    if request.method == "POST":
        email_text = request.form.get("email_text", "")
        label, score, reasons = analyse_text(email_text)

        username = session["username"]
        role = session["role"]

        save_result(username, label, score, reasons)
        log_event(
            f"DETECTION | user={username} | role={role} | result={label} | score={score} | triggers={len(reasons)}"
        )
        result = label

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        result=result,
        score=score,
        reasons=reasons,
        email_text=email_text,
    )


@app.route("/history")
def history():
    if not is_logged_in():
        return redirect(url_for("login"))
    rows = get_user_results(session["username"], limit=50)
    return render_template("history.html", rows=rows)


@app.route("/admin")
def admin():
    if not is_admin():
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard"))
    results = read_all_results(limit=100)
    logs = read_audit_log(limit=120)
    return render_template("admin.html", results=results, logs=logs)


@app.route("/logout")
def logout():
    if is_logged_in():
        log_event(f"LOGOUT | user={session.get('username')} | role={session.get('role')}")
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)