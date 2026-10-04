"""
Smart Security Camera + Crime Heat Map - web application.

Three role-based views rendered by one template (templates/app.html):
  /student  crime heat map (street-level density) + one-question feedback
  /security live camera, access events + alerts, visitor check-in, heat map with
            click-to-log incidents, analytics, CSV export
  /admin    everything Security has, plus enrolled-people and login-account
            management, data retention, model evaluation, feedback roll-up

Run:  python app.py      ->  http://localhost:5000
"""

import csv
import io
import json
import secrets
import threading
import time
from collections import defaultdict
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import config
import crime
import database
import face

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=8 * 1024 * 1024)      # enrolment photos only

ROLE_HOME = {"student": "student_home", "security": "staff_home", "admin": "staff_home"}
_camera_thread: threading.Thread | None = None
_camera_stop: threading.Event | None = None
_login_failures: dict[str, list[float]] = defaultdict(list)
_visitor_submissions: dict[str, list[float]] = defaultdict(list)
PENDING_DIR = config.DATA_DIR / "pending_visitors"

database.init_db()


# --- security helpers ---------------------------------------------------------

def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def _csrf_protect():
    """Every POST must carry the session's token (form field or X-CSRF-Token header)."""
    if request.method == "POST":
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Missing or invalid CSRF token. Reload the page and try again.")


def _safe_next(target: str | None) -> str | None:
    """Only allow same-site relative redirects (prevents open-redirect abuse)."""
    if (target and target.startswith("/") and not target.startswith("//")
            and not urlparse(target).netloc):
        return target
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("username"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "login required"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def roles_required(*allowed):
    """Admin is always allowed: admin duties are a superset of security's."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*a, **kw):
            role = session.get("role")
            if role != "admin" and role not in allowed:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "forbidden"}), 403
                flash("You don't have access to that section.", "error")
                return redirect(url_for(ROLE_HOME.get(role, "login")))
            return view(*a, **kw)
        return wrapped
    return decorator


def _filters():
    """Shared heat-map filters: ?days=30&types=Theft,Assault"""
    try:
        days = int(request.args.get("days", 0)) or None
    except ValueError:
        days = None
    types = [t for t in request.args.get("types", "").split(",") if t] or None
    return days, types


# --- auth ---------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip, now = request.remote_addr or "?", time.time()
        _login_failures[ip] = [t for t in _login_failures[ip]
                               if now - t < config.LOGIN_WINDOW_SECONDS]
        if len(_login_failures[ip]) >= config.LOGIN_MAX_FAILURES:
            flash("Too many failed attempts. Please wait a few minutes.", "error")
            return render_template("app.html", view="login"), 429
        user = database.get_user(request.form.get("username", "").strip())
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            _login_failures.pop(ip, None)
            session.clear()
            session["username"], session["role"] = user["username"], user["role"]
            return redirect(_safe_next(request.args.get("next"))
                            or url_for(ROLE_HOME[user["role"]]))
        _login_failures[ip].append(now)
        flash("Invalid username or password.", "error")
    return render_template("app.html", view="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    role = session.get("role")
    return redirect(url_for(ROLE_HOME[role]) if role in ROLE_HOME else url_for("login"))


# --- heat map data APIs (any logged-in role) -----------------------------------------

@app.route("/api/heatmap")
@login_required
def api_heatmap():
    days, types = _filters()
    return jsonify(crime.density_cells(days, types))


@app.route("/api/incidents")
@login_required
def api_incidents():
    days, types = _filters()
    return jsonify([
        {"id": r["id"], "lat": r["latitude"], "lng": r["longitude"], "crime_type": r["crime_type"],
         "occurred_at": r["occurred_at"], "street": r["street"]}
        for r in database.all_crime_incidents(days, types)])


@app.route("/api/density")
@login_required
def api_density():
    """Street-level density around a clicked point."""
    try:
        lat, lng = float(request.args["lat"]), float(request.args["lng"])
        radius = float(request.args.get("radius", config.STREET_RADIUS_M))
    except (KeyError, ValueError):
        return jsonify({"error": "lat and lng are required numbers"}), 400
    days, types = _filters()
    return jsonify(crime.density_at(lat, lng, min(max(radius, 30), 1000), days, types,
                                    street=request.args.get("street") or None))


@app.route("/api/hotspots")
@login_required
def api_hotspots():
    days, types = _filters()
    return jsonify(crime.hotspots(5, days, types))


@app.route("/api/streets")
@login_required
def api_streets():
    days, types = _filters()
    return jsonify(crime.top_streets(8, days, types))


@app.route("/api/crime-summary")
@login_required
def api_crime_summary():
    days, types = _filters()
    return jsonify(crime.incident_summary(days, types))


@app.route("/api/feedback", methods=["POST"])
@login_required
def api_feedback():
    p = request.get_json(silent=True) or {}
    stored = crime.record_feedback(bool(p.get("felt_more_aware")), p.get("comment"),
                                   p.get("session_id"))
    return jsonify({"ok": True, "duplicate": not stored})


# --- dashboards ---------------------------------------------------------------------

def _event_rows(limit=50):
    rows = []
    for r in database.recent_events(limit):
        d = dict(r)
        d["snapshot"] = (d["snapshot_path"] or "").replace("\\", "/").split("/")[-1] or None
        rows.append(d)
    return rows


def _eval_report():
    try:
        return json.loads(config.EVAL_REPORT_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _camera_running() -> bool:
    return _camera_thread is not None and _camera_thread.is_alive()


@app.route("/student")
@roles_required("student")
def student_home():
    return render_template("app.html", view="student", campus_lat=config.CAMPUS_LAT,
                           campus_lng=config.CAMPUS_LNG, street_radius=config.STREET_RADIUS_M)


@app.route("/staff")
@roles_required("security")
def staff_home():
    _release_visitor_faces()
    _purge_visitor_requests()
    """Security and admin dashboards (admin gets the extra administration block)."""
    view = "admin" if session["role"] == "admin" else "security"
    ctx = dict(view=view, campus_lat=config.CAMPUS_LAT, campus_lng=config.CAMPUS_LNG,
               street_radius=config.STREET_RADIUS_M, events=_event_rows(),
               unknown_24h=database.unknown_event_count(24),
               active_visitors=database.list_active_visitors(), camera_running=_camera_running(),
               pending_visitors=database.list_visitor_requests())
    if view == "admin":
        ctx.update(people=database.list_known_people(), users=database.list_users(),
                   eval_report=_eval_report(), feedback_summary=database.feedback_summary(),
                   retention_days=config.SNAPSHOT_RETENTION_DAYS)
    return render_template("app.html", **ctx)


# Friendly aliases: /security and /admin land on the same dashboard
@app.route("/security")
@app.route("/admin")
@roles_required("security")
def _staff_alias():
    return redirect(url_for("staff_home"))


# --- incidents (security + admin) ---------------------------------------------------------

@app.route("/security/incidents/add", methods=["POST"])
@roles_required("security")
def add_incident():
    p = request.get_json(silent=True) or {}
    try:
        lat, lng = float(p["lat"]), float(p["lng"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"ok": False, "error": "Missing or invalid coordinates."}), 400
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return jsonify({"ok": False, "error": "Coordinates out of range."}), 400
    raw = (p.get("occurred_at") or "").strip()
    try:        # one format everywhere, so the by-month chart always groups it correctly
        when = (datetime.fromisoformat(raw.replace("T", " ")) if raw
                else datetime.now()).isoformat(sep=" ", timespec="seconds")
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid date and time."}), 400
    new_id = database.insert_crime_incident(lat, lng, (p.get("crime_type") or "Other").strip()[:50],
                                            when,
                                            source="security_reported", street=(p.get("street")
                                                or "")[:120])
    return jsonify({"ok": True, "id": new_id})


@app.route("/security/incidents/<int:incident_id>/delete", methods=["POST"])
@roles_required("security")
def delete_incident(incident_id):
    database.delete_crime_incident(incident_id)
    return jsonify({"ok": True})


# --- visitors -----------------------------------------------------------------------------

def _release_visitor_faces() -> None:
    """Deletes the stored face data of visitors who checked out or whose time expired."""
    for key in database.release_visitor_faces():
        face.remove_person(key)


@app.route("/security/visitors/add", methods=["POST"])
@roles_required("security")
def add_visitor():
    name = request.form.get("name", "").strip()
    image = request.files.get("image")
    has_photo = bool(image and image.filename)
    if not name:
        flash("Visitor name is required.", "error")
        return redirect(url_for("staff_home"))
    if has_photo and not request.form.get("consent"):
        flash("Tick the consent box: the visitor must agree to their face being recorded.", "error")
        return redirect(url_for("staff_home"))
    try:
        hours = min(max(int(request.form.get("duration_hours", 8)), 1), 72)
    except ValueError:
        hours = 8
    visitor_id = database.add_visitor(name, request.form.get("purpose", "").strip(),
                                      request.form.get("host_name", "").strip(),
                                      session["username"], hours)
    if not has_photo:
        flash(f"Checked in visitor '{name}' (no face recorded).", "success")
        return redirect(url_for("staff_home"))
    # unique, so a visitor can never overwrite a known person
    face_key = f"{name} (visitor #{visitor_id})"
    ok, msg = face.enroll_upload(face_key, "visitor", image)
    if not ok:
        database.delete_visitor(visitor_id)                # no face, no check-in: ask them to retry
        flash(f"Visitor not checked in. {msg} Try again with a clear, front-facing photo.", "error")
        return redirect(url_for("staff_home"))
    database.set_visitor_face_key(visitor_id, face_key)
    flash(f"Checked in visitor '{name}' and recorded their face. "
          "It is deleted when they leave or expire.", "success")
    return redirect(url_for("staff_home"))


def _purge_visitor_requests() -> None:
    for name in database.purge_visitor_requests(24):
        (PENDING_DIR / name).unlink(missing_ok=True)


@app.route("/visitor", methods=["GET", "POST"])
def visitor_register():
    """Public page: a visitor records their own face. Staff approve it before it is enrolled."""
    if request.method == "GET":
        return render_template("visitor.html", done=bool(request.args.get("done")))
    ip, now = request.remote_addr or "?", time.time()
    _visitor_submissions[ip] = [t for t in _visitor_submissions[ip] if now - t < 600]
    if len(_visitor_submissions[ip]) >= 5:
        flash("Too many requests. Please wait a few minutes.", "error")
        return render_template("visitor.html", done=False), 429
    name = request.form.get("name", "").strip()[:80]
    image = request.files.get("image")
    if not name or not (image and image.filename):
        flash("Please enter your name and take or choose a photo of your face.", "error")
        return redirect(url_for("visitor_register"))
    if not request.form.get("consent"):
        flash("Please tick the box to agree to your face being recorded for this visit.", "error")
        return redirect(url_for("visitor_register"))
    _visitor_submissions[ip].append(now)
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    path = PENDING_DIR / f"{secrets.token_hex(16)}.jpg"
    image.save(path)
    if face.count_faces(path) != 1:
        path.unlink(missing_ok=True)
        flash("We need exactly one clear face. Retake the photo facing the camera, with only you "
              "in view.", "error")
        return redirect(url_for("visitor_register"))
    database.add_visitor_request(name, request.form.get("purpose", "").strip()[:120],
                                 request.form.get("host_name", "").strip()[:80], path.name)
    return redirect(url_for("visitor_register", done=1))


@app.route("/security/visitors/requests/<int:request_id>/photo")
@roles_required("security")
def visitor_request_photo(request_id):
    r = database.get_visitor_request(request_id)
    if not r:
        abort(404)
    return send_from_directory(PENDING_DIR, r["photo_file"])


@app.route("/security/visitors/requests/<int:request_id>/approve", methods=["POST"])
@roles_required("security")
def approve_visitor_request(request_id):
    r = database.get_visitor_request(request_id)
    if not r:
        flash("That request no longer exists.", "error")
        return redirect(url_for("staff_home"))
    path = PENDING_DIR / r["photo_file"]
    visitor_id = database.add_visitor(r["name"], r["purpose"] or "", r["host_name"] or "",
                                      session["username"], 8)
    face_key = f"{r['name']} (visitor #{visitor_id})"
    ok, msg = face.enroll_from_image(face_key, "visitor", path)
    if not ok:
        database.delete_visitor(visitor_id)
        flash(f"Could not approve: {msg}", "error")
        return redirect(url_for("staff_home"))
    database.set_visitor_face_key(visitor_id, face_key)
    database.delete_visitor_request(request_id)
    path.unlink(missing_ok=True)
    flash(f"Approved '{r['name']}'. Their face is recorded, so they will not "
          "trigger unknown-face alerts. It is deleted when they check out or expire.",
          "success")
    return redirect(url_for("staff_home"))


@app.route("/security/visitors/requests/<int:request_id>/reject", methods=["POST"])
@roles_required("security")
def reject_visitor_request(request_id):
    r = database.get_visitor_request(request_id)
    if r:
        (PENDING_DIR / r["photo_file"]).unlink(missing_ok=True)
        database.delete_visitor_request(request_id)
    flash("Visitor request rejected and the photo deleted.", "success")
    return redirect(url_for("staff_home"))


@app.route("/security/visitors/<int:visitor_id>/checkout", methods=["POST"])
@roles_required("security")
def checkout_visitor(visitor_id):
    database.check_out_visitor(visitor_id)
    _release_visitor_faces()
    flash("Visitor checked out.", "success")
    return redirect(url_for("staff_home"))


# --- camera -------------------------------------------------------------------------------

@app.route("/camera/start", methods=["POST"])
@roles_required("security")
def start_camera():
    global _camera_thread, _camera_stop
    if _camera_running():
        flash("Camera is already running.", "error")
        return redirect(url_for("staff_home"))
    try:
        import cv2, face_recognition  # noqa: F401 - availability check only
    except ImportError:
        flash("Camera dependencies (opencv-python / face_recognition / dlib) aren't installed "
              "here.", "error")
        return redirect(url_for("staff_home"))
    _camera_stop = threading.Event()
    _camera_thread = threading.Thread(
        target=face.run_camera, kwargs={"show_window": False, "stop_event": _camera_stop},
        daemon=True)
    _camera_thread.start()
    flash("Camera started.", "success")
    return redirect(url_for("staff_home"))


@app.route("/camera/stop", methods=["POST"])
@roles_required("security")
def stop_camera():
    global _camera_thread, _camera_stop
    if _camera_stop is not None:
        _camera_stop.set()
    if _camera_thread is not None:
        _camera_thread.join(timeout=5)
    _camera_thread = None
    flash("Camera stopped.", "success")
    return redirect(url_for("staff_home"))


@app.route("/camera/stream")
@roles_required("security")
def camera_stream():
    def generate():
        while _camera_running():
            jpeg = face.get_latest_jpeg()
            if jpeg:
                yield b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + jpeg + b"\r\n"
            time.sleep(0.1)                     # ~10 fps is plenty for a preview
    return Response(generate(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/api/events")
@roles_required("security")
def api_events():
    # polled every few seconds, so expiry is prompt
    _release_visitor_faces()
    return jsonify({"events": _event_rows(), "unknown_24h": database.unknown_event_count(24),
                    "camera_running": _camera_running()})


@app.route("/api/analytics/incidents-by-month")
@roles_required("security")
def api_incidents_by_month():
    return jsonify(database.incidents_by_month())


@app.route("/snapshots/<path:filename>")
@roles_required("security")
def serve_snapshot(filename):
    return send_from_directory(config.SNAPSHOT_DIR, filename)


# --- CSV export ---------------------------------------------------------------------------

def _csv_response(header, rows, filename):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(list(r))
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/security/export/logs.csv")
@roles_required("security")
def export_logs_csv():
    return _csv_response(["timestamp", "status", "person_name", "snapshot", "alert_sent"],
                         database.export_events_rows(), "access_events.csv")


@app.route("/admin/export/crime.csv")
@roles_required("admin")
def export_crime_csv():
    return _csv_response(["latitude", "longitude", "crime_type", "occurred_at", "source", "street"],
                         database.export_crime_rows(), "crime_incidents.csv")


# --- admin only ---------------------------------------------------------------------------

@app.route("/admin/logs/purge", methods=["POST"])
@roles_required("admin")
def purge_logs():
    deleted, files = database.purge_old_events(config.SNAPSHOT_RETENTION_DAYS)
    removed = 0
    for name in files:                           # also delete the evidence images from disk
        path = config.SNAPSHOT_DIR / name.replace("\\", "/").split("/")[-1]
        if path.is_file():
            path.unlink()
            removed += 1
    flash(f"Purged {deleted} event(s) and {removed} snapshot file(s) older than "
          f"{config.SNAPSHOT_RETENTION_DAYS} days.", "success")
    return redirect(url_for("staff_home"))


@app.route("/admin/users/add", methods=["POST"])
@roles_required("admin")
def add_user():
    username = request.form.get("username", "").strip()
    password, role = request.form.get("password", ""), request.form.get("role", "student")
    if role not in ("student", "security", "admin"):
        flash("Invalid role.", "error")
    elif not username or len(password) < 8:
        flash("Username is required and the password must be at least 8 characters.", "error")
    elif database.get_user(username):
        flash(f"Username '{username}' already exists.", "error")
    else:
        database.create_user(username, generate_password_hash(password), role=role)
        flash(f"Created {role} account '{username}'.", "success")
    return redirect(url_for("staff_home"))


@app.route("/admin/users/<username>/delete", methods=["POST"])
@roles_required("admin")
def delete_user_account(username):
    if username == session.get("username"):
        flash("You can't delete the account you're logged in with.", "error")
    else:
        database.delete_user(username)
        flash(f"Removed login account '{username}'.", "success")
    return redirect(url_for("staff_home"))


@app.route("/admin/people/add", methods=["POST"])
@roles_required("admin")
def add_person():
    name, role, image = request.form.get("name", "").strip(), request.form.get("role",
        "student"), request.files.get("image")
    if not name or not image or not image.filename:
        flash("Name and a face photo are both required.", "error")
    else:
        ok, msg = face.enroll_upload(name, role, image)
        flash(msg, "success" if ok else "error")
    return redirect(url_for("staff_home"))


@app.route("/admin/people/<name>/delete", methods=["POST"])
@roles_required("admin")
def remove_person(name):
    face.remove_person(name)
    flash(f"Removed '{name}'.", "success")
    return redirect(url_for("staff_home"))


if __name__ == "__main__":
    if config.SECRET_KEY == config.DEFAULT_SECRET:
        print("[!] Using the default Flask secret key. Set FACEGUARD_FLASK_SECRET in .env before "
              "real use.")
    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT)
