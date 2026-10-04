"""
Facial recognition module: encrypted template storage, alerting, enrollment,
the real-time camera loop and the accuracy evaluation.

Heavy libraries (cv2, face_recognition/dlib) are imported lazily inside the
functions that need them, so the web app still starts on a machine without a
webcam or without dlib installed.

Camera flow (project charter):
    Camera -> frame -> detect -> encode -> compare with enrolled faces
        known   -> log entry (rate-limited per person)
        unknown -> log entry + evidence snapshot + alert
"""

import json
import pickle
import smtplib
import ssl
import tempfile
import threading
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import numpy as np
from cryptography.fernet import Fernet

import config
import database


# =========================================================================
# Encrypted storage of face encodings (Fernet: AES-128-CBC + HMAC)
# =========================================================================

def _fernet() -> Fernet:
    config.ensure_directories()
    if config.KEY_PATH.exists():
        key = config.KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        config.KEY_PATH.write_bytes(key)
        try:
            config.KEY_PATH.chmod(0o600)
        except (NotImplementedError, PermissionError):
            pass
    return Fernet(key)


def save_encodings(known_faces: dict) -> None:
    """known_faces: {person_name: [128-d numpy encoding, ...]}"""
    config.ensure_directories()
    config.ENCODINGS_PATH.write_bytes(_fernet().encrypt(pickle.dumps(known_faces)))


def load_encodings() -> dict:
    if not config.ENCODINGS_PATH.exists():
        return {}
    return pickle.loads(_fernet().decrypt(config.ENCODINGS_PATH.read_bytes()))


def _flat_known():
    encodings, names = [], []
    for name, encs in load_encodings().items():
        for e in encs:
            encodings.append(e)
            names.append(name)
    return encodings, names


# =========================================================================
# Alerts (dashboard is implicit: events land in the DB; email is optional)
# =========================================================================

def _send_email(snapshot: Path | None, timestamp: str) -> bool:
    if not (config.EMAIL_ENABLED and config.ALERT_RECIPIENTS and config.SMTP_USERNAME):
        return False
    msg = EmailMessage()
    msg["Subject"] = "Security Alert: Unrecognized person detected"
    msg["From"] = config.SMTP_USERNAME
    msg["To"] = ", ".join(config.ALERT_RECIPIENTS)
    msg.set_content(f"An unrecognized individual was detected at {timestamp}.\n"
                    "Snapshot attached. Please review the dashboard.\n\n-- Automated security "
                    "alert")
    if snapshot and snapshot.exists():
        msg.add_attachment(snapshot.read_bytes(), maintype="image", subtype="jpeg",
                           filename=snapshot.name)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 - never crash the detection loop over alerting
        print(f"[!] Email alert failed: {exc}")
        return False


def dispatch_alert(snapshot: Path | None, timestamp: str) -> bool:
    """True if at least one external channel fired."""
    print(f"[ALERT] Unrecognized face at {timestamp} -> {snapshot}")
    return bool(config.ALERTS_ENABLED and _send_email(snapshot, timestamp))


# =========================================================================
# Enrollment
# =========================================================================

def enroll_from_image(name: str, role: str, image_path) -> tuple[bool, str]:
    """Encodes the first face in an image and stores it encrypted. Returns (ok, message)."""
    try:
        import face_recognition
    except ImportError:
        return False, "face_recognition isn't installed in this environment."

    image = face_recognition.load_image_file(str(image_path))
    locations = face_recognition.face_locations(image, model="hog")
    if not locations:
        return False, "No face detected in the photo."
    encoding = face_recognition.face_encodings(image, known_face_locations=locations)[0]

    known = load_encodings()
    known.setdefault(name, []).append(encoding)
    save_encodings(known)
    database.upsert_known_person(name, role)
    note = " (multiple faces found; used the first)" if len(locations) > 1 else ""
    return True, f"Enrolled '{name}' as {role}{note}."


def enroll_upload(name: str, role: str, file_storage) -> tuple[bool, str]:
    """Web enrollment: saves the upload to a random temp file (never named after user input)."""
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False, dir=config.DATA_DIR) as tmp:
        file_storage.save(tmp)
        path = Path(tmp.name)
    try:
        return enroll_from_image(name, role, path)
    finally:
        path.unlink(missing_ok=True)


def count_faces(image_path) -> int:
    """Number of faces found in an image (0 if unreadable). Used to vet visitor self-photos."""
    try:
        import face_recognition
        img = face_recognition.load_image_file(str(image_path))
        return len(face_recognition.face_locations(img, model="hog"))
    except Exception:
        return 0


def enroll_from_webcam(name: str, role: str, num_samples: int = 5) -> tuple[bool, str]:
    import cv2
    import face_recognition

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return False, "Could not open webcam."
    samples = []
    print("Look at the camera. Press 'q' to cancel.")
    while len(samples) < num_samples:
        ok, frame = cap.read()
        if not ok:
            break
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs = face_recognition.face_locations(rgb, model="hog")
        if locs:
            samples.append(face_recognition.face_encodings(rgb, known_face_locations=locs)[0])
        cv2.putText(frame, f"Samples: {len(samples)}/{num_samples}", (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 200, 0), 2)
        cv2.imshow("Enrollment", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
    cap.release()
    cv2.destroyAllWindows()
    if not samples:
        return False, "No usable face samples captured."
    known = load_encodings()
    known.setdefault(name, []).append(np.mean(samples, axis=0))
    save_encodings(known)
    database.upsert_known_person(name, role)
    return True, f"Enrolled '{name}' as {role}."


def remove_person(name: str) -> None:
    database.delete_known_person(name)
    known = load_encodings()
    known.pop(name, None)
    save_encodings(known)


# =========================================================================
# Live detection loop
# =========================================================================

_frame_lock = threading.Lock()
_latest_jpeg: bytes | None = None


def get_latest_jpeg() -> bytes | None:
    with _frame_lock:
        return _latest_jpeg


def _publish_frame(cv2, frame) -> None:
    global _latest_jpeg
    ok, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
    if ok:
        with _frame_lock:
            _latest_jpeg = buf.tobytes()


def _save_snapshot(cv2, frame, face_box, distance) -> Path:
    """Saves evidence with the triggering face boxed and its match distance drawn on it."""
    config.ensure_directories()
    path = config.SNAPSHOT_DIR / datetime.now().strftime("unknown_%Y%m%d_%H%M%S_%f.jpg")
    img = frame.copy()
    top, right, bottom, left = face_box
    cv2.rectangle(img, (left, top), (right, bottom), (0, 0, 255), 3)
    label = "UNRECOGNIZED FACE" + (f"  (distance {distance:.2f})" if distance is not None else "")
    (tw, th), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.6, 2)
    y0 = max(top - th - 12, 0)
    cv2.rectangle(img, (left, y0), (left + tw + 10, y0 + th + 10), (0, 0, 255), -1)
    cv2.putText(img, label, (left + 5, y0 + th + 4), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255),
                2)
    cv2.imwrite(str(path), img)
    return path


class UnknownFaceTracker:
    """
    Per-stranger alert cooldowns. Each recently seen unknown face gets its own clock
    (matched by face distance), so one lingering stranger never suppresses the alert
    for a different stranger who arrives a moment later.
    """

    def __init__(self, tolerance, cooldown, forget_after=300):
        self.tolerance, self.cooldown, self.forget_after = tolerance, cooldown, forget_after
        self._tracked: list[dict] = []

    def should_alert(self, encoding, now=None) -> bool:
        now = now if now is not None else time.time()
        self._tracked = [t for t in self._tracked if now - t["seen"] <= self.forget_after]
        if self._tracked:
            d = np.linalg.norm(np.array([t["enc"] for t in self._tracked]) - encoding, axis=1)
            i = int(np.argmin(d))
            if d[i] <= self.tolerance:
                t = self._tracked[i]
                t["seen"], t["enc"] = now, encoding
                if now - t["alerted"] >= self.cooldown:
                    t["alerted"] = now
                    return True
                return False
        self._tracked.append({"enc": encoding, "alerted": now, "seen": now})
        return True


def run_camera(camera_index=0, show_window=True, stop_event: threading.Event | None = None) -> None:
    """
    show_window=True : local OpenCV window (CLI use, quit with 'q').
    show_window=False: headless background thread for the web app; frames go to get_latest_jpeg().
    """
    import cv2
    import face_recognition

    database.init_db()
    known_enc, known_names = _flat_known()
    print(f"[i] Loaded {len(known_enc)} encoding(s) for {len(set(known_names))} known people.")

    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        print("[!] Could not open camera. Check camera_index / permissions.")
        return

    tracker = UnknownFaceTracker(config.MATCH_TOLERANCE, config.ALERT_COOLDOWN_SECONDS)
    last_known_log: dict[str, float] = {}
    frame_no, scale = 0, 1 / config.RESIZE_SCALE
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                print("[!] Failed to read from camera.")
                break
            frame_no += 1
            display = frame.copy()

            if frame_no % config.FRAME_SKIP == 0:
                small = cv2.resize(frame, (0, 0), fx=config.RESIZE_SCALE, fy=config.RESIZE_SCALE)
                rgb = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
                locations = face_recognition.face_locations(rgb, model="hog")
                encodings = face_recognition.face_encodings(rgb, known_face_locations=locations)

                for (t, r, b, l), enc in zip(locations, encodings):
                    t, r, b, l = int(t * scale), int(r * scale), int(b * scale), int(l * scale)
                    name, distance = None, None
                    if known_enc:
                        d = face_recognition.face_distance(known_enc, enc)
                        i = int(np.argmin(d))
                        distance = float(d[i])
                        if distance <= config.MATCH_TOLERANCE:
                            name = known_names[i]

                    color = (0, 200, 0) if name else (0, 0, 255)
                    cv2.rectangle(display, (l, t), (r, b), color, 2)
                    cv2.putText(display, name or "Unknown", (l, t - 10), cv2.FONT_HERSHEY_SIMPLEX,
                                0.7, color, 2)

                    now = time.time()
                    if name:
                        # log a known person at most once per cooldown, not once per frame
                        if now - last_known_log.get(name, 0) >= config.KNOWN_LOG_COOLDOWN_SECONDS:
                            last_known_log[name] = now
                            database.log_access_event("known", name, None)
                    elif tracker.should_alert(enc, now):
                        snap = _save_snapshot(cv2, frame, (t, r, b, l), distance)
                        sent = dispatch_alert(snap, datetime.now().isoformat(timespec="seconds"))
                        database.log_access_event("unknown", None, snap.name, alert_sent=sent)

            _publish_frame(cv2, display)
            if show_window:
                cv2.imshow("Smart Security Camera", display)
                if cv2.waitKey(1) & 0xFF == ord("q"):
                    break
            elif stop_event is not None and stop_event.is_set():
                break
            else:
                time.sleep(0.01)
    finally:
        cap.release()
        if show_window:
            cv2.destroyAllWindows()


# =========================================================================
# Model evaluation (charter objective: >= 85% accuracy)
# Dataset layout:  evaluation/test_dataset/<enrolled name>/*.jpg  (held-out photos
# of enrolled people) and evaluation/test_dataset/unknown/*.jpg (impostors).
# =========================================================================

def run_evaluation(tolerance: float | None = None) -> dict:
    import face_recognition

    tolerance = config.MATCH_TOLERANCE if tolerance is None else tolerance
    known_enc, known_names = _flat_known()
    results, no_face = [], 0

    for person_dir in sorted(p for p in config.EVAL_DATASET_DIR.iterdir() if p.is_dir()):
        for img_path in sorted(person_dir.iterdir()):
            if img_path.suffix.lower() not in (".jpg", ".jpeg", ".png"):
                continue
            start = time.perf_counter()
            image = face_recognition.load_image_file(str(img_path))
            locs = face_recognition.face_locations(image, model="hog")
            if not locs:
                no_face += 1
                continue
            enc = face_recognition.face_encodings(image, known_face_locations=locs)[0]
            predicted = "unknown"
            if known_enc:
                d = face_recognition.face_distance(known_enc, enc)
                i = int(np.argmin(d))
                if d[i] <= tolerance:
                    predicted = known_names[i]
            results.append({"image": f"{person_dir.name}/{img_path.name}", "true": person_dir.name,
                            "predicted": predicted, "latency": time.perf_counter() - start})

    if not results:
        return {"error": "No usable probe images found (see README, 'Evaluating the model').",
                "no_face_detected": no_face}

    known_p = [r for r in results if r["true"] != "unknown"]
    unknown_p = [r for r in results if r["true"] == "unknown"]
    correct = sum(r["true"] == r["predicted"] for r in results)
    accuracy = correct / len(results)
    frr = (sum(r["predicted"] == "unknown" for r in known_p) / len(known_p)) if known_p else None
    far = (sum(r["predicted"] != "unknown"
               for r in unknown_p) / len(unknown_p)) if unknown_p else None
    lat = [r["latency"] for r in results]

    per_person = {}
    for r in known_p:
        b = per_person.setdefault(r["true"], {"total": 0, "correct": 0})
        b["total"] += 1
        b["correct"] += int(r["true"] == r["predicted"])
    for b in per_person.values():
        b["accuracy"] = round(b["correct"] / b["total"], 4)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "match_tolerance_used": tolerance,
        "total_probe_images": len(results),
        "images_with_no_detectable_face": no_face,
        "accuracy": round(accuracy, 4),
        "meets_85pct_objective": accuracy >= 0.85,
        "false_reject_rate": round(frr, 4) if frr is not None else None,
        "false_accept_rate": round(far, 4) if far is not None else None,
        "mean_latency_seconds": round(sum(lat) / len(lat), 4),
        "max_latency_seconds": round(max(lat), 4),
        "known_probe_count": len(known_p),
        "unknown_probe_count": len(unknown_p),
        "per_person_accuracy": per_person,
        "misclassifications": [{"image": r["image"], "true_label": r["true"],
                                "predicted_label": r["predicted"]}
                               for r in results if r["true"] != r["predicted"]],
    }


def save_evaluation_report(report: dict) -> None:
    config.EVAL_DIR.mkdir(parents=True, exist_ok=True)
    config.EVAL_REPORT_PATH.write_text(json.dumps(report, indent=2))
