"""
One command-line tool for every setup / maintenance task.

    python manage.py create-admin --username admin1 --password "sa12345678"
    python manage.py seed-crime --count 250          # synthetic demo incidents
    python manage.py import-crime data.csv
        (real data: latitude,longitude,crime_type,occurred_at[,street])
    python manage.py backfill-streets
        (look up street names for incidents that have none; needs internet)
    python manage.py enroll --name "Jane Doe" --role student --image photo.jpg   (or --webcam)
    python manage.py camera                          # standalone camera window (press q to quit)
    python manage.py evaluate [--tolerance 0.45]     # accuracy / FAR / FRR / latency report
"""

import argparse
import json
import sys

from werkzeug.security import generate_password_hash

import config
import crime
import database


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("create-admin")
    a.add_argument("--username", required=True)
    a.add_argument("--password", required=True)

    w = sub.add_parser("set-password")
    w.add_argument("--username", required=True)
    w.add_argument("--password", required=True)

    s = sub.add_parser("seed-crime")
    s.add_argument("--count", type=int, default=250)

    i = sub.add_parser("import-crime")
    i.add_argument("csv_path")

    b = sub.add_parser("backfill-streets")
    b.add_argument("--limit", type=int, default=200)

    e = sub.add_parser("enroll")
    e.add_argument("--name", required=True)
    e.add_argument("--role", default="student", choices=["student", "staff", "security"])
    src = e.add_mutually_exclusive_group(required=True)
    src.add_argument("--image")
    src.add_argument("--webcam", action="store_true")

    sub.add_parser("camera")

    v = sub.add_parser("evaluate")
    v.add_argument("--tolerance", type=float)

    args = p.parse_args()
    config.ensure_directories()
    database.init_db()

    if args.cmd == "create-admin":
        database.create_user(args.username, generate_password_hash(args.password), role="admin")
        print(f"[+] Admin '{args.username}' ready. Log in at /login.")
    elif args.cmd == "set-password":
        if database.set_password(args.username, generate_password_hash(args.password)):
            print(f"[+] Password updated for '{args.username}'.")
        else:
            print(f"[!] No user named '{args.username}'.")
    elif args.cmd == "seed-crime":
        n = crime.generate_sample_data(args.count)
        print(f"[+] Inserted {n} SYNTHETIC incidents around ({config.CAMPUS_LAT}, {config.CAMPUS_LNG}).")
        print("    They lie along fake 'Sample' streets. Use import-crime with real data for a "
              "real deployment.")
    elif args.cmd == "import-crime":
        print(f"[+] Imported {crime.import_csv(args.csv_path)} incidents.")
        print("    Tip: run 'backfill-streets' if your file has no street column.")
    elif args.cmd == "backfill-streets":
        print(f"[+] Named {crime.backfill_streets(args.limit)} incident streets.")
    else:
        try:
            import face
            import cv2, face_recognition  # noqa: F401 - availability check
        except ImportError as exc:
            print(f"[!] {exc}. Install opencv-python and face_recognition (needs dlib) first.")
            return 1
        if args.cmd == "enroll":
            ok, msg = (face.enroll_from_webcam(args.name, args.role) if args.webcam
                       else face.enroll_from_image(args.name, args.role, args.image))
            print(("[+] " if ok else "[!] ") + msg)
            return 0 if ok else 1
        if args.cmd == "camera":
            face.run_camera(show_window=True)
        elif args.cmd == "evaluate":
            report = face.run_evaluation(args.tolerance)
            if "error" not in report:
                face.save_evaluation_report(report)
            print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
