# Smart Security Camera & Crime Heat Map

Capstone prototype: facial-recognition entry monitoring with real-time alerts, plus a
**street-level** crime heat map for safer route planning. One Flask app, three role-based views.

## Project layout (12 files)

```
app.py              Flask app: auth, all routes, JSON APIs
crime.py            Heat map maths (KDE, street density, hotspots), feedback, sample data, CSV import
face.py             Face recognition: encrypted encodings, enrolment, camera loop, alerts, evaluation
database.py         SQLite schema + queries
config.py           Settings (reads .env)
manage.py           Command-line tool: create-admin, seed-crime, import-crime, enroll, camera, evaluate ...
templates/app.html  The single template (login, student, security, admin)
static/style.css    Stylesheet
requirements.txt  .env.example  .gitignore  README.md
```

## Setup

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt                       # dlib needs CMake; on Windows try: conda install -c conda-forge dlib
cp .env.example .env                                  # set FACEGUARD_FLASK_SECRET and your campus coordinates
python manage.py create-admin --username admin1 --password "sa12345678"
# If admin1 already exists, update its password instead:
python manage.py set-password --username admin1 --password "sa12345678"
python manage.py seed-crime --count 250               # demo data (synthetic)
python app.py                                         # http://localhost:5000/login
```

Upgrading from the first prototype? Keep your `data/` folder: the database is migrated automatically
(a `street` column is added to `crime_incidents`).

## The crime heat map (what changed)

**Problem:** the old KDE bandwidth came from the spread of *all* incidents (about 1-2 km), so every
street blurred into one blob, and the browser drew it with a fixed pixel radius that meant nothing on the ground.

**Now:**
- The density surface uses a fixed real-world bandwidth (`FACEGUARD_HEAT_BANDWIDTH_M`, default 120 m) and is drawn as
  circles sized in metres, so it follows individual streets and scales correctly when you zoom.
- Every recorded incident is a coloured dot (colour = crime type) with a popup showing type, street and date.
- **Click anywhere on the map** (or on a dot) to see that street's density: incidents within
  `FACEGUARD_STREET_RADIUS_M` (default 150 m), incidents per km², a Very high / High / Moderate / Low level
  (percentile against all other recorded incident locations), last incident, last-30-day count,
  breakdown by crime type, and the street's all-time total. Street names come from OpenStreetMap (Nominatim).
- **Most Affected Streets** and **Density Hotspots** lists (click one to fly there and inspect it).
- Filters: time period (30 / 90 / 365 days) and crime type; layer toggles for density and incident dots.

Security and Admin can click a spot and choose **Log an incident here** (street auto-filled), and delete
mistaken records from a dot's popup.

### Using real data
The demo generator places incidents along fake "Sample Road" streets, so they will not line up with real roads
on the map. For a real deployment:
```bash
python manage.py import-crime incidents.csv     # columns: latitude,longitude,crime_type,occurred_at[,street]
python manage.py backfill-streets               # optional: look up street names (1 request/second, needs internet)
```
Density is only as good as the coordinates: use the most precise location available for each incident.

## Other new features and fixes

- **Live alert banner + sound** on the Security/Admin dashboard when a new unknown face is logged.
- **Camera log flood fixed:** known people are logged at most once per 30 s, and unknown faces only when an alert fires
  (before, every processed frame wrote a row).
- Snapshots are stored by file name (works on Windows paths); **purge also deletes the snapshot files**.
- Student feedback is limited to one response per anonymous browser id (the docs claimed this, the code did not enforce it).
- **Security hardening:** CSRF token on every POST, login rate limiting (5 failures / 5 min per IP),
  open-redirect fix on `?next=`, random temp file for enrolment uploads (the old one was named after user input),
  8+ character passwords, upload size limit, warning if the default secret key is in use.
- `/security` and `/admin` both go to one dashboard (`/staff`); admins additionally see an Administration section.

## Roles

| Role | Sees |
|------|------|
| Student | Heat map, street density, feedback prompt |
| Security | Live camera, events + alerts, visitor check-in, heat map with incident logging, analytics, CSV export |
| Admin | Everything Security has, plus enrolled people, login accounts, retention/purge, model evaluation, feedback roll-up, crime CSV export |

Accounts are created by an admin; there is no public sign-up.

## Evaluating the face model

Create `evaluation/test_dataset/` like this (use **held-out** photos, not the enrolment photo):
```
evaluation/test_dataset/
    Jane Doe/        photos of an enrolled person (folder name = enrolled name)
    unknown/         photos of people who are NOT enrolled
```
Then `python manage.py evaluate [--tolerance 0.45]`. It reports accuracy (target >= 85%), False Accept Rate,
False Reject Rate and latency, and the Admin dashboard shows the result. Aim for 5-10 photos per person and 10+ unknowns.

## Tuning (`config.py` / `.env`)

`MATCH_TOLERANCE` (lower = stricter faces), `ALERT_COOLDOWN_SECONDS`, `FRAME_SKIP`, `RESIZE_SCALE`,
`FACEGUARD_HEAT_BANDWIDTH_M`, `FACEGUARD_STREET_RADIUS_M`, `FACEGUARD_RETENTION_DAYS`.

## Known limitations

- SQLite and local files suit a demo, not a multi-building deployment.
- Street names and the map tiles need an internet connection (OpenStreetMap). Nominatim asks for at most 1 request/second;
  the app queues and caches lookups, but heavy use should switch to a self-hosted or paid geocoder.
- The density is a statistical estimate of *historical* crime; it is not a prediction or a live threat feed.
- The face model runs on CPU (dlib HOG) and may lag with several faces on low-end hardware.
- Flask's built-in server is for development. Put it behind a production WSGI server and HTTPS for anything real.
