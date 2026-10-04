"""
Crime heat map module (spatial analysis, street-level density, feedback, data loading).

Pipeline from the charter: coordinates -> spatial analysis -> density calculation
-> hotspot identification -> interactive map. Everything is computed in METRES
around the campus (a local flat-earth projection, accurate to well under 1% over
a city), so distances such as "150 m around this street" are real distances.

Why the first version looked wrong
    * its KDE bandwidth was derived from the spread of ALL incidents (~1-2 km),
      which blurs every street into a single blob;
    * the browser then drew each grid cell with a fixed *pixel* radius, so the
      blob did not correspond to any real distance on the ground.
Here the bandwidth is a fixed real-world distance (config.HEATMAP_BANDWIDTH_M) and
the map draws each cell as a circle with a radius in metres.
"""

import csv
import json
import math
import random
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

import numpy as np
from sklearn.neighbors import BallTree, KernelDensity

import config
import database

CRIME_TYPES = ["Robbery", "Burglary", "Assault", "Theft", "Vandalism", "Vehicle break-in"]

_M_PER_DEG_LAT = 110_540.0
_M_PER_DEG_LNG = 111_320.0 * math.cos(math.radians(config.CAMPUS_LAT))


# --- projection helpers ---------------------------------------------------------

def to_xy(lat, lng):
    """lat/lng (scalars or arrays) -> metres east/north of the campus."""
    return ((np.asarray(lng) - config.CAMPUS_LNG) * _M_PER_DEG_LNG,
            (np.asarray(lat) - config.CAMPUS_LAT) * _M_PER_DEG_LAT)


def to_latlng(x, y):
    return (config.CAMPUS_LAT + np.asarray(y) / _M_PER_DEG_LAT,
            config.CAMPUS_LNG + np.asarray(x) / _M_PER_DEG_LNG)


def _load(days=None, crime_types=None):
    rows = database.all_crime_incidents(days, crime_types)
    pts = np.array([to_xy(r["latitude"], r["longitude"]) for r in rows]) if rows else np.empty((0,
        2))
    return rows, pts


# --- density surface (the heat layer) -----------------------------------------------

def density_cells(days=None, crime_types=None) -> dict:
    """
    Gaussian KDE evaluated only on cells near incidents (sparse => small payload).
    Returns {"cells": [{lat, lng, w, per_km2}], "cell_m", "bandwidth_m", "count"}.
    `w` is 0-1 relative to the densest cell; `per_km2` is the estimated incidents per km^2.
    """
    rows, pts = _load(days, crime_types)
    bw, cell = config.HEATMAP_BANDWIDTH_M, config.HEATMAP_CELL_M
    out = {"cells": [], "cell_m": cell, "bandwidth_m": bw, "count": len(rows)}
    if len(pts) == 0:
        return out

    reach = 2.5 * bw
    while True:                                   # coarsen the grid if the area is huge
        k = int(reach // cell)
        offs = np.array([(i, j) for i in range(-k, k + 1) for j in range(-k, k + 1)
                         if math.hypot(i, j) * cell <= reach])
        idx = np.unique((np.round(pts / cell).astype(int)[:, None, :] + offs[None]).reshape(-1, 2),
                        axis=0)
        if len(idx) <= config.HEATMAP_MAX_CELLS:
            break
        cell *= 1.5
        out["cell_m"] = cell
    centres = idx * cell

    kde = KernelDensity(kernel="gaussian", bandwidth=bw, rtol=1e-3).fit(pts)
    per_m2 = np.exp(kde.score_samples(centres)) * len(pts)      # incidents per m^2
    weight = per_m2 / per_m2.max()
    keep = weight >= 0.04
    lat, lng = to_latlng(centres[keep, 0], centres[keep, 1])
    out["cells"] = [
        {"lat": round(float(a), 6), "lng": round(float(b), 6),
         "w": round(float(w), 3), "per_km2": round(float(d * 1e6), 1)}
        for a, b, w, d in zip(lat, lng, weight[keep], per_m2[keep])
    ]
    return out


# --- "how dense is it on THIS street?" -------------------------------------------------------

def _level(pct: float, count: int) -> str:
    if count == 0:
        return "None recorded"
    if pct >= 90:
        return "Very high"
    if pct >= 70:
        return "High"
    if pct >= 40:
        return "Moderate"
    return "Low"


def density_at(lat, lng, radius_m=None, days=None, crime_types=None, street=None) -> dict:
    """
    Incidents within `radius_m` of a clicked point, with a risk level that compares this
    spot to every other recorded incident location (percentile of nearby-incident counts).
    """
    radius_m = radius_m or config.STREET_RADIUS_M
    rows, pts = _load(days, crime_types)
    res = {"radius_m": radius_m, "count": 0, "per_km2": 0.0, "level": "None recorded",
           "percentile": 0, "by_type": {}, "last_incident": None, "last_30_days": 0,
           "street": street, "street_total": None, "total_incidents": len(rows)}
    if not rows:
        return res

    x, y = to_xy(lat, lng)
    tree = BallTree(pts)
    near = tree.query_radius([[float(x), float(y)]], r=radius_m)[0]
    res["count"] = int(len(near))
    res["per_km2"] = round(len(near) / (math.pi * (radius_m / 1000) ** 2), 1)

    neighbour_counts = tree.query_radius(pts, r=radius_m, count_only=True)
    pct = float((neighbour_counts <= len(near)).mean() * 100)
    res["percentile"] = round(pct)
    res["level"] = _level(pct, len(near))

    if len(near):
        picked = [rows[i] for i in near]
        res["by_type"] = dict(Counter(r["crime_type"] or "Other" for r in picked).most_common())
        dated = sorted(r["occurred_at"] for r in picked if r["occurred_at"])
        res["last_incident"] = dated[-1] if dated else None
        cutoff = (datetime.now() - timedelta(days=30)).isoformat(timespec="seconds")
        res["last_30_days"] = sum(1 for d in dated if d >= cutoff)

    if street:                                    # whole-street total by stored street name
        key = street.strip().lower()
        res["street_total"] = sum(1 for r in rows if (r["street"] or "").strip().lower() == key)
    return res


# --- rankings ------------------------------------------------------------------

def top_streets(top_n=8, days=None, crime_types=None) -> list[dict]:
    """Streets ranked by number of incidents (uses the street name stored on each incident)."""
    rows = database.all_crime_incidents(days, crime_types)
    by = {}
    for r in rows:
        name = (r["street"] or "").strip()
        if name:
            by.setdefault(name, []).append(r)
    ranked = sorted(by.items(), key=lambda kv: len(kv[1]), reverse=True)[:top_n]
    return [{
        "street": name, "count": len(items),
        "top_type": Counter(i["crime_type"] or "Other" for i in items).most_common(1)[0][0],
        "last_incident": max((i["occurred_at"] or "") for i in items) or None,
        "lat": sum(i["latitude"] for i in items) / len(items),
        "lng": sum(i["longitude"] for i in items) / len(items),
    } for name, items in ranked]


def hotspots(top_n=5, days=None, crime_types=None) -> list[dict]:
    """Distinct density peaks (peaks closer than 2 bandwidths are merged)
    with their nearest street name."""
    data = density_cells(days, crime_types)
    cells = sorted(data["cells"], key=lambda c: c["w"], reverse=True)
    rows = database.all_crime_incidents(days, crime_types)
    picked = []
    for c in cells:
        cx, cy = to_xy(c["lat"], c["lng"])
        if all(math.hypot(cx - px, cy - py) > 2 * config.HEATMAP_BANDWIDTH_M for px, py,
               _ in picked):
            picked.append((float(cx), float(cy), c))
        if len(picked) == top_n:
            break
    out = []
    for cx, cy, c in picked:
        near = [r for r in rows
                if math.hypot(*(np.subtract(to_xy(r["latitude"], r["longitude"]), (cx,
                    cy)))) <= config.STREET_RADIUS_M]
        streets = Counter((r["street"] or "").strip() for r in near if r["street"])
        out.append({"lat": c["lat"], "lng": c["lng"], "weight": c["w"],
                    "incidents_nearby": len(near),
                    "street": streets.most_common(1)[0][0] if streets else None})
    return out


def incident_summary(days=None, crime_types=None) -> dict:
    rows = database.all_crime_incidents(days, crime_types)
    return {"total": len(rows), "by_type": dict(Counter(r["crime_type"] or "Other"
                                                        for r in rows).most_common())}


# --- student feedback (charter objective #3) -------------------------------------------------

def record_feedback(felt_more_aware: bool, comment=None, session_id=None) -> bool:
    return database.insert_feedback(felt_more_aware, (comment or "").strip()[:500] or None,
                                    session_id)


# --- data loading -------------------------------------------------------------------------

# Fake "streets" (start/end offsets from campus, in metres) so the demo data lines up along
# street-like corridors. They are NOT real streets: replace with real data (import_csv).
_DEMO_STREETS = [
    ("Sample Road A", (-600, -200), (700, -150), 30),
    ("Sample Road B", (200, -900), (250, 800), 22),
    ("Sample Avenue C", (-900, 500), (100, 600), 14),
    ("Sample Street D", (-300, -700), (-350, 400), 10),
]


def generate_sample_data(count=250, seed=42) -> int:
    """Synthetic incidents clustered along the demo streets (plus ~15% scattered)."""
    rng = random.Random(seed)
    database.init_db()
    weights = [s[3] for s in _DEMO_STREETS]
    now, rows = datetime.now(), []
    for _ in range(count):
        if rng.random() < 0.15:
            x, y, street = rng.gauss(0, 900), rng.gauss(0, 900), None
        else:
            name, a, b, _w = rng.choices(_DEMO_STREETS, weights=weights)[0]
            t = min(max(rng.gauss(0.5, 0.25), 0), 1)
            x = a[0] + (b[0] - a[0]) * t + rng.gauss(0, 8)     # ~8 m of GPS jitter
            y = a[1] + (b[1] - a[1]) * t + rng.gauss(0, 8)
            street = name
        lat, lng = to_latlng(x, y)
        when = now - timedelta(days=rng.randint(0, 365), hours=rng.randint(0, 23))
        rows.append((float(lat), float(lng), rng.choice(CRIME_TYPES),
                     when.isoformat(timespec="seconds"), "synthetic_demo", street))
    return database.insert_crime_incidents_bulk(rows)


def import_csv(path: str) -> int:
    """Imports a real dataset. Columns: latitude, longitude, crime_type, occurred_at[, street]."""
    database.init_db()
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            try:
                rows.append((float(r["latitude"]), float(r["longitude"]),
                             (r.get("crime_type") or "Other").strip(),
                             (r.get("occurred_at")
                              or datetime.now().isoformat(timespec="seconds")).strip(),
                             "csv_import", (r.get("street") or "").strip() or None))
            except (KeyError, ValueError):
                continue
    return database.insert_crime_incidents_bulk(rows)


def reverse_geocode(lat, lng) -> str | None:
    """Street name for a coordinate via OpenStreetMap Nominatim
    (needs internet; be polite: 1 req/s)."""
    url = "https://nominatim.openstreetmap.org/reverse?" + urllib.parse.urlencode(
        {"lat": lat, "lon": lng, "format": "jsonv2", "zoom": 17})
    req = urllib.request.Request(url, headers={"User-Agent": "campus-security-prototype/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            addr = json.load(resp).get("address", {})
        return addr.get("road") or addr.get("pedestrian") or addr.get("suburb")
    except Exception:  # noqa: BLE001 - best effort
        return None


def backfill_streets(limit=200) -> int:
    """Fills in the street name for incidents that have none (slow: one lookup per second)."""
    done = 0
    for r in database.incidents_missing_street(limit):
        name = reverse_geocode(r["latitude"], r["longitude"])
        if name:
            database.set_incident_street(r["id"], name)
            done += 1
        time.sleep(1.1)
    return done
