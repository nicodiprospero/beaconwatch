from flask import Flask, jsonify, render_template
from flask_cors import CORS
import sqlite3
import os
import json
import threading
import time
import datetime

import mitre_mapper
import data_collector

# -------------------------------------------------------
# BeaconWatch Dashboard
# -------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "listener_state.db")

app = Flask(__name__)
CORS(app)

# -------------------------------------------------------
# Database Helpers
# -------------------------------------------------------

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_events(limit=500):
    conn = get_connection()

    rows = conn.execute(
        """
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    events = []

    for row in rows:

        item = dict(row)

        try:
            item["yara_hits"] = json.loads(
                item.get("yara_hits") or "[]"
            )
        except:
            item["yara_hits"] = []

        item["anomaly"] = bool(item.get("anomaly"))

        events.append(item)

    return events


# -------------------------------------------------------
# Dashboard Summary
# -------------------------------------------------------

def build_dashboard():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    mitre = mitre_mapper.get_heatmap_data()

    summary = analysis["summary"]

    return {

        "timestamp":
            datetime.datetime.now().isoformat(),

        "summary":
            summary,

        "mitre":
            mitre,

        "timeline":
            analysis["timeline"],

        "techniques":
            analysis["technique_counts"],

        "risk_scores":
            analysis["risk_scores"],

        "tactics":
            analysis["tactic_distribution"],

        "timing":
            analysis["timing"],

        "beacon":
            analysis["beacon_stats"],

        "anomalies":
            analysis["anomaly_events"]

    }


# -------------------------------------------------------
# Routes
# -------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/dashboard")
def api_dashboard():

    return jsonify(
        build_dashboard()
    )


@app.route("/api/events")
def api_events():

    return jsonify(
        fetch_events()
    )


@app.route("/api/mitre")
def api_mitre():

    return jsonify(
        mitre_mapper.get_heatmap_data()
    )


@app.route("/api/summary")
def api_summary():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    return jsonify(
        analysis["summary"]
    )


@app.route("/api/timeline")
def api_timeline():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    return jsonify(
        analysis["timeline"]
    )


@app.route("/api/tactics")
def api_tactics():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    return jsonify(
        analysis["tactic_distribution"]
    )


@app.route("/api/risk")
def api_risk():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    return jsonify({

        "score":
            analysis["summary"]["overall_risk_score"],

        "label":
            analysis["summary"]["overall_risk_label"],

        "risk_scores":
            analysis["risk_scores"]

    })


@app.route("/api/hardening")
def api_hardening():

    heat = mitre_mapper.get_heatmap_data()

    recommendations = []

    for item in heat:

        if item["count"] > 0:

            recommendations.append({

                "tid":
                    item["tid"],

                "name":
                    item["name"],

                "count":
                    item["count"],

                "recommendation":
                    item["hardening"]

            })

    recommendations.sort(
        key=lambda x: x["count"],
        reverse=True
    )

    return jsonify(
        recommendations
    )
# -------------------------------------------------------
# Export Routes
# -------------------------------------------------------

@app.route("/api/export/json")
def export_json():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    return jsonify(analysis)


@app.route("/api/export/stix")
def export_stix():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    bundle = data_collector.export_stix(
        analysis,
        events
    )

    return jsonify(bundle)


@app.route("/api/export/report")
def export_report():

    events = data_collector.load_events()

    analysis = data_collector.analyze(events)

    report = {

        "generated":
            datetime.datetime.now().isoformat(),

        "summary":
            analysis["summary"],

        "timing":
            analysis["timing"],

        "beacon":
            analysis["beacon_stats"],

        "techniques":
            analysis["technique_counts"],

        "risk":
            analysis["risk_scores"],

        "timeline":
            analysis["timeline"],

        "anomalies":
            analysis["anomaly_events"]

    }

    return jsonify(report)


# -------------------------------------------------------
# Metrics
# -------------------------------------------------------

@app.route("/api/stats")
def api_stats():

    events = fetch_events(10000)

    task_count = 0
    result_count = 0
    checkin_count = 0
    anomaly_count = 0
    yara_count = 0

    for e in events:

        if e["type"] == "task_sent":
            task_count += 1

        elif e["type"] == "result_received":
            result_count += 1

        elif e["type"] == "checkin":
            checkin_count += 1

        if e["anomaly"]:
            anomaly_count += 1

        yara_count += len(e["yara_hits"])

    return jsonify({

        "events":
            len(events),

        "tasks":
            task_count,

        "results":
            result_count,

        "checkins":
            checkin_count,

        "anomalies":
            anomaly_count,

        "yara_hits":
            yara_count

    })


# -------------------------------------------------------
# Top Techniques
# -------------------------------------------------------

@app.route("/api/top")
def api_top():

    heat = mitre_mapper.get_heatmap_data()

    heat.sort(
        key=lambda x: x["count"],
        reverse=True
    )

    return jsonify(
        heat[:10]
    )


# -------------------------------------------------------
# Background Cache
# -------------------------------------------------------

CACHE = {}

CACHE_LOCK = threading.Lock()


def cache_worker():

    global CACHE

    while True:

        try:

            dashboard = build_dashboard()

            with CACHE_LOCK:

                CACHE = dashboard

        except Exception as e:

            print("Cache error:", e)

        time.sleep(2)


@app.route("/api/live")
def api_live():

    with CACHE_LOCK:

        if CACHE:

            return jsonify(CACHE)

    return jsonify(build_dashboard())


# -------------------------------------------------------
# Health Check
# -------------------------------------------------------

@app.route("/health")
def health():

    return jsonify({

        "status": "ok",

        "database": os.path.exists(DB_PATH),

        "time": datetime.datetime.now().isoformat()

    })


# -------------------------------------------------------
# Error Handling
# -------------------------------------------------------

@app.errorhandler(404)
def not_found(error):

    return jsonify({

        "error": "Not Found"

    }), 404


@app.errorhandler(500)
def internal(error):

    return jsonify({

        "error": "Internal Server Error",

        "message": str(error)

    }), 500


# -------------------------------------------------------
# Startup
# -------------------------------------------------------

def start_background():

    thread = threading.Thread(

        target=cache_worker,

        daemon=True

    )

    thread.start()


if __name__ == "__main__":

    print()

    print("=" * 60)

    print(" BeaconWatch Dashboard")

    print("=" * 60)

    print()

    print(" Dashboard:")
    print(" http://127.0.0.1:5000")

    print()

    print(" APIs:")

    print(" /api/live")
    print(" /api/dashboard")
    print(" /api/events")
    print(" /api/mitre")
    print(" /api/risk")
    print(" /api/timeline")
    print(" /api/tactics")
    print(" /api/top")
    print(" /api/stats")
    print(" /api/export/json")
    print(" /api/export/stix")
    print(" /api/export/report")

    print()

    start_background()

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True,

        threaded=True

    )