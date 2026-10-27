"""Create listener_state.db with synthetic lab telemetry so the dashboard runs without a live exercise.

Every row is fabricated demo data: one simulated host checking in on a timer, discovery commands
being logged, and results coming back. Nothing here talks to a network or executes anything.
Run: python seed_demo.py [--events 120]
"""
import argparse, datetime, json, os, random, sqlite3

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "listener_state.db")
COMMANDS = [
    ("whoami", "T1033 - System Owner/User Discovery", "Discovery", 2),
    ("systeminfo", "T1082 - System Information Discovery", "Discovery", 2),
    ("ipconfig /all", "T1016 - System Network Config Discovery", "Discovery", 2),
    ("netstat -ano", "T1049 - System Network Connections Discovery", "Discovery", 3),
    ("net user", "T1087 - Account Discovery", "Discovery", 3),
    ("tasklist", "T1057 - Process Discovery", "Discovery", 2),
    ("schtasks /query", "T1053 - Scheduled Task/Job", "Persistence", 4),
    ("cmdkey /list", "T1555 - Credentials from Password Stores", "Credential Access", 5),
]

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--events", type=int, default=120); a = ap.parse_args()
    if os.path.exists(DB): os.remove(DB)
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, time TEXT, task TEXT,
                 technique TEXT, tactic TEXT, risk INTEGER, duration_ms REAL, task_time TEXT, result_time TEXT,
                 yara_hits TEXT, anomaly INTEGER)""")
    t = datetime.datetime.now() - datetime.timedelta(hours=2)
    rnd = random.Random(7)
    for i in range(a.events):
        t += datetime.timedelta(seconds=30 + rnd.uniform(-2, 2))          # simulated check-in roughly every 30 s
        c.execute("INSERT INTO events(type,time) VALUES('checkin',?)", (t.isoformat(),))
        if i % 3 == 0:
            cmd, tech, tactic, risk = rnd.choice(COMMANDS)
            dur = rnd.uniform(80, 900)
            res = t + datetime.timedelta(milliseconds=dur)
            hits = json.dumps(["Suspicious_Recon_Burst"] if tactic != "Discovery" else [])
            c.execute("INSERT INTO events(type,time,task,technique,tactic,risk) VALUES('task_sent',?,?,?,?,?)",
                      (t.isoformat(), cmd, tech, tactic, risk))
            c.execute("""INSERT INTO events(type,time,task,technique,tactic,risk,duration_ms,task_time,result_time,yara_hits,anomaly)
                         VALUES('result_received',?,?,?,?,?,?,?,?,?,?)""",
                      (res.isoformat(), cmd, tech, tactic, risk, round(dur, 1), t.isoformat(), res.isoformat(), hits, int(risk >= 4)))
    c.commit(); n = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]; c.close()
    print(f"wrote {n} synthetic events to {DB}")

if __name__ == "__main__":
    main()
