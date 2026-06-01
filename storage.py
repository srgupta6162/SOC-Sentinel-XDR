
import sqlite3
from datetime import datetime

DB_NAME = "siem.db"


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def init_db():

    conn = sqlite3.connect(DB_NAME)

    # ======================================
    # EVENTS TABLE
    # ======================================

    conn.execute("""
    CREATE TABLE IF NOT EXISTS events (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        type TEXT,
        status TEXT,
        ip TEXT,

        timestamp TEXT,

        raw TEXT

    )
    """)

    # ======================================
    # ALERTS TABLE (V14)
    # ======================================

    conn.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        severity TEXT,
        rule TEXT,
        ip TEXT,

        count INTEGER,

        source TEXT,

        timestamp TEXT,

        risk_score INTEGER,
        ip_type TEXT,

        message TEXT,

        country TEXT,
        asn TEXT,

        threat_score INTEGER,
        risk TEXT,

        mitre_technique TEXT,
        mitre_name TEXT,
        mitre_tactic TEXT

    )
    """)

    # ======================================
    # INCIDENTS TABLE
    # ======================================

    conn.execute("""
    CREATE TABLE IF NOT EXISTS incidents (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        alert_rule TEXT,

        ip TEXT,

        severity TEXT,

        status TEXT,

        created_at TEXT

    )
    """)

    conn.commit()
    conn.close()


# ==========================================
# EVENT FUNCTIONS
# ==========================================

def insert_event(event):

    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
    INSERT INTO events(

        type,
        status,
        ip,
        timestamp,
        raw

    )
    VALUES(?,?,?,?,?)
    """,
    (
        event.get("type"),
        event.get("status"),
        event.get("ip", ""),
        event.get("timestamp"),
        event.get("raw")
    ))

    conn.commit()
    conn.close()


# ==========================================
# ALERT FUNCTIONS
# ==========================================

def insert_alert(alert):

    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
    INSERT INTO alerts(

        severity,
        rule,
        ip,

        count,

        source,

        timestamp,

        risk_score,
        ip_type,

        message,

        country,
        asn,

        threat_score,
        risk,

        mitre_technique,
        mitre_name,
        mitre_tactic

    )
    
    VALUES(
       ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
    )
    """,
    (
        alert.get("severity"),

        alert.get("rule"),

        alert.get("ip"),

        alert.get("count"),

        alert.get("source"),

        alert.get("timestamp"),

        alert.get("risk_score"),

        alert.get("ip_type"),

        alert.get("message"),

        alert.get(
            "country",
            "Unknown"
        ),

        alert.get(
            "asn",
            "Unknown"
        ),

        alert.get(
            "threat_score",
            0
        ),

        alert.get(
            "risk",
            "LOW"
        ),

        alert.get(
            "mitre_technique",
            "Unknown"
        ),

        alert.get(
            "mitre_name",
            "Unknown"
        ),

        alert.get(
            "mitre_tactic",
            "Unknown"
        )
    ))

    conn.commit()
    conn.close()

def get_alerts():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT

        severity,
        rule,
        ip,

        count,

        source,

        timestamp,

        risk_score,
        ip_type,

        message,

        country,
        asn,

        threat_score,
        risk,

        mitre_technique,
        mitre_name,
        mitre_tactic

    FROM alerts

    ORDER BY id DESC
    """).fetchall()

    conn.close()

    return rows


# ==========================================
# INCIDENT MANAGEMENT
# ==========================================

def create_incident(alert):

    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
    INSERT INTO incidents(

        alert_rule,

        ip,

        severity,

        status,

        created_at

    )
    VALUES(?,?,?,?,?)
    """,
    (
        alert["rule"],

        alert["ip"],

        alert["severity"],

        "OPEN",

        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def get_incidents():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT

        id,

        alert_rule,

        ip,

        severity,

        status,

        created_at

    FROM incidents

    ORDER BY id DESC
    """).fetchall()

    conn.close()

    return rows


def update_incident_status(
    incident_id,
    status
):

    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
    UPDATE incidents
    SET status=?
    WHERE id=?
    """,
    (
        status,
        incident_id
    ))

    conn.commit()
    conn.close()


# ==========================================
# DASHBOARD STATS
# ==========================================

def get_total_events():

    conn = sqlite3.connect(DB_NAME)

    count = conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    conn.close()

    return count


def get_total_alerts():

    conn = sqlite3.connect(DB_NAME)

    count = conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    conn.close()

    return count


def get_unique_attackers():

    conn = sqlite3.connect(DB_NAME)

    count = conn.execute(
        "SELECT COUNT(DISTINCT ip) FROM alerts"
    ).fetchone()[0]

    conn.close()

    return count

def get_sigma_rule_count():

    import os

    return len([
        f for f in os.listdir("rules")
        if f.endswith(".yml")
    ])

# ==========================================
# ALERT SEVERITY STATS
# ==========================================

def get_alert_counts():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT

        severity,

        COUNT(*)

    FROM alerts

    GROUP BY severity
    """).fetchall()

    conn.close()

    return rows


# ==========================================
# ATTACK TIMELINE
# ==========================================

def get_attack_timeline():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT

        rule,

        COUNT(*)

    FROM alerts

    GROUP BY rule
    """).fetchall()

    conn.close()

    return rows


# ==========================================
# TOP ATTACKERS
# ==========================================

def get_top_attackers():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT

        ip,

        COUNT(*) as total

    FROM alerts

    GROUP BY ip

    ORDER BY total DESC

    LIMIT 10
    """).fetchall()

    conn.close()

    return rows


# ==========================================
# LOG SOURCE DISTRIBUTION
# ==========================================

def get_log_type_counts():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT

        type,

        COUNT(*)

    FROM events

    GROUP BY type
    """).fetchall()

    conn.close()

    return rows


# ==========================================
# MITRE ATT&CK STATS
# ==========================================

def get_mitre_counts():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT

        mitre_technique,

        COUNT(*)

    FROM alerts

    GROUP BY mitre_technique
    """).fetchall()

    conn.close()

    return rows


# ==========================================
# HIGH RISK ALERTS
# ==========================================

def get_high_risk_alerts():

    conn = sqlite3.connect(DB_NAME)

    rows = conn.execute("""
    SELECT *

    FROM alerts

    WHERE threat_score >= 80

    ORDER BY threat_score DESC
    """).fetchall()

    conn.close()

    return rows


# ==========================================
# SEVERITY COUNT
# ==========================================

def get_alerts_by_severity(
    severity
):

    conn = sqlite3.connect(DB_NAME)

    count = conn.execute("""
    SELECT COUNT(*)

    FROM alerts

    WHERE severity=?
    """,
    (severity,)
    ).fetchone()[0]

    conn.close()

    return count


# ==========================================
# INITIALIZE DATABASE
# ==========================================

init_db()
