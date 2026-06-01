
from flask import (
    Flask,
    render_template,
    redirect,
    request,
    send_file
)

from flask_socketio import SocketIO

import os
import zipfile

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet

from storage import (
    get_alerts,
    get_total_events,
    get_total_alerts,
    get_unique_attackers,
    get_alert_counts,
    get_attack_timeline,
    get_top_attackers,
    get_incidents,
    update_incident_status,
    insert_event
)

from parsers.auth_parser import parse_auth_log
from parsers.firewall_parser import parse_firewall_log
from parsers.nginx_parser import parse_web_log
from parsers.dns_parser import parse_dns_log

from utils.log_detector import detect_log_type

app = Flask(__name__)

socketio = SocketIO(app)

UPLOAD_FOLDER = "uploads"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    return render_template(
        "dashboard.html",

        alerts=get_alerts(),

        total_events=get_total_events(),

        total_alerts=get_total_alerts(),

        unique_attackers=get_unique_attackers(),

        severity_data=get_alert_counts(),

        attack_timeline=get_attack_timeline(),

        top_attackers=get_top_attackers()
    )


# ==========================================
# INCIDENT MANAGEMENT
# ==========================================

@app.route("/incidents")
def incidents():

    return render_template(
        "incidents.html",
        incidents=get_incidents()
    )


# ==========================================
# INCIDENT STATUS UPDATE
# ==========================================

@app.route(
    "/incident/<int:incident_id>/<status>"
)
def incident_action(
    incident_id,
    status
):

    status = status.upper()

    allowed = [
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "CLOSED"
    ]

    if status in allowed:

        update_incident_status(
            incident_id,
            status
        )

    return redirect("/incidents")


# ==========================================
# LOG UPLOAD PAGE
# ==========================================

@app.route("/upload")
def upload_page():

    return render_template(
        "upload.html"
    )


# ==========================================
# LOG UPLOAD HANDLER
# ==========================================

@app.route(
    "/upload-log",
    methods=["POST"]
)
def upload_log():

    files = request.files.getlist(
        "logfiles"
    )

    uploaded_files = []

    for file in files:

        if file.filename == "":
            continue

        filepath = os.path.join(
            UPLOAD_FOLDER,
            file.filename
        )

        file.save(filepath)

        uploaded_files.append(
            filepath
        )

        # ZIP SUPPORT

        if file.filename.lower().endswith(".zip"):

            extract_folder = os.path.join(
                UPLOAD_FOLDER,
                "extracted"
            )

            os.makedirs(
                extract_folder,
                exist_ok=True
            )

            with zipfile.ZipFile(
                filepath,
                "r"
            ) as zip_ref:

                zip_ref.extractall(
                    extract_folder
                )

            for root, dirs, extracted in os.walk(
                extract_folder
            ):
                for f in extracted:

                    uploaded_files.append(
                        os.path.join(
                            root,
                            f
                        )
                    )

    total_events = 0

    for filepath in uploaded_files:

        log_type = detect_log_type(
            filepath
        )

        print(
            f"Detected: {log_type} -> {filepath}"
        )

        events = []

        if log_type == "auth":

            events = parse_auth_log(
                filepath
            )

        elif log_type == "firewall":

            events = parse_firewall_log(
                filepath
            )

        elif log_type == "web":

            events = parse_web_log(
                filepath
            )

        elif log_type == "dns":

            events = parse_dns_log(
                filepath
            )

            print(
                f"DNS EVENTS FOUND: {len(events)}"
            )

        else:

            print(
                f"[WARNING] Unsupported log type: {filepath}"
            )

        for event in events:

            try:

                insert_event(event)

                total_events += 1

                if total_events % 100 == 0:

                    print(
                        f"Inserted {total_events} events"
                    )

            except Exception as e:

                print(
                    f"INSERT ERROR: {e}"
                )

    return f'''

    <h2>Upload Successful</h2>

    <p>
    Files Processed:
    {len(uploaded_files)}
    </p>

    <p>
    Events Parsed:
    {total_events}
    </p>

    <a href="/">
    Return Dashboard
    </a>

    '''


# ==========================================
# PDF REPORT
# ==========================================

@app.route("/generate-report")
def generate_report():

    pdf_path = "Security_Report.pdf"

    pdf = SimpleDocTemplate(
        pdf_path
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "SOC Sentinel Security Report",
            styles["Title"]
        )
    )

    content.append(
        Spacer(
            1,
            20
        )
    )

    content.append(
        Paragraph(
            f"Total Events: {get_total_events()}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Total Alerts: {get_total_alerts()}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Unique Attackers: {get_unique_attackers()}",
            styles["Normal"]
        )
    )

    pdf.build(
        content
    )

    return send_file(
        pdf_path,
        as_attachment=True
    )


# ==========================================
# HEALTH CHECK
# ==========================================

@app.route("/health")
def health():

    return {
        "status": "online",
        "service": "SOC Sentinel XDR"
    }


# ==========================================
# START APP
# ==========================================

if __name__ == "__main__":

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True
    )

