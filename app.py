from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from scapy.all import IP, TCP, UDP, ICMP
from collections import deque
from threading import Thread, Lock
from datetime import datetime
from modules.capture import start_capture
from modules.detection import analyze_packet
from modules.blocking import block_ip
from modules.statistics import (
    record_packet,
    record_response_time,
    get_all_statistics
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import time
import os
from werkzeug.utils import secure_filename
from modules.pcap_analyzer import analyze_pcap
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash

# ============================================================
# NFA - NETWORK FORENSICS ANALYSIS SYSTEM
# ============================================================

app = Flask(__name__)
app.secret_key = "nfa-development-secret-key"

DATABASE = "nfa_users.db"


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# LIVE NETWORK STATISTICS
# ============================================================

stats = {
    "total_packets": 0,
    "packets_sec": 0,
    "suspicious": 0,
    "dropped": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0
}


# ============================================================
# PACKET STORAGE
# ============================================================

packet_logs = deque(maxlen=20)
packet_times = deque(maxlen=1000)

lock = Lock()


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):

    # Ignore packets without IPv4
    if not packet.haslayer(IP):
        return

    start_time = time.perf_counter()

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    # --------------------------------------------------------
    # PROTOCOL DETECTION
    # --------------------------------------------------------

    if packet.haslayer(TCP):
        protocol = "TCP"

    elif packet.haslayer(UDP):
        protocol = "UDP"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    else:
        protocol = "OTHER"

    # --------------------------------------------------------
    # PROTOCOL STATISTICS
    # --------------------------------------------------------

    with lock:

        if protocol == "TCP":
            stats["tcp"] += 1

        elif protocol == "UDP":
            stats["udp"] += 1

        elif protocol == "ICMP":
            stats["icmp"] += 1

        else:
            stats["other"] += 1

    # --------------------------------------------------------
    # THREAT DETECTION
    # --------------------------------------------------------

    try:

        detection_result = analyze_packet(packet)

    except Exception as e:

        print("[DETECTION ERROR]", e)

        detection_result = {
            "suspicious": False,
            "threat": None,
            "severity": "Low"
        }

    suspicious = bool(
        detection_result.get("suspicious", False)
    )

    threat_name = detection_result.get(
        "threat",
        None
    )

    severity = detection_result.get(
        "severity",
        "Low"
    )
    

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    if suspicious:

        status = "Monitor"

        with lock:
            stats["suspicious"] += 1

    else:

        status = "Allowed"

    # --------------------------------------------------------
    # PACKETS PER SECOND
    # --------------------------------------------------------

    now = time.time()

    with lock:

        stats["total_packets"] += 1

        packet_times.append(now)

        five_seconds_ago = now - 5

        while (
            packet_times
            and packet_times[0] < five_seconds_ago
        ):
            packet_times.popleft()

        stats["packets_sec"] = int(
            len(packet_times) / 5
        )

    # --------------------------------------------------------
    # STATISTICS MODULE
    # --------------------------------------------------------

    try:

        record_packet(
            packet_size=packet_size,
            protocol=protocol,
            suspicious=suspicious,
            threat=threat_name
        )

    except Exception as e:

        print("[STATISTICS ERROR]", e)

    # --------------------------------------------------------
    # PACKET LOG
    # --------------------------------------------------------

    with lock:

        packet_logs.appendleft({

            "time":
                datetime.now().strftime("%H:%M:%S"),

            "protocol":
                protocol,

            "status":
                status,

            "source":
                src_ip,

            "destination":
                dst_ip,

            "size":
                packet_size,

            "threat":
                threat_name
                if threat_name
                else "-",

            "severity":
                severity
        })

    # --------------------------------------------------------
    # PROCESSING TIME
    # --------------------------------------------------------

    processing_time = (
        time.perf_counter() - start_time
    ) * 1000

    try:

        record_response_time(
            processing_time
        )

    except Exception as e:

        print("[RESPONSE TIME ERROR]", e)


# ============================================================
# BACKGROUND PACKET CAPTURE
# ============================================================

def capture_worker():

    try:

        start_capture(
            process_packet
        )

    except Exception as e:

        print("[CAPTURE ERROR]", e)


# ============================================================
# LIVE API
# ============================================================

@app.route("/api/live")
def live_data():

    with lock:
        current_stats = stats.copy()
        current_logs = list(packet_logs)

    try:

        statistics_data = get_all_statistics(
            total_packets=current_stats["total_packets"],
            suspicious_packets=current_stats["suspicious"]
        )

    except Exception as e:

        import traceback

        print("\n========== STATISTICS API ERROR ==========")
        print("ERROR:", repr(e))
        print("TRACEBACK:")
        print(traceback.format_exc())
        print("==========================================\n")

        statistics_data = {}

    return jsonify({

        "stats": current_stats,

        "statistics": statistics_data,

        "logs": current_logs

    })


# ============================================================
# CREATE ACCOUNT API
# ============================================================

@app.route(
    "/api/create-account",
    methods=["POST"]
)
def create_account_api():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        username = data.get(
            "username",
            ""
        ).strip()

        email = data.get(
            "email",
            ""
        ).strip()

        password = data.get(
            "password",
            ""
        )

        confirm_password = data.get(
            "confirm_password",
            ""
        )

        if (
            not username
            or not email
            or not password
            or not confirm_password
        ):

            return jsonify({

                "success": False,

                "message":
                    "All fields are required"

            }), 400

        if password != confirm_password:

            return jsonify({

                "success": False,

                "message":
                    "Passwords do not match"

            }), 400

        if len(password) < 4:

            return jsonify({

                "success": False,

                "message":
                    "Security key must contain at least 4 characters"

            }), 400

        conn = get_db()

        existing_user = conn.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
               OR email = ?
            """,
            (
                username,
                email
            )
        ).fetchone()

        if existing_user:

            conn.close()

            return jsonify({

                "success": False,

                "message":
                    "Operator ID or email already registered"

            }), 409

        password_hash = generate_password_hash(
            password
        )

        created_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        conn.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                email,
                password_hash,
                created_at
            )
        )

        conn.commit()

        conn.close()

        print(
            f"[ACCOUNT CREATED] {username}"
        )

        return jsonify({

            "success": True,

            "message":
                "Account created successfully"

        }), 201

    except sqlite3.IntegrityError:

        return jsonify({

            "success": False,

            "message":
                "Username or email already exists"

        }), 409

    except Exception as e:

        print(
            "[CREATE ACCOUNT ERROR]",
            e
        )

        return jsonify({

            "success": False,

            "message":
                "Server error while creating account"

        }), 500


# ============================================================
# LOGIN API
# ============================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
def login_api():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        username = data.get(
            "username",
            ""
        ).strip()

        password = data.get(
            "password",
            ""
        )

        if not username or not password:

            return jsonify({

                "success": False,

                "message":
                    "Username and password are required"

            }), 400

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        conn.close()

        if not user:

            return jsonify({

                "success": False,

                "message":
                    "Invalid credentials"

            }), 401

        if not check_password_hash(
            user["password_hash"],
            password
        ):

            return jsonify({

                "success": False,

                "message":
                    "Invalid credentials"

            }), 401

        session["logged_in"] = True

        session["user_id"] = user["id"]

        session["username"] = user["username"]

        print(
            f"[LOGIN SUCCESS] {user['username']}"
        )

        return jsonify({

            "success": True,

            "message":
                "Login successful",

            "username":
                user["username"]

        })

    except Exception as e:

        print(
            "[LOGIN ERROR]",
            e
        )

        return jsonify({

            "success": False,

            "message":
                "Server error during login"

        }), 500


# ============================================================
# CURRENT USER API
# ============================================================

@app.route("/api/me")
def api_me():

    if not session.get(
        "logged_in"
    ):

        return jsonify({

            "success": False,

            "message":
                "Not logged in"

        }), 401

    return jsonify({

        "success": True,

        "username":
            session.get("username")

    })


# ============================================================
# THREAT LOG API
# ============================================================

@app.route("/api/threats")
def threat_data():

    from modules.detection import (
        get_threat_logs
    )

    return jsonify({

        "success": True,

        "threats":
            get_threat_logs()

    })


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    username = session.get(
        "username",
        "unknown"
    )

    session.clear()

    print(
        f"[LOGOUT] {username}"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# CREATE ACCOUNT PAGE
# ============================================================

@app.route("/create-account")
def create_account():

    return render_template(
        "create_account.html"
    )


# ============================================================
# LOGIN / HOME
# ============================================================




# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            url_for("home")
        )

    return render_template(
        "dashboard_v2.html"
    )


# ============================================================
# ANALYSIS PAGE
# ============================================================

@app.route("/analysis")
def analysis():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            url_for("home")
        )

    return render_template(
        "analysis.html"
    )
# ============================================================
# LIVE CAPTURE PAGE
# ============================================================

@app.route("/live-capture")
def live_capture():

    if not session.get("logged_in"):

        return redirect(
            url_for("home")
        )

    return render_template(
        "live_capture.html"
    )




# ============================================================
# ALERTS PAGE
# ============================================================

@app.route("/alerts")
def alerts():

    if not session.get("logged_in"):
        return redirect(
            url_for("home")
        )

    return render_template(
        "alerts.html"
    )


# ============================================================
# THREAT ALERT API
# ============================================================

@app.route("/api/threats")
def api_threats():

    if not session.get("logged_in"):
        return jsonify([])

    from modules.detection import get_threat_logs

    return jsonify(
        get_threat_logs()
    )


# Add these imports at the top of app.py if they are not already present:
from flask import render_template, jsonify, session, redirect

# --------------------------------------------------
# REPORTS PAGE
# --------------------------------------------------
# Add this route only if /reports does not already exist.


@app.route("/reports", methods=["GET", "POST"])
def reports():
    if not session.get("logged_in"):
        return redirect("/")

    if request.method == "POST":
        file = request.files.get("pcap_file")

        if not file or not file.filename:
            flash("Please select a PCAP file.")
            return redirect(url_for("reports"))

        filename = secure_filename(file.filename)

        if not filename.lower().endswith((".pcap", ".pcapng")):
            flash("Only .pcap and .pcapng files are allowed.")
            return redirect(url_for("reports"))

        upload_folder = os.path.join(app.root_path, "uploads")
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, filename)

        try:
            file.save(file_path)
            result = analyze_pcap(file_path)
            session["pcap_result"] = result
            flash("PCAP uploaded and analyzed successfully.")
        except Exception:
            app.logger.exception("PCAP analysis failed")
            flash("Analysis failed. Check the PCAP file and try again.")

        return redirect(url_for("reports"))

    return render_template("reports.html")



@app.route("/upload-pcap", methods=["GET", "POST"])
def upload_pcap():
    if not session.get("logged_in"):
        return redirect("/")

    if request.method == "POST":
        if "pcap_file" not in request.files:
            flash("Please select a PCAP file.")
            return redirect(url_for("upload_pcap"))

        file = request.files["pcap_file"]

        if not file.filename:
            flash("Please select a file.")
            return redirect(url_for("upload_pcap"))

        filename = secure_filename(file.filename)
        if not filename.lower().endswith((".pcap", ".pcapng")):
            flash("Only .pcap and .pcapng files are allowed.")
            return redirect(url_for("upload_pcap"))

        upload_folder = os.path.join(app.root_path, "uploads")
        os.makedirs(upload_folder, exist_ok=True)

        file_path = os.path.join(upload_folder, filename)

        try:
            file.save(file_path)
            result = analyze_pcap(file_path)
            session["pcap_result"] = result
            flash("PCAP uploaded and analyzed successfully.")
            return redirect(url_for("upload_pcap"))
        except Exception as error:
            app.logger.exception("PCAP analysis failed")
            flash(f"Could not analyze this capture: {error}")
            return redirect(url_for("upload_pcap"))

    return render_template("upload_pcap.html")


@app.route("/api/analyze-pcap")
def api_analyze_pcap():
    if not session.get("logged_in"):
        return jsonify({"error": "Please log in first."}), 401

    result = session.get("pcap_result")
    if not result:
        return jsonify({"error": "No PCAP analyzed yet."}), 404

    return jsonify(result)


# ============================================================
# home page
# ============================================================


# HOME PAGE
@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


# LOGIN PAGE
@app.route("/login")
def login_page():
    return render_template("login.html")



# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print(" NETWORK FORENSICS ANALYSIS SYSTEM")
    print("=" * 60)

    # Database
    init_database()

    print(
        "[DATABASE] User database initialized."
    )

    # Packet capture
    print(
        "[CAPTURE] Starting live packet capture..."
    )

    capture_thread = Thread(
        target=capture_worker,
        daemon=True
    )

    capture_thread.start()

    print(
        "[CAPTURE] Live packet capture started."
    )

    # Flask
    print(
        "[SERVER] Starting Flask on "
        "http://127.0.0.1:5000"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )