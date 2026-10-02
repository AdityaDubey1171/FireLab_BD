from datetime import datetime
from functools import wraps
import re

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    session,
    flash
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ============================================================
# App setup
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = (
    "firewall-lab-secret-key-change-this"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///firewall.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ============================================================
# Database tables
# ============================================================

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="admin"
    )

    active = db.Column(
        db.Boolean,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.now
    )


class LoginAttempt(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        nullable=False
    )

    ip_address = db.Column(
        db.String(50),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.now
    )


class Attack(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    attack_type = db.Column(
        db.String(80),
        nullable=False
    )

    source_ip = db.Column(
        db.String(100),
        nullable=False
    )

    target = db.Column(
        db.String(120),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.now
    )


# ============================================================
# Attack information
# ============================================================

ATTACK_DETAILS = {

    "SQL Injection": {

        "subtitle":
            "Database manipulation attempt",

        "description":
            (
                "SQL Injection is an attack where an attacker "
                "attempts to manipulate a database query by "
                "placing malicious SQL-related input into an "
                "application input field."
            ),

        "severity":
            "HIGH",

        "target":
            "/login",

        "source_ip":
            "192.168.1.45",

        "detection": [
            "Suspicious database-related input detected.",
            "Input pattern matched a simulated SQL Injection rule.",
            "The simulated request was prevented from reaching the database.",
            "The security event was recorded in the firewall database."
        ],

        "flow": [
            "Attacker sends crafted input.",
            "Input reaches the login form.",
            "Web application receives the request.",
            "Application prepares a database query.",
            "Firewall security rule inspects the request.",
            "Suspicious SQL pattern is detected.",
            "Request is blocked."
        ],

        "timeline": [
            "Simulation started.",
            "Suspicious input received.",
            "Firewall inspected the request.",
            "SQL Injection rule matched.",
            "Firewall decision: BLOCKED.",
            "Attack event saved to database."
        ],

        "prevention": [
            "Use parameterized queries.",
            "Use prepared statements.",
            "Validate and sanitize user input.",
            "Use least-privilege database accounts.",
            "Monitor suspicious database requests."
        ]
    },


    "Brute Force": {

        "subtitle":
            "Repeated authentication attempts",

        "description":
            (
                "A brute-force attack attempts to discover "
                "valid login credentials by repeatedly trying "
                "different username and password combinations."
            ),

        "severity":
            "HIGH",

        "target":
            "/login",

        "source_ip":
            "10.0.0.25",

        "detection": [
            "Multiple authentication attempts were detected.",
            "Request frequency exceeded the simulated threshold.",
            "Rate-limiting rules identified the behavior.",
            "Further authentication requests were blocked."
        ],

        "flow": [
            "Attacker connects to login page.",
            "Login request is submitted.",
            "Multiple authentication attempts occur.",
            "Authentication system records the attempts.",
            "Firewall monitors request frequency.",
            "Threshold is exceeded.",
            "Further requests are blocked."
        ],

        "timeline": [
            "Simulation started.",
            "First authentication request detected.",
            "Repeated requests detected.",
            "Rate threshold exceeded.",
            "Firewall decision: BLOCKED.",
            "Attack event saved to database."
        ],

        "prevention": [
            "Use rate limiting.",
            "Temporarily lock accounts after repeated failures.",
            "Use multi-factor authentication.",
            "Use strong passwords.",
            "Monitor failed login attempts."
        ]
    },


    "Port Scan": {

        "subtitle":
            "Network reconnaissance activity",

        "description":
            (
                "A port scan attempts to identify open network "
                "ports and discover services running on a system."
            ),

        "severity":
            "MEDIUM",

        "target":
            "Server Network",

        "source_ip":
            "172.16.0.15",

        "detection": [
            "Multiple connection attempts were detected.",
            "Different network ports were targeted.",
            "The connection pattern matched a simulated scanning rule.",
            "The scanning source was blocked."
        ],

        "flow": [
            "Scanner sends a connection request.",
            "Network interface receives the request.",
            "Multiple ports are contacted.",
            "Port monitoring detects repeated connections.",
            "Traffic pattern is analyzed.",
            "Scanning behavior is detected.",
            "Source is blocked."
        ],

        "timeline": [
            "Simulation started.",
            "Network connection detected.",
            "Multiple ports targeted.",
            "Scanning pattern detected.",
            "Firewall decision: BLOCKED.",
            "Attack event saved to database."
        ],

        "prevention": [
            "Close unnecessary network ports.",
            "Use firewall rules.",
            "Monitor network connections.",
            "Use intrusion detection systems.",
            "Restrict exposed network services."
        ]
    },


    "Cross-Site Scripting (XSS)": {

        "subtitle":
            "Browser-side script injection attempt",

        "description":
            (
                "Cross-Site Scripting occurs when untrusted "
                "content is injected into a web application "
                "and is interpreted as executable content "
                "by a user's browser."
            ),

        "severity":
            "HIGH",

        "target":
            "/comments",

        "source_ip":
            "192.168.1.77",

        "detection": [
            "Script-like input was detected.",
            "The simulated input matched an XSS detection rule.",
            "Suspicious content was blocked.",
            "The security event was recorded."
        ],

        "flow": [
            "User submits content.",
            "Web form receives the input.",
            "Application processes the content.",
            "Output processing takes place.",
            "Security rules inspect the content.",
            "Suspicious script pattern is detected.",
            "Content is blocked."
        ],

        "timeline": [
            "Simulation started.",
            "User input received.",
            "Suspicious script pattern detected.",
            "XSS security rule matched.",
            "Firewall decision: BLOCKED.",
            "Attack event saved to database."
        ],

        "prevention": [
            "Escape untrusted output.",
            "Validate input.",
            "Use Content Security Policy.",
            "Avoid unsafe HTML insertion.",
            "Use framework security protections."
        ]
    },


    "DDoS": {

        "subtitle":
            "Service availability attack simulation",

        "description":
            (
                "A Distributed Denial-of-Service attack attempts "
                "to overwhelm a service with a large volume of "
                "requests. This project only simulates the "
                "detection process."
            ),

        "severity":
            "CRITICAL",

        "target":
            "/",

        "source_ip":
            "Multiple simulated sources",

        "detection": [
            "A sudden increase in simulated request volume was detected.",
            "Traffic exceeded the configured threshold.",
            "Traffic-monitoring rules identified abnormal behavior.",
            "The simulated mitigation process was triggered."
        ],

        "flow": [
            "Multiple simulated sources generate requests.",
            "Large request volume reaches the server.",
            "Traffic monitoring measures request frequency.",
            "Traffic exceeds the configured threshold.",
            "Security system identifies abnormal traffic.",
            "Mitigation is triggered.",
            "Suspicious traffic is blocked."
        ],

        "timeline": [
            "Simulation started.",
            "High-volume traffic simulated.",
            "Traffic threshold exceeded.",
            "DDoS detection rule matched.",
            "Firewall decision: BLOCKED.",
            "Attack event saved to database."
        ],

        "prevention": [
            "Use rate limiting.",
            "Use traffic filtering.",
            "Use CDN and DDoS protection services.",
            "Maintain normal traffic baselines.",
            "Prepare an incident response plan."
        ]
    },


    "Directory Traversal": {

        "subtitle":
            "Unauthorized file path access attempt",

        "description":
            (
                "Directory Traversal is an attack where an "
                "attacker attempts to access files outside "
                "the directory that the application is "
                "supposed to expose."
            ),

        "severity":
            "HIGH",

        "target":
            "/download",

        "source_ip":
            "10.10.0.42",

        "detection": [
            "An abnormal file path was detected.",
            "Path validation rules identified suspicious input.",
            "The simulated request was blocked.",
            "The security event was recorded."
        ],

        "flow": [
            "User sends a file request.",
            "Download endpoint receives the request.",
            "Application processes the requested path.",
            "Path validation rule checks the request.",
            "Suspicious path pattern is detected.",
            "Firewall security system blocks the request."
        ],

        "timeline": [
            "Simulation started.",
            "File request received.",
            "Suspicious path detected.",
            "Path validation rule matched.",
            "Firewall decision: BLOCKED.",
            "Attack event saved to database."
        ],

        "prevention": [
            "Validate file paths.",
            "Use allowlists.",
            "Restrict applications to approved directories.",
            "Never trust user-controlled file paths.",
            "Use least-privilege permissions."
        ]
    }
}


# ============================================================
# Attack URL names
# ============================================================

ATTACK_SLUGS = {

    "sql-injection":
        "SQL Injection",

    "brute-force":
        "Brute Force",

    "port-scan":
        "Port Scan",

    "xss":
        "Cross-Site Scripting (XSS)",

    "ddos":
        "DDoS",

    "directory-traversal":
        "Directory Traversal"
}


# ============================================================
# Firewall rules
# ============================================================

FIREWALL_RULES = {

    "SQL Injection": {
        "category": "Web Attack",
        "severity": "HIGH",
        "action": "BLOCK",
        "target": "/login"
    },

    "Brute Force": {
        "category": "Authentication Attack",
        "severity": "HIGH",
        "action": "BLOCK",
        "target": "/login"
    },

    "Port Scan": {
        "category": "Network Reconnaissance",
        "severity": "MEDIUM",
        "action": "BLOCK",
        "target": "Server Network"
    },

    "Cross-Site Scripting (XSS)": {
        "category": "Web Attack",
        "severity": "HIGH",
        "action": "BLOCK",
        "target": "/comments"
    },

    "DDoS": {
        "category": "Availability Attack",
        "severity": "CRITICAL",
        "action": "BLOCK",
        "target": "/"
    },

    "Directory Traversal": {
        "category": "File Access Attack",
        "severity": "HIGH",
        "action": "BLOCK",
        "target": "/download"
    }
}


# ============================================================
# Accept different ways of typing an attack name
# ============================================================

FIREWALL_ALIASES = {

    "sql injection":
        "SQL Injection",

    "sql-injection":
        "SQL Injection",

    "sqli":
        "SQL Injection",

    "brute force":
        "Brute Force",

    "bruteforce":
        "Brute Force",

    "brute-force":
        "Brute Force",

    "port scan":
        "Port Scan",

    "port scanning":
        "Port Scan",

    "port-scan":
        "Port Scan",

    "xss":
        "Cross-Site Scripting (XSS)",

    "cross site scripting":
        "Cross-Site Scripting (XSS)",

    "cross-site scripting":
        "Cross-Site Scripting (XSS)",

    "cross-site scripting (xss)":
        "Cross-Site Scripting (XSS)",

    "ddos":
        "DDoS",

    "denial of service":
        "DDoS",

    "directory traversal":
        "Directory Traversal",

    "directory-traversal":
        "Directory Traversal",

    "path traversal":
        "Directory Traversal"
}


# ============================================================
# Admin login check
# ============================================================

def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "admin_username" not in session:

            flash(
                "Please login as administrator first."
            )

            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


# ============================================================
# Home page
# ============================================================

@app.route("/")
def home():

    return render_template(
        "home.html",
        attack_details=ATTACK_DETAILS
    )


# ============================================================
# Login
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        ip_address = (
            request.remote_addr
            or "Unknown"
        )

        user = User.query.filter_by(
            username=username
        ).first()

        if (
            user
            and user.active
            and check_password_hash(
                user.password_hash,
                password
            )
        ):

            db.session.add(
                LoginAttempt(
                    username=username,
                    ip_address=ip_address,
                    status="SUCCESS"
                )
            )

            session["admin_username"] = username

            db.session.commit()

            return redirect(
                url_for("admin_dashboard")
            )

        db.session.add(
            LoginAttempt(
                username=username,
                ip_address=ip_address,
                status="FAILED"
            )
        )

        db.session.commit()

        flash(
            "Invalid username or password."
        )

    return render_template(
        "login.html"
    )


# ============================================================
# Admin dashboard
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    total = Attack.query.count()

    blocked = Attack.query.filter_by(
        status="BLOCKED"
    ).count()

    high = Attack.query.filter_by(
        severity="HIGH"
    ).count()

    critical = Attack.query.filter_by(
        severity="CRITICAL"
    ).count()

    recent_attacks = Attack.query.order_by(
        Attack.timestamp.desc()
    ).limit(10).all()

    return render_template(

        "admin.html",

        total=total,

        blocked=blocked,

        high=high,

        critical=critical,

        recent_attacks=recent_attacks
    )


# ============================================================
# Attack simulation checks
# ============================================================

def make_simulation_result(
    attack_type,
    form
):

    # SQL Injection
    if attack_type == "SQL Injection":

        value = form.get(
            "payload",
            ""
        ).strip()

        if not value:

            return {
                "detected": False,
                "score": 0,
                "message":
                    "Enter some sample input first.",
                "details": [
                    "Nothing was analyzed."
                ]
            }

        patterns = [

            r"\bor\b",
            r"\band\b",
            r"--",
            r"/\*",
            r"\*/",
            r"\bunion\b",
            r"\bselect\b",
            r"\bdrop\b",
            r"\binsert\b",
            r"\bdelete\b",
            r"\bupdate\b"
        ]

        matches = [

            pattern
            for pattern in patterns
            if re.search(
                pattern,
                value,
                re.IGNORECASE
            )
        ]

        if matches:

            score = min(
                95,
                40 + len(matches) * 8
            )

            return {

                "detected": True,

                "score": score,

                "message":
                    "The sample contains patterns commonly associated with SQL injection.",

                "details": [

                    f"{len(matches)} suspicious pattern(s) were detected.",

                    "The simulator did not execute the supplied input.",

                    "A real application should use parameterized queries."
                ]
            }

        return {

            "detected": False,

            "score": 10,

            "message":
                "No obvious SQL injection pattern was detected.",

            "details": [

                "The sample passed this basic demonstration check.",

                "Pattern matching alone cannot prove that an input is safe."
            ]
        }


    # Brute Force
    if attack_type == "Brute Force":

        try:

            attempts = int(
                form.get(
                    "attempts",
                    "0"
                )
            )

        except ValueError:

            attempts = 0

        attempts = max(
            0,
            min(
                attempts,
                100
            )
        )

        if attempts >= 20:

            return {

                "detected": True,

                "score":
                    min(
                        100,
                        50 + attempts
                    ),

                "message":
                    f"{attempts} simulated login attempts crossed the demonstration threshold.",

                "details": [

                    "Repeated authentication activity was detected.",

                    "A real application could rate-limit the source.",

                    "MFA and account protection can reduce this risk."
                ]
            }

        if attempts >= 5:

            return {

                "detected": True,

                "score": 55,

                "message":
                    f"{attempts} login attempts should be monitored.",

                "details": [

                    "The number of attempts is above the normal demonstration level.",

                    "A real system could introduce progressive delays."
                ]
            }

        return {

            "detected": False,

            "score": 15,

            "message":
                f"{attempts} simulated login attempt(s) are below the demonstration threshold.",

            "details": [

                "No significant repeated-login pattern was detected."
            ]
        }


    # Port Scan
    if attack_type == "Port Scan":

        raw_ports = form.get(
            "ports",
            ""
        )

        ports = []

        for value in raw_ports.split(","):

            value = value.strip()

            if value.isdigit():

                port = int(value)

                if 1 <= port <= 65535:

                    ports.append(port)

        if not ports:

            return {

                "detected": False,

                "score": 0,

                "message":
                    "No valid ports were entered.",

                "details": [

                    "Try an example such as 22, 80, 443, 3306."
                ]
            }

        services = {

            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP"
        }

        found = [

            f"{port} ({services[port]})"
            for port in ports
            if port in services
        ]

        if len(ports) >= 5:

            return {

                "detected": True,

                "score":
                    min(
                        100,
                        40 + len(ports) * 5
                    ),

                "message":
                    f"{len(ports)} ports were included in the simulation.",

                "details": [

                    "Ports checked: "
                    + ", ".join(
                        map(str, ports)
                    ),

                    "Known services: "
                    + (
                        ", ".join(found)
                        if found
                        else
                        "None identified"
                    ),

                    "Multiple connection attempts can represent reconnaissance activity."
                ]
            }

        return {

            "detected": False,

            "score": 20,

            "message":
                "The simulated port activity is limited.",

            "details": [

                "Ports checked: "
                + ", ".join(
                    map(str, ports)
                ),

                "Known services: "
                + (
                    ", ".join(found)
                    if found
                    else
                    "None identified"
                )
            ]
        }


    # XSS
    if attack_type == "Cross-Site Scripting (XSS)":

        value = form.get(
            "payload",
            ""
        ).strip()

        patterns = [

            r"<\s*script\b",
            r"javascript\s*:",
            r"onerror\s*=",
            r"onload\s*="
        ]

        matches = [

            pattern
            for pattern in patterns
            if re.search(
                pattern,
                value,
                re.IGNORECASE
            )
        ]

        if matches:

            return {

                "detected": True,

                "score":
                    min(
                        95,
                        55 + len(matches) * 10
                    ),

                "message":
                    "Script-like content was detected in the sample.",

                "details": [

                    "The simulator matched an XSS demonstration rule.",

                    "The supplied content was not executed."
                ]
            }

        return {

            "detected": False,

            "score": 10,

            "message":
                "No obvious XSS pattern was detected.",

            "details": [

                "This is only a basic demonstration check."
            ]
        }


    # Directory Traversal
    if attack_type == "Directory Traversal":

        value = form.get(
            "payload",
            ""
        ).strip()

        patterns = [

            r"\.\./",
            r"\.\.\\",
            r"%2e%2e",
            r"%2f",
            r"%5c"
        ]

        matches = [

            pattern
            for pattern in patterns
            if re.search(
                pattern,
                value,
                re.IGNORECASE
            )
        ]

        if matches:

            return {

                "detected": True,

                "score":
                    min(
                        95,
                        60 + len(matches) * 10
                    ),

                "message":
                    "A suspicious path traversal pattern was detected.",

                "details": [

                    "The simulator detected a path-related security pattern.",

                    "The sample was not used to access any file."
                ]
            }

        return {

            "detected": False,

            "score": 10,

            "message":
                "No obvious traversal pattern was detected.",

            "details": [

                "This demonstration does not access the filesystem."
            ]
        }


    # DDoS
    if attack_type == "DDoS":

        try:

            request_count = int(
                form.get(
                    "requests_count",
                    "0"
                )
            )

        except ValueError:

            request_count = 0

        request_count = max(
            0,
            min(
                request_count,
                100000
            )
        )

        if request_count >= 1000:

            score = min(
                100,
                60 + request_count // 500
            )

            return {

                "detected": True,

                "score": score,

                "message":
                    f"{request_count} simulated requests crossed the traffic threshold.",

                "details": [

                    "High request volume was detected.",

                    "No real network traffic was generated.",

                    "Real mitigation can include rate limiting and traffic filtering."
                ]
            }

        return {

            "detected": False,

            "score":
                min(
                    40,
                    request_count // 25
                ),

            "message":
                f"{request_count} simulated requests are below the demonstration threshold.",

            "details": [

                "No real network traffic was generated."
            ]
        }


    # Fallback
    return {

        "detected": True,

        "score": 50,

        "message":
            "The simulator recognized the selected attack type.",

        "details": [

            "This attack has been recorded as a demonstration event."
        ]
    }


# ============================================================
# Attack simulation page
# ============================================================

@app.route(
    "/simulate/<slug>",
    methods=["GET", "POST"]
)
def simulate_attack(slug):

    attack_type = ATTACK_SLUGS.get(
        slug
    )

    if attack_type is None:

        return (
            "Attack type not found",
            404
        )

    details = ATTACK_DETAILS[
        attack_type
    ]

    result = None

    if request.method == "POST":

        result = make_simulation_result(
            attack_type,
            request.form
        )

        event = Attack(

            attack_type=attack_type,

            source_ip=details[
                "source_ip"
            ],

            target=details[
                "target"
            ],

            severity=details[
                "severity"
            ],

            status=(
                "BLOCKED"
                if result["detected"]
                else
                "ALLOWED"
            )
        )

        db.session.add(
            event
        )

        db.session.commit()

    return render_template(

        "attacks_details.html",

        attack=details,

        attack_name=attack_type,

        slug=slug,

        result=result
    )


# ============================================================
# Attack Center
# ============================================================

@app.route("/attacks")
def attack_center():

    return render_template(
        "attacks.html"
    )


# ============================================================
# Individual attack record
# ============================================================

@app.route("/attack/<int:attack_id>")
@admin_required
def attack_details(attack_id):

    attack = Attack.query.get_or_404(
        attack_id
    )

    details = ATTACK_DETAILS.get(
        attack.attack_type
    )

    if details is None:

        return (
            "Attack information not available",
            404
        )

    result = {

        "detected":
            attack.status == "BLOCKED",

        "score":
            80
            if attack.status == "BLOCKED"
            else
            10,

        "message":
            f"Recorded event: {attack.status}.",

        "details": [

            f"Source: {attack.source_ip}",

            f"Target: {attack.target}",

            f"Severity: {attack.severity}",

            f"Recorded at: {attack.timestamp}"
        ]
    }

    return render_template(

        "attacks_details.html",

        attack=details,

        attack_name=attack.attack_type,

        result=result,

        slug=None
    )


# ============================================================
# Attack history
# ============================================================

@app.route("/attack-history")
@admin_required
def attack_history():

    attacks = Attack.query.order_by(
        Attack.timestamp.desc()
    ).all()

    return render_template(
        "attack_history.html",
        attacks=attacks
    )


# ============================================================
# Login history
# ============================================================

@app.route("/login-history")
@admin_required
def login_history():

    attempts = LoginAttempt.query.order_by(
        LoginAttempt.timestamp.desc()
    ).all()

    return render_template(

        "login_history.html",

        attempts=attempts
    )


# ============================================================
# Firewall laboratory
# ============================================================

@app.route(
    "/firewall",
    methods=["GET", "POST"]
)
def firewall():

    result = None

    if request.method == "POST":

        entered_type = request.form.get(
            "attack_type",
            ""
        ).strip()

        normalized = entered_type.lower()

        detected_attack = FIREWALL_ALIASES.get(
            normalized
        )

        # ----------------------------------------------------
        # Known attack found
        # ----------------------------------------------------

        if detected_attack:

            rule = FIREWALL_RULES[
                detected_attack
            ]

            result = {

                "detected": True,

                "attack": detected_attack,

                "category":
                    rule["category"],

                "severity":
                    rule["severity"],

                "action":
                    "BLOCKED",

                "system":
                    "SECURE",

                "message":
                    "The firewall matched a defined security rule and blocked the simulated attack.",

                "source_ip":
                    request.remote_addr
                    or "127.0.0.1",

                "target":
                    rule["target"]
            }

            # Save the blocked firewall event.
            event = Attack(

                attack_type=detected_attack,

                source_ip=(
                    request.remote_addr
                    or "127.0.0.1"
                ),

                target=rule[
                    "target"
                ],

                severity=rule[
                    "severity"
                ],

                status="BLOCKED"
            )

            db.session.add(
                event
            )

            db.session.commit()

        # ----------------------------------------------------
        # Unknown / normal traffic
        # ----------------------------------------------------

        else:

            result = {

                "detected": False,

                "attack":
                    entered_type
                    if entered_type
                    else
                    "Normal Traffic",

                "category":
                    "Normal Traffic",

                "severity":
                    "LOW",

                "action":
                    "ALLOWED",

                "system":
                    "SECURE",

                "message":
                    "No defined attack rule matched this traffic. The simulated request was allowed.",

                "source_ip":
                    request.remote_addr
                    or "127.0.0.1",

                "target":
                    "Application"
            }

            # Save normal traffic as an allowed event.
            event = Attack(

                attack_type=(
                    entered_type
                    if entered_type
                    else
                    "Normal Traffic"
                ),

                source_ip=(
                    request.remote_addr
                    or "127.0.0.1"
                ),

                target="Application",

                severity="LOW",

                status="ALLOWED"
            )

            db.session.add(
                event
            )

            db.session.commit()

    return render_template(
        "firewall.html",
        rules=FIREWALL_RULES,
        result=result
    )


# ============================================================
# Logout
# ============================================================

@app.route("/logout")
def logout():

    session.pop(
        "admin_username",
        None
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# Make sure database exists
# ============================================================

with app.app_context():

    db.create_all()


# ============================================================
# Start application
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )