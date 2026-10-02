# firelab_db

> Simulate the attack. Understand the defense. Keep the record.

**firelab_db** is an interactive cybersecurity learning platform that explains how a firewall works through safe, hands-on simulations. Every simulated event is stored in a database, so you can review it later.

No real attack traffic is generated, and no external system is scanned or attacked. Every simulation analyzes sample input only.

---

## Overview

Instead of only reading theory, users run simulated attacks and watch the firewall inspect each request, compare it with security rules, decide whether to allow or block it, and log the result.

The project is designed for students, beginners and educators who want to understand firewalls, threat detection and security logging through interaction.

---

## Features

### Firewall Decision Pipeline
A visual walkthrough of every step a request goes through:

**Request → Traffic Analysis → Rule Check → Threat Detection → Allow/Block → Log**

Each step can be expanded to show what it is, how it works, what the firewall does and why it matters.

### Attack Simulation Center

| Attack | Concept Taught |
|---|---|
| SQL Injection | Detecting suspicious database-related input |
| Brute Force | Rate limiting and repeated login attempts |
| Port Scan | Recognizing reconnaissance across ports |
| Cross-Site Scripting (XSS) | Spotting script-like input |
| DDoS | Detecting abnormal request volume |
| Directory Traversal | Restricting file path access |

Each simulation includes a definition, how the attack works, the detection concept, the firewall response, a security timeline, prevention tips and a risk score for the sample input.

### Database Integration
- Built with SQLAlchemy
- Stores every simulated attack with its type, source, target, severity and status
- Records every administrator login attempt, successful or failed

### Admin Dashboard
- Session-based admin authentication
- Statistics: total attacks, blocked, high severity and critical
- Recent security events
- Full attack history and login history

### Clean Learning Interface
- Responsive light-mode dashboard
- Expandable cards for quick learning
- Works on desktop and mobile

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLAlchemy, SQLite |
| Templates | Jinja2 |
| Frontend | HTML, CSS, Vanilla JavaScript |

---

## Project Structure

```
firelab_db/
├── app.py
├── static/
│   ├── style.css
│   └── script.js
└── templates/
    ├── home.html
    ├── login.html
    ├── admin.html
    ├── attacks.html
    ├── attacks_details.html
    ├── attack_history.html
    ├── login_history.html
    └── firewall_lab.html
```

---

## Getting Started

1. Download or clone this repository and open the project folder.
2. Install the dependencies:

```bash
pip install flask flask-sqlalchemy
```

3. Run the application:

```bash
python app.py
```

4. Open **http://127.0.0.1:5000** in your browser.

### Admin Login (demo)

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `admin123` |

---

## Security Notes

- Change the default admin credentials before deploying
- Store the Flask `SECRET_KEY` in an environment variable
- Do not run with `debug=True` in production

---

## Learning Outcomes

- How a firewall inspects, compares and decides
- How common web and network attacks are recognized
- Why logging and monitoring matter in security
- How a Flask app connects to a database with SQLAlchemy

---

## Disclaimer

This project is for **educational purposes only**. All attacks are simulated by analyzing sample input. Nothing is executed against real systems.
