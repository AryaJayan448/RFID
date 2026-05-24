# RFID Security Tester

A professional RFID card security testing framework built for Raspberry Pi. This tool scans and analyzes RFID cards for vulnerabilities, providing AI-powered threat analysis, blockchain-enhanced intelligence, and a real-time web dashboard — all from a single device.

---

##  Features

- **RFID Card Scanning** — Detects and reads 13.56MHz RFID cards using the RC522 module
- **Vulnerability Assessment** — Checks for known vulnerabilities (UID exposure, weak encryption, data accessibility) with CVSS scoring
- **AI Threat Analysis** — Pattern recognition engine that detects cloning attempts, relay attacks, brute-force attempts, and reconnaissance scans
- **Blockchain-Enhanced Intelligence** — Academic blockchain analyzer correlates scan data with peer-reviewed security research for deeper risk analysis
- **Web Dashboard** — Flask + Socket.IO powered browser interface accessible from any device on the network
- **Authentication System** — Secure login with OTP email verification and admin/user roles
- **Three Operating Modes** — Web + Console (combined), Console only, or Web only

---

##  Tech Stack

| Layer | Technology |
|---|---|
| Hardware | Raspberry Pi + RC522 RFID Reader |
| Language | Python 3 |
| Web Framework | Flask + Flask-Login + Socket.IO |
| Database | SQLite (users, scans, blockchain analysis) |
| AI Engine | Custom pattern recognition & threat scoring |
| Frontend | HTML/CSS/JS (Jinja2 templates) |

---

##  Project Structure

```
rfid_security_tester/
├── main.py                   # Entry point — menu and mode selection
├── rfid_scanner.py           # Core scanning framework (ProfessionalRFIDSecurityFramework)
├── ai_threat_analyzer.py     # AI threat pattern recognition engine
├── blockchain_handler.py     # Academic blockchain-based threat intelligence
├── auth_system.py            # User authentication with OTP email verification
├── rfid_web_integration.py   # Console ↔ Web coordinator
├── web_dashboard/
│   ├── app.py                # Flask web application
│   └── templates/
│       ├── login.html        # Login page
│       └── rfid_dashboard.html  # Main dashboard UI
```

---

## Hardware Requirements

- Raspberry Pi (any model with GPIO)
- RC522 RFID Reader Module
- Compatible RFID cards:
  - Building access cards (MIFARE Classic/Plus/DESFire)
  - Transit cards
  - Student ID cards
  - Hotel key cards
  - Any 13.56MHz RFID card

### RC522 Wiring (SPI)

| RC522 Pin | Raspberry Pi Pin |
|---|---|
| SDA | GPIO 8 (CE0) |
| SCK | GPIO 11 (SCLK) |
| MOSI | GPIO 10 |
| MISO | GPIO 9 |
| GND | GND |
| RST | GPIO 25 |
| 3.3V | 3.3V |

---

## Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/AryaJayan448/rfid_security_tester.git
cd rfid_security_tester
```

### 2. Install dependencies

```bash
pip install flask flask-login flask-socketio mfrc522 RPi.GPIO python-dotenv
```

### 3. Configure environment variables

Create a `.env` file in the root directory:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
```

### 4. Run the application

```bash
python main.py
```

You'll be presented with a menu to choose your mode:

```
1. Web Interface + Console (Recommended)
2. Console Only
3. Web Interface Only
```

For the web dashboard, open your browser and navigate to:
- On the Pi: `http://localhost:5000`
- From another device: `http://<pi-ip-address>:5000`

---

## Vulnerability Detection

The framework checks for the following vulnerability classes:

| Vulnerability | Severity | CVSS Score |
|---|---|---|
| UID Accessible without auth | Medium | 5.3 |
| Card responds to unauthorized scans | Low | 3.1 |
| Data readable without authentication | High | 7.2 |
| MIFARE Crypto-1 weakness | High | 7.8 |
| Relay attack susceptibility | Medium | 6.1 |

---

## AI Threat Patterns

The AI engine monitors scan sessions and flags:

- `cloning_attempt` — Risk multiplier: 2.5×
- `replay_attack` — Risk multiplier: 2.2×
- `reconnaissance_scan` — Risk multiplier: 1.8×
- `brute_force_attempt` — Risk multiplier: 3.0×

---

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**. Only test RFID cards and systems you own or have explicit permission to test. Unauthorized scanning of access cards may be illegal in your jurisdiction.

---

## License

