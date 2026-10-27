# Smart Banking System and Jarvis Virtual Assistant

A full-stack educational project combining a responsive banking dashboard, simulated account operations, transaction history, profile settings, and a browser-based Jarvis assistant.

> **Demo only:** This project does not connect to a real bank or payment network. Deposits and transfers are simulated. Do not enter real banking credentials or sensitive financial information.

## Features

- Account registration and login with Werkzeug password hashing
- Session-based authentication and CSRF tokens for state-changing requests
- SQLite storage using parameterized SQL
- Demo balance, deposits, withdrawals, and transfers between registered demo accounts
- Transaction history and audit events
- Responsive dashboard with activity metrics
- Jarvis command-based assistant for demo balance, account number, and recent transactions
- Optional browser voice input and text-to-speech
- Profile display-name editing
- Automated starter tests

## Tech stack

Python 3.10+, Flask, SQLite, HTML, CSS, JavaScript, Web Speech API, Git.

## Run locally

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open `http://127.0.0.1:5000`, register a test account, and sign in. The SQLite database is created automatically.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
app.py
requirements.txt
templates/
  base.html
  login.html
  register.html
  dashboard.html
  profile.html
  error.html
static/
  css/style.css
  js/app.js
  js/dashboard.js
tests/
  test_app.py
```

## GitHub upload

Create a new repository named `smart-banking-jarvis`, then run from this folder:

```bash
git init
git add .
git commit -m "Build SmartBank and Jarvis demo"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/smart-banking-jarvis.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your GitHub username. Keep `.env`, `banking.db`, virtual environments, and any real user data out of Git.

## Security and limitations

This is a portfolio/learning prototype, not production financial software. Before public deployment, add professional security review, login throttling, stronger account recovery, robust monitoring, backups, and an appropriate deployment configuration. Use HTTPS and set `COOKIE_SECURE=1` only when deployed behind HTTPS. The built-in assistant uses local command rules; it is not a connected LLM. Browser speech recognition availability varies by browser and may send audio to the browser vendor's speech service.
