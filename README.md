# Secure Login System

A secure web application built with Flask featuring hashed passwords, SQL injection protection, session management, and optional 2FA.

## Features
- **User Registration & Login** with hashed passwords (PBKDF2-SHA256)
- **SQL Injection Protection** — input validation on all fields
- **Session Management** with 30-minute timeout and secure logout
- **Two-Factor Authentication (2FA)** using TOTP (Google Authenticator compatible)
- Clean dark-theme UI with Bootstrap 5

## How to Run

```bash
pip install -r requirements.txt
python app.py
```

Open browser at: `http://127.0.0.1:5000`

## Security Features
| Feature | Implementation |
|---------|---------------|
| Password hashing | PBKDF2-SHA256 (260,000 iterations) |
| SQL Injection protection | ORM (SQLAlchemy) + input validation |
| Session management | Flask sessions with expiry |
| 2FA | TOTP via pyotp (RFC 6238) |
| Password policy | Min 8 chars, upper, lower, digit, special |

## Project Structure
```
secure-login-system/
├── app.py              # Main Flask application
├── requirements.txt    # Dependencies
└── templates/
    ├── base.html       # Base layout
    ├── login.html      # Login page
    ├── register.html   # Registration page
    ├── dashboard.html  # User dashboard
    ├── setup_2fa.html  # 2FA setup with QR code
    └── verify_2fa.html # 2FA verification
```

## Tech Used
- Python 3 / Flask
- SQLAlchemy (SQLite)
- Werkzeug (password hashing)
- pyotp + qrcode (2FA)
- Bootstrap 5
