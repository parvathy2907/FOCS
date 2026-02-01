# Secure Hospital System

A secure web application for managing hospital records, designed with a focus on security, data integrity, and role-based access control.  This project demonstrates a robust backend coupled with a user-friendly frontend.

## 🚀 Features

### Backend (Security & Logic)
- **Role-Based Access Control (RBAC)**: Distinct roles for **Admin**, **Doctor**, and **Patient**.
- **Multi-Factor Authentication (MFA)**: Integrated Time-based One-Time Password (TOTP) for secure logins using `pyotp`.
- **Data Encryption**: Medical records are encrypted using symmetric encryption (Fernet) before storage, ensuring confidentiality.
- **Data Integrity**: Uses Hashing (SHA-256) to verify that medical records have not been tampered with.
- **Secure File Handling**: Documents are Base64 encoded and securely stored in the database.
- **Access Logging**: Comprehensive tracking of user actions (logins, record creation) for auditing (Admin view).

### Frontend (User Experience)
- **Responsive Design**: Clean and modern interface powered by CSS3.
- **Dashboard Views**: Customized dashboards for each role:
    - **Admin**: View system-wide access logs.
    - **Doctor**: Create and view encrypted medical records for patients.
    - **Patient**: View personal medical records and upload documents.
- **Interactive Feedback**: Flash messages for success/error notifications.

## 🛠️ Tech Stack

- **Backend Framework**: Python (Flask)
- **Database**: SQLite (with SQLAlchemy ORM)
- **Security Libraries**:
    - `cryptography`: For encryption/decryption.
    - `pyotp`: For generating and verifying 2FA tokens.
    - `werkzeug`: For secure password hashing and filename handling.
- **Frontend**: HTML5, CSS3, Jinja2 Templating

## 📂 Project Structure

```
focs_eval/
├── app.py                 # Main Flask application entry point
├── database.py            # Database models and configuration
├── crypto_utils.py        # Helper functions for encryption/hashing
├── requirements.txt       # Project dependencies
├── templates/             # HTML Templates (Jinja2)
│   ├── base.html          # Base template
│   ├── login.html         # Login page
│   ├── register.html      # Registration page
│   ├── dashboard.html     # Main dashboard (role-specific)
│   └── ...
├── static/                # Static assets
│   └── css/
│       └── style.css      # Global styles
└── instance/              # SQLite database file location
```

## ⚙️ Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd focs_eval
    ```

2.  **Create a Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the Database:**
    The application will automatically create the database tables on the first run.

5.  **Run the Application:**
    ```bash
    python3 app.py
    ```
    The app will start at `http://127.0.0.1:5000/`.

## 📖 Usage Guide

1.  **Register a User**:
    - Go to `/register` and create an account.
    - Default **Admin** credentials (autocreated if missing): `admin` / `admin123`.

2.  **Login & MFA**:
    - Login with your credentials.
    - Enter the TOTP code (for testing, the code is printed in the server console).

3.  **Dashboard Actions**:
    - **Doctors**: Navigate to "Create Record", enter Patient Username and Content. The content is encrypted upon saving.
    - **Patients**: View your records (automatically decrypted for you) and Upload Documents (Base64 encoded).
    - **Admins**: Monitor the "Access Logs" section.

## 🛡️ Security Highlights
- **Encryption**: Data is encrypted at rest. Even if the database is compromised, the medical records remain unreadable without the key.
- **Integrity**: Content hashes ensure that data retrieved is exactly what was stored.
- **Session Management**: Secure session handling with timeouts and role checks.
