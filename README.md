# Serva — Server Access Permits

A web-based server access permit management system built with Flask and PostgreSQL. Users submit access requests, admins approve/reject, and approved requests require before/after photo evidence.

## Features

- **User registration & login** — Secure authentication with Flask-Login
- **Access request workflow** — Submit requests with title, server, duration, and description
- **Admin review** — Approve or reject requests with review notes
- **Photo evidence** — Upload before & after photos upon approval
- **Interactive dashboard** — Charts (status distribution, monthly trends, server usage) with Chart.js
- **User history** — Complete request history per user
- **Console logs** — Full audit trail with pagination, search, and admin management
- **Admin CRUD** — Edit/delete users, requests, and logs
- **Orange-blue theme** — Clean UI with Quicksand font and custom logo

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, SQLAlchemy |
| Database | PostgreSQL (or SQLite for dev) |
| Frontend | HTML, CSS, Chart.js, Lucide Icons |
| Auth | Flask-Login |
| Font | Quicksand (Google Fonts) |

## Quick Start

```bash
# Clone
git clone https://github.com/digia-dev/sevra.git
cd sevra

# Install deps
pip install -r requirements.txt

# Run (auto-creates DB tables)
python app.py
```

Open `http://127.0.0.1:5000`

## Default Accounts

| Role | Username | Password |
|------|----------|----------|
| Super Admin | `superadmin` | `SuperAdmin123!` |
| Admin | `admin` | `Admin123!` |
| User | `user` | `User123!` |

## Configuration

Edit `.env` in the project root:

```env
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://user:pass@localhost:5432/sevra
# For development (SQLite):
# DATABASE_URL=sqlite:///app.db
```

## Project Structure

```
sevra/
├── app.py              # Flask routes & logic
├── config.py           # App configuration
├── models.py           # SQLAlchemy models
├── requirements.txt    # Python dependencies
├── .env                # Environment variables
├── static/
│   ├── css/style.css   # Stylesheet
│   └── img/logo.png    # Custom logo
└── templates/          # Jinja2 templates
    ├── base.html
    ├── dashboard.html
    ├── admin_dashboard.html
    ├── admin_users.html
    ├── history.html
    ├── logs.html
    ├── view_request.html
    ├── upload_photos.html
    ├── request_form.html
    ├── login.html
    ├── register.html
    ├── index.html
    ├── 403.html
    └── 404.html
```
