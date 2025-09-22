### Identity & Profile Manager API (Django + DRF + JWT)

This project is a small identity management service built with Django, Django REST Framework (DRF), and JSON Web Tokens (JWT) using SimpleJWT. It lets users register, authenticate, and maintain an identity profile with multiple name variants. Other authenticated users can search for profiles and, based on explicit consent records, see limited profile fields. A minimal set of HTML pages provides a simple login/register flow and a search UI that calls the API.

---

### Tech stack
- **Django** (project: `IdentityAndProfileManagerAPI`)
- **DRF** for API endpoints
- **SimpleJWT** for token auth (access/refresh)
- **SQLite** default DB

---

### Repository layout
```
IdentityAPI/
  README.md  ← you are here
  requirements.txt
  identity-and-profile-manager-main/
    manage.py
    db.sqlite3
    IdentityAndProfileManagerAPI/        ← Django project
      settings.py
      urls.py
      asgi.py
      wsgi.py
    IdentityAndProfileManager/           ← Django app
      models.py
      serializers.py
      views.py
      admin.py
      migrations/
      templates/
        home.html
        registrationform.html
        profile_detail.html
```

---

### What the app does
- **Register** a new user and create an associated `IdentityProfile`.
- **Authenticate** via JWT (obtain/refresh tokens).
- **Search** for users by partial username via an authenticated API endpoint.
- **Retrieve** profile details via API; owners see full profile, other users see only fields for which they have explicit `Consent`.
- **Minimal UI**: HTML pages for login, register, search, and profile detail that interact with the API using `fetch`.

---

### Data model (in `IdentityAndProfileManager/models.py`)
- **IdentityProfile**
  - `user` (OneToOne to `auth.User`)
  - `legal_name`, `academic_name`, `social_name` (all optional strings)
- **Consent**
  - `owner` (FK `auth.User`) — the data owner
  - `requester` (FK `auth.User`) — the user who can view a field
  - `field_name` (string; one of the profile fields, e.g. `legal_name`)
  - `granted_at` (auto)
  - `expires_at` (nullable datetime)

Migrations live under `IdentityAndProfileManager/migrations/` and include the initial creation of both models.

---

### API endpoints
Defined in `IdentityAndProfileManagerAPI/urls.py` using DRF’s `DefaultRouter` and SimpleJWT views.

- **Auth**
  - `POST /IdentityAndProfileManagerAPI/token/` — obtain access/refresh tokens
  - `POST /IdentityAndProfileManagerAPI/token/refresh/` — refresh access token

- **Registration**
  - `POST /IdentityAndProfileManagerAPI/register/` — body: `{ username, password, legal_name?, academic_name?, social_name? }`

- **Profiles** (router-registered viewset `IdentityProfileViewSet`)
  - `GET /IdentityAndProfileManagerAPI/IdentityAndProfileManager/search/?q=<username>` — search by partial username; returns minimal info plus consented fields
  - `GET /IdentityAndProfileManagerAPI/IdentityAndProfileManager/<username>/` — retrieve a profile. The owner sees all fields; others see only fields for which consent exists.

Important: All profile endpoints require a valid `Authorization: Bearer <access_token>` header.

---

### Web pages (templates)
- `GET /` — `home.html` login form (obtains JWT and stores tokens in `localStorage`)
- `GET /profile/<username>/` — `profile_detail.html` read-only detail page

These views are wired in `IdentityAndProfileManagerAPI/urls.py` and implemented in `IdentityAndProfileManager/views.py`.

---

### How consent gates fields
When a non-owner retrieves a profile or search result, only fields with a corresponding `Consent` row (`owner` = profile owner, `requester` = current user, `field_name` = one of the profile fields) will be included. Otherwise, only the `username` is returned.

---

### Setup and run

#### Prerequisites
- **Python 3.10+** (Django 5.x requires ≥3.10)
- **Node.js 16+** and npm (for Tailwind CSS)
- Fresh virtual environment recommended

#### 1. Set up Python virtual environment
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# OR on Windows:
# .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

#### 2. Set up Node.js dependencies for Tailwind CSS
```bash
# Install Node.js dependencies
npm install
```

#### 3. Configure environment variables
```bash
# Copy the example environment file
cp env-example.txt .env
# or using cmd:
# copy env-example.txt .env

# Edit .env file with your configuration
# At minimum, set these for local development:
# SECRET_KEY=your-secret-key-here
# DEBUG=True
# ALLOWED_HOSTS=localhost,127.0.0.1
# FERNET_KEY=your-32-char-base64-key-here
```

**Generate secure keys:**
```bash
# Generate Django secret key
python -c "from django.core.management.utils import get_random_secret_key; print('SECRET_KEY=' + get_random_secret_key())"

# Generate Fernet encryption key
python -c "import secrets; print('FERNET_KEY=' + secrets.token_urlsafe(32))"
```

#### 4. Build Tailwind CSS
```bash
# Build CSS for production
npm run build:css

# OR for development with file watching (run in separate terminal)
npm run watch:css
```

#### 5. Set up database and run server
```bash
# Navigate to Django project directory
cd IdentityAndProfileManagerAPI

# Run database migrations
python manage.py migrate

# Create superuser (optional, for admin access)
python manage.py createsuperuser

# Collect static files (if needed)
python manage.py collectstatic --noinput

# Start development server
python manage.py runserver
```

#### 6. Development workflow
For active development, run these commands in separate terminals:

**Terminal 1 - Tailwind CSS watcher:**
```bash
# From project root
npm run watch:css
```

**Terminal 2 - Django development server:**
```bash
# From project root
source .venv/bin/activate  # if not already activated
cd IdentityAndProfileManagerAPI
python manage.py runserver
```

Visit:
- Home (login): `http://127.0.0.1:8000/`
- Admin: `http://127.0.0.1:8000/admin/`

---

### Quick API walkthrough
Use `curl` or any HTTP client. Replace placeholders as needed.

```bash
# 1) Register
curl -X POST http://127.0.0.1:8000/IdentityAndProfileManagerAPI/register/ \
  -H 'Content-Type: application/json' \
  -d '{
        "username": "alice",
        "password": "pass123",
        "legal_name": "Alice L",
        "academic_name": "A. Learner",
        "social_name": "Ali"
      }'

# 2) Obtain tokens
curl -X POST http://127.0.0.1:8000/IdentityAndProfileManagerAPI/token/ \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "pass123"}'

# 3) Search (use access token from step 2)
ACCESS=...  # paste access token
curl -H "Authorization: Bearer $ACCESS" \
  'http://127.0.0.1:8000/IdentityAndProfileManagerAPI/IdentityAndProfileManager/search/?q=ali'

# 4) Retrieve profile (owner sees all fields; others see only consented fields)
curl -H "Authorization: Bearer $ACCESS" \
  http://127.0.0.1:8000/IdentityAndProfileManagerAPI/IdentityAndProfileManager/alice/
```

---

### Configuration details (high level)
- `settings.py`:
  - `INSTALLED_APPS`: includes `rest_framework`, `rest_framework_simplejwt`, `IdentityAndProfileManager`
  - `REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES`: SimpleJWT
  - `SIMPLE_JWT` lifetimes: access 5 minutes, refresh 1 day; rotation + blacklist enabled
  - DB: SQLite (`db.sqlite3` in project folder)
  - `DEBUG=True`, `ALLOWED_HOSTS=[]` (development defaults)

---

### Extending the project
- Add more profile fields to `IdentityProfile` and include them in `Consent` checks.
- Create endpoints to grant/revoke consent (currently implicit via DB rows; no UI provided).
- Register models in `admin.py` for easy admin management.
- Harden for production (env-based settings, CSRF, HTTPS, secure cookie settings, proper `ALLOWED_HOSTS`).

---

## Security Features

This application has been hardened with comprehensive security measures:

### Data Encryption
- **Sensitive fields are encrypted at rest**: `email`, `home_address`, `emergency_contact`, and `phone_number` fields use AES encryption with Fernet (AES 128 in CBC mode)
- **Custom encrypted field implementation**: Uses Django's cryptography library for seamless encryption/decryption
- **Key management**: Encryption keys are managed through environment variables

### HTTPS and SSL Security
- **SSL/HTTPS enforcement**: `SECURE_SSL_REDIRECT=True` forces all HTTP traffic to HTTPS
- **HTTP Strict Transport Security (HSTS)**: Enabled with 1-year max-age, includes subdomains and preload
- **Content Security**: `SECURE_CONTENT_TYPE_NOSNIFF` and `SECURE_BROWSER_XSS_FILTER` enabled
- **Referrer Policy**: Set to `strict-origin-when-cross-origin`

### Session and CSRF Security
- **Secure cookies**: Session and CSRF cookies marked as secure and HTTP-only
- **SameSite protection**: Cookies use `Strict` SameSite policy
- **Session timeout**: 1-hour session expiration
- **CSRF trusted origins**: Configurable trusted domains for CSRF protection

### Configuration Security
- **Environment variables**: All sensitive settings moved to environment variables using `python-decouple`
- **Secure secret key**: SECRET_KEY loaded from environment (no longer hardcoded)
- **Production-ready settings**: DEBUG defaults to False, configurable ALLOWED_HOSTS

### Setup for Production
1. Copy `env-example.txt` to `.env`
2. Generate secure keys:
   ```bash
   # Generate SECRET_KEY
   python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

   # Generate FERNET_KEY
   python -c 'import secrets; print(secrets.token_urlsafe(32))'
   ```
3. Configure your `.env` file with production values
4. Set up HTTPS with a reverse proxy (nginx) or load balancer
5. Use a production database (PostgreSQL recommended)

---

### Known considerations
- Secret key and `DEBUG=True` are for local use only; external deployments should move secrets to environment variables and disable debug.
- All sensitive data is now encrypted; existing data will be encrypted on next save operation.
