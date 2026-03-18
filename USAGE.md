# WebSecure360 — Complete Local Usage Guide

## ─── LAUNCH (One Command) ───────────────────────────────

```bash
cd websecure360
python run.py
```

That's it. It will:
✅ Check your Python version
✅ Create a .env file with auto-generated secret key
✅ Install all dependencies automatically
✅ Create the database
✅ Create your admin account
✅ Start the server at http://localhost:5000

---

## ─── ADMIN ACCOUNT ──────────────────────────────────────

When you run for the first time, your admin account is created automatically:

  Email    →  admin@websecure360.local
  Password →  admin1234
  Plan     →  ENTERPRISE (full access, unlimited scans)

⚠ Change your password after first login:
  Account → Change Password

---

## ─── NAVIGATION GUIDE ───────────────────────────────────

### As Admin you have:

┌─────────────────────────────────────────────────────┐
│  http://localhost:5000           Landing page        │
│  http://localhost:5000/login     Login               │
│  http://localhost:5000/dashboard Your dashboard      │
│  http://localhost:5000/projects  Your projects       │
│  http://localhost:5000/pricing   Pricing page        │
│  http://localhost:5000/account   Account settings    │
│  http://localhost:5000/admin     Admin panel ⚙       │
└─────────────────────────────────────────────────────┘

### Admin Panel (/admin):
- See all registered users
- Change any user's plan (Free → Pro → Enterprise)
- Delete users
- View total scans and projects

---

## ─── HOW TO RUN A SCAN ──────────────────────────────────

1. Login at http://localhost:5000/login
2. Go to Projects → Create a project
   Example: Name = "Test Project"
3. Click "+ New Scan"
4. Enter a target:
   Example: https://example.com
5. Select scan modules (tick the ones you want)
6. Click "Start Scan"
7. Watch the live progress bar
8. View results when complete

---

## ─── SCAN MODULES ───────────────────────────────────────

FREE modules (always available):
  🔍 WHOIS       → Domain registrar, creation/expiry dates
  🔒 SSL/TLS     → Certificate validity, expiry, issuer
  🛡 Headers     → Missing security headers (CSP, HSTS etc.)
  🌐 DNS         → IP address, IPv6

PRO / ENTERPRISE modules:
  📡 Subdomains  → Find live subdomains
  🚪 Ports       → Open ports (MySQL, SSH, RDP etc.)
  🔎 URL Fuzzer  → Exposed files (.env, .git, admin, config)
  ⚡ XSS         → Reflected XSS on GET parameters
  💉 SQLi        → SQL injection error detection
  🧩 Tech        → CMS, server, framework fingerprinting

Since you're admin (Enterprise plan), all modules are available.

---

## ─── TESTING USER ACCOUNTS ──────────────────────────────

To test how a Free or Pro user sees the platform:

1. Open http://localhost:5000/register in another browser
   (or incognito window)
2. Register with any email/password
3. They start on Free plan (5 scans, 2 projects, 4 modules)
4. Go to Admin panel → find their account → change plan to Pro

---

## ─── API USAGE (Pro / Enterprise) ──────────────────────

1. Go to Account → API Access → Generate API Key
2. Your key looks like: ws360_abc123...

Test with curl:
```bash
# Get your account info
curl -H "Authorization: Bearer ws360_YOUR_KEY" \
     http://localhost:5000/api/v1/me

# List your projects
curl -H "Authorization: Bearer ws360_YOUR_KEY" \
     http://localhost:5000/api/v1/projects

# List scans in project 1
curl -H "Authorization: Bearer ws360_YOUR_KEY" \
     http://localhost:5000/api/v1/projects/1/scans

# Get full scan results
curl -H "Authorization: Bearer ws360_YOUR_KEY" \
     http://localhost:5000/api/v1/scans/SCAN_ID
```

---

## ─── STRIPE / PAYMENTS ───────────────────────────────────

Stripe is DISABLED in local mode.
The checkout button will fail because the keys are placeholders.

To enable payments:
1. Create account at https://stripe.com
2. Get your keys from Stripe Dashboard → Developers → API Keys
3. Open .env file and replace:
   STRIPE_SECRET_KEY=sk_test_your_real_key
   STRIPE_PUBLISHABLE_KEY=pk_test_your_real_key
4. Create products in Stripe → copy Price IDs into .env
5. Restart: python run.py

For local testing, just use the Admin panel to manually
change user plans — no payment needed.

---

## ─── RESTART / RESET ─────────────────────────────────────

Restart server:     CTRL+C → python run.py
Reset database:     Delete websecure360.db → python run.py
                    (admin account will be recreated)
View database:      pip install datasette → datasette websecure360.db

---

## ─── FILES EXPLAINED ────────────────────────────────────

  run.py          ← START HERE — one-command launcher
  app.py          ← All routes: auth, projects, scans, API, admin
  web_scanner.py  ← Scanner engine (10 modules)
  websecure360.db ← SQLite database (auto-created)
  .env            ← Config (auto-created, keep secret)
  requirements.txt ← Python dependencies
  templates/      ← HTML pages
  static/         ← CSS + JS

---

## ─── COMMON ISSUES ──────────────────────────────────────

❌ "Module not found"
   → pip install -r requirements.txt

❌ "Address already in use"
   → Another app is using port 5000
   → Change port in run.py: app.run(port=5001)
   → Then open http://localhost:5001

❌ Scan stuck / no results
   → Some targets block automated scanners
   → Try: https://example.com or https://httpbin.org

❌ PDF download fails
   → Install wkhtmltopdf:
     Mac:   brew install wkhtmltopdf
     Linux: sudo apt install wkhtmltopdf
