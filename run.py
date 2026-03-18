#!/usr/bin/env python3
"""
WebSecure360 — One-Command Launcher
Run: python run.py
"""
import os
import sys
import subprocess

# ── Step 1: Check Python version ─────────────────────────────────────────────
if sys.version_info < (3, 8):
    print("❌ Python 3.8+ required. Download from https://python.org")
    sys.exit(1)

print("\n" + "="*55)
print("  ⬡  WebSecure360 — Local Launcher")
print("="*55)

# ── Step 2: Create .env if missing ───────────────────────────────────────────
if not os.path.exists('.env'):
    import secrets
    secret_key = secrets.token_hex(32)
    with open('.env', 'w') as f:
        f.write(f"""# WebSecure360 — Local Config
SECRET_KEY={secret_key}
DATABASE_URL=sqlite:///websecure360.db
FLASK_ENV=development

# Stripe (leave as-is for local testing — payments won't work without real keys)
STRIPE_SECRET_KEY=sk_test_placeholder
STRIPE_PUBLISHABLE_KEY=pk_test_placeholder
STRIPE_PRO_PRICE_ID=price_placeholder
STRIPE_ENTERPRISE_PRICE_ID=price_placeholder_enterprise
STRIPE_WEBHOOK_SECRET=
""")
    print("✅ Created .env with auto-generated secret key")
else:
    print("✅ .env found")

# ── Step 3: Load .env ─────────────────────────────────────────────────────────
with open('.env') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, _, val = line.partition('=')
            os.environ.setdefault(key.strip(), val.strip())

# ── Step 4: Install dependencies ─────────────────────────────────────────────
print("\n📦 Checking dependencies...")
try:
    import flask, flask_sqlalchemy, flask_login, stripe, requests
    print("✅ All dependencies installed")
except ImportError:
    print("📥 Installing dependencies...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt', '-q'])
    print("✅ Dependencies installed")

# ── Step 5: Init DB + Admin account ──────────────────────────────────────────
print("\n🗄  Setting up database...")

# Import app here after env is set
from app import app, db, User, PLANS
from datetime import datetime, timedelta

with app.app_context():
    db.create_all()

    # Create admin account if it doesn't exist
    ADMIN_EMAIL    = 'admin@websecure360.local'
    ADMIN_PASSWORD = 'admin1234'
    ADMIN_NAME     = 'Md Mahmudul Hasan'

    admin = User.query.filter_by(email=ADMIN_EMAIL).first()
    if not admin:
        admin = User(
            name=ADMIN_NAME,
            email=ADMIN_EMAIL,
            plan='enterprise',   # Admin gets Enterprise
            scans_used=0,
            scan_reset_date=datetime.utcnow() + timedelta(days=365),
        )
        admin.set_password(ADMIN_PASSWORD)
        admin.generate_api_key()
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Admin account created")
    else:
        # Ensure admin always has enterprise
        if admin.plan != 'enterprise':
            admin.plan = 'enterprise'
            db.session.commit()
        print(f"✅ Admin account found")

    admin = User.query.filter_by(email=ADMIN_EMAIL).first()

# ── Step 6: Print dashboard ───────────────────────────────────────────────────
print("\n" + "="*55)
print("  🚀  WEBSECURE360 IS READY")
print("="*55)
print(f"""
  🌐  URL          →  http://localhost:5000

  👤  ADMIN LOGIN
      Email        →  {ADMIN_EMAIL}
      Password     →  {ADMIN_PASSWORD}
      Plan         →  ENTERPRISE (unlimited)

  🔑  API Key      →  {admin.api_key or 'Generate from Account page'}

  📁  Database     →  websecure360.db (auto-created)

  ⚠   Stripe       →  Payments disabled in local mode
                       (upgrade plans manually via admin)

  💡  HOW TO USE:
      1. Open http://localhost:5000
      2. Login with admin credentials above
      3. Create a project → run a scan
      4. To test as a regular user → register a new account

  🛑  Stop server  →  Press CTRL+C
""")
print("="*55 + "\n")

# ── Step 7: Run Flask ─────────────────────────────────────────────────────────
os.environ['FLASK_ENV'] = 'development'
app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
