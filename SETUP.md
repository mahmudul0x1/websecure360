# WebSecure360 — Setup Guide

## Quick Start

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Mac/Linux
# venv\Scripts\activate           # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
export SECRET_KEY="your-secret-key-here"
export STRIPE_SECRET_KEY="sk_test_your_stripe_key"
export STRIPE_PUBLISHABLE_KEY="pk_test_your_stripe_key"
export STRIPE_PRO_PRICE_ID="price_your_pro_price_id"
export STRIPE_ENTERPRISE_PRICE_ID="price_your_enterprise_price_id"

# 4. Run
python app.py
```

Open http://localhost:5000

---

## Stripe Setup

1. Create account at https://stripe.com
2. Go to Products → Create two products:
   - **Pro Plan** — $15/month recurring
   - **Enterprise Plan** — $49/month recurring
3. Copy the Price IDs (starts with `price_`) into your env vars
4. For webhooks (subscription cancellations):
   - Stripe Dashboard → Webhooks → Add endpoint
   - URL: `https://yourdomain.com/billing/webhook`
   - Events: `customer.subscription.deleted`
   - Copy webhook secret → `STRIPE_WEBHOOK_SECRET`

---

## PDF Reports (Optional)

Install wkhtmltopdf:
- **Mac:** `brew install wkhtmltopdf`
- **Ubuntu:** `apt install wkhtmltopdf`

---

## Project Structure

```
websecure360/
├── app.py              ← Main Flask app — routes, auth, billing, API
├── web_scanner.py      ← Scanner engine — all 10 modules
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── index.html      ← Landing page
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── projects.html
│   ├── project_detail.html
│   ├── new_scan.html
│   ├── scan_running.html
│   ├── scan_results.html
│   ├── pricing.html
│   ├── account.html
│   └── error.html
└── static/
    ├── css/main.css
    └── js/main.js
```

---

## REST API Usage (Pro / Enterprise)

```bash
# Get your API key from Account → API Access

# Account info
curl -H "Authorization: Bearer ws360_your_key" http://localhost:5000/api/v1/me

# List projects
curl -H "Authorization: Bearer ws360_your_key" http://localhost:5000/api/v1/projects

# Get scan results
curl -H "Authorization: Bearer ws360_your_key" http://localhost:5000/api/v1/scans/SCAN_ID
```

---

## Plans

| | Free | Pro | Enterprise |
|---|---|---|---|
| Price | $0 | $15/mo | $49/mo |
| Scans/month | 5 | 100 | 1,000 |
| Projects | 2 | 20 | 100 |
| Scan modules | 4 | 10 | 10 |
| PDF reports | ✗ | ✓ | ✓ |
| API access | ✗ | ✓ | ✓ |
| Priority support | ✗ | ✗ | ✓ |
