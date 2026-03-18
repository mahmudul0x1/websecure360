<div align="center">

# ⬡ WebSecure360

**Web Security Assessment Platform**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mahmudul0x1-red?style=flat-square)](https://github.com/mahmudul0x1)
[![Modules](https://img.shields.io/badge/Scan%20Modules-39-orange?style=flat-square)]()

A full-stack web security assessment platform with 39 scan modules, project management, PDF reports, REST API, and 3-tier subscription billing.

</div>

---

## Screenshots

![Dashboard](screenshots/dashboard.png)

![Scan Results](screenshots/scan_results.png)

![Homepage](screenshots/homepage.png)

---

## Quick Start

```bash
git clone https://github.com/mahmudul0x1/websecure360
cd websecure360
pip install -r requirements.txt
python run.py
```

Open **http://localhost:5000**

Admin login is printed in the terminal on first run.

---

## Requirements

**Python 3.8+** — https://python.org

**wkhtmltopdf** *(optional — for PDF export)*

| OS | Install |
|---|---|
| macOS | `brew install wkhtmltopdf` or download `.pkg` from https://wkhtmltopdf.org |
| Ubuntu | `sudo apt install wkhtmltopdf` |
| Windows | Download from https://wkhtmltopdf.org/downloads.html |

> Reports also download as `.html` — open in Chrome and print to PDF with `Cmd+P`.

---

## Scan Modules (39 Total)

### 🆓 Free — Always Available
| Module | What it checks |
|---|---|
| 🔍 WHOIS Lookup | Registrar, creation/expiry dates, name servers |
| 🔒 SSL/TLS Analysis | Certificate validity, expiry, issuer, days remaining |
| 🛡 Security Headers | CSP, HSTS, X-Frame-Options, Referrer-Policy and more |
| 🌐 DNS Intelligence | IPv4, IPv6, hostname resolution |

### ⬡ Pro / Enterprise — Discovery & Recon
| Module | What it checks |
|---|---|
| 📡 Subdomain Enumeration | 30+ common subdomains with live IP resolution |
| 🚪 Port Scanner | MySQL, Redis, MongoDB, RDP, SSH, FTP and more |
| 🔎 URL Fuzzer | .env, .git, admin, phpinfo, config files |
| 🔐 Admin Panel Finder | 60+ admin & login path patterns |
| 📁 Directory Listing | Open directories — storage, uploads, logs |
| 🧩 Tech Detection | CMS, framework, server, CDN/WAF fingerprinting |

### ⬡ Pro / Enterprise — Secrets & Credentials
| Module | What it checks |
|---|---|
| 🌿 .ENV File Exposure | Laravel .env, DB credentials, API keys |
| 📦 Git / SVN Exposure | .git/config, HEAD, credentials, Dockerfile |
| 🔑 JSON Secrets | credentials.json, appsettings, service accounts |
| 📜 JS File Secrets | Firebase keys, API tokens in config.js |
| 🗝 SSH / Private Keys | id_rsa, id_dsa, .pem, PuTTY keys |
| 📡 FTP Config Leak | .ftpconfig, sftp.json, FileZilla configs |
| 🔏 Sensitive Config | AWS credentials, Redis conf, Prometheus |
| 📄 YAML Config Leak | docker-compose, CI/CD secrets, parameters |
| 🗂 XML Config Leak | .idea configs, Magento local.xml, FileZilla |

### ⬡ Pro / Enterprise — Vulnerabilities
| Module | What it checks |
|---|---|
| ⚡ XSS Detection | Reflected XSS across common GET parameters |
| 💉 SQL Injection | Error-based SQLi detection on input parameters |
| ◈ GraphQL Introspection | Exposed schemas via GET and POST probing |
| 📋 Swagger / OpenAPI | Exposed API specs, swagger-ui, redoc endpoints |
| 🗄 SQL Backup Exposure | dump.sql, database.sql, sqlite files |
| 💾 Backup File Exposure | site.zip, backup.tar.gz, .bak archives |
| 📋 Log File Exposure | laravel.log, npm-debug.log, error logs |
| 🐘 PHP Config Backup | wp-config.php.bak, config.inc.php.old |
| ℹ PHP Info / Adminer | phpinfo.php, adminer, phpmyadmin exposure |
| 🗃 File Manager Exposed | elfinder, Laravel filemanager, TinyMCE |

### ⬡ Pro / Enterprise — Frameworks & Servers
| Module | What it checks |
|---|---|
| 🔥 Laravel Vulnerabilities | Debugbar, Telescope, Ignition, PHPUnit eval-stdin |
| 🐍 Django Debug Mode | DEBUG=True page, admin panel, settings.py |
| 🌱 Spring Boot Actuator | /actuator/env, /heapdump, Jolokia endpoints |
| 💎 Ruby / Rails Config | schema.rb, secret_token.rb, credentials.db |
| ☕ Apache Tomcat | Manager UI, host-manager, path traversal |
| ⚙ JK / Nginx Status | jkstatus, server-status, nginx_status |
| 🔧 Jenkins Exposure | Script Console, API, open registration |
| 🪟 IIS / Telerik | Telerik WebResource, DialogHandler, RAU upload |
| 🌐 WordPress Vulnerabilities | Open registration, user enumeration via REST API |
| ⚙ WordPress Setup / Install | Exposed wp-admin/install.php, setup-config |

---

## Plans

| | Free | Pro | Enterprise |
|---|---|---|---|
| Price | $0/mo | $15/mo | $49/mo |
| Scans / month | 5 | 100 | 1,000 |
| Projects | 2 | 20 | 100 |
| Scan modules | 4 | 39 | 39 |
| PDF reports | ✗ | ✓ | ✓ |
| REST API access | ✗ | ✓ | ✓ |
| Priority support | ✗ | ✗ | ✓ |

---

## REST API

Pro and Enterprise users can access scan results via API:

```bash
# Account info
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:5000/api/v1/me

# List projects
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:5000/api/v1/projects

# List scans in a project
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:5000/api/v1/projects/1/scans

# Get full scan results
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:5000/api/v1/scans/SCAN_ID
```

Generate your API key from **Account → API Access** after upgrading to Pro.

---

## Stack

- **Backend** — Python, Flask, SQLAlchemy, Flask-Login
- **Database** — SQLite (local) / PostgreSQL (production)
- **Payments** — Stripe (subscriptions)
- **Frontend** — Vanilla HTML/CSS/JS — no frameworks
- **Reports** — HTML export (print to PDF via browser)

---

## Legal

> For authorized security testing only. Do not scan targets you do not own or have explicit written permission to test. The author is not responsible for misuse.

---

## Author

**Md Mahmudul Hasan** — Security Engineer & Red Teamer

[![LinkedIn](https://img.shields.io/badge/LinkedIn-mahmudul--hasan-blue?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/mahmudul-hasan-816a471a4)
[![Medium](https://img.shields.io/badge/Medium-mahmudul24x7-black?style=flat-square&logo=medium)](https://medium.com/@mahmudul24x7)
[![Email](https://img.shields.io/badge/Email-mahmudul24x7@gmail.com-red?style=flat-square)](mailto:mahmudul24x7@gmail.com)

- 500+ vulnerabilities disclosed across 70+ enterprises
- Member of Yogosha Strike Force (invitation-only red team)
- Hall of Fame: Microsoft, UNICEF, QNAP, Neo4j, Foxit Software
