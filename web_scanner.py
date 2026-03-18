"""
WebSecure360 - Web Scanner Engine
Improved scanner with proper HTTPS support, real parsing, and progress callbacks.
"""
import socket
import ssl
import requests
import subprocess
import json
import re
import time
import certifi
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Callable, Optional

requests.packages.urllib3.disable_warnings()


class WebScanner:
    def __init__(self, target: str, modules: List[str],
                 progress_callback: Optional[Callable] = None):
        self.target   = self._normalize(target)
        self.domain   = self._extract_domain(self.target)
        self.modules  = modules
        self.callback = progress_callback or (lambda p, s: None)
        self.results  = {}
        self.session  = requests.Session()
        self.session.headers.update({'User-Agent': 'WebSecure360-Scanner/1.0'})
        self.session.verify = certifi.where()  # Use certifi certs

    # ── Normalization ─────────────────────────────────────────────────────────
    def _normalize(self, target: str) -> str:
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target.rstrip('/')

    def _extract_domain(self, url: str) -> str:
        return urlparse(url).hostname or url

    def _update(self, progress: int, status: str):
        self.callback(progress, status)

    # ── Main Run ──────────────────────────────────────────────────────────────
    def run_scan(self) -> dict:
        total   = len(self.modules)
        done    = 0

        module_map = {
            'whois':      self._whois,
            'ssl':        self._ssl_check,
            'headers':    self._security_headers,
            'dns':        self._dns_info,
            'subdomains': self._subdomains,
            'ports':      self._port_scan,
            'fuzzer':     self._url_fuzzer,
            'xss':        self._xss_check,
            'sqli':       self._sqli_check,
            'tech':       self._tech_detect,
            # ── Anan's tools ──
            'admin_finder':   self._admin_finder,
            'swagger':        self._swagger_finder,
            'sql_backup':     self._sql_backup,
            'yaml_config':    self._yaml_config,
            'json_secrets':   self._json_secrets,
            'tomcat':         self._tomcat_check,
            'wp_vulns':       self._wp_vulns,
            'jk_nginx':       self._jk_nginx,
            'env_exposure':   self._env_exposure,
            'git_exposure':   self._git_exposure,
            'sensitive_config': self._sensitive_config,
            'js_secrets':     self._js_secrets,
            'xml_config':     self._xml_config,
            'graphql':        self._graphql,
            'dir_listing':    self._dir_listing,
            'log_exposure':   self._log_exposure,
            'ftp_config':     self._ftp_config,
            'ssh_keys':       self._ssh_keys,
            'backup_files':   self._backup_files,
            'php_backup':     self._php_backup,
            'php_info':       self._php_info,
            'file_manager':   self._file_manager,
            'laravel_vulns':  self._laravel_vulns,
            'django_debug':   self._django_debug,
            'spring_boot':    self._spring_boot,
            'ruby_config':    self._ruby_config,
            'jenkins':        self._jenkins,
            'iis_telerik':    self._iis_telerik,
            'wp_setup':       self._wp_setup,
        }

        for module in self.modules:
            if module in module_map:
                label = module.upper().replace('_', ' ')
                self._update(int((done / total) * 95), f'Running {label}...')
                try:
                    module_map[module]()
                except Exception as e:
                    self.results[module] = {'error': str(e)}
                done += 1

        self._update(100, 'Complete')
        return self.results

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    def _whois(self):
        try:
            import whois
            info = whois.whois(self.domain)
            def fmt_date(d):
                if isinstance(d, list): d = d[0]
                return d.strftime('%Y-%m-%d') if hasattr(d, 'strftime') else str(d)
            self.results['whois'] = {
                'domain':      self.domain,
                'registrar':   str(info.registrar or 'N/A'),
                'created':     fmt_date(info.creation_date)   if info.creation_date   else 'N/A',
                'expires':     fmt_date(info.expiration_date) if info.expiration_date else 'N/A',
                'name_servers': list(info.name_servers or []),
                'status':      str(info.status or 'N/A'),
            }
        except Exception as e:
            self.results['whois'] = {'error': str(e)}

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    def _ssl_check(self):
        try:
            # Fix Mac certificate issue
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
            verified = True
            cert = None

            try:
                with ctx.wrap_socket(socket.socket(),
                                     server_hostname=self.domain) as s:
                    s.settimeout(10)
                    s.connect((self.domain, 443))
                    cert = s.getpeercert()
            except ssl.SSLCertVerificationError:
                # Certificate is invalid/untrusted — still get info
                verified = False
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode    = ssl.CERT_NONE
                with ctx2.wrap_socket(socket.socket(),
                                      server_hostname=self.domain) as s:
                    s.settimeout(10)
                    s.connect((self.domain, 443))
                    cert = s.getpeercert(binary_form=False)

            if not cert:
                self.results['ssl'] = {
                    'valid': False,
                    'error': 'No certificate returned'
                }
                return

            not_after  = datetime.strptime(cert['notAfter'],  '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            days_left  = (not_after - datetime.utcnow()).days
            issuer     = dict(x[0] for x in cert.get('issuer', []))
            subject    = dict(x[0] for x in cert.get('subject', []))

            self.results['ssl'] = {
                'valid':         verified,
                'issuer':        issuer.get('organizationName', 'Unknown'),
                'subject':       subject.get('commonName', self.domain),
                'expires':       not_after.strftime('%Y-%m-%d'),
                'issued':        not_before.strftime('%Y-%m-%d'),
                'days_left':     days_left,
                'expiring_soon': days_left < 30,
            }
            if not verified:
                self.results['ssl']['warning'] = 'Certificate verification failed — untrusted or self-signed'

        except ConnectionRefusedError:
            self.results['ssl'] = {'valid': False, 'error': 'Port 443 not open — HTTPS not available'}
        except socket.timeout:
            self.results['ssl'] = {'valid': False, 'error': 'Connection timed out'}
        except Exception as e:
            self.results['ssl'] = {'valid': False, 'error': str(e)}

    # ── Security Headers ──────────────────────────────────────────────────────
    def _security_headers(self):
        SECURITY_HEADERS = {
            'Strict-Transport-Security': 'Enforces HTTPS connections',
            'Content-Security-Policy':   'Prevents XSS and injection attacks',
            'X-Frame-Options':           'Prevents clickjacking attacks',
            'X-Content-Type-Options':    'Prevents MIME type sniffing',
            'Referrer-Policy':           'Controls referrer information',
            'Permissions-Policy':        'Controls browser feature access',
            'X-XSS-Protection':          'Legacy XSS protection header',
        }
        try:
            r       = self.session.get(self.target, timeout=10, verify=False)
            present = {}
            missing = []
            for h, desc in SECURITY_HEADERS.items():
                if h in r.headers:
                    present[h] = r.headers[h]
                else:
                    missing.append({'header': h, 'description': desc})

            self.results['headers'] = {
                'present': present,
                'missing': missing,
                'score':   int((len(present) / len(SECURITY_HEADERS)) * 100),
                'server':  r.headers.get('Server', 'Hidden'),
                'powered_by': r.headers.get('X-Powered-By', 'Hidden'),
            }
        except Exception as e:
            self.results['headers'] = {'error': str(e)}

    # ── DNS ───────────────────────────────────────────────────────────────────
    def _dns_info(self):
        try:
            ip    = socket.gethostbyname(self.domain)
            addrs = socket.getaddrinfo(self.domain, None)
            ipv6  = next((a[4][0] for a in addrs if a[0].name == 'AF_INET6'), None)
            self.results['dns'] = {
                'ip':   ip,
                'ipv6': ipv6,
                'hostname': self.domain,
            }
        except Exception as e:
            self.results['dns'] = {'error': str(e)}

    # ── Subdomain Enumeration ─────────────────────────────────────────────────
    def _subdomains(self):
        common = [
            'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'beta',
            'admin', 'blog', 'support', 'shop', 'portal', 'secure',
            'static', 'cdn', 'images', 'media', 'news', 'status',
            'app', 'docs', 'help', 'dashboard', 'old', 'test',
            'vpn', 'remote', 'login', 'auth', 'oauth', 'git',
        ]
        found = []
        for sub in common:
            subdomain = f'{sub}.{self.domain}'
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({'subdomain': subdomain, 'ip': ip})
            except socket.error:
                continue
        self.results['subdomains'] = {'found': found, 'count': len(found)}

    # ── Port Scan ─────────────────────────────────────────────────────────────
    def _port_scan(self):
        COMMON_PORTS = {
            21:   'FTP',   22:   'SSH',    23:  'Telnet',
            25:   'SMTP',  53:   'DNS',    80:  'HTTP',
            110:  'POP3',  143:  'IMAP',   443: 'HTTPS',
            445:  'SMB',   3306: 'MySQL',  3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB',
        }
        open_ports  = []
        closed_ports = []
        ip = socket.gethostbyname(self.domain)

        for port, service in COMMON_PORTS.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    open_ports.append({'port': port, 'service': service})
                else:
                    closed_ports.append(port)
            except Exception:
                closed_ports.append(port)

        self.results['ports'] = {'open': open_ports, 'ip': ip}

    # ── URL Fuzzer ────────────────────────────────────────────────────────────
    def _url_fuzzer(self):
        WORDLIST = [
            'admin', 'login', 'dashboard', 'wp-admin', 'wp-login.php',
            'phpmyadmin', 'config', 'config.php', 'configuration.php',
            'backup', 'backup.zip', 'db.sql', '.git', '.env',
            'robots.txt', 'sitemap.xml', 'phpinfo.php', 'info.php',
            'server-status', 'admin.php', 'upload', 'uploads',
            'api', 'api/v1', 'api/v2', 'swagger', 'swagger-ui.html',
            'actuator', 'actuator/health', 'console', 'manager',
            'readme.md', 'README.md', 'CHANGELOG', 'composer.json',
            'package.json', 'webpack.config.js', '.htaccess',
        ]
        found = []
        for path in WORDLIST:
            url = f'{self.target}/{path}'
            try:
                r = self.session.get(url, timeout=5, verify=False,
                                     allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    found.append({'url': url, 'status': r.status_code,
                                  'size': len(r.content)})
            except Exception:
                continue
        self.results['fuzzer'] = {'found': found, 'count': len(found)}

    # ── XSS Check ─────────────────────────────────────────────────────────────
    def _xss_check(self):
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><img src=x onerror=alert(1)>",
            '<svg onload=alert(1)>',
        ]
        params   = ['q', 's', 'search', 'query', 'id', 'page', 'name', 'input']
        findings = []

        for param in params:
            for payload in payloads[:2]:   # limit to 2 payloads per param
                url = f'{self.target}?{param}={requests.utils.quote(payload)}'
                try:
                    r = self.session.get(url, timeout=5, verify=False)
                    if payload.lower() in r.text.lower():
                        findings.append({'url': url, 'param': param,
                                         'payload': payload, 'type': 'Reflected XSS'})
                        break
                except Exception:
                    continue

        self.results['xss'] = {'found': len(findings) > 0, 'findings': findings}

    # ── SQLi Check ────────────────────────────────────────────────────────────
    def _sqli_check(self):
        payloads = ["'", "' OR '1'='1", "1; DROP TABLE--", '" OR "1"="1']
        errors   = ['sql syntax', 'mysql_fetch', 'ora-', 'syntax error',
                    'unclosed quotation', 'quoted string not properly']
        params   = ['id', 'user', 'page', 'item', 'product', 'cat', 'q']
        findings = []

        for param in params:
            for payload in payloads[:2]:
                url = f'{self.target}?{param}={requests.utils.quote(payload)}'
                try:
                    r = self.session.get(url, timeout=5, verify=False)
                    text_lower = r.text.lower()
                    for err in errors:
                        if err in text_lower:
                            findings.append({'url': url, 'param': param,
                                             'payload': payload, 'error': err})
                            break
                except Exception:
                    continue

        self.results['sqli'] = {'found': len(findings) > 0, 'findings': findings}

    # ── Technology Detection ──────────────────────────────────────────────────
    def _tech_detect(self):
        try:
            r    = self.session.get(self.target, timeout=10, verify=False)
            html = r.text
            hdrs = r.headers
            tech = {}

            CMS_PATTERNS = {
                'WordPress':  ['wp-content', 'wp-includes', 'wp-json'],
                'Drupal':     ['drupal.js', 'sites/all', 'drupal.org'],
                'Joomla':     ['/media/system/js/', 'Joomla!'],
                'Magento':    ['Mage.Cookies', 'magento'],
                'Shopify':    ['cdn.shopify.com', 'shopify'],
                'Wix':        ['wix.com', '_wix_'],
                'Squarespace': ['squarespace.com'],
                'Ghost':      ['ghost.io', 'content/themes/ghost'],
                'Laravel':    ['laravel_session', 'XSRF-TOKEN'],
                'Django':     ['csrfmiddlewaretoken', 'django'],
                'Next.js':    ['__next', '_next/static'],
                'React':      ['react-root', '__react'],
                'Vue.js':     ['vue-router', '__vue__'],
                'Angular':    ['ng-version', 'angular.js'],
            }

            for cms, patterns in CMS_PATTERNS.items():
                if any(p.lower() in html.lower() for p in patterns):
                    tech['CMS/Framework'] = cms
                    break

            server = hdrs.get('Server', '')
            if server: tech['Server'] = server

            if hdrs.get('X-Powered-By'): tech['Backend'] = hdrs['X-Powered-By']
            if 'cloudflare' in server.lower(): tech['CDN/WAF'] = 'Cloudflare'
            if 'akamai' in server.lower():     tech['CDN']     = 'Akamai'

            # Programming language hints
            if '.php' in html:      tech['Language'] = 'PHP'
            elif '.asp' in html:    tech['Language'] = 'ASP.NET'
            elif '.jsp' in html:    tech['Language'] = 'Java'

            self.results['tech'] = {'detected': tech, 'count': len(tech)}
        except Exception as e:
            self.results['tech'] = {'error': str(e)}

    # ══════════════════════════════════════════════════════════════════
    # ANAN'S TOOLS — integrated as WebSecure360 scan modules
    # ══════════════════════════════════════════════════════════════════

    def _probe(self, path: str, timeout: int = 6) -> requests.Response | None:
        """Safe GET probe — returns response or None on any error."""
        try:
            url = f'{self.target.rstrip("/")}{path}'
            r = self.session.get(url, timeout=timeout, verify=False,
                                 allow_redirects=True)
            return r
        except Exception:
            return None

    def _head(self, path: str, timeout: int = 5) -> requests.Response | None:
        try:
            url = f'{self.target.rstrip("/")}{path}'
            r = self.session.head(url, timeout=timeout, verify=False,
                                  allow_redirects=True)
            return r
        except Exception:
            return None

    # ── 1. Admin Panel Finder ─────────────────────────────────────────
    def _admin_finder(self):
        """Checks 60 high-signal admin/login paths for accessible panels."""
        HIGH_SIGNAL = [
            '/admin', '/login', '/dashboard', '/admin/login',
            '/administrator', '/wp-admin', '/wp-login.php',
            '/cpanel', '/phpmyadmin', '/admin.php', '/login.php',
            '/admin/index', '/admin/dashboard', '/admin/login.php',
            '/auth/login', '/auth/signin', '/account/login',
            '/user/login', '/users/login', '/panel', '/control',
            '/manage', '/manager', '/backend', '/cms', '/cms/admin',
            '/portal', '/portal/login', '/secure', '/secure/login',
            '/api/admin', '/api/login', '/superadmin', '/staff',
            '/staff/login', '/dev', '/dev/admin', '/staging/admin',
            '/sso', '/sso/login', '/auth', '/signin', '/sign_in',
            '/signup', '/register', '/access', '/system/login',
            '/controlpanel', '/filemanager', '/pma', '/db/admin',
            '/adminer', '/administration', '/admin_area', '/web/admin',
            '/app/admin', '/site/admin', '/shop/admin', '/support/login',
        ]
        found = []
        auth_keywords = re.compile(
            r'type=["\']password["\']|type=["\']email["\']'
            r'|login|signin|sign.in|dashboard|control.panel'
            r'|admin|administrator|cpanel',
            re.IGNORECASE
        )
        for path in HIGH_SIGNAL:
            r = self._probe(path)
            if r and r.status_code == 200 and auth_keywords.search(r.text[:5000]):
                found.append({'path': path, 'url': r.url, 'status': r.status_code})
        self.results['admin_finder'] = {'found': found, 'count': len(found)}

    # ── 2. Swagger / OpenAPI Exposure ─────────────────────────────────
    def _swagger_finder(self):
        """Detects exposed Swagger UI and OpenAPI spec endpoints."""
        PATHS = [
            '/swagger-ui.html', '/swagger-ui/index.html', '/swagger.json',
            '/swagger.yaml', '/swagger/index.html', '/api-docs',
            '/api-docs/swagger.json', '/api/swagger.json', '/api/docs',
            '/api/v1/docs', '/api/v2/docs', '/api/v3/docs',
            '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
            '/openapi.json', '/docs', '/redoc',
            '/webjars/swagger-ui/index.html',
            '/swagger/v1/swagger.json', '/api/swagger-ui.html',
        ]
        SWAGGER_RE = re.compile(
            r'swagger|Swagger\s*UI|openapi|"paths"\s*:|"info"\s*:|'
            r'swagger-ui-bundle|Swagger\s*2\.0',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and SWAGGER_RE.search(r.text[:8000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['swagger'] = {'found': found, 'count': len(found)}

    # ── 3. SQL Backup Exposure ────────────────────────────────────────
    def _sql_backup(self):
        """Checks for publicly accessible SQL dump/backup files."""
        dn = self.domain.split('.')[0]
        rdn = '.'.join(self.domain.split('.')[-2:]).split('.')[0]
        PATHS = [
            '/backup.sql', '/database.sql', '/dump.sql', '/db.sql',
            '/mysql.sql', '/data.sql', '/site.sql', '/wordpress.sql',
            f'/{dn}.sql', f'/{rdn}.sql',
            f'/{dn}_backup.sql', f'/{rdn}_backup.sql',
            f'/{dn}_db.sql', '/backup/database.sql', '/backup/dump.sql',
            '/wp-content/mysql.sql', '/wp-content/uploads/dump.sql',
            '/2024.sql', '/db_backup.sql', '/sqldump.sql',
            '/database.sqlite', '/db.sqlite', '/db.sqlite3',
        ]
        SQL_RE = re.compile(
            r'DROP TABLE|CREATE TABLE|INSERT INTO|SQLite format',
            re.IGNORECASE
        )
        CONTENT_TYPES = ['application/sql', 'application/x-sql',
                         'application/vnd.sqlite3', 'application/octet-stream']
        found = []
        for path in PATHS:
            r = self._probe(path, timeout=8)
            if r and r.status_code == 200:
                ct = r.headers.get('Content-Type', '').lower()
                text = r.text[:5000]
                if SQL_RE.search(text) or any(c in ct for c in CONTENT_TYPES):
                    found.append({'path': path, 'url': str(r.url),
                                  'content_type': ct})
        self.results['sql_backup'] = {'found': found, 'count': len(found)}

    # ── 4. YAML / Config File Exposure ────────────────────────────────
    def _yaml_config(self):
        """Checks for exposed YAML and configuration files with sensitive data."""
        PATHS = [
            '/docker-compose.yml', '/docker-compose.yaml',
            '/.gitlab-ci.yml', '/.travis.yml', '/.github/workflows/main.yml',
            '/config.yml', '/config.yaml', '/app.yml', '/app.yaml',
            '/application.yml', '/application.yaml',
            '/parameters.yml', '/secrets.yml', '/settings.yml',
            '/config/database.yml', '/config/secrets.yml',
            '/docker-compose.prod.yml', '/docker-compose.production.yml',
            '/azure-pipelines.yml', '/.circleci/config.yml',
            '/bitbucket-pipelines.yml', '/appspec.yml',
            '/config/configuration.yml', '/phinx.yml',
        ]
        YAML_RE = re.compile(
            r'password:|username:|secret_key|database:|MYSQL_PASSWORD'
            r'|MYSQL_ROOT_PASSWORD|api_key|token:|private_key'
            r'|services:|container_name:|version:\s*["\']?\d',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and YAML_RE.search(r.text[:8000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['yaml_config'] = {'found': found, 'count': len(found)}

    # ── 5. JSON Secrets Exposure ──────────────────────────────────────
    def _json_secrets(self):
        """Checks for exposed JSON files containing credentials or API keys."""
        PATHS = [
            '/credentials.json', '/config.json', '/config/config.json',
            '/appsettings.json', '/appsettings.Production.json',
            '/client_secrets.json', '/.docker/config.json',
            '/google-services.json', '/google-api-private-key.json',
            '/service-account-credentials.json', '/auth.json',
            '/token.json', '/oauth-credentials.json',
            '/.well-known/jwks.json', '/jwks.json',
            '/deployment-config.json', '/keycloak.json',
            '/robomongo.json', '/.remote-sync.json',
        ]
        SECRET_RE = re.compile(
            r'client_secret|private_key|access_token|refresh_token'
            r'|api_key|secret_key|password|credentials|auth_token'
            r'|aws_secret|ConnectionStrings',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200:
                ct = r.headers.get('Content-Type', '').lower()
                if ('json' in ct or 'text' in ct) and SECRET_RE.search(r.text[:8000]):
                    found.append({'path': path, 'url': str(r.url)})
        self.results['json_secrets'] = {'found': found, 'count': len(found)}

    # ── 6. Apache Tomcat Detection ────────────────────────────────────
    def _tomcat_check(self):
        """Detects exposed Apache Tomcat manager, examples, and status pages."""
        PATHS = [
            '/manager/html', '/host-manager/html', '/manager/status',
            '/docs/', '/examples/', '/examples/servlets/index.html',
            '/examples/jsp/index.html', '/..;/manager/html',
            '/axis2/axis2-web/HappyAxis.jsp', '/happyaxis.jsp',
            '/web-console/ServerInfo.jsp', '/server-status', '/jkstatus',
        ]
        TOMCAT_RE = re.compile(
            r'Apache\s+Tomcat|Tomcat\s+Manager|tomcat-users\.xml'
            r'|manager-gui|Axis\s+Happiness|Apache\s+Server\s+Status'
            r'|JSP\s+Examples|Servlets\s+Examples|WebSocket\s+Examples'
            r'|JK\s+Status\s+Manager',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code in (200, 401, 403):
                if TOMCAT_RE.search(r.text[:5000]):
                    found.append({
                        'path':   path,
                        'url':    str(r.url),
                        'status': r.status_code,
                        'note':   'Auth required' if r.status_code in (401, 403) else 'Open'
                    })
        self.results['tomcat'] = {'found': found, 'count': len(found)}

    # ── 7. WordPress Vulnerabilities ──────────────────────────────────
    def _wp_vulns(self):
        """Checks for WordPress open registration and exposed installation."""
        findings = []

        # Open registration check
        REG_PATHS = [
            '/wp-login.php?action=register',
            '/wp/wp-login.php?action=register',
            '/blog/wp-login.php?action=register',
        ]
        for path in REG_PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and 'Registration Form' in r.text:
                findings.append({
                    'type': 'Open Registration',
                    'url': str(r.url),
                    'severity': 'MEDIUM',
                    'detail': 'WordPress user registration is publicly open'
                })
                break

        # Exposed install check
        INSTALL_PATHS = [
            '/wp-admin/install.php',
            '/wordpress/wp-admin/install.php',
        ]
        for path in INSTALL_PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and 'WordPress' in r.text:
                findings.append({
                    'type': 'Exposed Install',
                    'url': str(r.url),
                    'severity': 'HIGH',
                    'detail': 'WordPress installation page is publicly accessible'
                })
                break

        # wp-json user enumeration
        r = self._probe('/wp-json/wp/v2/users')
        if r and r.status_code == 200:
            try:
                users = r.json()
                if isinstance(users, list) and len(users) > 0:
                    names = [u.get('name', '') for u in users[:5]]
                    findings.append({
                        'type': 'User Enumeration',
                        'url': str(r.url),
                        'severity': 'MEDIUM',
                        'detail': f'WordPress REST API exposes users: {", ".join(names)}'
                    })
            except Exception:
                pass

        self.results['wp_vulns'] = {'found': findings, 'count': len(findings)}

    # ── 8. JK / Nginx Status Exposure ────────────────────────────────
    def _jk_nginx(self):
        """Detects exposed JK status manager and Nginx/Apache server-status pages."""
        PATHS = [
            '/jkstatus', '/jk-status', '/jkmanager',
            '/server-status', '/status', '/nginx_status',
        ]
        EXTRA_HEADERS = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {},   # no extra header
        ]
        STATUS_RE = re.compile(
            r'JK Status Manager|Apache Server Status|Server Version'
            r'|nginx status|Active connections|requests accepted',
            re.IGNORECASE
        )
        found = []
        seen = set()
        for path in PATHS:
            for extra in EXTRA_HEADERS:
                try:
                    url = f'{self.target.rstrip("/")}{path}'
                    headers = {'User-Agent': 'WebSecure360-Scanner/1.0', **extra}
                    r = self.session.get(url, headers=headers, timeout=6,
                                        verify=False, allow_redirects=True)
                    if r.status_code == 200 and STATUS_RE.search(r.text[:5000]):
                        key = path
                        if key not in seen:
                            seen.add(key)
                            found.append({'path': path, 'url': str(r.url),
                                          'header_bypass': bool(extra)})
                        break
                except Exception:
                    continue
        self.results['jk_nginx'] = {'found': found, 'count': len(found)}

    # ── 9. .ENV File Exposure ─────────────────────────────────────────
    def _env_exposure(self):
        dn = self.domain.split('.')[0]
        rdn = '.'.join(self.domain.split('.')[-2:]).split('.')[0]
        PATHS = [
            '/.env', '/.env.bak', '/.env.dev', '/.env.local', '/.env.prod',
            '/.env.production', '/.env.staging', '/.env.backup', '/.env.old',
            '/.env.example', '/.env.save', '/.env.swp', '/.env.txt',
            f'/{dn}/.env', f'/{rdn}/.env',
            '/api/.env', '/app/.env', '/web/.env', '/public/.env',
            '/backend/.env', '/frontend/.env', '/laravel/.env',
            '/config/.env', '/src/.env', '/www/.env',
        ]
        ENV_RE = re.compile(
            r'APP_KEY=|APP_ENV=|DB_PASSWORD=|DB_HOST=|DB_DATABASE='
            r'|MAIL_PASSWORD=|AWS_SECRET|REDIS_PASSWORD|SG\.[A-Za-z0-9_-]{22}',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and ENV_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url), 'severity': 'CRITICAL'})
        self.results['env_exposure'] = {'found': found, 'count': len(found)}

    # ── 10. Git / SVN / Config Exposure ──────────────────────────────
    def _git_exposure(self):
        PATHS = [
            '/.git/config', '/.git/HEAD', '/.git/logs/HEAD',
            '/.git/', '/.git/description', '/.svn/entries',
            '/.svn/wc.db', '/.git-credentials', '/.gitignore',
            '/Dockerfile', '/.Dockerfile', '/.hg/hgrc',
            '/static../.git/config', '/js../.git/config',
            '/css../.git/config', '/assets../.git/config',
        ]
        GIT_RE = re.compile(
            r'\[core\]|\[remote\]|ref: refs/heads/|repositoryformatversion'
            r'|logallrefupdates|Unnamed repository|credentials|SVN',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and GIT_RE.search(r.text[:3000]):
                found.append({'path': path, 'url': str(r.url), 'severity': 'HIGH'})
        self.results['git_exposure'] = {'found': found, 'count': len(found)}

    # ── 11. Sensitive Config Files ────────────────────────────────────
    def _sensitive_config(self):
        PATHS = [
            '/.aws/credentials', '/.aws/config', '/redis.conf',
            '/prometheus', '/metrics', '/api/metrics',
            '/.mailmap', '/debug/vars', '/config.ru',
            '/.bzr/branch/branch.conf', '/sphinx.conf',
            '/config/development.sphinx.conf', '/.apdisk',
            '/configurations/config_default',
            '/.config/gcloud/configurations/config_default',
            '/debug/default/view', '/files/ldap.debug.txt',
        ]
        SENSITIVE_RE = re.compile(
            r'aws_access_key|aws_secret|BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE'
            r'|password\s*=|secret\s*=|api_key\s*=|token\s*=|redis|prometheus',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and SENSITIVE_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url), 'severity': 'HIGH'})
        self.results['sensitive_config'] = {'found': found, 'count': len(found)}

    # ── 12. JavaScript Secrets ────────────────────────────────────────
    def _js_secrets(self):
        PATHS = [
            '/config.js', '/assets/env.js', '/env.js', '/env.development.js',
            '/env.production.js', '/config/env.js', '/config/runtime-env.js',
            '/public/config.js', '/webpack.config.js', '/vite.config.js',
            '/rollup.config.js', '/babel.config.js', '/Gruntfile.js',
            '/js/salesforce.js', '/salesforce.js',
        ]
        JS_RE = re.compile(
            r'apiKey\s*:|authDomain\s*:|databaseURL\s*:|storageBucket\s*:'
            r'|module\.exports\s*=|secret\s*:|password\s*:|api_key\s*:',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and JS_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['js_secrets'] = {'found': found, 'count': len(found)}

    # ── 13. XML Config Exposure ───────────────────────────────────────
    def _xml_config(self):
        PATHS = [
            '/config.xml', '/.idea/deployment.xml', '/.idea/WebServers.xml',
            '/.idea/dataSources.xml', '/app/etc/local.xml',
            '/backup/config.xml', '/db.xml', '/_notes/dwsync.xml',
            '/filezilla.xml', '/sitemanager.xml', '/FileZilla.xml',
            '/.idea/workspace.xml', '/psalm.xml',
        ]
        XML_RE = re.compile(
            r'<password>|password=|username=|<config>|<dbname>'
            r'|<DBPASS>|<ServerName>|<FileZilla|<Servers>|<dwsync>'
            r'|WebServers|DataSourceManagerImpl',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and XML_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['xml_config'] = {'found': found, 'count': len(found)}

    # ── 14. GraphQL Introspection ─────────────────────────────────────
    def _graphql(self):
        PATHS = [
            '/graphql', '/graphiql', '/api/graphql', '/graphql/v1',
            '/v1/graphql', '/v2/graphql', '/playground', '/explorer',
            '/graphql-playground', '/altair', '/graph', '/gql',
            '/graphql/schema.json', '/api/v1/graphql', '/laravel-graphql-playground',
        ]
        GRAPHQL_RE = re.compile(
            r'GraphQL|graphiql|__schema|"data"\s*:|introspection'
            r'|graphql-playground|"types"\s*:\s*\[',
            re.IGNORECASE
        )
        # Also try POST introspection query
        INTROSPECTION = '{"query":"{__schema{types{name}}}"}'
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and GRAPHQL_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url), 'method': 'GET'})
                continue
            try:
                url = f'{self.target.rstrip("/")}{path}'
                r2 = self.session.post(url, data=INTROSPECTION,
                                       headers={'Content-Type': 'application/json'},
                                       timeout=6, verify=False)
                if r2.status_code == 200 and '__schema' in r2.text:
                    found.append({'path': path, 'url': url, 'method': 'POST',
                                  'note': 'Introspection enabled'})
            except Exception:
                pass
        self.results['graphql'] = {'found': found, 'count': len(found)}

    # ── 15. Directory Listing ─────────────────────────────────────────
    def _dir_listing(self):
        PATHS = [
            '/storage/', '/uploads/', '/upload/', '/backup/', '/backups/',
            '/files/', '/file/', '/images/', '/img/', '/assets/', '/logs/',
            '/log/', '/config/', '/configs/', '/.ssh/', '/temp/', '/tmp/',
            '/dev/', '/test/', '/data/', '/export/', '/reports/',
        ]
        DIR_RE = re.compile(
            r'Index of /|Directory listing|Parent Directory'
            r'|\[To Parent Directory\]|<title>Index of',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and DIR_RE.search(r.text[:3000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['dir_listing'] = {'found': found, 'count': len(found)}

    # ── 16. Log File Exposure ─────────────────────────────────────────
    def _log_exposure(self):
        PATHS = [
            '/npm-debug.log', '/yarn-error.log', '/storage/logs/laravel.log',
            '/logs/errors.log', '/logs/error.log', '/logs/access.log',
            '/error.log', '/debug.log', '/.idea/httpRequests/http-requests-log.http',
            '/roundcube/logs/errors.log', '/webmail/logs/errors.log',
            '/ws_ftp.log', '/_debug_toolbar/', '/__clockwork/app',
            '/npm-debug.log', '/assets/npm-debug.log',
        ]
        LOG_RE = re.compile(
            r'ERROR|Exception|Warning|Fatal|Traceback|Stack trace'
            r'|local\.ERROR|InvalidArgumentException|password|secret|token',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and LOG_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['log_exposure'] = {'found': found, 'count': len(found)}

    # ── 17. FTP Config Exposure ───────────────────────────────────────
    def _ftp_config(self):
        PATHS = [
            '/.ftpconfig', '/ftpsync.settings', '/ws_ftp.ini',
            '/filezilla.xml', '/sitemanager.xml', '/FileZilla.xml',
            '/wpeprivate/config.json', '/sftp-config.json',
            '/sftp.json', '/.config/sftp.json', '/.vscode/sftp.json',
        ]
        FTP_RE = re.compile(
            r'"protocol":|"host":|"user":|"passphrase":|FTPSync'
            r'|<FileZilla|<Servers>|WPENGINE|"password":|"remote_path":',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and FTP_RE.search(r.text[:3000]):
                found.append({'path': path, 'url': str(r.url), 'severity': 'HIGH'})
        self.results['ftp_config'] = {'found': found, 'count': len(found)}

    # ── 18. SSH Keys / Private Keys ───────────────────────────────────
    def _ssh_keys(self):
        PATHS = [
            '/.ssh/id_rsa', '/.ssh/id_dsa', '/.ssh/id_ecdsa',
            '/.ssh/id_ed25519', '/.ssh/authorized_keys', '/.ssh/known_hosts',
            '/id_rsa', '/id_dsa', '/private.key', '/server.key',
            '/key.pem', '/.circleci/ssh-config', '/my.ppk', '/putty.ppk',
            '/deployment.ini', '/deploy.ini', '/production.ini',
            '/localhost.key', '/host.key', '/www.key', '/private-key',
        ]
        KEY_RE = re.compile(
            r'BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY'
            r'|ssh-rsa |ssh-dss |ssh-ed25519 |ecdsa-sha2'
            r'|PuTTY-User-Key-File',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and KEY_RE.search(r.text[:3000]):
                found.append({'path': path, 'url': str(r.url), 'severity': 'CRITICAL'})
        self.results['ssh_keys'] = {'found': found, 'count': len(found)}

    # ── 19. Backup File Exposure ──────────────────────────────────────
    def _backup_files(self):
        dn = self.domain.split('.')[0]
        PATHS = [
            f'/{dn}.zip', f'/{dn}.tar.gz', f'/{dn}.tar', f'/{dn}.rar',
            f'/{dn}.7z', f'/{dn}.bak', f'/{dn}.backup',
            '/backup.zip', '/backup.tar.gz', '/site.zip', '/website.zip',
            '/www.zip', '/html.zip', '/web.zip', '/public.zip',
            '/backup/', '/backups/', '/backup.tar', '/full-backup.zip',
            '/wp-content/uploads/backup.zip',
        ]
        BACKUP_CT = ['application/zip', 'application/x-tar', 'application/gzip',
                     'application/x-rar', 'application/octet-stream']
        found = []
        for path in PATHS:
            r = self._head(path)
            if r and r.status_code == 200:
                ct = r.headers.get('Content-Type', '').lower()
                if any(b in ct for b in BACKUP_CT):
                    found.append({'path': path, 'url': f'{self.target}{path}',
                                  'content_type': ct, 'severity': 'HIGH'})
        self.results['backup_files'] = {'found': found, 'count': len(found)}

    # ── 20. PHP Backup / Config Files ────────────────────────────────
    def _php_backup(self):
        BASE_PATHS = [
            '/wp-config.php', '/includes/config.php', '/config/config.php',
            '/db.php', '/conn.php', '/database.php', '/db_config.php',
            '/config.inc.php', '/data/config.php',
        ]
        EXTENSIONS = ['.bak', '.old', '.orig', '.txt', '.swp', '~', '.save', '_bak']
        PHP_RE = re.compile(
            r'DB_PASSWORD|DB_HOST|DB_USER|database_type|define\(\'DB'
            r'|\$dbpass|\$dbhost|\$dbname|mysql_connect',
            re.IGNORECASE
        )
        found = []
        for base in BASE_PATHS:
            for ext in EXTENSIONS:
                path = base + ext
                r = self._probe(path)
                if r and r.status_code == 200 and PHP_RE.search(r.text[:3000]):
                    found.append({'path': path, 'url': str(r.url), 'severity': 'CRITICAL'})
        self.results['php_backup'] = {'found': found, 'count': len(found)}

    # ── 21. PHP Info / Admin Pages ────────────────────────────────────
    def _php_info(self):
        PATHS = [
            '/phpinfo.php', '/info.php', '/php.php', '/php_info.php',
            '/test.php', '/i.php', '/phpversion.php', '/infos.php',
            '/php-info.php', '/?phpinfo=1', '/_profiler/phpinfo',
            '/adminer.php', '/_adminer.php', '/adminer/', '/editor.php',
            '/mysql.php', '/sql.php', '/phpmyadmin/', '/pma/',
        ]
        PHP_RE = re.compile(
            r'phpinfo\(\)|PHP Version|PHP Extension|phpMyAdmin'
            r'|Adminer|<title>phpinfo|PHP_SELF',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and PHP_RE.search(r.text[:3000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['php_info'] = {'found': found, 'count': len(found)}

    # ── 22. File Manager Exposure ─────────────────────────────────────
    def _file_manager(self):
        PATHS = [
            '/filemanager/', '/file-manager/', '/lfm/', '/fm/', '/elfinder/',
            '/laravel-filemanager/', '/filemanager/dialog.php',
            '/tiny_mce/plugins/ajaxfilemanager/ajaxfilemanager.php',
            '/FCKeditor/editor/filemanager/connectors/php/connector.php',
            '/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php',
            '/assets/vendor/laravel-filemanager/index.html',
        ]
        FM_RE = re.compile(
            r'File Manager|elfinder|filemanager|ajaxfilemanager'
            r'|FCKeditor|Upload File|Browse Server',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and FM_RE.search(r.text[:3000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['file_manager'] = {'found': found, 'count': len(found)}

    # ── 23. Laravel Vulnerabilities ───────────────────────────────────
    def _laravel_vulns(self):
        findings = []

        # Debugbar
        for path in ['/_debugbar/open?max=20&offset=0', '/_debugbar/open']:
            r = self._probe(path)
            if r and r.status_code == 200 and 'application/json' in r.headers.get('Content-Type', ''):
                findings.append({'type': 'Debugbar Open', 'url': str(r.url), 'severity': 'HIGH'})
                break

        # Horizon
        for path in ['/horizon/api/stats', '/api/stats']:
            r = self._probe(path)
            if r and r.status_code == 200 and 'application/json' in r.headers.get('Content-Type', ''):
                try:
                    data = r.json()
                    if 'status' in data or 'jobs' in data:
                        findings.append({'type': 'Horizon API', 'url': str(r.url), 'severity': 'MEDIUM'})
                        break
                except Exception:
                    pass

        # Telescope
        r = self._probe('/telescope/requests')
        if r and r.status_code == 200 and 'Telescope' in r.text:
            findings.append({'type': 'Telescope Exposed', 'url': str(r.url), 'severity': 'HIGH'})

        # Ignition
        r = self._probe('/_ignition/health-check')
        if r and r.status_code == 200 and 'can_execute_commands' in r.text:
            findings.append({'type': 'Ignition Health Check', 'url': str(r.url), 'severity': 'HIGH'})

        # Laravel log
        r = self._probe('/storage/logs/laravel.log')
        if r and r.status_code == 200 and re.search(r'local\.ERROR|ErrorException|InvalidArgumentException', r.text):
            findings.append({'type': 'Laravel Log Exposed', 'url': str(r.url), 'severity': 'MEDIUM'})

        # Symfony profiler
        for path in ['/_profiler/empty/search/results?limit=10', '/_profiler/phpinfo']:
            r = self._probe(path)
            if r and r.status_code == 200 and re.search(r'Symfony Profiler|PHP Version|PHP Extension', r.text):
                findings.append({'type': 'Symfony Profiler', 'url': str(r.url), 'severity': 'MEDIUM'})
                break

        # PHPUnit eval-stdin
        for path in ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                     '/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php',
                     '/phpunit/phpunit/src/Util/PHP/eval-stdin.php']:
            r = self._probe(path)
            if r and r.status_code in (200, 500):
                findings.append({'type': 'PHPUnit eval-stdin', 'url': str(r.url), 'severity': 'CRITICAL'})
                break

        self.results['laravel_vulns'] = {'found': findings, 'count': len(findings)}

    # ── 24. Django Debug Mode ─────────────────────────────────────────
    def _django_debug(self):
        findings = []

        # Trigger debug page with non-existent path
        r = self._probe('/NON_EXISTING_PATH_WS360/')
        if r and r.status_code == 404:
            if re.search(r'DEBUG\s*=\s*True|URLconf defined|Django tried these URL patterns', r.text):
                findings.append({'type': 'Django Debug Mode ON', 'url': str(r.url),
                                 'severity': 'HIGH', 'detail': 'Django debug page exposed'})

        # Admin login
        r = self._probe('/admin/login/?next=/admin/')
        if r and r.status_code == 200 and re.search(r'Django administration', r.text):
            findings.append({'type': 'Django Admin', 'url': str(r.url),
                             'severity': 'INFO', 'detail': 'Django admin panel accessible'})

        # Exposed settings
        for path in ['/manage.py', '/settings.py', '/app/settings.py']:
            r = self._probe(path)
            if r and r.status_code == 200 and re.search(r'SECRET_KEY|DATABASES|DEBUG', r.text):
                findings.append({'type': 'Django Settings Exposed', 'url': str(r.url), 'severity': 'CRITICAL'})
                break

        self.results['django_debug'] = {'found': findings, 'count': len(findings)}

    # ── 25. Spring Boot Actuator ──────────────────────────────────────
    def _spring_boot(self):
        PATHS = [
            '/actuator', '/actuator/env', '/actuator/metrics',
            '/actuator/dump', '/actuator/heapdump', '/actuator/trace',
            '/actuator/mappings', '/actuator/beans', '/actuator/info',
            '/actuator/health', '/actuator/logfile', '/actuator/configprops',
            '/env', '/metrics', '/dump', '/health', '/info', '/trace',
            '/actuator/jolokia/list', '/jolokia/list',
        ]
        SPRING_RE = re.compile(
            r'"contexts":|"beans":|"mappings":|"activeProfiles"'
            r'|"systemProperties":|jolokia|"status":\s*"UP"'
            r'|spring\.datasource|"hikaricp\.',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and SPRING_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url),
                              'note': 'Spring Boot Actuator endpoint exposed'})
        self.results['spring_boot'] = {'found': found, 'count': len(found)}

    # ── 26. Ruby / Rails Config ───────────────────────────────────────
    def _ruby_config(self):
        PATHS = [
            '/db/schema.rb', '/schema.rb', '/config/initializers/secret_token.rb',
            '/secret_token.rb', '/.chef/config.rb', '/config.rb',
            '/config/environment.rb', '/environment.rb',
            '/credentials.db', '/.config/gcloud/credentials.db',
            '/access_tokens.db', '/.config/gcloud/access_tokens.db',
            '/collibra.properties', '/config.properties',
            '/nbproject/project.properties',
        ]
        RUBY_RE = re.compile(
            r'ActiveRecord::Schema|secret_key_base|mysql_password|mysql_username'
            r'|:ip\s|:port\s|:hostname\s|jdbc:|password=|secretkey=|collibra\.password',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and RUBY_RE.search(r.text[:5000]):
                found.append({'path': path, 'url': str(r.url)})
        self.results['ruby_config'] = {'found': found, 'count': len(found)}

    # ── 27. Jenkins Exposure ──────────────────────────────────────────
    def _jenkins(self):
        PATHS = [
            '/', '/jenkins/', '/script/', '/jenkins/script',
            '/api/xml', '/adjuncts/3a890183/',
        ]
        JENKINS_RE = re.compile(
            r'Dashboard \[Jenkins\]|Script Console|hudson\.model\.Hudson'
            r'|println\(Jenkins\.instance|java\.lang\.StringIndexOutOfBoundsException',
            re.IGNORECASE
        )
        findings = []

        # Check for open Jenkins
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and JENKINS_RE.search(r.text[:5000]):
                findings.append({'type': 'Jenkins Exposed', 'url': str(r.url),
                                 'path': path, 'severity': 'HIGH'})
                break

        # Check open signup
        r = self._probe('/signup')
        if r and r.status_code == 200 and 'Create an account' in r.text and 'Jenkins' in r.text:
            findings.append({'type': 'Jenkins Open Registration', 'url': str(r.url),
                             'severity': 'MEDIUM'})

        self.results['jenkins'] = {'found': findings, 'count': len(findings)}

    # ── 28. IIS / Telerik Vulnerability ──────────────────────────────
    def _iis_telerik(self):
        PATHS = [
            '/Telerik.Web.UI.WebResource.axd?type=rau',
            '/Telerik.Web.UI.DialogHandler.aspx',
            '/Telerik.RadEditor.WebResource.axd?type=rau',
            '/Telerik.RadEditor.DialogHandler.aspx',
            '/DesktopModules/Admin/RadEditorProvider/WebResource.axd?type=rau',
            '/Providers/HtmlEditorProviders/Telerik/Telerik.Web.UI.WebResource.axd?type=rau',
            '/Login.aspx',
        ]
        TELERIK_RE = re.compile(
            r'Telerik|RadEditor|Rad Upload|This handler is not accessible directly',
            re.IGNORECASE
        )
        found = []
        for path in PATHS:
            r = self._probe(path)
            if r and r.status_code in (200, 500) and TELERIK_RE.search(r.text[:3000]):
                found.append({'path': path, 'url': str(r.url),
                              'note': 'IIS/Telerik endpoint detected'})
        self.results['iis_telerik'] = {'found': found, 'count': len(found)}

    # ── 29. WordPress Setup / Install Exposure ────────────────────────
    def _wp_setup(self):
        findings = []
        SETUP_PATHS = [
            '/wp-admin/setup-config.php?step=1&language=EN',
            '/wordpress/wp-admin/setup-config.php?step=1&language=EN',
            '/blog/wp-admin/setup-config.php?step=1&language=EN',
        ]
        INSTALL_PATHS = [
            '/wp-admin/install.php?step=1&language=EN',
            '/wordpress/wp-admin/install.php?step=1&language=EN',
        ]

        for path in SETUP_PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and 'Setup Configuration File' in r.text:
                findings.append({'type': 'WP Setup Exposed', 'url': str(r.url), 'severity': 'CRITICAL'})
                break

        for path in INSTALL_PATHS:
            r = self._probe(path)
            if r and r.status_code == 200 and 'WordPress' in r.text and 'Already Installed' not in r.text:
                findings.append({'type': 'WP Install Exposed', 'url': str(r.url), 'severity': 'CRITICAL'})
                break

        self.results['wp_setup'] = {'found': findings, 'count': len(findings)}
