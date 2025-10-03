`# Juice Shop - Security Assessment Report`

`**Author:** Martín Vallejo Torres`    
`**Date:** 2025-10-02`    
`**Context / Source:** OWASP Juice Shop lab (TryHackMe). Assessment performed via **static/manual analysis** of project files and artifacts provided by the lab. No active exploitation was performed against external systems.`

`---`

`## Executive Summary`  
`An assessment of the OWASP Juice Shop lab was performed through manual/static analysis of the project files and artifacts. The review identified several security issues of varying severity, including an SQL Injection vector in the products search endpoint, an authentication brute-force risk on the login endpoint, exposed FTP anonymous download of backup files, and evidence of credential disclosure. These findings could enable unauthorized access, data exfiltration, and potential server compromise if present in a production system. Immediate remediation steps are recommended to reduce risk and protect sensitive data.`

`---`

`## Scope & Methodology`  
`**Scope:** OWASP Juice Shop application (lab environment). The review focused on source/config artifacts and provided logs/artifacts within the lab files.`    
`**Methodology:** Static/manual file review (code and config inspection, artifact analysis). No active network attacks or execution against real production systems were performed. The assessment identifies insecure patterns, exposed artifacts, and misconfigurations found in the provided files.`

`Tools *suggested* for expanded/active testing (not used here): Nmap, Burp Suite, sqlmap, Nessus, Wireshark, Hydra.`

`---`

`## Summary of Findings (High-level)`  
`| # | Finding | Affected Endpoint / File | Severity (approx.) | CVSS v3 (approx.) |`  
`|---:|---|---|---:|---:|`  
``| 1 | SQL Injection - unsanitized search parameter | `GET /rest/products/search` (param `q`) | Critical | 9.1 |``  
``| 2 | Authentication: Brute-forceable login endpoint | `POST /rest/user/login` | High | 7.5 |``  
``| 3 | Anonymous FTP access and exposed backup files | `/ftp` → `coupons_2013.md.bak`, `www-data.bak` | High | 7.0 |``  
`| 4 | Credentials / sensitive data disclosure (emails/passwords in artifacts) | Artifacts / logs | Critical | 9.0 |`  
``| 5 | Evidence of SSH access using `www-data` account | Logs/artifacts | High | 8.0 |``

`> Notes: CVSS scores above are **approximate** and intended to provide triage guidance.`

`---`

`## Detailed Findings, Evidence & Remediation`

`### Finding 1 — SQL Injection in products search`  
`` - **Affected endpoint:** `GET /rest/products/search` ``    
``- **Parameter:** `q` (search query)``    
`- **Methodology:** Static analysis of request/response artifacts and file contents revealed input that is insufficiently sanitized and poses SQL Injection risk.`  
``- **Evidence:** lab artifacts list `Parameter that was used to SQL Injection: "q"`. (See `reports/Juice Shop logs`).``    
`- **Impact:** Critical — allows an attacker to read or modify database contents, potentially exposing user data and credentials. Could lead to full DB compromise and data exfiltration.`  
`- **Approx. CVSS:** 9.1 (High/Critical)`  
`- **Remediation:**`    
  `1. Use parameterized queries / prepared statements for all database access.`    
  `2. Apply server-side input validation and output encoding.`    
  `3. Employ least-privilege database accounts (no admin rights for app user).`    
  `4. Add web application firewall (WAF) rules for SQLi patterns and monitoring for anomaly detection.`    
  `5. Add automated SAST and DAST testing to CI/CD (e.g., SonarQube, OWASP ZAP, Burp, sqlmap during testing).`

`---`

`### Finding 2 — Authentication: Brute-forceable login endpoint`  
`` - **Affected endpoint:** `POST /rest/user/login` ``    
``- **Methodology:** Artifact review indicates repeated login attempts and a timestamped successful login (example: `11/Apr/2021:09:16:31 +0000`) and presence of attacker tools in notes.``    
``- **Evidence:** `Vulnerable endpoint to Brute-Force: /rest/user/login`. Timestamp of successful login in artifacts.``    
`- **Impact:** High — brute-force attacks can allow account takeover, exposing personal data and potentially enabling privilege escalation.`    
`- **Approx. CVSS:** 7.5`  
`- **Remediation:**`    
  `1. Implement rate-limiting and account lockout policies after several failed attempts.`    
  `2. Add multi-factor authentication (MFA) for sensitive accounts.`    
  `3. Implement progressive delays and CAPTCHAs for repeated failed attempts.`    
  `4. Enforce strong password policies and monitoring of authentication logs for anomalous patterns.`    
  `5. Use adaptive authentication for high-risk flows.`

`---`

`### Finding 3 — Anonymous FTP & exposed backup files`  
``- **Affected artifact / endpoint:** `/ftp` (anonymous FTP access) with files `coupons_2013.md.bak` and `www-data.bak` observed.``    
`- **Methodology:** Artifacts list exposed files available via FTP and an anonymous account.`  
``- **Evidence:** `File that try to download: coupons_2013.md.bak, www-data.bak` and `Service and Account: ftp anonymous`.``    
`- **Impact:** High — backup files often contain sensitive data or credentials; anonymous FTP increases the attack surface and enables exfiltration.`    
`- **Approx. CVSS:** 7.0`  
`- **Remediation:**`    
  `1. Disable anonymous FTP and remove public access to backup files.`    
  `2. Remove sensitive backups from publicly accessible directories and ensure backups are encrypted at rest.`    
  `3. Serve files over secure protocols (SFTP, HTTPS) with authentication.`    
  `4. Review retention policies and ensure backups are not stored in webroot.`    
  `5. Monitor and alert on unusual FTP activity.`

`---`

`### Finding 4 — Sensitive data (emails/passwords) present in artifacts`  
`- **Affected artifacts:** logs and provided artifacts contained user emails and passwords.`    
`- **Methodology:** Static review of artifacts detected exposed credentials and user data.`    
``- **Evidence:** `Information that attacker was able to retrieve: email, password` (from uploaded lab artifacts).``    
`- **Impact:** Critical — immediate risk of credential stuffing, account takeover, and downstream breaches if credentials are reused.`    
`- **Approx. CVSS:** 9.0`  
`- **Remediation:**`    
  `1. Ensure no plaintext credentials are stored in logs, code, or backups.`    
  `2. Use secret management (environment variables, Vault, AWS Secrets Manager).`    
  `3. Enforce password hashing (bcrypt/argon2) with salts; never store plaintext passwords.`    
  `4. Rotate exposed credentials (in lab only—if this was real, rotate immediately).`    
  `5. Remove credentials from history (git history) and sanitized artifacts prior to publishing.`

`---`

``### Finding 5 — Evidence of SSH access using `www-data` account``  
``- **Affected service/account:** `ssh` with `www-data` user indicated in artifacts.``    
`- **Methodology:** Artifact review identified service and account potentially used to gain shell access.`    
``- **Evidence:** `Service and username that were used to gain shell access to server: ssh / www-data`.``    
`- **Impact:** High — shell access via application account can enable lateral movement and privilege escalation.`    
`- **Approx. CVSS:** 8.0`  
`- **Remediation:**`    
  ``1. Disable SSH access for service accounts (like `www-data`) and ensure proper account separation.``    
  `2. Use key-based authentication for SSH and disable password-based login.`    
  `3. Apply sudo restrictions and remove unnecessary privileges from service accounts.`    
  ``4. Harden SSH configuration (`PermitRootLogin no`, `AllowUsers` whitelist) and monitor `/var/log/auth.log` for anomalies.``

`---`

`## Recommendations (Prioritized)`  
`1. **Fix SQL Injection and credential leakage immediately** — these are the most severe. Use prepared statements and stop storing plaintext secrets.`    
`2. **Disable anonymous FTP & remove exposed backups** — remove public backups and encrypt stored backups.`    
`3. **Harden authentication** — add rate-limiting, lockout, and MFA.`    
``4. **Harden server/service accounts** — remove SSH from `www-data`, enforce least privilege.``    
`5. **Integrate security into CI/CD** — SAST, DAST, dependency scanning (SCA), and automated regression checks.`    
`6. **Monitoring & Logging** — centralize logs in SIEM and set alerts for suspicious auth and file-access patterns.`    
`7. **Awareness & Secrets Management** — introduce secret management and developer training on secure coding and storage.`

`---`

`## Suggested Next Steps (for a deeper test)`  
`- Perform active dynamic testing using Burp Suite and sqlmap in an isolated environment.`    
`- Run authenticated DAST scans and schedule regular Nessus scans.`    
`- Execute a controlled penetration test focusing on privilege escalation and post-exploitation.`    
`- Perform a git history review to ensure secrets were not committed historically (BFG repository cleaner).`

`---`

`## Appendix`   
`- **Disclaimer:** This report is based on manual/static analysis of lab-provided artifacts. No active attacks were performed outside the lab environment. Findings should be validated in a controlled test environment before applying to production.`

`---`

`**Prepared by:** Martín Vallejo Torres`

