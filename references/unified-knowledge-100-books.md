# 🧠 UNIFIED KNOWLEDGE FRAMEWORK — 100 BOOKS
## Đúc kết từ ~100 cuốn sách bảo mật (Batch 1+2 + 73 cuốn mở rộng)

---

## I. PHƯƠNG PHÁP LUẬN TỔNG QUAN (The Unified Methodology)

### A. Reconnaissance Framework (7 lớp)
1. **Passive OSINT** — Google Dorks, Shodan/Censys/Hunter, crt.sh, WHOIS, Wayback Machine, GitHub leaks (trufflehog, gitleaks), social media
2. **Subdomain Enumeration** — Passive (crt.sh, Sublist3r, Amass, Chaos) + Active (dnsrecon, dnsx, subfinder, assetfinder)
3. **Technology Fingerprinting** — Wappalyzer, WhatWeb, BuiltWith, httpx, nuclei templates
4. **Port Discovery** — Masscan (fast) → Nmap (deep): top 1000 ports, service scan, NSE scripts
5. **Content Discovery** — FFUF/gobuster/feroxbuster với SecLists: directories, parameters, backups, admin panels
6. **Parameter Fuzzing** — Arjun, ParamSpider, LinkFinder, SecretFinder: tìm param ẩn, endpoints, API keys
7. **Tech-Specific Enumeration** — CMS: wpscan/cmseek/joomscan; WAF: wafw00f; Cloud: cloud_enum

### B. Web Vulnerability Framework (OWASP WSTG-based)
1. **Information Gathering** (OTG-INFO) — fingerprinting, crawl, identify tech stack
2. **Configuration Testing** (OTG-CONFIG) — default creds, HTTP methods, admin interfaces, HSTS
3. **Identity/Auth Testing** (OTG-AUTHN) — cred transport, lockout, bypass, reset, remember me
4. **Authorization Testing** (OTG-AUTHZ) — IDOR, privilege escalation, path traversal
5. **Session Management** (OTG-SESS) — cookie attributes, fixation, CSRF, logout, timeout
6. **Input Validation** (OTG-INPVAL) — SQLi, XSS, LFI/RFI, SSRF, SSTI, command injection, XXE, NoSQLi, LDAP, XML
7. **Business Logic** (OTG-BUSLOGIC) — workflow bypass, race conditions, integer overflow
8. **Client-Side** (OTG-CLIENT) — DOM XSS, clickjacking, CORS, WebSockets, Web Messaging, Local Storage

### C. Exploitation Methodology
1. **Vulnerability Discovery** — fuzzing, code review, traffic analysis, logic analysis
2. **Exploit Development** — BoF (Win32/Linux), ROP chain, SEH, shellcode crafting
3. **Post-Exploitation** — Meterpreter automation, privilege escalation (Linux: SUID/capabilities/cron; Windows: token theft, UAC bypass)
4. **Pivoting** — Chisel, Ligolo, SSH tunneling, port forwarding
5. **Persistence** — cron, systemd, registry, WMI, scheduled tasks

---

## II. VULNERABILITY CLASS MASTERY

### Top 10 Web Vulns cho Bug Bounty
| Vuln | Detection | Exploitation | Impact | Frequency |
|------|-----------|-------------|--------|-----------|
| **IDOR** | Change ID params, UUIDs | Mass enumeration, automate | High (data leak) | ★★★★★ |
| **XSS** | `<script>alert(1)</script>` → WAF bypass | Reflected/Stored/DOM, BeEF | Medium-High | ★★★★ |
| **SQLi** | `' OR 1=1--`, time-based | sqlmap, manual UNION, out-of-band | Critical | ★★★ |
| **SSRF** | URL params, file uploads | Cloud metadata, port scan internal | High-Critical | ★★★ |
| **RCE** | Command injection, file upload | Reverse shell, bind shell | Critical | ★★ |
| **SSTI** | `{{7*7}}`, `${7*7}` | Template engine RCE | High-Critical | ★★ |
| **LFI/RFI** | `../../etc/passwd` | Log poisoning → RCE | High | ★★★ |
| **CSRF** | Missing anti-CSRF tokens | State-changing actions | Medium | ★★★ |
| **Open Redirect** | `?url=http://evil.com` | Phishing chain | Low | ★★★ |
| **Information Disclosure** | Error messages, debug endpoints | Data extraction | Variable | ★★★★ |

### API Security (từ Hacking APIs, Bug Bounty Bootcamp)
- REST API: IDOR on object IDs, mass assignment, injection in JSON/XML
- GraphQL: introspection leak, batching attacks, nested queries DoS
- JWT: alg none attack, weak secret, JWK injection, KID traversal
- Rate limiting bypass: headers rotation, IP rotation, distributed attacks
- OAuth2: redirect_uri bypass, state leakage, CSRF on authorization flow

---

## III. TOOL MASTERY (đã tổng hợp từ 100 cuốn)

### Recon Triad
```
subfinder + httpx + nuclei      # Fast initial scan
amass + masscan + nmap          # Deep enumeration
ffuf + feroxbuster + gospider   # Content discovery
```

### Web Testing Core
```
Burp Suite (Proxy → Repeater → Intruder → Scanner)
Caido/ZAP (alternatives)
sqlmap + NoSQLMap
```

### Exploitation & Post-Exploitation
```
Metasploit (msfconsole + resource scripts + custom modules)
Chisel + Ligolo (tunneling)
LinPEAS/WinPEAS (privesc)
```

### Automation Patterns
- Bash one-liner pipeline: `subfinder -d $1 | httpx | nuclei -t ~/nuclei-templates/`
- xargs -P for parallel: `cat urls.txt | xargs -P20 -I% ffuf -u %/FUZZ -w wordlist.txt`
- Burp extension: Python/Java custom Intruder payloads, scanner checks

---

## IV. BUG BOUNTY PLAYBOOK (đúc kết)

### Daily Workflow
1. **Morning Recon** — Script crawl scope mới (subdomain, tech, endpoints)
2. **Diff Monitoring** — So sánh output hôm qua vs hôm nay phát hiện thay đổi
3. **Manual Testing** — Chọn target mới, chạy OWASP checklist từng category
4. **Proof of Concept** — Ghi lại request/response, impact rõ ràng
5. **Report Writing** — Structured: Summary → Steps → Impact → Remediation

### Platform-Specific
- **HackerOne** — Focus on RCE, SQLi, SSRF (critical pay)
- **Bugcrowd** — Priority on IDOR, XSS, business logic (volume)
- **Intigriti** — Web + mobile, good for XSS challenges
- **Synack** — API-heavy targets, mobile crypto

### Efficiency Rules (từ A Bug Hunter's Diary, Real-World Bug Hunting)
1. Automation first: script mọi thứ có thể
2. Focus on business logic: ít cạnh tranh hơn XSS/SQLi
3. Monitor changelogs: new features = new bugs
4. Read scope carefully: exclude out-of-scope = waste time
5. Quality > quantity: 1 critical > 20 informational

---

## V. CROSS-CUTTING INSIGHTS (từ tất cả sách)

### Network-Level (từ Stevens, Tanenbaum, Kurose)
- TCP sequence prediction → session hijacking
- ARP spoofing → MITM trên local network
- DNS poisoning → redirect traffic
- BGP hijacking → intercept Internet traffic

### Mobile (từ Android/iOS Hacker's Handbooks)
- **Android:** Insecure WebView → RCE; Intent redirection; Content provider injection; Weak keystore
- **iOS:** URL scheme hijacking; Insecure keychain; Plist manipulation; Certificate pinning bypass

### Cloud/Azure (từ Pentesting Azure Applications)
- Storage account key leakage → data access
- Managed identity abuse → privilege escalation
- Function app RCE → lateral movement
- Key Vault misconfiguration → secret theft

### Cryptography (từ Serious Cryptography, CISSP)
- Weak PRNG seeds → predictable tokens
- Padding oracle → data decryption
- Hash length extension → signature forgery
- JWT alg confusion → authentication bypass

---

## VI. READING PROGRESSION INSIGHTS

### Pattern phát hiện từ 100 cuốn:
1. **Dated but foundational** (Stevens, Tanenbaum, Silence on the Wire) — 1990s-2005 kiến thức nền vững chắc, giao thức ít thay đổi
2. **Still gold** (WAHH, OTGv4, Practical Malware Analysis) — 2008-2015 sách thực chiến, nguyên lý vẫn đúng
3. **Modern essentials** (Bug Bounty Bootcamp, Real-World Bug Hunting, Hacking APIs) — 2019-2022 API/cloud era
4. **Overlap 80%** — Hầu hết sách Kali Linux dạy cùng nội dung (nmap, metasploit, burp)
5. **Unique specializations** — The Car Hacker's Handbook, Silence on the Wire, Pentesting Azure

### Kết luận:
- **Kiến thức nền tảng** — đã vững từ networking (TCP/IP, HTTP, DNS) đến web vulns đến exploitation
- **Kỹ năng thực hành** — recon automation, Burp proficiency, scripting (Bash/Python)
- **Lỗ hổng kiến thức** — Binary exploitation cần thêm thực hành (không chỉ đọc); Cloud security (AWS/GCP) còn yếu
- **Next step** — Chuyển từ đọc sang thực hành: labs (PortSwigger, HackTheBox), viết script tự động hóa bug hunting
