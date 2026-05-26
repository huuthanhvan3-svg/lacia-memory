# 🧠 Lacia Extended Memory

**Knowledge base, patterns, decisions, and evolution engine for Lacia AGI Bootstrap Protocol V6.**

## 📚 Knowledge Mastery

| File | Size | Covers |
|------|------|--------|
| `references/unified-knowledge-100-books.md` | 8KB | Foundation framework: Recon 7-layer, OWASP WSTG, tool stack |
| `references/mobile-pentest-mastery.md` | 125KB | Android + iOS pentest: Frida, Objection, APKTool, SSL bypass |
| `references/aws-pentest-mastery.md` | 104KB | AWS Cloud: IAM, S3, EC2, Lambda, KMS, SSRF→IMDS, Pacu |
| `references/ad-pentest-mastery.md` | 117KB | Active Directory: Kerberos, NTLM, AD CS ESC1-10, BloodHound |
| `references/container-k8s-security-mastery.md` | 139KB | Docker+K8s: escape, kubelet API, RBAC, supply chain |
| `references/redteam-mastery.md` | 138KB | C2/EDR: Sliver, CobaltStrike, AMSI bypass, direct syscalls |
| `references/wireless-iot-mastery.md` | 124KB | WiFi, BLE, RFID, SDR, UART, JTAG, hardware hacking |

**Total: ~750KB condensed security knowledge across all domains.**

## 🗄️ SQLite Database

- `lacia_memory.db` — decisions, patterns, predictions, edges
- Managed via `lacia-mem` CLI
- Commands: dec, pattern, pred, edge, outcome, qdec, qpat, calib, nightly

## 🤖 Evolution Engine

- `lacia_evolution.py` — 3 engines: calibration, conscience, pattern-miner
- `lacia_memory.py` — SQLite CLI backend

## 🔄 Cron Jobs

- Every hour: calibrate, conscience, pattern-miner, core-self-check
- Nightly: GitHub backup + consolidation
